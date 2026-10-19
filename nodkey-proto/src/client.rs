//! The agent's side of pairing and requests, shared by every agent (the `nodkey` binary and the
//! browser extension). Network calls, key storage and the X25519 step of opening stay with the
//! caller: it opens a sealed box with [`crate::Purpose::open_box`] (private key in memory) or
//! [`crate::dh::open_with_dh`] (key in WebCrypto) and hands the plaintext to the `read_*`
//! functions here.

use zeroize::Zeroizing;

use crate::{
    Answer, Error, Kind, PairingGrant, PublicKeys, Purpose, Request, RequestEnvelope, SealedBox,
    aad, b64u, check, parse_plaintext,
    seal::{OsRng, seal_attachment_body},
};

/// Longest `reason` and `target` the agent sends, in characters.
pub const MAX_REASON: usize = 500;
pub const MAX_TARGET: usize = 200;
/// Longest `ct` (b64u characters) of a sealed request the relay takes, so the push stays under
/// APNs' 4 KB (relay `REQUEST_CT_MAX`).
pub const REQUEST_CT_MAX: usize = 3400;

/// The length of `ct` once `r` is sealed: the JSON plus the 16-byte tag, in b64u characters.
pub fn sealed_ct_len(r: &Request) -> usize {
    let sealed = serde_json::to_vec(r).map_or(usize::MAX / 8, |v| v.len()) + 16;
    (4 * sealed).div_ceil(3)
}

/// Checks a request before it is sealed: what each kind needs, and the length limits. The text
/// is meant for the person or model that made the request.
pub fn check_request(r: &Request) -> Result<(), String> {
    let needs_target = matches!(
        r.kind,
        Kind::Code
            | Kind::Login
            | Kind::Save
            | Kind::Passkey
            | Kind::Card
            | Kind::Suggest
            | Kind::SmsCode
            | Kind::Secret
            | Kind::SaveSecret
    );
    if needs_target && r.target.trim().is_empty() {
        return Err(
            "target is required (a site or issuer, optionally /account, e.g. github.com/alex)"
                .into(),
        );
    }
    if r.reason.trim().is_empty() {
        return Err(
            "reason is required: say in a short sentence why you need it; the user reads it on their iPhone"
                .into(),
        );
    }
    if r.reason.chars().count() > MAX_REASON || r.target.chars().count() > MAX_TARGET {
        return Err("target or reason is too long".into());
    }
    let checked: Result<(), String> = match (r.kind, &r.filter, &r.save) {
        (Kind::Cleanup, None, _) => Err("filter needs at least one criterion".into()),
        (Kind::Cleanup, Some(f), _) if f.is_empty() => {
            Err("filter needs at least one criterion".into())
        }
        (Kind::Save, _, Some(_)) if r.save_card.is_some() => {
            Err("a save request carries a login or a card, not both".into())
        }
        (Kind::Save, _, None) => match &r.save_card {
            Some(c) => c.check(),
            None => Err("a save request needs the login or card to save".into()),
        },
        (Kind::Save, _, Some(s)) if s.username.trim().is_empty() || s.password.ct.is_empty() => {
            Err("a save request needs a user name and a password".into())
        }
        (Kind::Save, _, Some(s)) if s.url.chars().count() > 2000 => {
            Err("the page address is too long".into())
        }
        _ if r.save_card.is_some() => Err("only a save request carries a card to save".into()),
        _ => Ok(()),
    };
    checked?;
    match (r.kind, &r.passkey) {
        (Kind::Passkey, None) => Err("a passkey request needs the passkey data".into()),
        (Kind::Passkey, Some(p)) => p.check(&r.target).map(|_| ()),
        (_, Some(_)) => Err("only a passkey request carries passkey data".into()),
        _ => Ok(()),
    }?;
    match (r.kind, &r.bundle) {
        (Kind::Bundle, None) => Err("a bundle request needs its items".into()),
        (Kind::Bundle, Some(_)) if !r.target.is_empty() => {
            Err("a bundle has no target of its own; give each item its target".into())
        }
        (Kind::Bundle, Some(b)) => b.check(),
        (_, Some(_)) => Err("only a bundle request carries items".into()),
        _ => Ok(()),
    }?;
    match (r.kind, &r.card) {
        (Kind::Card, None) => Err("a card request needs the merchant and the amount".into()),
        (Kind::Card, Some(c)) => c.check(&r.target).map_err(|(_, e)| e),
        (_, Some(_)) => Err("only a card request carries card data".into()),
        _ => Ok(()),
    }?;
    check_signin(r)?;
    crate::apikey::check_request(r)?;
    check_session(r)?;
    if sealed_ct_len(r) > REQUEST_CT_MAX {
        return Err(
            "the request is too large to send to the phone; ask for fewer items or shorten the reason"
                .into(),
        );
    }
    Ok(())
}

/// The `suggest` and `sms_code` rules: a suggestion names a clean site and a valid method, and
/// `wait_seconds` belongs to `sms_code` only, within its range.
fn check_signin(r: &Request) -> Result<(), String> {
    match (r.kind, &r.suggest) {
        (Kind::Suggest, None) => Err("a suggest request needs the method and the outcome".into()),
        (Kind::Suggest, Some(_))
            if crate::signin::site(&r.target).as_deref() != Some(r.target.as_str()) =>
        {
            Err("a suggestion's target is the site's host, for example example.com".into())
        }
        (Kind::Suggest, Some(s)) => s.check(),
        (_, Some(_)) => Err("only a suggest request carries a suggestion".into()),
        _ => Ok(()),
    }?;
    match (r.kind, r.wait_seconds) {
        (Kind::SmsCode, w) if crate::signin::sms_wait(w).is_none() => Err(format!(
            "wait_seconds must be {} to {}",
            crate::signin::SMS_WAIT_MIN,
            crate::signin::SMS_WAIT_MAX
        )),
        (Kind::SmsCode, _) | (_, None) => Ok(()),
        (_, Some(_)) => Err("only an sms_code request carries wait_seconds".into()),
    }
}

/// The task session rules: `session_end` names a session and nothing else; a session id has the
/// right shape and goes only on requests a session can cover.
fn check_session(r: &Request) -> Result<(), String> {
    match (&r.kind, &r.session_id) {
        (Kind::SessionEnd, None) => Err("session_end needs the session_id".into()),
        (Kind::SessionEnd, Some(_)) if !r.target.is_empty() => {
            Err("session_end has no target".into())
        }
        (_, Some(id)) if !crate::session::valid_id(id) => {
            Err("session_id must be 22 base64url characters".into())
        }
        (Kind::Code | Kind::Login | Kind::Passkey | Kind::Secret | Kind::SessionEnd, _)
        | (_, None) => Ok(()),
        (_, Some(_)) => {
            Err("only code, login, passkey and secret requests belong to a session".into())
        }
    }
}

/// Seals a checked request to the phone: the envelope to `POST /v1/phones/{phone_id}/requests`.
/// `attachment` says whether a picture follows.
pub fn seal_request(
    request: &Request,
    agent_id: &str,
    phone_kem: &[u8; 32],
    attachment: bool,
) -> Result<RequestEnvelope, Error> {
    let plain = Zeroizing::new(serde_json::to_vec(request)?);
    let sealed = Purpose::Request.seal(phone_kem, &aad(&request.request_id, agent_id), &plain)?;
    Ok(RequestEnvelope {
        request_id: request.request_id.clone(),
        enc: b64u::encode(&sealed.enc),
        ct: b64u::encode(&sealed.ct),
        attachment: attachment.then_some(true),
        ttl: relay_ttl(request),
    })
}

/// The envelope's `ttl`: an `sms_code` request stays at the relay for its wait plus the time to
/// approve; every other request keeps the relay's 120 s.
pub fn relay_ttl(request: &Request) -> Option<u32> {
    (request.kind == Kind::SmsCode).then(|| {
        crate::signin::sms_wait(request.wait_seconds).unwrap_or(crate::signin::SMS_WAIT_DEFAULT)
            + crate::signin::SMS_APPROVE_MARGIN
    })
}

/// Seals the password of a `save` request to the phone on its own. The result can be kept and
/// sent again in a new request; only the phone can open it.
pub fn seal_password(
    agent_id: &str,
    phone_kem: &[u8; 32],
    password: &str,
) -> Result<SealedBox, Error> {
    if password.is_empty() {
        return Err(Error::Encoding("empty password"));
    }
    Ok(Purpose::Password
        .seal(phone_kem, agent_id.as_bytes(), password.as_bytes())?
        .to_box())
}

/// Seals a card number or CVC for a `save` request to the phone on its own, like a password.
pub fn seal_card_secret(
    agent_id: &str,
    phone_kem: &[u8; 32],
    secret: &str,
) -> Result<SealedBox, Error> {
    if secret.trim().is_empty() {
        return Err(Error::Encoding("empty card value"));
    }
    Ok(Purpose::Card
        .seal(phone_kem, agent_id.as_bytes(), secret.as_bytes())?
        .to_box())
}

/// Seals a picture for `PUT /v1/requests/{request_id}/attachment`.
pub fn seal_attachment(
    request_id: &str,
    agent_id: &str,
    phone_kem: &[u8; 32],
    image: &[u8],
) -> Result<Vec<u8>, Error> {
    seal_attachment_body(phone_kem, &aad(request_id, agent_id), image, &mut OsRng)
}

/// The `aad` of the phone's answer to `request_id`.
pub fn answer_aad(request_id: &str, phone_id: &str) -> Vec<u8> {
    aad(request_id, phone_id)
}

/// The `aad` of the pairing grant for `code` (canonical, without the dash).
pub fn grant_aad(code: &str, phone_id: &str) -> Vec<u8> {
    aad(code, phone_id)
}

/// Reads an opened answer and checks that it belongs to `request_id`.
pub fn read_answer(plain: &[u8], request_id: &str) -> Result<Answer, Error> {
    let answer: Answer = parse_plaintext(plain)?;
    if answer.request_id != request_id {
        return Err(Error::Json(
            "the answer belongs to a different request".into(),
        ));
    }
    Ok(answer)
}

/// Reads an opened pairing grant and checks its check number against the one computed from both
/// sides' public keys. A different number means someone swapped keys: do not save the pairing.
pub fn read_grant(
    plain: &[u8],
    agent: &PublicKeys,
    phone: &PublicKeys,
) -> Result<PairingGrant, Error> {
    let grant: PairingGrant = parse_plaintext(plain)?;
    let n = check::check_number(agent, phone);
    if grant.check != check::digits(n) {
        return Err(Error::CheckMismatch {
            phone: grant.check.clone(),
            computed: check::display(n),
        });
    }
    Ok(grant)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CleanupFilter, Decision, KeyPair, SaveLogin, VERSION};

    fn request(kind: Kind, target: &str, reason: &str) -> Request {
        Request {
            v: VERSION,
            request_id: crate::random_id(),
            kind,
            target: target.into(),
            reason: reason.into(),
            agent: "Test".into(),
            ts: 1,
            attachment: None,
            filter: None,
            save: None,
            passkey: None,
            bundle: None,
            card: None,
            save_card: None,
            client: None,
            session_id: None,
            suggest: None,
            wait_seconds: None,
            save_secret: None,
        }
    }

    #[test]
    fn bundle_checks_and_the_sealed_size() {
        let item = |id: &str, target: &str| crate::BundleItem {
            id: id.into(),
            kind: Kind::Login,
            target: target.into(),
        };
        let mut b = request(Kind::Bundle, "", "Sign in to two sites");
        assert!(check_request(&b).unwrap_err().contains("items"));
        b.bundle = Some(crate::BundleRequest {
            items: vec![item("1", "chatgpt.com"), item("2", "github.com")],
            follow_up: None,
            session: None,
        });
        assert!(check_request(&b).is_ok());
        b.target = "chatgpt.com".into();
        assert!(check_request(&b).unwrap_err().contains("no target"));
        let mut c = request(Kind::Code, "github.com", "Merge");
        c.bundle = b.bundle.clone();
        assert!(check_request(&c).unwrap_err().contains("only a bundle"));

        // Six long targets, a long reason and every client field at its longest do not fit in a push.
        b.target = String::new();
        b.reason = "r".repeat(500);
        let long = || Some("c".repeat(80));
        b.client = Some(crate::ClientInfo {
            app: long(),
            app_version: long(),
            model: long(),
            effort: long(),
            os: long(),
            host: long(),
            workdir: long(),
            mcp_version: long(),
        });
        b.bundle = Some(crate::BundleRequest {
            items: (1..=6)
                .map(|i| item(&i.to_string(), &"t".repeat(200)))
                .collect(),
            follow_up: Some(600),
            session: None,
        });
        assert!(sealed_ct_len(&b) > REQUEST_CT_MAX);
        assert!(check_request(&b).unwrap_err().contains("too large"));
        // The length is the b64u length of the JSON and the tag.
        let small = request(Kind::List, "", "See");
        let n = serde_json::to_vec(&small).unwrap().len() + 16;
        assert_eq!(sealed_ct_len(&small), b64u::encode(&vec![0u8; n]).len());
    }

    #[test]
    fn checks() {
        assert!(check_request(&request(Kind::Code, "github.com", "Merge")).is_ok());
        assert!(check_request(&request(Kind::Code, " ", "Merge")).is_err());
        assert!(check_request(&request(Kind::List, "", "See")).is_ok());
        assert!(check_request(&request(Kind::List, "", " ")).is_err());
        assert!(check_request(&request(Kind::Code, "x", &"r".repeat(501))).is_err());
        let mut c = request(Kind::Cleanup, "", "Old routers");
        assert!(check_request(&c).is_err());
        c.filter = Some(CleanupFilter::default());
        assert!(check_request(&c).is_err());
        c.filter = Some(CleanupFilter {
            ip_only: Some(true),
            ..Default::default()
        });
        assert!(check_request(&c).is_ok());
        let mut s = request(Kind::Save, "vg.no", "Save the login");
        assert!(check_request(&s).is_err());
        s.save = Some(SaveLogin {
            url: "https://vg.no".into(),
            username: "alex".into(),
            password: SealedBox {
                enc: String::new(),
                ct: String::new(),
            },
            title: None,
        });
        assert!(check_request(&s).is_err());
        let phone = KeyPair::generate();
        let sealed = seal_password("agent", &phone.public().kem, "pw").unwrap();
        s.save.as_mut().unwrap().password = sealed.clone();
        assert!(check_request(&s).is_ok());
        let opened = Purpose::Password
            .open_box(phone.kem_secret(), &sealed, b"agent")
            .unwrap();
        assert_eq!(&opened[..], b"pw");
        assert!(
            Purpose::Password
                .open_box(phone.kem_secret(), &sealed, b"other")
                .is_err()
        );
        assert!(seal_password("agent", &phone.public().kem, "").is_err());

        let mut p = request(Kind::Passkey, "webauthn.io", "Sign in");
        assert!(check_request(&p).is_err());
        let cd = crate::passkey::build_client_data_json(
            crate::PasskeyOp::Get,
            "AAEC",
            "https://webauthn.io",
        );
        p.passkey = Some(crate::PasskeyRequest::Get(crate::PasskeyGet {
            rp_id: "webauthn.io".into(),
            client_data_json: b64u::encode(cd.as_bytes()),
            allow_credentials: vec![],
            user_verification: crate::Requirement::Preferred,
            prf: None,
        }));
        assert!(check_request(&p).is_ok());
        p.target = "evil.example".into();
        assert!(check_request(&p).is_err());
        p.kind = Kind::Code;
        assert!(check_request(&p).is_err());
    }

    #[test]
    fn signin_checks() {
        let mut s = request(Kind::Suggest, "renderfarm.example", "Signed in with Google");
        assert!(
            check_request(&s)
                .unwrap_err()
                .contains("method and the outcome")
        );
        s.suggest = Some(crate::Suggestion {
            method: crate::SignInMethod::federated(crate::Provider::Google, None),
            outcome: crate::SuggestOutcome::SignedIn,
        });
        assert!(check_request(&s).is_ok());
        s.target = "https://renderfarm.example/login".into();
        assert!(check_request(&s).unwrap_err().contains("host"));
        s.target = "renderfarm.example".into();
        s.session_id = Some("Qm9vdHN0cmFwU2Vzc2lvbg".into());
        assert!(
            check_request(&s)
                .unwrap_err()
                .contains("belong to a session")
        );
        s.session_id = None;
        s.suggest.as_mut().unwrap().method.provider = None;
        assert!(check_request(&s).unwrap_err().contains("provider"));
        let mut l = request(Kind::Login, "vg.no", "Sign in");
        l.suggest = s.suggest.clone();
        assert!(check_request(&l).unwrap_err().contains("only a suggest"));

        let mut m = request(
            Kind::SmsCode,
            "appleid.example",
            "The site sent a code by SMS",
        );
        assert!(check_request(&m).is_ok());
        m.wait_seconds = Some(300);
        assert!(check_request(&m).is_ok());
        m.wait_seconds = Some(301);
        assert!(check_request(&m).unwrap_err().contains("30 to 300"));
        m.target = String::new();
        m.wait_seconds = None;
        assert!(check_request(&m).unwrap_err().contains("target"));
        let mut c = request(Kind::Code, "github.com", "Merge");
        c.wait_seconds = Some(120);
        assert!(check_request(&c).unwrap_err().contains("only an sms_code"));
    }

    #[test]
    fn card_checks() {
        let money = |v: &str| crate::Money::parse(v, "NOK").unwrap();
        let mut c = request(
            Kind::Card,
            "shop.example.com",
            "Buy the cable you asked for",
        );
        assert!(
            check_request(&c)
                .unwrap_err()
                .contains("merchant and the amount")
        );
        c.card = Some(crate::CardRequest {
            mode: crate::CardMode::Reveal,
            merchant: "shop.example.com".into(),
            amount: Some(money("499")),
            origin: None,
            page_total: None,
            total_source: None,
        });
        assert!(check_request(&c).is_ok());
        c.card.as_mut().unwrap().amount = None;
        assert!(check_request(&c).unwrap_err().contains("amount"));
        let mut code = request(Kind::Code, "github.com", "Merge");
        code.card = c.card.clone();
        assert!(check_request(&code).unwrap_err().contains("only a card"));

        let phone = KeyPair::generate();
        let number = seal_card_secret("agent", &phone.public().kem, "4242424242424242").unwrap();
        let opened = Purpose::Card
            .open_box(phone.kem_secret(), &number, b"agent")
            .unwrap();
        assert_eq!(&opened[..], b"4242424242424242");
        assert!(
            Purpose::Password
                .open_box(phone.kem_secret(), &number, b"agent")
                .is_err()
        );
        assert!(seal_card_secret("agent", &phone.public().kem, " ").is_err());
        let mut s = request(
            Kind::Save,
            "shop.example.com",
            "Save the card you just used",
        );
        s.save_card = Some(crate::SaveCard {
            number,
            cvc: None,
            exp_month: 12,
            exp_year: 2030,
            holder: None,
            url: None,
            last4: "4242".into(),
        });
        assert!(check_request(&s).is_ok());
        s.save = Some(SaveLogin {
            url: "https://vg.no".into(),
            username: "alex".into(),
            password: seal_password("agent", &phone.public().kem, "pw").unwrap(),
            title: None,
        });
        assert!(check_request(&s).unwrap_err().contains("not both"));
        let mut l = request(Kind::Login, "vg.no", "Sign in");
        l.save_card = s.save_card.clone();
        assert!(check_request(&l).unwrap_err().contains("only a save"));
    }

    #[test]
    fn request_and_answer_round_trip() {
        let phone = KeyPair::generate();
        let agent = KeyPair::generate();
        let (agent_id, phone_id) = (crate::random_id(), crate::random_id());
        let r = request(Kind::Code, "github.com", "Merge");
        let env = seal_request(&r, &agent_id, &phone.public().kem, false).unwrap();
        assert_eq!(env.attachment, None);
        let plain = Purpose::Request
            .open(
                phone.kem_secret(),
                &b64u::decode(&env.enc).unwrap(),
                &aad(&r.request_id, &agent_id),
                &b64u::decode(&env.ct).unwrap(),
            )
            .unwrap();
        let back: Request = parse_plaintext(&plain).unwrap();
        assert_eq!(back, r);

        let answer = Answer::decision(&r.request_id, Decision::Denied);
        let sealed = Purpose::Answer
            .seal(
                &agent.public().kem,
                &answer_aad(&r.request_id, &phone_id),
                &serde_json::to_vec(&answer).unwrap(),
            )
            .unwrap();
        let plain = Purpose::Answer
            .open_box(
                agent.kem_secret(),
                &sealed.to_box(),
                &answer_aad(&r.request_id, &phone_id),
            )
            .unwrap();
        assert_eq!(read_answer(&plain, &r.request_id).unwrap(), answer);
        assert!(read_answer(&plain, "other").is_err());
    }

    #[test]
    fn grant_check_number() {
        let (agent, phone) = (KeyPair::generate().public(), KeyPair::generate().public());
        let n = check::check_number(&agent, &phone);
        let grant = |check: String| {
            serde_json::to_vec(&PairingGrant {
                v: VERSION,
                phone_name: "Test iPhone".into(),
                scope: crate::Scope::Selected,
                check,
            })
            .unwrap()
        };
        assert!(read_grant(&grant(check::digits(n)), &agent, &phone).is_ok());
        let wrong = check::digits((n + 1) % 1_000_000);
        assert!(matches!(
            read_grant(&grant(wrong), &agent, &phone),
            Err(Error::CheckMismatch { .. })
        ));
    }
}
