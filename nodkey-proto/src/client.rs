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

/// Checks a request before it is sealed: what each kind needs, and the length limits. The text
/// is meant for the person or model that made the request.
pub fn check_request(r: &Request) -> Result<(), String> {
    let needs_target = matches!(
        r.kind,
        Kind::Code | Kind::Login | Kind::Save | Kind::Passkey
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
        (Kind::Save, _, None) => Err("a save request needs the login to save".into()),
        (Kind::Save, _, Some(s)) if s.username.trim().is_empty() || s.password.ct.is_empty() => {
            Err("a save request needs a user name and a password".into())
        }
        (Kind::Save, _, Some(s)) if s.url.chars().count() > 2000 => {
            Err("the page address is too long".into())
        }
        _ => Ok(()),
    };
    checked?;
    match (r.kind, &r.passkey) {
        (Kind::Passkey, None) => Err("a passkey request needs the passkey data".into()),
        (Kind::Passkey, Some(p)) => p.check(&r.target).map(|_| ()),
        (_, Some(_)) => Err("only a passkey request carries passkey data".into()),
        _ => Ok(()),
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
            client: None,
        }
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
        }));
        assert!(check_request(&p).is_ok());
        p.target = "evil.example".into();
        assert!(check_request(&p).is_err());
        p.kind = Kind::Code;
        assert!(check_request(&p).is_err());
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
