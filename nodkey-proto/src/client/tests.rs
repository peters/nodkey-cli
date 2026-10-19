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
        project: None,
        nonce: None,
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
    // With the signature, which always comes along.
    let n = n - 1 + crate::signed::SUFFIX_LEN;
    assert_eq!(sealed_ct_len(&small), b64u::encode(&vec![0u8; n]).len());
    let phone = KeyPair::generate().public().kem;
    let env = seal_request(
        &small,
        "a",
        "p",
        &phone,
        &KeyPair::generate().signing_key(),
        false,
    );
    assert_eq!(env.unwrap().ct.len(), sealed_ct_len(&small));
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
    let env = seal_request(
        &r,
        &agent_id,
        &phone_id,
        &phone.public().kem,
        &agent.signing_key(),
        false,
    )
    .unwrap();
    assert_eq!(env.attachment, None);
    let plain = Purpose::Request
        .open(
            phone.kem_secret(),
            &b64u::decode(&env.enc).unwrap(),
            &aad(&r.request_id, &agent_id),
            &b64u::decode(&env.ct).unwrap(),
        )
        .unwrap();
    // A phone made before signatures reads the request as before.
    let back: Request = parse_plaintext(&plain).unwrap();
    assert_eq!(back, r);
    // A phone that checks: the agent's key, this agent and this phone.
    let opened = signed::open(
        Direction::Request,
        &agent_id,
        &phone_id,
        &plain,
        &agent.public().sign,
        true,
    )
    .unwrap();
    assert!(opened.signed);
    assert_eq!(parse_plaintext::<Request>(&opened.body).unwrap(), r);

    // The same request signed elsewhere (WebCrypto) gives the same plaintext.
    let to_sign = request_to_sign(&r, &agent_id, &phone_id).unwrap();
    use ed25519_dalek::Signer;
    let sig = agent.signing_key().sign(&to_sign.message).to_bytes();
    let kem = phone.public().kem;
    let env2 = seal_signed_request(&r, &to_sign.body, &sig, &agent_id, &kem, false).unwrap();
    let plain2 = Purpose::Request
        .open_box(
            phone.kem_secret(),
            &SealedBox {
                enc: env2.enc,
                ct: env2.ct,
            },
            &aad(&r.request_id, &agent_id),
        )
        .unwrap();
    assert_eq!(&plain2[..], &plain[..]);

    let answer = Answer::decision(&r.request_id, Decision::Denied);
    let from = AnswerFrom {
        agent_id: &agent_id,
        phone_id: &phone_id,
        sign: &phone.public().sign,
        signs: true,
    };
    let seal_answer = |plain: &[u8]| {
        let sealed = Purpose::Answer
            .seal(
                &agent.public().kem,
                &answer_aad(&r.request_id, &phone_id),
                plain,
            )
            .unwrap();
        Purpose::Answer
            .open_box(
                agent.kem_secret(),
                &sealed.to_box(),
                &answer_aad(&r.request_id, &phone_id),
            )
            .unwrap()
    };
    let json = serde_json::to_vec(&answer).unwrap();
    let signed_plain = seal_answer(
        &signed::sign(
            Direction::Answer,
            &agent_id,
            &phone_id,
            &json,
            &phone.signing_key(),
        )
        .unwrap(),
    );
    assert_eq!(
        read_answer(&signed_plain, &r.request_id, &from).unwrap(),
        (answer.clone(), true)
    );
    assert!(read_answer(&signed_plain, "other", &from).is_err());
    // Unsigned: refused once the phone signs, read as before from a phone that never did.
    let unsigned = seal_answer(&json);
    assert!(matches!(
        read_answer(&unsigned, &r.request_id, &from),
        Err(Error::BadSignature(_))
    ));
    let older = AnswerFrom {
        signs: false,
        ..from
    };
    assert_eq!(
        read_answer(&unsigned, &r.request_id, &older).unwrap(),
        (answer, false)
    );
    // Signed by someone else: refused, also from a phone that never signed.
    let forged = seal_answer(
        &signed::sign(
            Direction::Answer,
            &agent_id,
            &phone_id,
            &json,
            &KeyPair::generate().signing_key(),
        )
        .unwrap(),
    );
    assert!(read_answer(&forged, &r.request_id, &older).is_err());
}

#[test]
fn pairing_check_requests() {
    let mut r = crate::pairing::check_request("Test agent", &[7; 32], 1);
    assert!(check_request(&r).is_ok());
    r.reason = "Pair".into();
    assert!(check_request(&r).unwrap_err().contains("only the nonce"));
    r.reason = String::new();
    r.nonce = Some("short".into());
    assert!(check_request(&r).unwrap_err().contains("nonce"));
    let mut c = request(Kind::Code, "github.com", "Merge");
    c.nonce = Some(b64u::encode(&[7; 32]));
    assert!(
        check_request(&c)
            .unwrap_err()
            .contains("only a pairing_check")
    );
}

#[test]
fn attachment_hash() {
    let info = attachment_info(ImageType::Png, b"png bytes", None);
    assert_eq!(info.bytes, 9);
    assert_eq!(
        info.sha256.unwrap(),
        b64u::encode(&Sha256::digest(b"png bytes"))
    );
}
