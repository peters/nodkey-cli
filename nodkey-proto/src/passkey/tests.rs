use super::*;

fn cd(kind: &str, origin: &str) -> Vec<u8> {
    format!(r#"{{"type":"{kind}","challenge":"AAEC","origin":"{origin}","crossOrigin":false}}"#)
        .into_bytes()
}

#[test]
fn client_data_rules() {
    let get = PasskeyOp::Get;
    let ok = |rp: &str, origin: &str| check_client_data(get, rp, &cd("webauthn.get", origin));
    assert_eq!(
        ok("webauthn.io", "https://webauthn.io").unwrap().origin,
        "https://webauthn.io"
    );
    assert!(ok("webauthn.io", "https://www.webauthn.io").is_ok());
    assert!(ok("webauthn.io", "https://webauthn.io:8443").is_ok());
    assert!(ok("localhost", "http://localhost:8080").is_ok());
    assert!(ok("localhost", "https://localhost").is_ok());
    assert!(ok("example.com", "https://Login.Example.com").is_ok());

    assert!(ok("webauthn.io", "https://evilwebauthn.io").is_err());
    assert!(ok("webauthn.io", "https://webauthn.io.evil.com").is_err());
    assert!(ok("webauthn.io", "http://webauthn.io").is_err());
    assert!(ok("www.webauthn.io", "https://webauthn.io").is_err());
    assert!(ok("io", "https://webauthn.io").is_err());
    assert!(ok("127.0.0.1", "https://127.0.0.1").is_err());
    // A public suffix is never an rp_id: shared hosting and country endings alike.
    assert!(ok("github.io", "https://alice.github.io").is_err());
    assert!(ok("co.uk", "https://shop.example.co.uk").is_err());
    assert!(ok("herokuapp.com", "https://app.herokuapp.com").is_err());
    assert!(ok("alice.github.io", "https://alice.github.io").is_ok());
    assert!(ok("example.co.uk", "https://shop.example.co.uk").is_ok());
    assert!(ok("webauthn.io", "https://webauthn.io/").is_err());
    assert!(ok("webauthn.io", "https://webauthn.io:").is_err());
    assert!(ok("webauthn.io", "https://webauthn.io:99999").is_err());
    assert!(ok("webauthn.io", "https://user@webauthn.io").is_err());
    assert!(ok("webauthn.io", "android:apk-key-hash:abc").is_err());
    assert!(ok("localhost", "http://localhost.evil.com").is_err());

    // Wrong type, cross origin, no challenge, not JSON.
    assert!(
        check_client_data(
            get,
            "webauthn.io",
            &cd("webauthn.create", "https://webauthn.io")
        )
        .is_err()
    );
    assert!(
        check_client_data(
            PasskeyOp::Create,
            "webauthn.io",
            &cd("webauthn.create", "https://webauthn.io")
        )
        .is_ok()
    );
    let cross = br#"{"type":"webauthn.get","challenge":"AAEC","origin":"https://webauthn.io","crossOrigin":true}"#;
    assert!(check_client_data(get, "webauthn.io", cross).is_err());
    let absent = br#"{"type":"webauthn.get","challenge":"AAEC","origin":"https://webauthn.io"}"#;
    assert!(check_client_data(get, "webauthn.io", absent).is_ok());
    let no_challenge = br#"{"type":"webauthn.get","origin":"https://webauthn.io"}"#;
    assert!(check_client_data(get, "webauthn.io", no_challenge).is_err());
    let twice = br#"{"type":"webauthn.get","challenge":"AAEC","origin":"https://evil.com","origin":"https://webauthn.io"}"#;
    assert!(check_client_data(get, "webauthn.io", twice).is_err());
    assert!(check_client_data(get, "webauthn.io", b"[]").is_err());
}

#[test]
fn built_client_data_passes_its_own_check() {
    let json = build_client_data_json(PasskeyOp::Create, "AAEC", "https://webauthn.io");
    assert_eq!(
        json,
        r#"{"type":"webauthn.create","challenge":"AAEC","origin":"https://webauthn.io","crossOrigin":false}"#
    );
    let c = check_client_data(PasskeyOp::Create, "webauthn.io", json.as_bytes()).unwrap();
    assert_eq!(c.challenge, "AAEC");
}

#[test]
fn request_json_shape() {
    let get: PasskeyRequest =
        serde_json::from_str(r#"{"op":"get","rp_id":"webauthn.io","client_data_json":"e30"}"#)
            .unwrap();
    let PasskeyRequest::Get(g) = &get else {
        panic!("get")
    };
    assert!(g.allow_credentials.is_empty());
    assert_eq!(g.user_verification, Requirement::Preferred);
    let text = serde_json::to_string(&get).unwrap();
    assert!(
        text.starts_with(r#"{"op":"get","rp_id":"webauthn.io""#),
        "{text}"
    );

    let create = PasskeyRequest::Create(PasskeyCreate {
        rp_id: "webauthn.io".into(),
        rp_name: "WebAuthn.io".into(),
        client_data_json: b64u::encode(&cd("webauthn.create", "https://webauthn.io")),
        user: PasskeyUser {
            id: "AAEC".into(),
            name: "alex".into(),
            display_name: "Alex".into(),
        },
        algorithms: vec![ES256, -257],
        exclude_credentials: vec![],
        resident_key: Requirement::Required,
        user_verification: Requirement::Required,
        prf: None,
    });
    assert!(create.check("webauthn.io").is_ok());
    assert!(create.check("other.example").is_err());
    let back: PasskeyRequest =
        serde_json::from_str(&serde_json::to_string(&create).unwrap()).unwrap();
    assert_eq!(back, create);
    let mut bad = create.clone();
    if let PasskeyRequest::Create(c) = &mut bad {
        c.user.id = String::new();
    }
    assert!(bad.check("webauthn.io").is_err());
    let mut bad = create;
    if let PasskeyRequest::Create(c) = &mut bad {
        c.exclude_credentials = vec!["not base64!".into()];
    }
    assert!(bad.check("webauthn.io").is_err());
}
