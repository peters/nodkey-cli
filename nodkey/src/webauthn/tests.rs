use super::*;
use nodkey_proto::{Answer, PasskeyAnswer, b64u, passkey::build_client_data_json, webauthn};

fn get_input(origin: &str, client_origin: &str) -> Vec<u8> {
    let cd = build_client_data_json(PasskeyOp::Get, "AAEC", client_origin);
    json!({
        "version": 1, "op": "get", "rp_id": "webauthn.io", "origin": origin,
        "client_data_json": b64u::encode(cd.as_bytes()),
        "requester": {"app": "Horizon", "agent": "Claude Code"},
    })
    .to_string()
    .into_bytes()
}

#[test]
fn parse_checks_the_origin_and_fills_defaults() {
    let c = parse(&get_input("https://webauthn.io", "https://webauthn.io")).unwrap();
    assert_eq!(c.reason, "Sign in to webauthn.io with a passkey");
    assert_eq!(c.app.as_deref(), Some("Horizon (Claude Code)"));
    assert_eq!(c.passkey.op(), PasskeyOp::Get);

    let e = parse(&get_input("https://evil.example", "https://webauthn.io")).unwrap_err();
    assert!(e.contains("not the origin"), "{e}");
    assert!(parse(&get_input("http://webauthn.io", "http://webauthn.io")).is_err());
    assert!(parse(b"{}").is_err());
    let mut v: Value =
        serde_json::from_slice(&get_input("https://webauthn.io", "https://webauthn.io")).unwrap();
    v["version"] = json!(2);
    assert!(
        parse(v.to_string().as_bytes())
            .unwrap_err()
            .contains("version")
    );
    v["version"] = json!(1);
    v["op"] = json!("create");
    // A create needs its own fields and a create client data type.
    assert!(
        parse(v.to_string().as_bytes())
            .unwrap_err()
            .contains("rp_name")
    );
}

fn exchanged(answer: Option<Answer>) -> Exchanged {
    Exchanged {
        answer,
        request_id: "rid".into(),
        phone: "Test iPhone".into(),
        attachment_warning: None,
    }
}

#[test]
fn results_and_exit_codes() {
    let cd = build_client_data_json(PasskeyOp::Get, "AAEC", "https://webauthn.io");
    let request = parse(&get_input("https://webauthn.io", "https://webauthn.io"))
        .unwrap()
        .passkey;

    let (v, code) = result(&request, &exchanged(None));
    assert_eq!((v["status"].as_str(), code), (Some("expired"), 3));

    let mut denied = Answer::decision("rid", Decision::Denied);
    for (error, status, exit) in [
        (Some("no_passkey"), "not_found", 2),
        (Some("excluded"), "excluded", 2),
        (Some("bad_client_data"), "denied", 2),
        (Some("unsupported_kind"), "error", 1),
        (None, "denied", 2),
    ] {
        denied.error = error.map(str::to_owned);
        let (v, code) = result(&request, &exchanged(Some(denied.clone())));
        assert_eq!(
            (v["status"].as_str(), code),
            (Some(status), exit),
            "{error:?}"
        );
        assert_eq!(v["error"].as_str(), error);
        assert_eq!(v["version"], 1);
    }

    let key = webauthn::signing_key(&[5; 32]).unwrap();
    let auth = webauthn::authenticator_data("webauthn.io", None);
    let mut ok = Answer::decision("rid", Decision::Approved);
    ok.passkey = Some(PasskeyAnswer {
        credential_id: b64u::encode(&[1; 16]),
        attestation_object: None,
        authenticator_data: b64u::encode(&auth),
        signature: Some(b64u::encode(&webauthn::sign(&key, &auth, cd.as_bytes()))),
        user_handle: Some(b64u::encode(&[2; 16])),
        user_name: Some("alex".into()),
        public_key: None,
        public_key_algorithm: None,
        prf: None,
    });
    let (v, code) = result(&request, &exchanged(Some(ok.clone())));
    assert_eq!((v["status"].as_str(), code), (Some("ok"), 0));
    assert!(v.get("user_name").is_none() && v.get("transports").is_none());
    assert_eq!(
        v["signature"],
        ok.passkey.as_ref().unwrap().signature.clone().unwrap()
    );

    // An answer for another site is not handed on.
    ok.passkey.as_mut().unwrap().authenticator_data =
        b64u::encode(&webauthn::authenticator_data("evil.example", None));
    let (v, code) = result(&request, &exchanged(Some(ok)));
    assert_eq!((v["status"].as_str(), code), (Some("error"), 1));
}

fn with_prf(mut input: Value, prf: Value) -> Vec<u8> {
    input["extensions"] = json!({"prf": prf, "credProps": true});
    input.to_string().into_bytes()
}

fn get_value() -> Value {
    serde_json::from_slice(&get_input("https://webauthn.io", "https://webauthn.io")).unwrap()
}

#[test]
fn parse_takes_the_prf_extension_in_webauthn_form() {
    let id = b64u::encode(&[1; 16]);
    let mut v = get_value();
    v["allow_credentials"] = json!([id]);
    let c = parse(&with_prf(
        v.clone(),
        json!({"eval": {"first": "AAEC"}, "evalByCredential": {id.clone(): {"first": "AQ"}}}),
    ))
    .unwrap();
    assert_eq!(c.reason, "Unlock a key for webauthn.io");
    let prf = c.passkey.prf().unwrap();
    assert_eq!(prf.values_for(&id).unwrap().first, "AQ");
    assert!(c.passkey.needs_prf_output());

    // WebAuthn's rules: get needs inputs, keys must be allowed, no unknown prf fields.
    assert!(parse(&with_prf(v.clone(), json!({}))).is_err());
    let other = b64u::encode(&[2; 16]);
    let e = parse(&with_prf(
        v.clone(),
        json!({"evalByCredential": {other: {"first": "AQ"}}}),
    ))
    .unwrap_err();
    assert!(e.contains("allow_credentials"), "{e}");
    assert!(parse(&with_prf(v, json!({"eval": {"first": "AQ"}, "evil": 1}))).is_err());
}

fn ok_answer(request: &PasskeyRequest, prf: Option<nodkey_proto::PrfOutput>) -> Answer {
    let key = webauthn::signing_key(&[5; 32]).unwrap();
    let auth = webauthn::authenticator_data("webauthn.io", None);
    let cd = b64u::decode(request.client_data_json()).unwrap();
    let mut ok = Answer::decision("rid", Decision::Approved);
    ok.passkey = Some(PasskeyAnswer {
        credential_id: b64u::encode(&[1; 16]),
        attestation_object: None,
        authenticator_data: b64u::encode(&auth),
        signature: Some(b64u::encode(&webauthn::sign(&key, &auth, &cd))),
        user_handle: Some(b64u::encode(&[2; 16])),
        user_name: Some("alex".into()),
        public_key: None,
        public_key_algorithm: None,
        prf,
    });
    ok
}

#[test]
fn prf_results_and_refusals() {
    let request = parse(&with_prf(
        get_value(),
        json!({"eval": {"first": "AAEC", "second": "AQ"}}),
    ))
    .unwrap()
    .passkey;
    let out = |n: u8| nodkey_proto::Secret::new(b64u::encode(&[n; 32]));
    let prf = nodkey_proto::PrfOutput {
        enabled: None,
        results: Some(nodkey_proto::PrfResults {
            first: out(3),
            second: Some(out(4)),
        }),
    };
    let (v, code) = result(
        &request,
        &exchanged(Some(ok_answer(&request, Some(prf.clone())))),
    );
    assert_eq!(code, 0, "{v}");
    assert_eq!(
        v["clientExtensionResults"],
        json!({"prf": {"results": {"first": b64u::encode(&[3; 32]), "second": b64u::encode(&[4; 32])}}})
    );

    // Signed without PRF output (an old passkey or app): not handed on as a success.
    let (v, code) = result(&request, &exchanged(Some(ok_answer(&request, None))));
    assert_eq!((v["status"].as_str(), code), (Some("prf_unsupported"), 2));
    // The phone's refusal at once.
    let mut denied = Answer::decision("rid", Decision::Denied);
    denied.error = Some("prf_unsupported".into());
    let (v, code) = result(&request, &exchanged(Some(denied)));
    assert_eq!((v["status"].as_str(), code), (Some("prf_unsupported"), 2));
    assert_eq!(v["error"], "prf_unsupported");

    // A PRF answer from a lease is refused; PRF needs Face ID.
    let mut leased = ok_answer(&request, Some(prf.clone()));
    leased.lease = Some(nodkey_proto::Lease {
        kind: LeaseKind::Day,
        until: Some(1),
    });
    let (v, code) = result(&request, &exchanged(Some(leased)));
    assert_eq!((v["status"].as_str(), code), (Some("error"), 1), "{v}");

    // Only the second output: does not match the inputs.
    let mut half = prf;
    half.results.as_mut().unwrap().second = None;
    let (v, code) = result(&request, &exchanged(Some(ok_answer(&request, Some(half)))));
    assert_eq!((v["status"].as_str(), code), (Some("error"), 1), "{v}");

    // No prf in the request: no clientExtensionResults.
    let plain = parse(&get_input("https://webauthn.io", "https://webauthn.io"))
        .unwrap()
        .passkey;
    let (v, _) = result(&plain, &exchanged(Some(ok_answer(&plain, None))));
    assert!(v.get("clientExtensionResults").is_none());
}
