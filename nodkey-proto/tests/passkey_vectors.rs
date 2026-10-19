//! Checks the passkey vectors of a phone without a passcode in `vectors/v1.json`: the
//! `webauthn.no_passcode` table decides the same way as `PasskeyRequest::needs_passcode`, the
//! refusals carry `no_passcode`, and the answers without UV verify and pass the agent's check.

use nodkey_proto::{Answer, Decision, PasskeyRequest, Request, b64u, passkey, webauthn};
use serde_json::{Value, json};

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/v1.json");

fn load() -> Value {
    serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap()
}

fn plaintext<T: serde::de::DeserializeOwned>(v: &Value, name: &str) -> T {
    let h = v["hpke"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["name"] == name)
        .unwrap_or_else(|| panic!("{name}"));
    serde_json::from_str(h["plaintext"].as_str().unwrap()).unwrap()
}

#[test]
fn the_table_decides_like_the_library() {
    let v = load();
    let cases = v["webauthn"]["no_passcode"].as_array().unwrap();
    assert!(cases.iter().any(|c| c["refused"] == true));
    assert!(cases.iter().any(|c| c["refused"] == false));
    for c in cases {
        let mut r = json!({"op": c["op"], "rp_id": "webauthn.io", "client_data_json": "e30",
                           "user_verification": c["user_verification"]});
        if c["op"] == "create" {
            r["rp_name"] = json!("WebAuthn.io");
            r["user"] = json!({"id": "AAEC", "name": "alex", "display_name": "Alex"});
            r["algorithms"] = json!([-7]);
        }
        if c["prf"] == true {
            r["prf"] = json!({"eval": {"first": "AAEC"}});
        }
        let request: PasskeyRequest = serde_json::from_value(r).unwrap();
        assert_eq!(request.needs_passcode(), c["refused"] == true, "{c}");
    }
}

#[test]
fn refusals_and_answers_without_uv() {
    let v = load();
    for (answer, request) in [
        ("answer_passkey_no_passcode", "request_passkey_get"),
        (
            "answer_passkey_get_prf_no_passcode",
            "request_passkey_get_prf",
        ),
    ] {
        let a: Answer = plaintext(&v, answer);
        let r: Request = plaintext(&v, request);
        assert_eq!(a.request_id, r.request_id);
        assert_eq!(
            (a.decision, a.error.as_deref()),
            (Decision::Denied, Some(passkey::errors::NO_PASSCODE))
        );
        assert!(r.passkey.unwrap().needs_passcode(), "{request}");
    }

    let key = webauthn::key_from_spki(
        &b64u::decode(v["webauthn"]["public_key_spki"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    for (answer, request, flags) in [
        (
            "answer_passkey_get_without_uv",
            "request_passkey_get_preferred",
            webauthn::FLAGS_WITHOUT_UV,
        ),
        (
            "answer_passkey_create_without_uv",
            "request_passkey_create_preferred",
            webauthn::FLAGS_WITHOUT_UV | webauthn::FLAG_AT,
        ),
    ] {
        let a: Answer = plaintext(&v, answer);
        let r: Request = plaintext(&v, request);
        let passkey = r.passkey.unwrap();
        assert!(!passkey.needs_passcode(), "{request}");
        let p = a.passkey.unwrap();
        let auth = b64u::decode(&p.authenticator_data).unwrap();
        assert_eq!(auth[32], flags, "{answer}");
        webauthn::check_answer(&passkey, &p).unwrap();
        if let Some(sig) = &p.signature {
            let client_data = b64u::decode(passkey.client_data_json()).unwrap();
            webauthn::verify(&key, &auth, &client_data, &b64u::decode(sig).unwrap()).unwrap();
        }
    }
}
