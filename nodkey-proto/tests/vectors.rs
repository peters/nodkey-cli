//! Checks `vectors/v1.json`: it must match what the generator makes today (stability), and
//! every vector must verify on its own the way a recipient would check it.

use nodkey_proto::{
    KeyPair, PublicKeys, Purpose, auth, b64u, check, code,
    seal::{self, ENC_LEN},
    testing::FixedRng,
};
use serde_json::Value;

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/v1.json");

fn load() -> Value {
    let text = std::fs::read_to_string(PATH).expect("vectors file exists; run the vectors example");
    serde_json::from_str(&text).expect("valid JSON")
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or_else(|| panic!("{k} missing"))
}

fn arr32(v: &Value, k: &str) -> [u8; 32] {
    b64u::decode_array(s(v, k)).unwrap()
}

#[test]
fn file_matches_generator() {
    let mut expected = serde_json::to_string_pretty(&nodkey_proto::vectors::build()).unwrap();
    expected.push('\n');
    let actual = std::fs::read_to_string(PATH).unwrap();
    assert!(
        actual == expected,
        "vectors/v1.json is stale or the generator changed: run `cargo run -p nodkey-proto --example vectors`"
    );
}

#[test]
fn keys_are_consistent() {
    let v = load();
    for side in ["agent", "phone"] {
        let k = &v["keys"][side];
        let kp = KeyPair::from_bytes(arr32(k, "kem_sk"), arr32(k, "sign_sk"));
        let p = kp.public();
        assert_eq!(p.kem_b64u(), s(k, "kem_pk"));
        assert_eq!(p.sign_b64u(), s(k, "sign_pk"));
        nodkey_proto::validate_id(s(k, "id")).unwrap();
    }
}

#[test]
fn check_number_matches() {
    let c = &load()["check"];
    let a = PublicKeys::from_b64u(s(c, "agent_sign"), s(c, "agent_kem")).unwrap();
    let p = PublicKeys::from_b64u(s(c, "phone_sign"), s(c, "phone_kem")).unwrap();
    let n = check::check_number(&a, &p);
    assert_eq!(u64::from(n), c["number"].as_u64().unwrap());
    assert_eq!(check::digits(n), s(c, "digits"));
    assert_eq!(check::display(n), s(c, "display"));
}

#[test]
fn every_hpke_vector_opens_and_reseals() {
    let v = load();
    let list = v["hpke"].as_array().unwrap();
    assert!(list.len() >= 10);
    for h in list {
        let name = s(h, "name");
        let purpose = match s(h, "purpose") {
            "request" => Purpose::Request,
            "answer" => Purpose::Answer,
            "pairing" => Purpose::Pairing,
            "attachment" => Purpose::Attachment,
            "password" => Purpose::Password,
            other => panic!("{other}"),
        };
        assert_eq!(purpose.info(), s(h, "info"), "{name}");
        let sk = arr32(h, "recipient_kem_sk");
        let pk = arr32(h, "recipient_kem_pk");
        let enc = b64u::decode(s(h, "enc")).unwrap();
        let ct = b64u::decode(s(h, "ct")).unwrap();
        let aad = s(h, "aad").as_bytes();
        let pt = b64u::decode(s(h, "plaintext_b64u")).unwrap();
        if let Some(text) = h["plaintext"].as_str() {
            assert_eq!(text.as_bytes(), &pt[..], "{name}");
            let _: Value = serde_json::from_str(text).unwrap();
        }
        // Recipient side.
        assert_eq!(
            &*purpose.open(&sk, &enc, aad, &ct).unwrap(),
            &pt[..],
            "{name}"
        );
        // Recipient side with the X25519 step done outside (as in a browser's WebCrypto).
        let enc32: [u8; 32] = enc.clone().try_into().unwrap();
        let dh = x25519_dalek::x25519(sk, enc32);
        assert_eq!(
            &*nodkey_proto::dh::open_with_dh(purpose.info().as_bytes(), &dh, &pk, &enc, aad, &ct)
                .unwrap(),
            &pt[..],
            "{name}"
        );
        // Sender side, with the recorded ephemeral input.
        let ikm = b64u::decode(s(h, "ikm_e")).unwrap();
        let again = seal::seal_with_rng(
            purpose.info().as_bytes(),
            &pk,
            aad,
            &pt,
            &mut FixedRng::new(&ikm),
        )
        .unwrap();
        assert_eq!(again.enc.to_vec(), enc, "{name}");
        assert_eq!(again.ct, ct, "{name}");
        // Tampering with any part fails.
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(purpose.open(&sk, &enc, aad, &bad).is_err(), "{name}");
        let mut bad_aad = aad.to_vec();
        bad_aad[0] ^= 1;
        assert!(purpose.open(&sk, &enc, &bad_aad, &ct).is_err(), "{name}");
        if purpose == Purpose::Attachment {
            let body = b64u::decode(s(h, "body_b64u")).unwrap();
            assert_eq!(&body[..ENC_LEN], &enc[..]);
            assert_eq!(
                &*seal::open_attachment_body(&sk, aad, &body).unwrap(),
                &pt[..]
            );
        }
    }
}

#[test]
fn aad_rules() {
    let v = load();
    let agent = s(&v["keys"]["agent"], "id");
    let phone = s(&v["keys"]["phone"], "id");
    for h in v["hpke"].as_array().unwrap() {
        let pt: Value = match h["plaintext"].as_str() {
            Some(t) => serde_json::from_str(t).unwrap(),
            None => Value::Null,
        };
        let expected = match s(h, "purpose") {
            "request" => format!("{}{agent}", s(&pt, "request_id")),
            "answer" => format!("{}{phone}", s(&pt, "request_id")),
            "pairing" => format!("{}{phone}", s(&v["pairing_code"], "code")),
            "password" => agent.to_owned(),
            _ => {
                // attachment: request_id of the login request with the attachment.
                let req = v["hpke"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|x| x["name"] == "request_login_with_attachment")
                    .unwrap();
                let rp: Value = serde_json::from_str(s(req, "plaintext")).unwrap();
                assert_eq!(
                    rp["attachment"]["bytes"].as_u64().unwrap() as usize,
                    b64u::decode(s(h, "plaintext_b64u")).unwrap().len()
                );
                format!("{}{agent}", s(&rp, "request_id"))
            }
        };
        assert_eq!(s(h, "aad"), expected, "{}", s(h, "name"));
    }
}

#[test]
fn every_auth_vector_verifies() {
    let v = load();
    for a in v["auth"].as_array().unwrap() {
        let name = s(a, "name");
        let body = match a["body"].as_str() {
            Some(t) => t.as_bytes().to_vec(),
            None => b64u::decode(s(a, "body_b64u")).unwrap(),
        };
        let ts = a["ts"].as_u64().unwrap();
        let (method, path) = (s(a, "method"), s(a, "path"));
        assert_eq!(
            auth::message(method, path, ts, &body),
            s(a, "message"),
            "{name}"
        );
        let pk = arr32(a, "sign_pk");
        let header = s(a, "header");
        assert_eq!(
            auth::verify(header, &pk, method, path, &body, ts).unwrap(),
            s(a, "id"),
            "{name}"
        );
        assert!(
            auth::verify(header, &pk, method, &format!("{path}x"), &body, ts).is_err(),
            "{name}"
        );
        assert!(
            auth::verify(header, &pk, method, path, &body, ts + 121).is_err(),
            "{name}"
        );
    }
}

#[test]
fn pairing_code_vectors() {
    let c = &load()["pairing_code"];
    assert!(code::is_canonical(s(c, "code")));
    assert_eq!(code::display(s(c, "code")), s(c, "display"));
    for n in c["normalize"].as_array().unwrap() {
        assert_eq!(code::normalize(s(n, "input")).unwrap(), s(n, "code"));
    }
    for bad in c["invalid"].as_array().unwrap() {
        assert!(code::normalize(bad.as_str().unwrap()).is_err());
    }
}
