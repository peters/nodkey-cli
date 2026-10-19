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
            "card" => Purpose::Card,
            "secret" => Purpose::Secret,
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
            "password" | "card" | "secret" => agent.to_owned(),
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

#[test]
fn webauthn_vector() {
    use nodkey_proto::{
        PasskeyOp, PasskeyRequest,
        passkey::{check_client_data, client_data_hash},
        webauthn,
    };
    let v = load();
    let w = &v["webauthn"];
    let d = |x: &Value, k: &str| b64u::decode(s(x, k)).unwrap();
    let key = webauthn::signing_key(&arr32(w, "private_key")).unwrap();
    let public = key.verifying_key();
    assert_eq!(webauthn::spki_der(public), d(w, "public_key_spki"));
    assert_eq!(webauthn::cose_key(public), d(w, "cose_key"));
    assert_eq!(&d(w, "aaguid_b64u")[..], &webauthn::AAGUID);
    let rp_id = s(w, "rp_id");
    let pk = webauthn::key_from_spki(&d(w, "public_key_spki")).unwrap();

    let (get, create) = (&w["get"], &w["create"]);
    for (op, c) in [(PasskeyOp::Get, get), (PasskeyOp::Create, create)] {
        let text = s(c, "client_data_json").as_bytes();
        assert_eq!(d(c, "client_data_json_b64u"), text);
        assert_eq!(&d(c, "client_data_hash")[..], &client_data_hash(text));
        assert_eq!(
            check_client_data(op, rp_id, text).unwrap().origin,
            s(w, "origin")
        );
    }
    let auth_get = d(get, "authenticator_data");
    assert_eq!(webauthn::authenticator_data(rp_id, None), auth_get);
    let cd_get = s(get, "client_data_json").as_bytes();
    assert_eq!(
        webauthn::signed_data(&auth_get, cd_get),
        d(get, "signed_data")
    );
    webauthn::verify(&pk, &auth_get, cd_get, &d(get, "signature")).unwrap();
    assert!(webauthn::verify(&pk, &auth_get, b"{}", &d(get, "signature")).is_err());
    let cred = d(w, "credential_id");
    let auth_create = webauthn::authenticator_data(rp_id, Some((&cred, &pk)));
    assert_eq!(auth_create, d(create, "authenticator_data"));
    assert_eq!(
        webauthn::attestation_object(&auth_create),
        d(create, "attestation_object")
    );

    for case in w["client_data_checks"].as_array().unwrap() {
        let op = if s(case, "op") == "get" {
            PasskeyOp::Get
        } else {
            PasskeyOp::Create
        };
        let text = s(case, "client_data_json").as_bytes();
        let ok = check_client_data(op, s(case, "rp_id"), text).is_ok();
        assert_eq!(ok, case["ok"].as_bool().unwrap(), "{}", s(case, "name"));
    }

    // The sealed requests carry this client data, and the answers this passkey.
    let plaintext = |name: &str| -> Value {
        let h = v["hpke"]
            .as_array()
            .unwrap()
            .iter()
            .find(|h| h["name"] == name)
            .unwrap();
        serde_json::from_str(s(h, "plaintext")).unwrap()
    };
    for (name, op, c) in [
        ("request_passkey_get", "get", get),
        ("request_passkey_create", "create", create),
    ] {
        let r = plaintext(name);
        assert_eq!(r["kind"], "passkey");
        assert_eq!(r["target"], rp_id);
        assert_eq!(r["passkey"]["op"], op);
        assert_eq!(r["passkey"]["client_data_json"], c["client_data_json_b64u"]);
        let p: PasskeyRequest = serde_json::from_value(r["passkey"].clone()).unwrap();
        p.check(rp_id).unwrap();
    }
    let a = plaintext("answer_passkey_get");
    assert_eq!(a["passkey"]["signature"], get["signature"]);
    assert_eq!(a["passkey"]["user_handle"], w["user_handle"]);
    let a = plaintext("answer_passkey_create");
    assert_eq!(a["passkey"]["public_key"], w["public_key_spki"]);
    assert_eq!(a["passkey"]["public_key_algorithm"], -7);
}

#[test]
fn card_checks_match() {
    use nodkey_proto::{CardRequest, Money, card};
    let c = &load()["cards"];
    for a in c["amounts"].as_array().unwrap() {
        let parsed = Money::parse(s(a, "value"), s(a, "currency"));
        assert_eq!(parsed.is_ok(), a["ok"].as_bool().unwrap(), "{a}");
        if let Ok(m) = parsed {
            assert_eq!(serde_json::to_value(&m).unwrap(), a["normalized"]);
            assert_eq!(m.thousandths().unwrap(), a["thousandths"].as_u64().unwrap());
        }
    }
    for r in c["requests"].as_array().unwrap() {
        let card: CardRequest = serde_json::from_value(r["card"].clone()).unwrap();
        let got = card.check(s(r, "target")).err().and_then(|(code, _)| code);
        assert_eq!(
            got.is_none() && card.check(s(r, "target")).is_ok(),
            r["ok"].as_bool().unwrap(),
            "{}",
            s(r, "name")
        );
        assert_eq!(got, r["error"].as_str(), "{}", s(r, "name"));
    }
    for n in c["numbers"].as_array().unwrap() {
        let number = s(n, "number");
        assert_eq!(card::luhn(number), n["luhn"].as_bool().unwrap());
        assert_eq!(card::brand(number), s(n, "brand"));
        assert_eq!(card::last4(number).as_deref(), n["last4"].as_str());
    }
}

#[test]
fn signin_checks_match() {
    use nodkey_proto::{SecondStep, SecondStepOrder, SignInMethod, Suggestion, Via, signin};
    let v = load();
    let c = &v["signin"];
    for m in c["methods"].as_array().unwrap() {
        let read = serde_json::from_str::<SignInMethod>(s(m, "input")).ok();
        assert_eq!(serde_json::to_value(&read).unwrap(), m["reads_as"], "{m}");
    }
    for case in c["suggestions"].as_array().unwrap() {
        let sug: Suggestion = serde_json::from_value(case["suggest"].clone()).unwrap();
        let target = s(case, "target");
        let ok = signin::site(target).as_deref() == Some(target) && sug.check().is_ok();
        assert_eq!(ok, case["ok"].as_bool().unwrap(), "{}", s(case, "name"));
    }
    for p in c["second_step_picks"].as_array().unwrap() {
        let order: SecondStepOrder = serde_json::from_value(p["order"].clone()).unwrap();
        let offered: Vec<SecondStep> = serde_json::from_value(p["offered"].clone()).unwrap();
        assert_eq!(
            serde_json::to_value(order.pick(&offered)).unwrap(),
            p["pick"],
            "{p}"
        );
    }
    for f in c["via_fill"].as_array().unwrap() {
        let method: SignInMethod = serde_json::from_value(f["method"].clone()).unwrap();
        let via: Via = serde_json::from_value(serde_json::json!({
            "account": {"issuer": "Provider", "name": "alex@example.com", "site": f["via_site"]}
        }))
        .unwrap();
        assert_eq!(
            signin::may_fill_via(s(f, "host"), s(f, "target"), &method, &via),
            f["allowed"].as_bool().unwrap(),
            "{f}"
        );
    }
    for x in c["sites"].as_array().unwrap() {
        assert_eq!(signin::site(s(x, "input")).as_deref(), x["site"].as_str());
    }
    // The answers read with every new field, and the sms_code envelope carries its ttl.
    let plaintext = |name: &str| -> Value {
        let h = v["hpke"]
            .as_array()
            .unwrap()
            .iter()
            .find(|h| h["name"] == name)
            .unwrap_or_else(|| panic!("{name}"));
        serde_json::from_str(s(h, "plaintext")).unwrap()
    };
    let a: nodkey_proto::Answer =
        serde_json::from_value(plaintext("answer_login_federated")).unwrap();
    assert_eq!(
        a.method.unwrap().provider,
        Some(nodkey_proto::Provider::Google)
    );
    assert_eq!(
        a.via.unwrap().account.site.as_deref(),
        Some("accounts.google.com")
    );
    assert_eq!(a.second_step, Some(SecondStepOrder::default()));
    let q: nodkey_proto::Answer =
        serde_json::from_value(plaintext("answer_suggest_queued")).unwrap();
    assert_eq!(q.decision, nodkey_proto::Decision::Queued);
    let r: nodkey_proto::Request = serde_json::from_value(plaintext("request_sms_code")).unwrap();
    assert_eq!(r.kind, nodkey_proto::Kind::SmsCode);
    let post = v["auth"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["name"] == "post_request_sms_code")
        .unwrap();
    let body: Value = serde_json::from_str(s(post, "body")).unwrap();
    assert_eq!(body["ttl"], 180);
}

#[test]
fn quota_vectors() {
    use nodkey_proto::{Answer, Decision, quota};
    let v = load();
    let q = &v["quota"];
    assert_eq!(q["default_limit"], quota::DEFAULT_LIMIT);
    assert_eq!(q["pause_above"], quota::PAUSE_ABOVE);
    assert_eq!(q["limit_choices"], serde_json::json!([5, 10, 25]));
    assert_eq!(q["errors"], serde_json::json!(["quota_warning", "paused"]));
    let answer = |name: &str| -> Answer {
        let h = v["hpke"]
            .as_array()
            .unwrap()
            .iter()
            .find(|h| h["name"] == name)
            .unwrap_or_else(|| panic!("{name}"));
        serde_json::from_str(s(h, "plaintext")).unwrap()
    };
    let warned = answer("answer_code_quota_warning");
    assert_eq!(warned.decision, Decision::Approved);
    assert_eq!(warned.error.as_deref(), Some("quota_warning"));
    assert_eq!(warned.quota.as_ref().map(|q| q.new_today), Some(12));
    assert!(
        answer("answer_login_quota_warning_burst")
            .quota
            .unwrap()
            .burst
    );
    assert_eq!(
        answer("answer_bundle_quota_warning").items.unwrap().len(),
        2
    );
    let by_user = answer("answer_paused");
    assert_eq!(by_user.error.as_deref(), Some("paused"));
    assert!(by_user.quota.is_none());
    let by_limit = answer("answer_paused_by_limit");
    assert_eq!(by_limit.decision, Decision::Denied);
    assert_eq!(by_limit.quota.unwrap().new_today, quota::PAUSE_ABOVE);
}

#[test]
fn prf_vectors() {
    use nodkey_proto::{Answer, PrfInput, Request, prf};
    let v = load();
    let p = &v["prf"];
    assert_eq!(s(p, "label").as_bytes(), prf::LABEL);
    let cred = arr32(p, "cred_random");
    let d = |x: &Value, k: &str| b64u::decode(s(x, k)).unwrap();
    let mut outputs = Vec::new();
    for c in p["derivations"].as_array().unwrap() {
        let input = d(c, "input");
        assert_eq!(
            &prf::salt(&input)[..],
            &d(c, "salt")[..],
            "{}",
            s(c, "name")
        );
        assert_eq!(&prf::evaluate(&cred, &input)[..], &d(c, "output")[..]);
        if let Some(text) = c["input_text"].as_str() {
            assert_eq!(text.as_bytes(), &input[..]);
        }
        outputs.push(s(c, "output").to_owned());
    }
    // Other inputs give other outputs.
    outputs.sort();
    outputs.dedup();
    assert_eq!(outputs.len(), p["derivations"].as_array().unwrap().len());
    for c in p["input_checks"].as_array().unwrap() {
        let input: PrfInput = serde_json::from_value(c["prf"].clone()).unwrap();
        let allow: Vec<String> = serde_json::from_value(c["allow_credentials"].clone()).unwrap();
        let create = c["op"] == "create";
        assert_eq!(
            input.check(create, &allow).is_ok(),
            c["ok"].as_bool().unwrap(),
            "{}",
            s(c, "name")
        );
    }

    let plain = |name: &str| -> String {
        let h = v["hpke"]
            .as_array()
            .unwrap()
            .iter()
            .find(|h| h["name"] == name)
            .unwrap_or_else(|| panic!("{name}"));
        s(h, "plaintext").to_owned()
    };
    for (request, answer) in [
        ("request_passkey_create_prf", "answer_passkey_create_prf"),
        ("request_passkey_get_prf", "answer_passkey_get_prf"),
        (
            "request_passkey_get_prf_by_credential",
            "answer_passkey_get_prf_by_credential",
        ),
    ] {
        let r: Request = serde_json::from_str(&plain(request)).unwrap();
        let a: Answer = serde_json::from_str(&plain(answer)).unwrap();
        let (r, a) = (r.passkey.unwrap(), a.passkey.unwrap());
        nodkey_proto::webauthn::check_answer(&r, &a).unwrap();
        let asked = r.prf().unwrap().values_for(&a.credential_id).unwrap();
        let results = a.prf.unwrap().results.unwrap();
        let out = |input: &str| b64u::encode(&*prf::evaluate(&cred, &b64u::decode(input).unwrap()));
        assert_eq!(results.first.expose(), out(&asked.first), "{answer}");
        assert_eq!(
            results.second.as_ref().map(|s| s.expose().to_owned()),
            asked.second.as_deref().map(out)
        );
    }
    let refused: Answer = serde_json::from_str(&plain("answer_passkey_prf_unsupported")).unwrap();
    assert_eq!(refused.error.as_deref(), Some("prf_unsupported"));
}
