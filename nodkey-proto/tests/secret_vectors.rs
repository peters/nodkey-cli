//! Checks the API key vectors in `vectors/v1.json`: the `secrets` section decides the same way as
//! `nodkey_proto::apikey`, and the key requests and answers read back with the right fields.

use nodkey_proto::{Answer, Decision, Kind, LeaseKind, Request, SecretTarget, apikey};
use serde_json::Value;

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
fn targets_and_matches() {
    let v = load();
    let s = &v["secrets"];
    for t in s["targets"].as_array().unwrap() {
        let target = t["target"].as_str().unwrap();
        let parsed = SecretTarget::parse(target);
        assert_eq!(parsed.is_ok(), t["ok"].as_bool().unwrap(), "{target:?}");
        if let Ok(p) = parsed {
            assert_eq!(p.service.as_deref(), t["service"].as_str(), "{target}");
            assert_eq!(p.variable.as_deref(), t["variable"].as_str(), "{target}");
        }
    }
    let matches = s["matches"].as_array().unwrap();
    assert!(matches.iter().any(|m| m["match"] == true));
    assert!(matches.iter().any(|m| m["match"] == false));
    for m in matches {
        let target = SecretTarget::parse(m["target"].as_str().unwrap()).unwrap();
        assert_eq!(
            target.matches(m["service"].as_str(), m["variable"].as_str()),
            m["match"].as_bool().unwrap(),
            "{m}"
        );
    }
    assert_eq!(s["max_save_value"], apikey::MAX_SAVE_VALUE);
    assert_eq!(
        s["errors"],
        serde_json::json!(["no_secret", "bad_secret_request", "not_allowed"])
    );
}

#[test]
fn requests_and_answers() {
    let v = load();
    let r: Request = plaintext(&v, "request_secret");
    assert_eq!(r.kind, Kind::Secret);
    nodkey_proto::client::check_request(&r).unwrap();
    let a: Answer = plaintext(&v, "answer_secret");
    let key = a.secret.unwrap();
    assert_eq!(key.value.unwrap().expose(), "sk-test-0000");
    assert_eq!(key.variable.as_deref(), Some("OPENAI_API_KEY"));
    let refused: Answer = plaintext(&v, "answer_secret_no_secret");
    assert_eq!(refused.decision, Decision::Denied);
    assert_eq!(refused.error.as_deref(), Some(apikey::errors::NO_SECRET));

    let save: Request = plaintext(&v, "request_save_secret");
    assert_eq!(save.kind, Kind::SaveSecret);
    assert_eq!(save.target, "openai.com/OPENAI_API_KEY");
    nodkey_proto::client::check_request(&save).unwrap();
    let sealed = &v["hpke"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["name"] == "save_secret_value")
        .unwrap();
    assert_eq!(sealed["info"], "nodkey/v1/secret");
    assert_eq!(
        save.save_secret.unwrap().value.ct,
        sealed["ct"].as_str().unwrap()
    );

    let two: Request = plaintext(&v, "request_bundle_secrets");
    nodkey_proto::client::check_request(&two).unwrap();
    let answer: Answer = plaintext(&v, "answer_bundle_secrets");
    assert!(
        answer
            .items
            .unwrap()
            .iter()
            .all(|i| i.secret.as_ref().unwrap().value.is_some())
    );

    let plan: Answer = plaintext(&v, "answer_bundle_secret_session");
    let items = plan.items.unwrap();
    assert!(items[1].secret.as_ref().unwrap().value.is_none());
    assert!(items[1].lease.is_none());
    let in_session: Request = plaintext(&v, "request_secret_in_session");
    nodkey_proto::client::check_request(&in_session).unwrap();
    assert_eq!(in_session.session_id, Some(plan.session.unwrap().id));
    let covered: Answer = plaintext(&v, "answer_secret_in_session");
    assert_eq!(covered.lease.unwrap().kind, LeaseKind::Session);

    let list: Answer = plaintext(&v, "answer_list_with_secrets");
    assert_eq!(list.secrets.unwrap().len(), 2);
    let warned: Answer = plaintext(&v, "answer_secret_quota_warning");
    assert_eq!(warned.error.as_deref(), Some("quota_warning"));
}
