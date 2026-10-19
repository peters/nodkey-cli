use super::*;
use nodkey_proto::Secret;
use serde_json::json;

#[test]
fn targets_from_names() {
    assert_eq!(
        target(Some("OPENAI_API_KEY"), Some("https://www.OpenAI.com/v1")).unwrap(),
        "openai.com/OPENAI_API_KEY"
    );
    assert_eq!(
        target(None, Some("api.example.com")).unwrap(),
        "api.example.com"
    );
    assert_eq!(
        target(Some(" EXAMPLE_TOKEN "), None).unwrap(),
        "EXAMPLE_TOKEN"
    );
    assert!(target(None, None).unwrap_err().contains("name the key"));
    assert!(
        target(Some("OPENAI-KEY"), None)
            .unwrap_err()
            .contains("not a variable")
    );
    assert!(
        target(None, Some("not a host"))
            .unwrap_err()
            .contains("not a service")
    );
}

#[test]
fn expiry_dates() {
    assert_eq!(expires(None).unwrap(), None);
    assert_eq!(
        expires(Some(&json!(1_800_000_000))).unwrap(),
        Some(1_800_000_000)
    );
    assert_eq!(
        expires(Some(&json!("2027-01-01"))).unwrap(),
        Some(1_798_761_600)
    );
    assert!(expires(Some(&json!("soon"))).is_err());
    assert!(expires(Some(&json!(true))).is_err());
}

fn key() -> SecretAnswer {
    SecretAnswer {
        title: "OpenAI".into(),
        service: Some("openai.com".into()),
        variable: Some("OPENAI_API_KEY".into()),
        value: Some(Secret::new("sk-test-0000")),
        expires: None,
    }
}

#[test]
fn results() {
    let mut a = Answer::decision("rid", Decision::Approved);
    a.secret = Some(key());
    let v: Value = serde_json::from_str(&text(&outcome(&a, "openai.com", "P"))).unwrap();
    assert_eq!(v["secret"]["value"], "sk-test-0000");
    let m = v["message"].as_str().unwrap();
    assert!(
        m.contains("nodkey run --secret") && m.contains("never in a file"),
        "{m}"
    );

    for (error, want) in [
        (apikey::errors::NO_SECRET, "no such key"),
        (apikey::errors::NOT_ALLOWED, "codes only"),
        ("paused", "paused"),
        ("unsupported_kind", "protocol versions"),
    ] {
        let mut d = Answer::decision("rid", Decision::Denied);
        d.error = Some(error.into());
        d.secret = Some(key());
        let v: Value = serde_json::from_str(&text(&outcome(&d, "x", "P"))).unwrap();
        assert!(v["message"].as_str().unwrap().contains(want), "{error}");
        assert!(v.get("secret").is_none(), "a refusal never passes a key on");
    }

    let mut s = Answer::decision("rid", Decision::Approved);
    s.saved = Some(nodkey_proto::Saved::Updated);
    let v: Value =
        serde_json::from_str(&text(&save_outcome(&s, "openai.com/OPENAI_API_KEY", "P"))).unwrap();
    assert_eq!(v["saved"], "updated");
    let m = v["message"].as_str().unwrap();
    assert!(m.contains("nodkey run --secret OPENAI_API_KEY --"), "{m}");
    let v: Value = serde_json::from_str(&text(&save_outcome(
        &Answer::decision("rid", Decision::Denied),
        "X",
        "P",
    )))
    .unwrap();
    assert!(v["message"].as_str().unwrap().contains("did not save"));
}
