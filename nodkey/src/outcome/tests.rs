use super::*;
use crate::agent::text;
use serde_json::json;

#[test]
fn outcome_messages() {
    let mut a = Answer::decision("rid", Decision::Approved);
    a.code = Some(nodkey_proto::Secret::new("123456"));
    a.seconds_left = Some(20);
    let t = text(&Outcome::from_answer(
        &a,
        Kind::Code,
        "Test iPhone",
        "",
        None,
    ));
    let v: serde_json::Value = serde_json::from_str(&t).unwrap();
    assert_eq!(v["code"], "123456");
    assert_eq!(v["decision"], "approved");
    assert_eq!(v["phone"], "Test iPhone");
    assert!(v.get("password").is_none());
    let t = text(&Outcome::expired(
        "rid",
        "P",
        Duration::from_secs(120),
        None,
    ));
    assert!(t.contains("120 s"));
}

#[test]
fn no_passcode_on_the_phone() {
    let mut a = Answer::decision("rid", Decision::Denied);
    a.error = Some("no_passcode".into());
    let v: serde_json::Value = serde_json::from_str(&text(&Outcome::from_answer(
        &a,
        Kind::Login,
        "Test iPhone",
        "webauthn.io",
        None,
    )))
    .unwrap();
    assert_eq!(v["error"], "no_passcode");
    let m = v["message"].as_str().unwrap();
    assert!(
        m.contains("no passcode") && m.contains("Face ID & Passcode"),
        "{m}"
    );
}

#[test]
fn chosen_account_and_extra_websites() {
    let mut a = Answer::decision("rid", Decision::Approved);
    a.username = Some("alex@example.com".into());
    a.password = Some(nodkey_proto::Secret::new("pw"));
    a.account = Some(Account {
        issuer: "OpenAI".into(),
        name: "alex@example.com".into(),
        site: Some("openai.com".into()),
        sites: Some(vec!["chatgpt.com".into()]),
    });
    a.match_kind = Some(MatchKind::Chosen);
    let result = |a: &Answer, target: &str| -> serde_json::Value {
        serde_json::from_str(&text(&Outcome::from_answer(
            a,
            Kind::Login,
            "P",
            target,
            None,
        )))
        .unwrap()
    };
    let v = result(&a, "sora.com/alex@example.com");
    assert_eq!(v["match"], "chosen");
    assert_eq!(v["account"]["sites"], json!(["chatgpt.com"]));
    let message = v["message"].as_str().unwrap();
    assert!(message.contains("picked it by hand"));
    // Picked by hand for sora.com: filled only there.
    assert_eq!(v["fill_only_on"], json!(["sora.com"]));
    assert!(message.contains("host is sora.com or below"));
    a.match_kind = Some(MatchKind::Alias);
    let v = result(&a, "https://chatgpt.com/auth/login");
    assert_eq!(v["match"], "alias");
    assert!(!v["message"].as_str().unwrap().contains("by hand"));
    assert_eq!(v["fill_only_on"], json!(["openai.com", "chatgpt.com"]));
    // Denied: nothing to fill.
    let v = result(&Answer::decision("rid", Decision::Denied), "chatgpt.com");
    assert!(v.get("fill_only_on").is_none());
}

#[test]
fn cleanup_outcomes() {
    let mut a = Answer::decision("rid", Decision::Approved);
    a.moved = Some(2);
    a.accounts = Some(vec![
        AccountEntry {
            issuer: "192.168.1.1".into(),
            name: "admin".into(),
            site: Some("192.168.1.1".into()),
            has_code: false,
            has_password: true,
            sites: None,
        },
        AccountEntry {
            issuer: "Printer".into(),
            name: "demo".into(),
            site: None,
            has_code: false,
            has_password: true,
            sites: None,
        },
    ]);
    let v: serde_json::Value = serde_json::from_str(&text(&Outcome::from_answer(
        &a,
        Kind::Cleanup,
        "P",
        "",
        None,
    )))
    .unwrap();
    assert_eq!(v["moved"], 2);
    assert_eq!(
        v["accounts"],
        json!([{"title": "192.168.1.1", "name": "admin", "site": "192.168.1.1"}, {"title": "Printer", "name": "demo"}])
    );
    assert!(v["message"].as_str().unwrap().contains("Recently deleted"));

    a.moved = Some(0);
    a.accounts = Some(vec![]);
    let v: serde_json::Value = serde_json::from_str(&text(&Outcome::from_answer(
        &a,
        Kind::Cleanup,
        "P",
        "",
        None,
    )))
    .unwrap();
    assert_eq!(v["moved"], 0);
    assert!(v["message"].as_str().unwrap().contains("nothing was moved"));

    let mut refused = Answer::decision("rid", Decision::Denied);
    refused.error = Some("empty_filter".into());
    let v: serde_json::Value = serde_json::from_str(&text(&Outcome::from_answer(
        &refused,
        Kind::Cleanup,
        "P",
        "",
        None,
    )))
    .unwrap();
    assert_eq!(v["decision"], "denied");
    assert!(v.get("moved").is_none() && v.get("accounts").is_none());
    assert!(v["message"].as_str().unwrap().contains("no criterion"));
}

#[test]
fn limit_warning_and_pause() {
    let mut a = Answer::decision("rid", Decision::Approved);
    a.code = Some(nodkey_proto::Secret::new("123456"));
    a.error = Some("quota_warning".into());
    a.quota = Some(Quota {
        new_today: 12,
        limit: 10,
        burst: false,
    });
    let v: serde_json::Value =
        serde_json::from_str(&text(&Outcome::from_answer(&a, Kind::Code, "P", "", None))).unwrap();
    assert_eq!(v["code"], "123456");
    assert_eq!(v["quota"], json!({"new_today": 12, "limit": 10}));
    let m = v["message"].as_str().unwrap();
    assert!(m.starts_with("The user approved."), "{m}");
    assert!(m.contains("12 in the last 24 hours; the user's limit for this agent is 10"));

    let mut p = Answer::decision("rid", Decision::Denied);
    p.error = Some("paused".into());
    let v: serde_json::Value =
        serde_json::from_str(&text(&Outcome::from_answer(&p, Kind::Login, "P", "", None))).unwrap();
    assert!(v.get("quota").is_none());
    assert!(
        v["message"]
            .as_str()
            .unwrap()
            .starts_with("The user has paused")
    );
    p.quota = Some(Quota {
        new_today: 25,
        limit: 10,
        burst: false,
    });
    for kind in [Kind::Login, Kind::Cleanup] {
        let v: serde_json::Value =
            serde_json::from_str(&text(&Outcome::from_answer(&p, kind, "P", "", None))).unwrap();
        assert_eq!(v["error"], "paused");
        assert_eq!(v["quota"]["new_today"], 25);
        assert!(
            v["message"]
                .as_str()
                .unwrap()
                .contains("received 25 new logins")
        );
    }
}
