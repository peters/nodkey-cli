use super::*;

#[test]
fn protocol_examples_parse() {
    let g: PairingGrant = parse_plaintext(
        br#"{"v":1, "phone_name":"Test iPhone", "scope":"selected", "check":"418902"}"#,
    )
    .unwrap();
    assert_eq!(g.scope, Scope::Selected);

    let r: Request = parse_plaintext(
        br#"{"v":1, "request_id":"AAECAwQFBgcICQoLDA0ODw", "kind":"code", "target":"github.com/alex",
            "reason":"Merge PR #42", "agent":"Agent \u00b7 Horizon", "ts":1791620000,
            "attachment":{"type":"image/png","bytes":12345,"caption":"vg.no login page"}}"#,
    )
    .unwrap();
    assert_eq!(r.kind, Kind::Code);
    assert_eq!(r.attachment.unwrap().kind, ImageType::Png);

    let a: Answer = parse_plaintext(
        br#"{"v":1, "request_id":"x", "decision":"approved",
            "lease":{"kind":"day", "until":1791706400},
            "account":{"issuer":"GitHub", "name":"alex", "site":"github.com"},
            "code":"190274", "seconds_left":12, "username":"alex", "password":"pw",
            "accounts":[{"issuer":"GitHub","name":"alex","site":"github.com","has_code":true,"has_password":true}]}"#,
    )
    .unwrap();
    assert_eq!(a.decision, Decision::Approved);
    assert_eq!(a.code.as_ref().unwrap().expose(), "190274");
    assert_eq!(a.lease.as_ref().unwrap().kind, LeaseKind::Day);
    assert!(a.accounts.as_ref().unwrap()[0].has_password);
}

#[test]
fn cleanup_request_and_answer() {
    let r: Request = parse_plaintext(
        br#"{"v":1, "request_id":"x", "kind":"cleanup", "target":"", "reason":"Old router logins",
            "agent":"A", "ts":1791620000, "filter":{"ip_only":true, "username":"admin"}}"#,
    )
    .unwrap();
    assert_eq!(r.kind, Kind::Cleanup);
    let f = r.filter.unwrap();
    assert_eq!(f.ip_only, Some(true));
    assert_eq!(f.username.as_deref(), Some("admin"));
    assert!(!f.is_empty());

    let a: Answer = parse_plaintext(
        br#"{"v":1, "request_id":"x", "decision":"approved", "moved":1,
            "accounts":[{"issuer":"Router","name":"admin","site":"192.168.1.1"}]}"#,
    )
    .unwrap();
    assert_eq!(a.moved, Some(1));
    assert_eq!(a.accounts.unwrap()[0].site.as_deref(), Some("192.168.1.1"));
    let refused: Answer = parse_plaintext(
        br#"{"v":1, "request_id":"x", "decision":"denied", "error":"empty_filter"}"#,
    )
    .unwrap();
    assert_eq!(refused.error.as_deref(), Some("empty_filter"));
}

#[test]
fn empty_cleanup_filters() {
    assert!(CleanupFilter::default().is_empty());
    let blank = CleanupFilter {
        query: Some("  ".into()),
        username: Some(String::new()),
        ip_only: Some(false),
        never_used: Some(false),
        ..Default::default()
    };
    assert!(blank.is_empty());
    assert_eq!(
        serde_json::to_string(&CleanupFilter::default()).unwrap(),
        "{}"
    );
    for f in [
        CleanupFilter {
            query: Some("*.old.no".into()),
            ..Default::default()
        },
        CleanupFilter {
            username: Some("alex@example.com".into()),
            ..Default::default()
        },
        CleanupFilter {
            domain: Some("old.no".into()),
            ..Default::default()
        },
        CleanupFilter {
            ip_only: Some(true),
            ..Default::default()
        },
        CleanupFilter {
            last_used_before: Some(1),
            ..Default::default()
        },
        CleanupFilter {
            added_before: Some(1),
            ..Default::default()
        },
        CleanupFilter {
            password_changed_before: Some(1),
            ..Default::default()
        },
        CleanupFilter {
            never_used: Some(true),
            ..Default::default()
        },
    ] {
        assert!(!f.is_empty(), "{f:?}");
    }
}

#[test]
fn optional_fields_are_omitted() {
    let a = Answer::decision("rid", Decision::Denied);
    assert_eq!(
        serde_json::to_string(&a).unwrap(),
        r#"{"v":1,"request_id":"rid","decision":"denied"}"#
    );
}

#[test]
fn wrong_version_is_rejected() {
    let e = parse_plaintext::<Answer>(br#"{"v":2,"request_id":"x","decision":"denied"}"#);
    assert!(e.is_err());
}

#[test]
fn secrets_are_redacted_in_debug() {
    let mut a = Answer::decision("rid", Decision::Approved);
    a.code = Some(Secret::new("190274"));
    a.password = Some(Secret::new("hunter2"));
    let s = format!("{a:?}");
    assert!(!s.contains("190274") && !s.contains("hunter2"));
    assert!(serde_json::to_string(&a).unwrap().contains("hunter2"));
}

#[test]
fn image_sniffing() {
    assert_eq!(
        ImageType::sniff(b"\x89PNG\r\n\x1a\n...."),
        Some(ImageType::Png)
    );
    assert_eq!(
        ImageType::sniff(&[0xff, 0xd8, 0xff, 0xe0]),
        Some(ImageType::Jpeg)
    );
    assert_eq!(ImageType::sniff(b"GIF89a.."), Some(ImageType::Gif));
    assert_eq!(ImageType::sniff(b"GIF87a.."), Some(ImageType::Gif));
    assert_eq!(ImageType::sniff(b"<svg"), None);
    assert_eq!(
        serde_json::to_string(&AttachmentInfo {
            kind: ImageType::Jpeg,
            bytes: 3,
            caption: None
        })
        .unwrap(),
        r#"{"type":"image/jpeg","bytes":3}"#
    );
}

#[test]
fn answers_from_newer_apps_still_read() {
    // A method kind or a second step this version does not know: the answer reads without them.
    let a: Answer = parse_plaintext(
        br#"{"v":1, "request_id":"x", "decision":"approved", "username":"alex", "password":"pw",
            "method":{"kind":"magic_link"}, "second_step":{"prefer":["hardware_key","totp"]}}"#,
    )
    .unwrap();
    assert_eq!(a.method, None);
    assert_eq!(a.second_step.unwrap().prefer, vec![crate::SecondStep::Totp]);
    let a: Answer = parse_plaintext(
        br#"{"v":1, "request_id":"x", "decision":"approved", "second_step":"passkey first"}"#,
    )
    .unwrap();
    assert_eq!(a.second_step, None);
    let q: Answer = parse_plaintext(br#"{"v":1, "request_id":"x", "decision":"queued"}"#).unwrap();
    assert_eq!(q.decision, Decision::Queued);
}
