use super::*;

fn method(json: &str) -> SignInMethod {
    serde_json::from_str(json).unwrap()
}

fn via(site: &str) -> Via {
    Via {
        account: Account {
            issuer: "Google".into(),
            name: "alex@example.com".into(),
            site: Some(site.into()),
            sites: None,
        },
        username: Some("alex@example.com".into()),
        password: Some(Secret::new("pw")),
        code: None,
        seconds_left: None,
        next_code: None,
        next_seconds_left: None,
    }
}

#[test]
fn wire_names() {
    let mut m = SignInMethod::new(SignInKind::EmailCode);
    m.mailbox = Some("alex@example.com".into());
    m.certainty = Some(Certainty::Seen);
    m.source = Some(MethodSource::Extension);
    assert_eq!(
        serde_json::to_string(&m).unwrap(),
        r#"{"kind":"email_code","certainty":"seen","mailbox":"alex@example.com","source":"extension"}"#
    );
    let g = SignInMethod::federated(Provider::Github, None);
    assert_eq!(
        serde_json::to_string(&g).unwrap(),
        r#"{"kind":"federated","provider":"github"}"#
    );
    let order = SecondStepOrder::default();
    assert_eq!(
        serde_json::to_string(&order).unwrap(),
        r#"{"prefer":["passkey","totp"],"avoid":["app_prompt","sms"]}"#
    );
    let s = Suggestion {
        method: g,
        outcome: SuggestOutcome::SignedIn,
    };
    assert_eq!(
        serde_json::to_string(&s).unwrap(),
        r#"{"method":{"kind":"federated","provider":"github"},"outcome":"signed_in"}"#
    );
}

#[test]
fn tolerant_reading() {
    // Another provider by its own name, as the app sends it.
    let m = method(r#"{"kind":"federated","provider":"Okta","certainty":"confirmed"}"#);
    assert_eq!(m.provider, Some(Provider::Other));
    assert_eq!(m.provider_name.as_deref(), Some("Okta"));
    assert_eq!(m.provider_label().as_deref(), Some("Okta"));
    let m = method(r#"{"kind":"federated","provider":"other","provider_name":"Okta"}"#);
    assert_eq!(m.provider_name.as_deref(), Some("Okta"));
    assert!(m.check().is_ok());
    let m = method(r#"{"kind":"federated","provider":"Google"}"#);
    assert_eq!(m.provider, Some(Provider::Google));
    // An unknown certainty reads as likely, an unknown source as none.
    let m = method(r#"{"kind":"password","certainty":"sure","source":"robot"}"#);
    assert_eq!(m.certainty, Some(Certainty::Likely));
    assert_eq!(m.source, None);
    // An unknown kind fails the method.
    assert!(serde_json::from_str::<SignInMethod>(r#"{"kind":"magic_link"}"#).is_err());
    // Unknown second steps are left out.
    let o: SecondStepOrder =
        serde_json::from_str(r#"{"prefer":["hardware_key","passkey"],"avoid":["sms"]}"#).unwrap();
    assert_eq!(o.prefer, vec![SecondStep::Passkey]);
    assert_eq!(o.avoid, vec![SecondStep::Sms]);
    let o: SecondStepOrder = serde_json::from_str("{}").unwrap();
    assert!(o.prefer.is_empty() && o.avoid.is_empty());
}

#[test]
fn method_rules() {
    assert!(SignInMethod::new(SignInKind::Password).check().is_ok());
    let no_provider = SignInMethod::new(SignInKind::Federated);
    assert!(no_provider.check().unwrap_err().contains("provider"));
    let mut p = SignInMethod::new(SignInKind::Password);
    p.provider = Some(Provider::Google);
    assert!(p.check().unwrap_err().contains("only a federated"));
    let other = SignInMethod::federated(Provider::Other, None);
    assert!(other.check().unwrap_err().contains("provider_name"));
    let other = SignInMethod::federated(Provider::Other, Some(" "));
    assert!(other.check().is_err());
    let long = "x".repeat(MAX_PROVIDER_NAME + 1);
    assert!(
        SignInMethod::federated(Provider::Other, Some(&long))
            .check()
            .is_err()
    );
    let named = SignInMethod::federated(Provider::Google, Some("Google"));
    assert!(named.check().unwrap_err().contains("only provider other"));
    let mut mail = SignInMethod::new(SignInKind::EmailCode);
    mail.mailbox = Some("not-an-address".into());
    assert!(mail.check().is_err());
    mail.mailbox = Some("alex@example.com".into());
    assert!(mail.check().is_ok());
    let mut sms = SignInMethod::new(SignInKind::Sms);
    sms.mailbox = Some("alex@example.com".into());
    assert!(sms.check().unwrap_err().contains("only an email_code"));
}

#[test]
fn suggestion_rules() {
    let mut s = Suggestion {
        method: SignInMethod::federated(Provider::Google, None),
        outcome: SuggestOutcome::SignedIn,
    };
    s.method.certainty = Some(Certainty::Seen);
    s.method.source = Some(MethodSource::Agent);
    assert!(s.check().is_ok());
    s.method.certainty = Some(Certainty::Confirmed);
    assert!(s.check().unwrap_err().contains("only the user confirms"));
    s.method.certainty = None;
    s.method.source = Some(MethodSource::Import);
    assert!(s.check().is_err());
    s.method.source = None;
    s.method.provider = None;
    assert!(s.check().is_err());
}

#[test]
fn second_step_pick() {
    use SecondStep::*;
    let order = SecondStepOrder::default();
    assert_eq!(order.pick(&[Sms, Totp, Passkey]), Some(Passkey));
    assert_eq!(order.pick(&[AppPrompt, Totp]), Some(Totp));
    // Email is in neither list: allowed after the preferred ones.
    assert_eq!(order.pick(&[AppPrompt, Email]), Some(Email));
    assert_eq!(order.pick(&[AppPrompt, Sms]), None);
    let own = SecondStepOrder {
        prefer: vec![Totp, Passkey],
        avoid: vec![],
    };
    assert_eq!(own.pick(&[Passkey, Totp]), Some(Totp));
    assert_eq!(own.pick(&[Sms]), Some(Sms));
}

#[test]
fn sites() {
    assert_eq!(
        site("https://www.Example.com/login?x=1").as_deref(),
        Some("example.com")
    );
    assert_eq!(
        site("alex@accounts.example.com:8443").as_deref(),
        Some("accounts.example.com")
    );
    assert_eq!(site("localhost:3000").as_deref(), Some("localhost"));
    assert_eq!(site("example.com.").as_deref(), Some("example.com"));
    assert_eq!(site("Example"), None);
    assert_eq!(site("exa mple.com"), None);
    assert_eq!(site("a..b"), None);
    assert_eq!(site(""), None);
}

#[test]
fn where_via_may_be_filled() {
    let google = SignInMethod::federated(Provider::Google, None);
    let v = via("accounts.google.com");
    assert!(may_fill_via(
        "accounts.google.com",
        "renderfarm.example",
        &google,
        &v
    ));
    assert!(may_fill_via(
        "https://accounts.google.com/v3/signin",
        "renderfarm.example",
        &google,
        &v
    ));
    // Never on the target site, never on a look-alike.
    assert!(!may_fill_via(
        "renderfarm.example",
        "renderfarm.example",
        &google,
        &v
    ));
    assert!(!may_fill_via(
        "login.renderfarm.example",
        "renderfarm.example",
        &google,
        &v
    ));
    assert!(!may_fill_via(
        "accounts.google.com.evil.example",
        "renderfarm.example",
        &google,
        &v
    ));
    assert!(!may_fill_via(
        "google.co",
        "renderfarm.example",
        &google,
        &v
    ));
    // Another provider: only the via account's own site.
    let okta = SignInMethod::federated(Provider::Other, Some("Okta"));
    let v = via("acme.okta.example");
    assert_eq!(via_sites(&okta, &v), vec!["acme.okta.example".to_owned()]);
    assert!(may_fill_via(
        "acme.okta.example",
        "tools.example.com",
        &okta,
        &v
    ));
    assert!(!may_fill_via(
        "okta.example",
        "tools.example.com",
        &okta,
        &v
    ));
    let ms = SignInMethod::federated(Provider::Microsoft, None);
    assert!(may_fill_via(
        "login.microsoftonline.com",
        "tools.example.com",
        &ms,
        &v
    ));
}

#[test]
fn sms_wait_range() {
    assert_eq!(sms_wait(None), Some(120));
    assert_eq!(sms_wait(Some(300)), Some(300));
    assert_eq!(sms_wait(Some(30)), Some(30));
    assert_eq!(sms_wait(Some(29)), None);
    assert_eq!(sms_wait(Some(301)), None);
}
