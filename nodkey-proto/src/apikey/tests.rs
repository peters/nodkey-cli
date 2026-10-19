use super::*;

#[test]
fn variable_names() {
    for ok in ["OPENAI_API_KEY", "_X", "a1", "Token_2"] {
        assert!(valid_variable(ok), "{ok}");
    }
    for bad in [
        "",
        "1A",
        "A-B",
        "A B",
        "openai.com",
        "ÆØÅ",
        &"A".repeat(101),
    ] {
        assert!(!valid_variable(bad), "{bad}");
    }
}

#[test]
fn targets() {
    let t = |s: &str| SecretTarget::parse(s);
    assert_eq!(
        t("openai.com").unwrap(),
        SecretTarget {
            service: Some("openai.com".into()),
            variable: None
        }
    );
    assert_eq!(
        t(" OPENAI_API_KEY ").unwrap(),
        SecretTarget {
            service: None,
            variable: Some("OPENAI_API_KEY".into())
        }
    );
    let both = t("api.example.com/EXAMPLE_TOKEN").unwrap();
    assert_eq!(both.to_target(), "api.example.com/EXAMPLE_TOKEN");
    assert_eq!(
        t("localhost/DEV_TOKEN").unwrap().service.as_deref(),
        Some("localhost")
    );
    for bad in [
        "",
        "/",
        "openai.com/",
        "/OPENAI_API_KEY",
        "OpenAI.com",
        "https://openai.com",
        "openai.com/OPENAI-KEY",
        "www.openai.com",
        "a b",
    ] {
        assert!(t(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn matching() {
    let t = |s: &str| SecretTarget::parse(s).unwrap();
    let key = (Some("openai.com"), Some("OPENAI_API_KEY"));
    for (target, want) in [
        ("openai.com", true),
        ("api.openai.com", true),
        ("OPENAI_API_KEY", true),
        ("openai_api_key", true),
        ("openai.com/OPENAI_API_KEY", true),
        ("openai.com/OPENAI_ADMIN_KEY", false),
        ("anthropic.com", false),
        ("notopenai.com", false),
        ("openai.com.evil.example", false),
    ] {
        assert_eq!(t(target).matches(key.0, key.1), want, "{target}");
    }
    assert!(!t("openai.com").matches(None, Some("OPENAI_API_KEY")));
    assert!(!t("OPENAI_API_KEY").matches(Some("openai.com"), None));
    assert!(t("openai.com").matches(Some("api.openai.com"), None));
}

#[test]
fn saves() {
    let phone = crate::KeyPair::generate();
    let value = seal_value("agent", &phone.public().kem, "sk-test-0000").unwrap();
    let opened = Purpose::Secret
        .open_box(phone.kem_secret(), &value, b"agent")
        .unwrap();
    assert_eq!(&opened[..], b"sk-test-0000");
    assert!(
        Purpose::Password
            .open_box(phone.kem_secret(), &value, b"agent")
            .is_err()
    );
    assert!(seal_value("agent", &phone.public().kem, " ").is_err());
    let long = "x".repeat(MAX_SAVE_VALUE + 1);
    assert!(seal_value("agent", &phone.public().kem, &long).is_err());

    let save = SaveSecret {
        variable: "OPENAI_API_KEY".into(),
        service: Some("openai.com".into()),
        title: Some("OpenAI".into()),
        notes: None,
        expires: None,
        value,
    };
    assert_eq!(save.target(), "openai.com/OPENAI_API_KEY");
    assert!(save.check("openai.com/OPENAI_API_KEY").is_ok());
    assert!(save.check("openai.com").is_err());
    let with = |f: &dyn Fn(&mut SaveSecret)| {
        let mut s = save.clone();
        f(&mut s);
        let target = s.target();
        s.check(&target)
    };
    assert!(with(&|s| s.service = None).is_ok());
    assert!(with(&|s| s.variable = "OPENAI-KEY".into()).is_err());
    assert!(with(&|s| s.service = Some("OpenAI.com".into())).is_err());
    assert!(with(&|s| s.value.ct = String::new()).is_err());
    assert!(with(&|s| s.title = Some("t".repeat(101))).is_err());
    assert!(with(&|s| s.notes = Some("n".repeat(501))).is_err());
}

#[test]
fn wire_names() {
    let a = SecretAnswer {
        title: "OpenAI".into(),
        service: Some("openai.com".into()),
        variable: Some("OPENAI_API_KEY".into()),
        value: Some(Secret::new("sk-test-0000")),
        expires: None,
    };
    assert_eq!(
        serde_json::to_string(&a).unwrap(),
        r#"{"title":"OpenAI","service":"openai.com","variable":"OPENAI_API_KEY","value":"sk-test-0000"}"#
    );
    assert!(!format!("{a:?}").contains("sk-test"));
}
