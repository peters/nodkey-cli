use super::*;
use nodkey_proto::{Lease, LeaseKind};

fn args(list: &[&str]) -> Args {
    Args::parse(&list.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
}

fn approved(saved: Saved) -> Answer {
    let mut a = Answer::decision("rid", Decision::Approved);
    a.saved = Some(saved);
    a.account = Some(Account {
        issuer: "Example Cloud".into(),
        name: "alex@example.com".into(),
        site: Some("accounts.example.com".into()),
        sites: None,
    });
    a.username = Some("alex@example.com".into());
    a.password = Some(Secret::new("q7Hs-Tw2k.Xp9_mRv4!z"));
    a
}

fn refused(error: &str) -> Answer {
    let mut a = Answer::decision("rid", Decision::Denied);
    a.error = Some(error.into());
    a
}

#[test]
fn the_request_names_the_page() {
    let new = NewLogin {
        site: "https://Accounts.Example.com/signup?invite=abc#top",
        username: Some(" alex@example.com "),
        title: Some(""),
        ..NewLogin::default()
    };
    let (target, g) = new.request().unwrap();
    assert_eq!(target, "accounts.example.com");
    assert_eq!(
        g.url.as_deref(),
        Some("https://Accounts.Example.com/signup")
    );
    assert_eq!(g.username.as_deref(), Some("alex@example.com"));
    assert_eq!((g.title, g.rules, g.change), (None, None, false));
    let bare = NewLogin {
        site: "example.com",
        ..NewLogin::default()
    };
    assert_eq!(bare.request().unwrap().1.url, None);
    for site in ["GitHub", "ftp://example.com", ""] {
        let bad = NewLogin {
            site,
            ..NewLogin::default()
        };
        assert!(bad.request().is_err(), "{site}");
    }
    let long = "u".repeat(201);
    let bad = NewLogin {
        site: "example.com",
        username: Some(&long),
        ..NewLogin::default()
    };
    assert!(bad.request().unwrap_err().contains("username"));
}

#[test]
fn command_line_options() {
    let a = args(&[
        "--site",
        "https://accounts.example.com/signup",
        "--user",
        "alex@example.com",
        "--rules",
        "required: digit",
        "--min",
        "12",
        "--max",
        "64",
        "--pattern",
        ".{12,}",
        "--change",
    ]);
    check_cli(&a).unwrap();
    let new = cli_login(&a).unwrap();
    assert!(new.change);
    assert_eq!(
        new.rules,
        Rules {
            passwordrules: Some("required: digit".into()),
            min_length: Some(12),
            max_length: Some(64),
            pattern: Some(".{12,}".into()),
        }
    );
    assert!(check_cli(&args(&[])).unwrap_err().contains("--site"));
    assert!(check_cli(&args(&["--site", "example.com", "--min", "ten"])).is_err());
    assert!(check_cli(&args(&["example.com"])).is_err());
    assert!(check_cli(&args(&["--site", "example.com", "--ip-only"])).is_err());
    assert!(check_cli(&args(&["--site", "GitHub"])).is_err());
}

#[test]
fn approved_results_say_where_to_fill() {
    let out = outcome(
        approved(Saved::Added),
        "accounts.example.com",
        "Test iPhone",
    )
    .unwrap();
    assert_eq!(exit_code(&out), 0);
    assert_eq!(
        out.fill_only_on.as_deref(),
        Some(&["example.com".to_owned()][..])
    );
    assert!(out.message.contains("new login") && out.message.contains("example.com"));
    assert_eq!(
        summary(&out),
        "saved the login alex@example.com on accounts.example.com in Nodkey on Test iPhone. \
         Fill the password only on example.com."
    );
    let out = outcome(
        approved(Saved::Updated),
        "accounts.example.com",
        "Test iPhone",
    )
    .unwrap();
    assert!(out.message.contains("30 days") && summary(&out).contains("30 days"));
    // An answer the agent must not use.
    let mut leased = approved(Saved::Added);
    leased.lease = Some(Lease {
        kind: LeaseKind::Always,
        until: None,
    });
    assert!(outcome(leased, "accounts.example.com", "Test iPhone").is_err());
    let mut unsaved = approved(Saved::Added);
    unsaved.saved = None;
    assert!(outcome(unsaved, "accounts.example.com", "Test iPhone").is_err());
}

#[test]
fn refusals_and_exit_codes() {
    let code = |a: Answer| {
        let out = outcome(a, "example.com", "Test iPhone").unwrap();
        assert!(out.password.is_none() && out.fill_only_on.is_none());
        (exit_code(&out), out.message)
    };
    assert_eq!(code(refused("paused")).0, PAUSED);
    let (c, m) = code(refused(errors::NO_PASSCODE));
    assert!(c == NO_PASSCODE_EXIT && m.contains("passcode"));
    let (c, m) = code(refused(errors::BAD_RULES));
    assert!(c == BAD_RULES_EXIT && m.contains("rules"));
    assert_eq!(code(refused(errors::BAD_GENERATE)).0, 1);
    let (c, m) = code(refused(errors::SAVE_FAILED));
    assert!(c == 1 && m.contains("nothing changed"));
    let (c, m) = code(refused(errors::NOT_ALLOWED));
    assert!(c == DENIED && m.contains("codes only"));
    let (c, m) = code(refused("unsupported_kind"));
    assert!(c == DENIED && m.contains("newer Nodkey"));
    let (c, m) = code(Answer::decision("rid", Decision::Denied));
    assert!(c == DENIED && m.contains("did not make"));
    assert_eq!(code(Answer::decision("rid", Decision::Expired)).0, EXPIRED);
}
