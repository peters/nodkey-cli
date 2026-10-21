use super::*;
use crate::{Lease, Secret};

fn rules(text: &str) -> Rules {
    Rules {
        passwordrules: Some(text.into()),
        ..Rules::default()
    }
}

#[test]
fn classes() {
    assert_eq!(CharSet::SPECIAL.len(), 33);
    assert!(CharSet::SPECIAL.contains(' ') && CharSet::SPECIAL.contains('~'));
    assert!(!CharSet::SPECIAL.contains('a') && !CharSet::SPECIAL.contains('5'));
    assert_eq!(CharSet::PRINTABLE.len(), 95);
    assert_eq!(CharSet::of(SYMBOLS).text(), SYMBOLS);
    assert!(!CharSet::PRINTABLE.contains('\u{e9}') && !CharSet::PRINTABLE.contains('\n'));
    assert_eq!(CharSet::PRINTABLE.usable().len(), 94);
}

#[test]
fn reads_apples_syntax() {
    let r = rules(
        "minlength: 8; maxlength: 64; required: lower; required: upper, digit; \
         allowed: [-_.]; max-consecutive: 3; MaxLength: 32",
    )
    .read();
    assert_eq!(r.required.len(), 2);
    assert_eq!(r.required[0], CharSet::LOWER);
    assert_eq!(r.required[1], CharSet::UPPER.union(CharSet::DIGIT));
    let allowed = CharSet::LOWER
        .union(CharSet::UPPER)
        .union(CharSet::DIGIT)
        .union(CharSet::of("-_."));
    assert_eq!(r.allowed, allowed);
    assert_eq!(
        (r.min_length, r.max_length, r.max_consecutive),
        (Some(8), Some(32), Some(3))
    );
    assert_eq!(r.length(), 20);
}

#[test]
fn custom_classes() {
    let set = |t: &str| rules(&format!("allowed: {t}")).read().allowed.text();
    assert_eq!(set("[-_.]]"), "-.]_");
    assert_eq!(set("[a-z]"), "az");
    assert_eq!(set("[]]"), "]");
    assert_eq!(set("[;,]"), ",;");
    assert_eq!(set("[ab\u{e9}]"), "ab");
    assert_eq!(set("[[]"), "[");
    // `[]abc]` is an empty class with text after it: not a class, so nothing is allowed by it.
    assert_eq!(set("[]abc], digit"), "0123456789");
    // A `;` inside a class does not end the property.
    let r = rules("required: [;!]; required: digit").read();
    assert_eq!(r.required.len(), 2);
    assert_eq!(r.required[0].text(), "!;");
}

#[test]
fn lenient_parts_are_left_out() {
    let r = rules("nonsense; colour: blue; required: sparkly, digit; minlength: ten; ;").read();
    assert_eq!(r.required, vec![CharSet::DIGIT]);
    assert_eq!(r.min_length, None);
    assert_eq!(r.allowed, CharSet::DIGIT);
    // Only unknown classes: the property counts for nothing.
    let r = rules("required: sparkly").read();
    assert!(r.required.is_empty());
    assert_eq!(r.allowed, CharSet::PRINTABLE);
    assert_eq!(Rules::default().read(), Reading::default());
}

#[test]
fn field_attributes_join_in() {
    let r = Rules {
        passwordrules: Some("minlength: 10; maxlength: 40".into()),
        min_length: Some(12),
        max_length: Some(64),
        pattern: None,
    }
    .read();
    assert_eq!((r.min_length, r.max_length), (Some(12), Some(40)));
    let short = Rules {
        max_length: Some(16),
        ..Rules::default()
    }
    .read();
    assert_eq!(short.length(), 16);
    let long = Rules {
        min_length: Some(32),
        ..Rules::default()
    }
    .read();
    assert_eq!(long.length(), 32);
}

#[test]
fn rules_no_password_can_meet() {
    let bad = |r: Rules| r.check().is_err();
    let len = |min: Option<u32>, max: Option<u32>| Rules {
        min_length: min,
        max_length: max,
        ..Rules::default()
    };
    assert!(bad(len(Some(20), Some(10))));
    assert!(bad(len(None, Some(0))));
    assert!(bad(len(Some(129), None)));
    assert!(!bad(len(Some(128), None)));
    assert!(!bad(len(Some(10), Some(10))));
    assert!(bad(rules("max-consecutive: 0")));
    assert!(bad(rules("required: [ ]")));
    assert!(bad(rules("required: []")));
    assert!(bad(rules("allowed: [ ]")));
    assert!(bad(rules(
        "required: upper; required: lower; required: digit; maxlength: 2"
    )));
    assert!(!bad(rules(
        "required: upper; required: lower; required: digit; maxlength: 3"
    )));
    assert!(bad(rules("allowed: [a]; max-consecutive: 1")));
    assert!(!bad(rules(
        "allowed: [a]; max-consecutive: 1; maxlength: 1"
    )));
    assert!(!bad(rules("allowed: [ab]; max-consecutive: 1")));
    assert!(!bad(rules("required: special")));
}

#[test]
fn fits() {
    let r =
        rules("minlength: 4; maxlength: 6; required: digit; allowed: lower; max-consecutive: 2");
    assert!(r.fits("abc1"));
    assert!(!r.fits("abcd"), "no digit");
    assert!(!r.fits("ab1"), "too short");
    assert!(!r.fits("abcdef1"), "too long");
    assert!(!r.fits("abC1"), "not allowed");
    assert!(!r.fits("aaa1"), "three in a row");
    assert!(r.fits("aa1aa"));
}

#[test]
fn made_passwords_fit() {
    let cases = [
        "",
        "minlength: 12; required: lower; required: upper; required: digit; allowed: [-_.!];",
        "required: digit; maxlength: 6; minlength: 6",
        "allowed: digit; max-consecutive: 1",
        "required: [~^]; allowed: lower",
        "allowed: [ab]; max-consecutive: 1; minlength: 30",
        "required: upper; required: upper; required: special; maxlength: 3",
        "allowed: ascii-printable; max-consecutive: 2; minlength: 128",
        "allowed: [a]; maxlength: 1; max-consecutive: 1",
    ];
    for text in cases {
        let r = rules(text);
        let reading = r.check().unwrap_or_else(|e| panic!("{text}: {e}"));
        for _ in 0..50 {
            let p = reading
                .make()
                .unwrap_or_else(|| panic!("{text}: none made"));
            let p = p.expose();
            assert!(r.fits(p), "{text}: {p:?}");
            assert!(!p.contains(' '), "{text}: a space");
            assert_eq!(p.chars().count() as u32, reading.length(), "{text}");
        }
    }
}

#[test]
fn default_password_mixes_classes() {
    for _ in 0..50 {
        let p = Reading::default().make().unwrap();
        let p = p.expose();
        assert_eq!(p.len(), 20);
        assert!(p.chars().any(|c| c.is_ascii_lowercase()));
        assert!(p.chars().any(|c| c.is_ascii_uppercase()));
        assert!(p.chars().any(|c| c.is_ascii_digit()));
        assert!(p.chars().any(|c| SYMBOLS.contains(c)));
        assert!(
            p.chars()
                .all(|c| c.is_ascii_alphanumeric() || SYMBOLS.contains(c))
        );
    }
    assert!(rules("maxlength: 0").read().make().is_none());
}

#[test]
fn pages() {
    assert_eq!(
        page("https://Accounts.Example.com/signup?invite=abc#top"),
        Some((
            "accounts.example.com".into(),
            Some("https://Accounts.Example.com/signup".into())
        ))
    );
    assert_eq!(
        page("accounts.example.com"),
        Some(("accounts.example.com".into(), None))
    );
    assert_eq!(page("ftp://example.com"), None);
    assert_eq!(page("GitHub"), None);
}

#[test]
fn request_checks() {
    let ok = GenerateRequest {
        url: Some("https://accounts.example.com/signup".into()),
        username: Some("alex@example.com".into()),
        ..GenerateRequest::default()
    };
    assert!(ok.check("accounts.example.com").is_ok());
    assert!(ok.check("example.com").is_err(), "url on another host");
    assert!(ok.check("Accounts.example.com").is_err(), "not lower case");
    assert!(
        GenerateRequest::default()
            .check("example.com/alex")
            .is_err()
    );
    assert!(GenerateRequest::default().check("GitHub").is_err());
    assert!(GenerateRequest::default().check("192.168.1.1").is_ok());
    let with = |f: fn(&mut GenerateRequest)| {
        let mut g = ok.clone();
        f(&mut g);
        g.check("accounts.example.com")
    };
    assert!(with(|g| g.url = Some("https://accounts.example.com/signup?t=1".into())).is_err());
    assert!(with(|g| g.url = Some("accounts.example.com/signup".into())).is_err());
    assert!(
        with(|g| g.url = Some(format!("https://accounts.example.com/{}", "a".repeat(500))))
            .is_err()
    );
    assert!(with(|g| g.username = Some("alex\n".into())).is_err());
    assert!(with(|g| g.title = Some("t".repeat(101))).is_err());
    assert!(with(|g| g.rules = Some(rules(&"a".repeat(301)))).is_err());
    assert!(with(|g| g.rules = Some(rules("required: digit"))).is_ok());
}

#[test]
fn answers_the_agent_uses() {
    let mut a = Answer::decision("rid", Decision::Approved);
    assert!(check_answer(&a).is_err());
    a.password = Some(Secret::new("x7#Kq"));
    assert!(check_answer(&a).is_err(), "not saved");
    a.saved = Some(Saved::Unchanged);
    assert!(check_answer(&a).is_err());
    a.saved = Some(Saved::Added);
    assert!(check_answer(&a).is_ok());
    a.lease = Some(Lease {
        kind: LeaseKind::Day,
        until: Some(1),
    });
    assert!(check_answer(&a).is_err());
    assert!(check_answer(&Answer::decision("rid", Decision::Denied)).is_ok());
    assert_eq!(fill_only_on("accounts.example.com"), ["example.com"]);
}
