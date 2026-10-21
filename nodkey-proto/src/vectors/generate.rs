//! Vectors for a new password (peters/nodkey#131): `generate` requests for a sign-up and a
//! password change (plain and signed), the approved answers and each refusal, and the `generate`
//! section: the limits, the classes, which requests pass the checks, how rules read and which
//! passwords fit them. Invented values only.

use serde_json::{Value, json};

use super::{Ctx, Side, label_id, pairing::signed_vector, request, to_json};
use crate::{
    Account, Answer, Decision, GenerateRequest, Kind, Purpose, Saved, Secret,
    generate::{self, CharSet, Rules, errors},
    signed::Direction,
};

/// The rules of the sign-up page in the vectors.
pub const SIGNUP_RULES: &str =
    "minlength: 12; required: lower; required: upper; required: digit; allowed: [-_.!];";
/// The password the phone made for it (it fits [`SIGNUP_RULES`]).
pub const SIGNUP_PASSWORD: &str = "q7Hs-Tw2k.Xp9_mRv4!z";
/// The password the phone made for the change (it fits the change page's pattern and length).
pub const CHANGE_PASSWORD: &str = "Vb3$kQ9.wz+Lr2@nTx7=";

/// The vectors' sign-up request.
pub fn signup_request(rid: &str) -> crate::Request {
    let mut r = request(
        rid,
        Kind::Generate,
        "accounts.example.com",
        "Sign up for Example Cloud, as you asked",
        None,
    );
    r.generate = Some(GenerateRequest {
        url: Some("https://accounts.example.com/signup".into()),
        username: Some("alex@example.com".into()),
        title: Some("Example Cloud".into()),
        change: false,
        rules: Some(Rules {
            passwordrules: Some(SIGNUP_RULES.into()),
            min_length: Some(12),
            max_length: Some(64),
            pattern: None,
        }),
    });
    r
}

/// The vectors' password change request.
pub fn change_request(rid: &str) -> crate::Request {
    let mut r = request(
        rid,
        Kind::Generate,
        "www.example.org",
        "Change the password you asked me to change",
        None,
    );
    r.generate = Some(GenerateRequest {
        url: Some("https://www.example.org/account/password".into()),
        username: Some("alex".into()),
        title: None,
        change: true,
        rules: Some(Rules {
            passwordrules: None,
            min_length: Some(12),
            max_length: Some(32),
            pattern: Some("(?=.*[0-9]).{12,32}".into()),
        }),
    });
    r
}

/// Adds the HPKE vectors and returns the `generate` section and the signed request.
pub(super) fn add(ctx: &mut Ctx, agent: &Side, phone: &Side) -> (Value, Value) {
    let rid = label_id("nodkey/v1/vectors/request/generate");
    let rid_change = label_id("nodkey/v1/vectors/request/generate_change");
    let signup = signup_request(&rid);
    let change = change_request(&rid_change);
    for (name, r) in [
        ("request_generate", &signup),
        ("request_generate_change", &change),
    ] {
        ctx.seal(
            name,
            Purpose::Request,
            "agent",
            phone,
            format!("{}{}", r.request_id, agent.id),
            &to_json(r),
            true,
        );
    }
    let (signed, plain) = signed_vector(
        "request_generate_signed",
        "request_generate_signed",
        Direction::Request,
        agent,
        agent,
        phone,
        &to_json(&signup),
    );
    ctx.seal(
        "request_generate_signed",
        Purpose::Request,
        "agent",
        phone,
        format!("{rid}{}", agent.id),
        &plain,
        true,
    );

    let mut added = Answer::decision(&rid, Decision::Approved);
    added.saved = Some(Saved::Added);
    added.account = Some(Account {
        issuer: "Example Cloud".into(),
        name: "alex@example.com".into(),
        site: Some("accounts.example.com".into()),
        sites: None,
    });
    added.username = Some("alex@example.com".into());
    added.password = Some(Secret::new(SIGNUP_PASSWORD));
    // The user corrected the user name on the phone; the login was saved for the bare domain.
    let mut updated = Answer::decision(&rid_change, Decision::Approved);
    updated.saved = Some(Saved::Updated);
    updated.account = Some(Account {
        issuer: "Example Org".into(),
        name: "alex.k".into(),
        site: Some("example.org".into()),
        sites: None,
    });
    updated.username = Some("alex.k".into());
    updated.password = Some(Secret::new(CHANGE_PASSWORD));
    let mut answers = vec![
        ("answer_generate_added", added),
        ("answer_generate_updated", updated),
    ];
    for (name, error) in [
        ("answer_generate_no_passcode", errors::NO_PASSCODE),
        ("answer_generate_not_allowed", errors::NOT_ALLOWED),
        ("answer_generate_bad_generate", errors::BAD_GENERATE),
        ("answer_generate_bad_rules", errors::BAD_RULES),
        ("answer_generate_save_failed", errors::SAVE_FAILED),
    ] {
        let mut a = Answer::decision(&rid, Decision::Denied);
        a.error = Some(error.into());
        answers.push((name, a));
    }
    for (name, a) in &answers {
        ctx.seal(
            name,
            Purpose::Answer,
            "phone",
            agent,
            format!("{}{}", a.request_id, phone.id),
            &to_json(a),
            true,
        );
    }
    (section(&signup, &change), signed)
}

fn section(signup: &crate::Request, change: &crate::Request) -> Value {
    json!({
        "limits": {
            "default_length": generate::DEFAULT_LENGTH,
            "max_length": generate::MAX_LENGTH,
            "max_url": generate::MAX_URL,
            "max_username": generate::MAX_USERNAME,
            "max_title": generate::MAX_TITLE,
            "max_rules": generate::MAX_RULES,
            "max_pattern": generate::MAX_PATTERN,
            "pattern_tries": generate::PATTERN_TRIES,
            "keep_old_days": generate::KEEP_OLD_DAYS,
        },
        "symbols": generate::SYMBOLS,
        "classes": {
            "upper": CharSet::UPPER.text(),
            "lower": CharSet::LOWER.text(),
            "digit": CharSet::DIGIT.text(),
            "special": CharSet::SPECIAL.text(),
            "ascii-printable": CharSet::PRINTABLE.text(),
            "unicode": CharSet::PRINTABLE.text(),
        },
        "errors": errors::IN_ORDER,
        "requests": {"signup": "request_generate", "change": "request_generate_change"},
        "fill_only_on": [
            {"target": signup.target, "fill_only_on": generate::fill_only_on(&signup.target)},
            {"target": change.target, "fill_only_on": generate::fill_only_on(&change.target)},
            {"target": "192.168.1.1", "fill_only_on": generate::fill_only_on("192.168.1.1")},
        ],
        "checks": checks(signup),
        "rules": rule_cases(),
        "fits": fit_cases(),
    })
}

fn checks(signup: &crate::Request) -> Value {
    let ok = serde_json::to_value(signup.generate.as_ref().expect("generate")).expect("json");
    let target = signup.target.as_str();
    let with = |key: &str, value: Value| {
        let mut v = ok.clone();
        v[key] = value;
        v
    };
    let rules = |key: &str, value: Value| {
        let mut v = ok.clone();
        v["rules"][key] = value;
        v
    };
    let url = |path: &str| json!(format!("https://accounts.example.com{path}"));
    let longest = generate::MAX_URL - "https://accounts.example.com/".len();
    let empty = json!({});
    let cases: Vec<(&str, &str, Value)> = vec![
        ("signup", target, ok.clone()),
        ("bare_host", "example.com", empty.clone()),
        ("ip_address", "192.168.1.1", empty.clone()),
        ("localhost", "localhost", empty.clone()),
        ("change", "www.example.org", json!({"change": true})),
        ("empty_rules", target, with("rules", json!({}))),
        ("upper_case_target", "Accounts.example.com", empty.clone()),
        ("account_in_target", "example.com/alex", empty.clone()),
        ("bare_name", "GitHub", empty.clone()),
        ("port_in_target", "example.com:8443", empty.clone()),
        ("scheme_in_target", "https://example.com", empty.clone()),
        ("blank_target", "", empty.clone()),
        (
            "url_on_other_host",
            target,
            with("url", json!("https://login.example.com/signup")),
        ),
        (
            "url_with_query",
            target,
            with("url", url("/signup?invite=abc")),
        ),
        (
            "url_with_fragment",
            target,
            with("url", url("/signup#step2")),
        ),
        (
            "url_other_scheme",
            target,
            with("url", json!("ftp://accounts.example.com/signup")),
        ),
        (
            "url_without_scheme",
            target,
            with("url", json!("accounts.example.com/signup")),
        ),
        (
            "url_http",
            target,
            with("url", json!("http://accounts.example.com/signup")),
        ),
        (
            "longest_url",
            target,
            with("url", url(&format!("/{}", "a".repeat(longest)))),
        ),
        (
            "long_url",
            target,
            with("url", url(&format!("/{}", "a".repeat(longest + 1)))),
        ),
        (
            "longest_username",
            target,
            with("username", json!("u".repeat(200))),
        ),
        (
            "long_username",
            target,
            with("username", json!("u".repeat(201))),
        ),
        (
            "control_in_username",
            target,
            with("username", json!("alex\n")),
        ),
        ("long_title", target, with("title", json!("t".repeat(101)))),
        (
            "longest_rules",
            target,
            rules("passwordrules", json!("a".repeat(300))),
        ),
        (
            "long_rules",
            target,
            rules("passwordrules", json!("a".repeat(301))),
        ),
        (
            "control_in_rules",
            target,
            rules("passwordrules", json!("required: digit;\nminlength: 8")),
        ),
        (
            "long_pattern",
            target,
            rules("pattern", json!("a".repeat(301))),
        ),
    ];
    let cases: Vec<Value> = cases
        .into_iter()
        .map(|(name, target, generate)| {
            let g: GenerateRequest = serde_json::from_value(generate.clone()).expect("generate");
            let error = g.check(target).err().map(|_| errors::BAD_GENERATE);
            json!({"name": name, "target": target, "generate": generate, "error": error})
        })
        .collect();
    Value::Array(cases)
}

fn rules_of(text: Option<&str>, min: Option<u32>, max: Option<u32>) -> Rules {
    Rules {
        passwordrules: text.map(str::to_owned),
        min_length: min,
        max_length: max,
        pattern: None,
    }
}

fn rule_cases() -> Value {
    let t = |s: &str| rules_of(Some(s), None, None);
    let cases: Vec<(&str, Rules)> = vec![
        ("none", Rules::default()),
        ("signup", rules_of(Some(SIGNUP_RULES), Some(12), Some(64))),
        (
            "typical",
            t(
                "minlength: 8; maxlength: 16; required: lower; required: upper; required: digit; \
               required: [!#$%&*?@]; allowed: [-_.];",
            ),
        ),
        ("field_only", rules_of(None, Some(12), Some(64))),
        (
            "field_and_rules",
            rules_of(Some("minlength: 10; maxlength: 40"), Some(12), Some(64)),
        ),
        (
            "digits_only",
            t("allowed: digit; minlength: 6; maxlength: 6"),
        ),
        ("dash_first_and_bracket", t("allowed: [-_.]]")),
        ("dash_not_first", t("allowed: [a-z]")),
        ("empty_class_then_text", t("allowed: []abc], digit")),
        ("semicolon_in_class", t("required: [;!]; required: digit")),
        ("letters_outside_ascii", t("required: [ab\u{e9}\u{f8}]")),
        (
            "case_and_spaces",
            t("  MinLength : 9 ;REQUIRED:Upper , Digit"),
        ),
        (
            "unknown_parts",
            t("nonsense; colour: blue; required: sparkly, digit; minlength: ten; ;"),
        ),
        ("only_unknown_class", t("required: sparkly")),
        ("unicode", t("required: unicode; required: digit")),
        ("special", t("required: special")),
        (
            "smallest_and_largest_win",
            t(
                "max-consecutive: 3; max-consecutive: 2; maxlength: 30; maxlength: 24; \
               minlength: 8; minlength: 10",
            ),
        ),
        ("longest", rules_of(None, Some(128), None)),
        (
            "one_character_once",
            t("allowed: [a]; max-consecutive: 1; maxlength: 1"),
        ),
        (
            "min_above_max",
            rules_of(Some("minlength: 20"), None, Some(16)),
        ),
        ("max_zero", rules_of(None, None, Some(0))),
        ("min_above_128", rules_of(None, Some(129), None)),
        ("max_consecutive_zero", t("max-consecutive: 0")),
        ("required_space_only", t("required: [ ]")),
        ("required_empty", t("required: []")),
        ("allowed_space_only", t("allowed: [ ]")),
        (
            "too_many_required",
            t("required: upper; required: lower; required: digit; maxlength: 2"),
        ),
        (
            "one_character_repeated",
            t("allowed: [a]; max-consecutive: 1"),
        ),
    ];
    let cases: Vec<Value> = cases
        .into_iter()
        .map(|(name, rules)| {
            let r = rules.read();
            json!({
                "name": name,
                "rules": rules,
                "read": {
                    "required": r.required.iter().map(|s| s.text()).collect::<Vec<_>>(),
                    "allowed": r.allowed.text(),
                    "max_consecutive": r.max_consecutive,
                    "min_length": r.min_length,
                    "max_length": r.max_length,
                    "length": r.length(),
                },
                "error": r.problem().map(|_| errors::BAD_RULES),
            })
        })
        .collect();
    Value::Array(cases)
}

fn fit_cases() -> Value {
    let small = "minlength: 4; maxlength: 6; required: digit; allowed: lower; max-consecutive: 2";
    let cases: Vec<(&str, Rules, &str)> = vec![
        ("fits", rules_of(Some(small), None, None), "abc1"),
        ("no_digit", rules_of(Some(small), None, None), "abcd"),
        ("too_short", rules_of(Some(small), None, None), "ab1"),
        ("too_long", rules_of(Some(small), None, None), "abcdef1"),
        ("not_allowed", rules_of(Some(small), None, None), "abC1"),
        ("three_in_a_row", rules_of(Some(small), None, None), "aaa1"),
        ("two_in_a_row", rules_of(Some(small), None, None), "aa1aa"),
        (
            "signup",
            rules_of(Some(SIGNUP_RULES), Some(12), Some(64)),
            SIGNUP_PASSWORD,
        ),
        ("no_rules_space", Rules::default(), "correct horse"),
        ("no_rules_outside_ascii", Rules::default(), "p\u{e4}ssword"),
        ("field_max", rules_of(None, None, Some(8)), "abcdefghi"),
    ];
    let cases: Vec<Value> = cases
        .into_iter()
        .map(|(name, rules, password)| {
            json!({"name": name, "rules": rules, "password": password, "fits": rules.fits(password)})
        })
        .collect();
    Value::Array(cases)
}
