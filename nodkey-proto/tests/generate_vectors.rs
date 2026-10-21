//! Checks the vectors for a new password in `vectors/v1.json`: the requests pass the agent's
//! checks, the checks, readings and fits decide the same way as `nodkey_proto::generate`, and
//! the approved answers carry a saved password that fits the request's rules.

use nodkey_proto::{
    Answer, Decision, GenerateRequest, Kind, Request, Saved,
    generate::{self, CharSet, Rules, errors},
    parse_plaintext,
};
use serde_json::Value;

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/v1.json");

fn load() -> Value {
    serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap()
}

fn hpke<'a>(v: &'a Value, name: &str) -> &'a Value {
    v["hpke"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["name"] == name)
        .unwrap_or_else(|| panic!("{name}"))
}

fn plain<T: serde::de::DeserializeOwned + nodkey_proto::Versioned>(v: &Value, name: &str) -> T {
    parse_plaintext(hpke(v, name)["plaintext"].as_str().unwrap().as_bytes()).unwrap()
}

#[test]
fn requests_pass_the_checks() {
    let v = load();
    for name in ["request_generate", "request_generate_change"] {
        let r: Request = plain(&v, name);
        assert_eq!(r.kind, Kind::Generate, "{name}");
        nodkey_proto::client::check_request(&r).unwrap();
        assert!(r.session_id.is_none() && r.bundle.is_none());
    }
    let change: Request = plain(&v, "request_generate_change");
    assert!(change.generate.unwrap().change);
    let signed = v["signed"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == "request_generate_signed")
        .unwrap();
    assert_eq!(signed["body"], hpke(&v, "request_generate")["plaintext"]);
}

#[test]
fn answers_carry_a_saved_password_or_a_refusal() {
    let v = load();
    for (answer, request, saved) in [
        ("answer_generate_added", "request_generate", Saved::Added),
        (
            "answer_generate_updated",
            "request_generate_change",
            Saved::Updated,
        ),
    ] {
        let a: Answer = plain(&v, answer);
        let r: Request = plain(&v, request);
        assert_eq!(a.request_id, r.request_id);
        assert_eq!(a.decision, Decision::Approved);
        assert_eq!(a.saved, Some(saved));
        assert!(a.lease.is_none() && a.match_kind.is_none() && a.code.is_none());
        generate::check_answer(&a).unwrap();
        let account = a.account.as_ref().unwrap();
        assert_eq!(Some(&account.name), a.username.as_ref());
        assert!(nodkey_proto::site::same_site(
            account.site.as_deref().unwrap(),
            &r.target
        ));
        let rules = r.generate.unwrap().rules.unwrap_or_default();
        let password = a.password.as_ref().unwrap().expose();
        assert!(rules.fits(password), "{answer}");
        assert!(!password.contains(' '));
    }
    for name in [
        "answer_generate_no_passcode",
        "answer_generate_not_allowed",
        "answer_generate_bad_generate",
        "answer_generate_bad_rules",
        "answer_generate_save_failed",
    ] {
        let a: Answer = plain(&v, name);
        assert_eq!(a.decision, Decision::Denied, "{name}");
        assert!(a.password.is_none() && a.saved.is_none());
        let error = a.error.unwrap();
        assert_eq!(name, format!("answer_generate_{error}"));
        assert!(errors::IN_ORDER.contains(&error.as_str()) || error == errors::SAVE_FAILED);
    }
}

#[test]
fn section_matches_the_code() {
    let v = load();
    let g = &v["generate"];
    assert_eq!(g["errors"], serde_json::json!(errors::IN_ORDER));
    assert_eq!(g["symbols"], generate::SYMBOLS);
    assert_eq!(g["limits"]["default_length"], generate::DEFAULT_LENGTH);
    assert_eq!(g["limits"]["max_length"], generate::MAX_LENGTH);
    assert_eq!(g["classes"]["special"], CharSet::SPECIAL.text());
    for c in g["fill_only_on"].as_array().unwrap() {
        let target = c["target"].as_str().unwrap();
        assert_eq!(
            c["fill_only_on"],
            serde_json::json!(generate::fill_only_on(target))
        );
    }
}

#[test]
fn checks_decide_the_same() {
    let v = load();
    for c in v["generate"]["checks"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let g: GenerateRequest = serde_json::from_value(c["generate"].clone()).unwrap();
        let got = g
            .check(c["target"].as_str().unwrap())
            .err()
            .map(|_| errors::BAD_GENERATE);
        assert_eq!(got, c["error"].as_str(), "{name}");
    }
}

#[test]
fn rules_read_the_same() {
    let v = load();
    let mut refused = 0;
    for c in v["generate"]["rules"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let rules: Rules = serde_json::from_value(c["rules"].clone()).unwrap();
        let r = rules.read();
        let want = &c["read"];
        let required: Vec<String> = r.required.iter().map(|s| s.text()).collect();
        assert_eq!(serde_json::json!(required), want["required"], "{name}");
        assert_eq!(
            r.allowed.text(),
            want["allowed"].as_str().unwrap(),
            "{name}"
        );
        let num = |k: &str| want[k].as_u64().map(|n| n as u32);
        assert_eq!(r.max_consecutive, num("max_consecutive"), "{name}");
        assert_eq!(r.min_length, num("min_length"), "{name}");
        assert_eq!(r.max_length, num("max_length"), "{name}");
        assert_eq!(Some(r.length()), num("length"), "{name}");
        let error = rules.check().err().map(|_| errors::BAD_RULES);
        assert_eq!(error, c["error"].as_str(), "{name}");
        if error.is_some() {
            refused += 1;
        } else {
            let made = r.make().unwrap();
            assert!(rules.fits(made.expose()), "{name}");
        }
    }
    assert!(refused >= 9);
}

#[test]
fn fits_decide_the_same() {
    let v = load();
    for c in v["generate"]["fits"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let rules: Rules = serde_json::from_value(c["rules"].clone()).unwrap();
        let fits = rules.fits(c["password"].as_str().unwrap());
        assert_eq!(Some(fits), c["fits"].as_bool(), "{name}");
    }
}
