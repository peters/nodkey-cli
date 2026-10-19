//! API key vectors: a `secret` request and its answers (the key, `no_secret`, the agent limit
//! warning), a `save_secret` request with the value sealed on its own and its answer, a bundle of
//! two keys (what `nodkey run` sends for two `--secret` options), a task plan with a key (its item
//! carries no value) and a key request answered in that session, a list answer with key names, and
//! the `secrets` section: targets, matches and the limits every side uses. Test values only.

use serde_json::{Value, json};

use super::{Ctx, Side, label_id, request, to_json};
use crate::{
    Answer, BundleItem, BundleItemAnswer, BundleRequest, Decision, Kind, Lease, LeaseKind, Purpose,
    Quota, SaveSecret, Secret, SecretAnswer, SecretEntry, SecretTarget, SessionInfo, apikey,
};

const SESSION_ID: &str = "U2VjcmV0U2Vzc2lvbklkMQ";
const UNTIL: u64 = super::TS + 1800;

fn key(value: Option<&str>) -> SecretAnswer {
    SecretAnswer {
        title: "OpenAI".into(),
        service: Some("openai.com".into()),
        variable: Some("OPENAI_API_KEY".into()),
        value: value.map(Secret::new),
        expires: Some(super::TS + 90 * 86_400),
        from: None,
        project: None,
    }
}

fn example_key() -> SecretAnswer {
    SecretAnswer {
        title: "Example API".into(),
        service: Some("api.example.com".into()),
        variable: Some("EXAMPLE_TOKEN".into()),
        value: Some(Secret::new("tok-test-1111")),
        expires: None,
        from: None,
        project: None,
    }
}

fn item(id: &str, kind: Kind, target: &str) -> BundleItem {
    BundleItem {
        id: id.into(),
        kind,
        target: target.into(),
    }
}

fn once() -> Option<Lease> {
    Some(Lease {
        kind: LeaseKind::Once,
        until: None,
    })
}

/// Adds the HPKE vectors and returns the `secrets` section.
pub(super) fn add(ctx: &mut Ctx, agent: &Side, phone: &Side) -> Value {
    let to_phone = |rid: &str| format!("{rid}{}", agent.id);
    let to_agent = |rid: &str| format!("{rid}{}", phone.id);
    let mut requests = Vec::new();
    let mut answers = Vec::new();

    // A key by service and variable name, and the phone's answers.
    let rid = label_id("nodkey/v1/vectors/request/secret");
    let r = request(
        &rid,
        Kind::Secret,
        "openai.com/OPENAI_API_KEY",
        "Run the test suite that calls the OpenAI API",
        None,
    );
    requests.push(("request_secret", r));
    let mut a = Answer::decision(&rid, Decision::Approved);
    a.lease = once();
    a.secret = Some(key(Some("sk-test-0000")));
    answers.push(("answer_secret", a.clone()));
    a.error = Some(crate::quota::errors::QUOTA_WARNING.into());
    a.quota = Some(Quota {
        new_today: 11,
        limit: crate::quota::DEFAULT_LIMIT,
        burst: false,
    });
    answers.push(("answer_secret_quota_warning", a));
    let mut a = Answer::decision(&rid, Decision::Denied);
    a.error = Some(apikey::errors::NO_SECRET.into());
    answers.push(("answer_secret_no_secret", a));

    // A key by variable name only.
    let rid = label_id("nodkey/v1/vectors/request/secret_by_variable");
    let r = request(
        &rid,
        Kind::Secret,
        "EXAMPLE_TOKEN",
        "Deploy the preview with the example API",
        None,
    );
    requests.push(("request_secret_by_variable", r));

    // Save a key the agent just made: the value is sealed to the phone on its own.
    let rid = label_id("nodkey/v1/vectors/request/save_secret");
    let value = ctx.seal(
        "save_secret_value",
        Purpose::Secret,
        "agent",
        phone,
        agent.id.clone(),
        b"sk-test-0000",
        false,
    );
    let save = SaveSecret {
        variable: "OPENAI_API_KEY".into(),
        service: Some("openai.com".into()),
        title: Some("OpenAI".into()),
        notes: Some("Made for the test project".into()),
        expires: Some(super::TS + 90 * 86_400),
        projects: vec![],
        value,
    };
    let mut r = request(
        &rid,
        Kind::SaveSecret,
        &save.target(),
        "Save the API key I just made in the OpenAI dashboard",
        None,
    );
    r.save_secret = Some(save);
    requests.push(("request_save_secret", r));
    let mut a = Answer::decision(&rid, Decision::Approved);
    a.saved = Some(crate::Saved::Added);
    answers.push(("answer_save_secret", a));

    // Two keys in one request, as `nodkey run --secret A --secret B` asks.
    let rid = label_id("nodkey/v1/vectors/request/bundle_secrets");
    let mut r = request(&rid, Kind::Bundle, "", "Run the integration tests", None);
    r.bundle = Some(BundleRequest {
        items: vec![
            item("1", Kind::Secret, "OPENAI_API_KEY"),
            item("2", Kind::Secret, "api.example.com/EXAMPLE_TOKEN"),
        ],
        follow_up: None,
        session: None,
    });
    requests.push(("request_bundle_secrets", r));
    let mut first = BundleItemAnswer::decision("1", Decision::Approved);
    first.lease = once();
    first.secret = Some(key(Some("sk-test-0000")));
    let mut second = BundleItemAnswer::decision("2", Decision::Approved);
    second.lease = once();
    second.secret = Some(example_key());
    let mut a = Answer::decision(&rid, Decision::Approved);
    a.items = Some(vec![first, second]);
    answers.push(("answer_bundle_secrets", a));

    // A task plan with a login and a key: the key item carries no value; a later key request in
    // the session is answered under it.
    let rid = label_id("nodkey/v1/vectors/request/bundle_secret_session");
    let mut r = request(&rid, Kind::Bundle, "", "Release the new version", None);
    r.bundle = Some(BundleRequest {
        items: vec![
            item("1", Kind::Login, "accounts.example.com"),
            item("2", Kind::Secret, "openai.com/OPENAI_API_KEY"),
        ],
        follow_up: None,
        session: Some(1800),
    });
    requests.push(("request_bundle_secret_session", r));
    let session_lease = Some(Lease {
        kind: LeaseKind::Session,
        until: Some(UNTIL),
    });
    let mut login = BundleItemAnswer::decision("1", Decision::Approved);
    login.lease = session_lease.clone();
    login.account = Some(crate::Account {
        issuer: "Example".into(),
        name: "alex@example.com".into(),
        site: Some("accounts.example.com".into()),
        sites: None,
    });
    login.username = Some("alex@example.com".into());
    login.password = Some(Secret::new("correct horse battery staple"));
    let mut plan_key = BundleItemAnswer::decision("2", Decision::Approved);
    plan_key.secret = Some(key(None));
    let mut a = Answer::decision(&rid, Decision::Approved);
    a.session = Some(SessionInfo {
        id: SESSION_ID.into(),
        until: UNTIL,
    });
    a.items = Some(vec![login, plan_key]);
    answers.push(("answer_bundle_secret_session", a));
    let rid = label_id("nodkey/v1/vectors/request/secret_in_session");
    let mut r = request(
        &rid,
        Kind::Secret,
        "openai.com/OPENAI_API_KEY",
        "Run the release checks",
        None,
    );
    r.session_id = Some(SESSION_ID.into());
    requests.push(("request_secret_in_session", r));
    let mut a = Answer::decision(&rid, Decision::Approved);
    a.lease = session_lease;
    a.secret = Some(key(Some("sk-test-0000")));
    answers.push(("answer_secret_in_session", a));

    // A list answer with the names of the keys.
    let rid = label_id("nodkey/v1/vectors/request/list");
    let mut a = Answer::decision(&rid, Decision::Approved);
    a.accounts = Some(vec![]);
    a.secrets = Some(vec![
        SecretEntry {
            title: "OpenAI".into(),
            service: Some("openai.com".into()),
            variable: Some("OPENAI_API_KEY".into()),
            projects: vec![],
        },
        SecretEntry {
            title: "Example API".into(),
            service: Some("api.example.com".into()),
            variable: Some("EXAMPLE_TOKEN".into()),
            projects: vec![],
        },
    ]);
    answers.push(("answer_list_with_secrets", a));

    for (name, r) in &requests {
        ctx.seal(
            name,
            Purpose::Request,
            "agent",
            phone,
            to_phone(&r.request_id),
            &to_json(r),
            true,
        );
    }
    for (name, a) in &answers {
        ctx.seal(
            name,
            Purpose::Answer,
            "phone",
            agent,
            to_agent(&a.request_id),
            &to_json(a),
            true,
        );
    }
    section()
}

/// Targets, matches and limits every side must decide the same way.
fn section() -> Value {
    let targets: Vec<Value> = [
        "openai.com",
        "OPENAI_API_KEY",
        "openai.com/OPENAI_API_KEY",
        "localhost/DEV_TOKEN",
        "_PRIVATE",
        "OpenAI.com",
        "https://openai.com",
        "www.openai.com",
        "openai.com/",
        "/OPENAI_API_KEY",
        "openai.com/OPENAI-KEY",
        "1PASSWORD",
        "",
    ]
    .iter()
    .map(|t| match SecretTarget::parse(t) {
        Ok(p) => json!({"target": t, "ok": true, "service": p.service, "variable": p.variable}),
        Err(_) => json!({"target": t, "ok": false}),
    })
    .collect();
    let keys = [
        ("openai.com", "OPENAI_API_KEY"),
        ("api.example.com", "EXAMPLE_TOKEN"),
    ];
    let matches: Vec<Value> = [
        "openai.com",
        "api.openai.com",
        "platform.openai.com/OPENAI_API_KEY",
        "openai_api_key",
        "openai.com/OPENAI_ADMIN_KEY",
        "notopenai.com",
        "openai.com.evil.example",
        "example.com",
        "EXAMPLE_TOKEN",
        "ANTHROPIC_API_KEY",
    ]
    .iter()
    .flat_map(|t| {
        let target = SecretTarget::parse(t).expect("a valid target");
        keys.iter().map(move |(service, variable)| {
            json!({
                "target": t, "service": service, "variable": variable,
                "match": target.matches(Some(service), Some(variable)),
            })
        })
    })
    .collect();
    json!({
        "targets": targets,
        "matches": matches,
        "max_variable": apikey::MAX_VARIABLE,
        "max_save_value": apikey::MAX_SAVE_VALUE,
        "max_title": apikey::MAX_TITLE,
        "max_notes": apikey::MAX_NOTES,
        "errors": [apikey::errors::NO_SECRET, apikey::errors::BAD_SECRET_REQUEST, apikey::errors::NOT_ALLOWED,
                   apikey::errors::NO_PASSCODE],
    })
}

/// `answer_secret_no_passcode`: the phone has no passcode, so it refuses `request_secret` at once.
/// After every other HPKE vector, so the bytes of the earlier ones stay the same.
pub(super) fn add_no_passcode(ctx: &mut Ctx, agent: &Side, phone: &Side) {
    let rid = label_id("nodkey/v1/vectors/request/secret");
    let mut a = Answer::decision(&rid, Decision::Denied);
    a.error = Some(apikey::errors::NO_PASSCODE.into());
    ctx.seal(
        "answer_secret_no_passcode",
        Purpose::Answer,
        "phone",
        agent,
        format!("{rid}{}", phone.id),
        &to_json(&a),
        true,
    );
}
