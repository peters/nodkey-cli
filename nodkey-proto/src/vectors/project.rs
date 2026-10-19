//! Keys by project (peters/nodkey#98): a key request in a project and its answers (the project's
//! key, the global key, a key picked by hand), `global/NAME`, a bundle of three keys with a shared
//! project (what `nodkey run` sends for a `.nodkey` file), a task plan in a project, a save with
//! projects, a list with the keys' projects, and the `key_projects` section: project names,
//! targets, the lookup and which key a save updates. Test values only.

use serde_json::{Value, json};

use super::{Ctx, Side, label_id, request, to_json};
use crate::{
    Answer, BundleItem, BundleItemAnswer, BundleRequest, Decision, Kind, Lease, LeaseKind, Purpose,
    SaveSecret, Secret, SecretAnswer, SecretEntry, SecretTarget, SessionInfo,
    apikey::{self, KeyFrom, KeyNames},
};

const PROJECT: &str = "sparrow";
const SESSION_ID: &str = "UHJvamVjdFNlc3Npb24x";
const UNTIL: u64 = super::TS + 1800;

/// A key as the phone answers with it: from the project "Sparrow", from the global keys, or
/// picked by hand.
fn key(variable: &str, value: Option<&str>, from: KeyFrom) -> SecretAnswer {
    SecretAnswer {
        title: match from {
            KeyFrom::Project => format!("{variable} (Sparrow)"),
            _ => variable.to_owned(),
        },
        service: None,
        variable: Some(variable.into()),
        value: value.map(Secret::new),
        expires: None,
        from: Some(from),
        project: (from == KeyFrom::Project).then(|| "Sparrow".into()),
    }
}

fn item(id: &str, target: &str) -> BundleItem {
    BundleItem {
        id: id.into(),
        kind: Kind::Secret,
        target: target.into(),
    }
}

fn approved(id: &str, key: SecretAnswer, lease: Option<Lease>) -> BundleItemAnswer {
    let mut a = BundleItemAnswer::decision(id, Decision::Approved);
    a.lease = lease;
    a.secret = Some(key);
    a
}

fn once() -> Option<Lease> {
    Some(Lease {
        kind: LeaseKind::Once,
        until: None,
    })
}

/// Adds the HPKE vectors and returns the `key_projects` section.
pub(super) fn add(ctx: &mut Ctx, agent: &Side, phone: &Side) -> Value {
    let mut requests = Vec::new();
    let mut answers = Vec::new();

    // One key in a project: the project's key, a global key, or one the user picked by hand.
    let rid = label_id("nodkey/v1/vectors/request/secret_project");
    let mut r = request(
        &rid,
        Kind::Secret,
        "OPENAI_API_KEY",
        "Run the tests that call the OpenAI API",
        None,
    );
    r.project = Some(PROJECT.into());
    requests.push(("request_secret_project", r));
    let one = |from: KeyFrom, value: &str| {
        let mut a = Answer::decision(&rid, Decision::Approved);
        a.lease = once();
        a.secret = Some(key("OPENAI_API_KEY", Some(value), from));
        a
    };
    answers.push((
        "answer_secret_project",
        one(KeyFrom::Project, "sk-test-sparrow-0000"),
    ));
    answers.push((
        "answer_secret_project_global",
        one(KeyFrom::Global, "sk-test-global-0000"),
    ));
    answers.push((
        "answer_secret_project_chosen",
        one(KeyFrom::Chosen, "sk-test-otter-0000"),
    ));

    // Only the global key, whatever the project; and another project's key by its target.
    let rid = label_id("nodkey/v1/vectors/request/secret_global");
    let mut r = request(
        &rid,
        Kind::Secret,
        "global/OPENAI_API_KEY",
        "Run the tests with the shared key",
        None,
    );
    r.project = Some(PROJECT.into());
    requests.push(("request_secret_global", r));
    let mut a = Answer::decision(&rid, Decision::Approved);
    a.lease = once();
    a.secret = Some(key(
        "OPENAI_API_KEY",
        Some("sk-test-global-0000"),
        KeyFrom::Global,
    ));
    answers.push(("answer_secret_global", a));
    let rid = label_id("nodkey/v1/vectors/request/secret_project_target");
    let r = request(
        &rid,
        Kind::Secret,
        "otter/OPENAI_API_KEY",
        "Run the Otter tests",
        None,
    );
    requests.push(("request_secret_project_target", r));

    // Three keys in one request with a shared project, as `nodkey run` asks for a `.nodkey` file.
    let rid = label_id("nodkey/v1/vectors/request/bundle_project");
    let mut r = request(&rid, Kind::Bundle, "", "Run the integration tests", None);
    r.project = Some(PROJECT.into());
    r.bundle = Some(BundleRequest {
        items: vec![
            item("1", "OPENAI_API_KEY"),
            item("2", "ANTHROPIC_API_KEY"),
            item("3", "ADMIN_TOKEN"),
        ],
        follow_up: None,
        session: None,
    });
    requests.push(("request_bundle_project", r));
    let mut a = Answer::decision(&rid, Decision::Approved);
    a.items = Some(vec![
        approved(
            "1",
            key(
                "OPENAI_API_KEY",
                Some("sk-test-sparrow-0000"),
                KeyFrom::Project,
            ),
            once(),
        ),
        approved(
            "2",
            key(
                "ANTHROPIC_API_KEY",
                Some("sk-ant-test-0000"),
                KeyFrom::Global,
            ),
            once(),
        ),
        approved(
            "3",
            key("ADMIN_TOKEN", Some("adm-test-2222"), KeyFrom::Project),
            once(),
        ),
    ]);
    answers.push(("answer_bundle_project", a));

    // A task plan in a project: the key item carries no value; a later request goes through.
    let rid = label_id("nodkey/v1/vectors/request/bundle_project_session");
    let mut r = request(&rid, Kind::Bundle, "", "Release the new version", None);
    r.project = Some(PROJECT.into());
    r.bundle = Some(BundleRequest {
        items: vec![item("1", "OPENAI_API_KEY")],
        follow_up: None,
        session: Some(1800),
    });
    requests.push(("request_bundle_project_session", r));
    let mut a = Answer::decision(&rid, Decision::Approved);
    a.session = Some(SessionInfo {
        id: SESSION_ID.into(),
        until: UNTIL,
    });
    a.items = Some(vec![approved(
        "1",
        key("OPENAI_API_KEY", None, KeyFrom::Project),
        None,
    )]);
    answers.push(("answer_bundle_project_session", a));

    // Save a key for one project.
    let rid = label_id("nodkey/v1/vectors/request/save_secret_projects");
    let value = ctx.seal(
        "save_secret_projects_value",
        Purpose::Secret,
        "agent",
        phone,
        agent.id.clone(),
        b"sk-test-sparrow-0000",
        false,
    );
    let save = SaveSecret {
        variable: "OPENAI_API_KEY".into(),
        service: Some("openai.com".into()),
        title: Some("OpenAI for Sparrow".into()),
        notes: None,
        expires: None,
        projects: vec!["Sparrow".into()],
        value,
    };
    let mut r = request(
        &rid,
        Kind::SaveSecret,
        &save.target(),
        "Save the API key I just made for Sparrow",
        None,
    );
    r.save_secret = Some(save);
    requests.push(("request_save_secret_projects", r));
    let mut a = Answer::decision(&rid, Decision::Approved);
    a.saved = Some(crate::Saved::Added);
    answers.push(("answer_save_secret_projects", a));

    // A list answer: the keys with their projects (none for a global key).
    let rid = label_id("nodkey/v1/vectors/request/list");
    let mut a = Answer::decision(&rid, Decision::Approved);
    a.accounts = Some(vec![]);
    let entry = |title: &str, variable: &str, projects: &[&str]| SecretEntry {
        title: title.into(),
        service: None,
        variable: Some(variable.into()),
        projects: projects.iter().map(|p| p.to_string()).collect(),
    };
    a.secrets = Some(vec![
        entry("OpenAI (Sparrow)", "OPENAI_API_KEY", &["Sparrow"]),
        entry(
            "OpenAI (Otter, Heron)",
            "OPENAI_API_KEY",
            &["Otter", "Heron"],
        ),
        entry("OpenAI", "OPENAI_API_KEY", &[]),
    ]);
    answers.push(("answer_list_with_key_projects", a));

    for (name, r) in &requests {
        let aad = format!("{}{}", r.request_id, agent.id);
        ctx.seal(
            name,
            Purpose::Request,
            "agent",
            phone,
            aad,
            &to_json(r),
            true,
        );
    }
    for (name, a) in &answers {
        let aad = format!("{}{}", a.request_id, phone.id);
        ctx.seal(
            name,
            Purpose::Answer,
            "phone",
            agent,
            aad,
            &to_json(a),
            true,
        );
    }
    section()
}

/// Project names, targets, the lookup and saves, which every side must decide the same way.
fn section() -> Value {
    let names: Vec<Value> = [
        "Sparrow",
        "Otter app",
        "otter.example",
        "Bådbygger",
        "",
        " Sparrow",
        "a/b",
        "a,b",
        "a\nb",
        "global",
        "GLOBAL",
        &"p".repeat(apikey::MAX_PROJECT),
        &"p".repeat(apikey::MAX_PROJECT + 1),
    ]
    .iter()
    .map(|n| json!({"name": n, "ok": apikey::valid_project(n)}))
    .collect();
    let same: Vec<Value> = [
        ("sparrow", "Sparrow"),
        ("BÅDBYGGER", "Bådbygger"),
        ("Sparrow", "Otter"),
        ("Otter app", "otter app"),
        ("Otter app", "Otterapp"),
    ]
    .iter()
    .map(|(a, b)| json!({"a": a, "b": b, "same": apikey::same_project(a, b)}))
    .collect();
    let targets: Vec<Value> = [
        "sparrow/OPENAI_API_KEY",
        "Otter app/ADMIN_TOKEN",
        "global/OPENAI_API_KEY",
        "Global/OPENAI_API_KEY",
        "openai.com/OPENAI_API_KEY",
        "localhost/DEV_TOKEN",
        "otter.example/OPENAI_API_KEY",
        "sparrow/",
        "global/",
        "/OPENAI_API_KEY",
        "a,b/OPENAI_API_KEY",
        "sparrow/OPENAI-KEY",
        "OPENAI_API_KEY",
    ]
    .iter()
    .map(|t| match SecretTarget::parse(t) {
        Ok(p) => json!({
            "target": t, "ok": true, "service": p.service, "variable": p.variable,
            "project": p.project, "global": p.global,
        }),
        Err(_) => json!({"target": t, "ok": false}),
    })
    .collect();

    let keys: Vec<(Option<&str>, &str, Vec<String>)> = vec![
        (None, "OPENAI_API_KEY", vec!["Sparrow".into()]),
        (None, "OPENAI_API_KEY", vec!["Otter".into(), "Heron".into()]),
        (Some("openai.com"), "OPENAI_API_KEY", vec![]),
        (None, "ADMIN_TOKEN", vec!["Sparrow".into()]),
        (None, "GITHUB_TOKEN", vec![]),
        (None, "GITHUB_TOKEN", vec![]),
    ];
    let names_of: Vec<KeyNames> = keys
        .iter()
        .map(|(service, variable, projects)| KeyNames {
            service: *service,
            variable: Some(variable),
            projects,
        })
        .collect();
    let lookups: Vec<Value> = [
        ("OPENAI_API_KEY", Some("sparrow")),
        ("OPENAI_API_KEY", Some("HERON")),
        ("OPENAI_API_KEY", Some("Puffin")),
        ("OPENAI_API_KEY", None),
        ("global/OPENAI_API_KEY", Some("Sparrow")),
        ("otter/OPENAI_API_KEY", Some("Sparrow")),
        ("otter/OPENAI_API_KEY", None),
        ("openai.com/OPENAI_API_KEY", Some("Sparrow")),
        ("openai.com", Some("Otter")),
        ("ADMIN_TOKEN", Some("Sparrow")),
        ("ADMIN_TOKEN", Some("Otter")),
        ("ADMIN_TOKEN", None),
        ("GITHUB_TOKEN", Some("Sparrow")),
        ("ANTHROPIC_API_KEY", Some("Sparrow")),
    ]
    .iter()
    .map(|(target, project)| {
        let t = SecretTarget::parse(target).expect("a valid target");
        let found = apikey::lookup(&t, *project, &names_of);
        json!({
            "target": target, "project": project,
            "from": found.as_ref().map(|f| f.from),
            "keys": found.map(|f| f.keys).unwrap_or_default(),
        })
    })
    .collect();
    let saves: Vec<Value> = [
        (None, "openai_api_key", vec!["sparrow"]),
        (None, "OPENAI_API_KEY", vec!["Heron", "Otter"]),
        (None, "OPENAI_API_KEY", vec!["Otter"]),
        (Some("openai.com"), "OPENAI_API_KEY", vec![]),
        (None, "OPENAI_API_KEY", vec![]),
        (None, "GITHUB_TOKEN", vec![]),
        (None, "ADMIN_TOKEN", vec!["Otter"]),
    ]
    .iter()
    .map(|(service, variable, projects)| {
        let projects: Vec<String> = projects.iter().map(|p| p.to_string()).collect();
        json!({
            "service": service, "variable": variable, "projects": projects,
            "updates": apikey::saved_key(*service, variable, &projects, &names_of),
        })
    })
    .collect();
    json!({
        "global": apikey::GLOBAL,
        "max_project": apikey::MAX_PROJECT,
        "max_projects": apikey::MAX_PROJECTS,
        "from": ["project", "global", "chosen"],
        "names": names,
        "same": same,
        "targets": targets,
        "keys": keys.iter().map(|(service, variable, projects)| json!({
            "service": service, "variable": variable, "projects": projects,
        })).collect::<Vec<_>>(),
        "lookups": lookups,
        "saves": saves,
    })
}
