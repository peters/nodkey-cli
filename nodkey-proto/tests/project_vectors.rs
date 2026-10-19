//! Checks the key project vectors in `vectors/v1.json`: the `key_projects` section decides the
//! same way as `nodkey_proto::apikey::project`, and the requests and answers read back with the
//! right fields.

use nodkey_proto::{
    Answer, Kind, Request, SecretTarget,
    apikey::{self, KeyFrom, KeyNames},
};
use serde_json::Value;

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/v1.json");

fn load() -> Value {
    serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap()
}

fn plaintext<T: serde::de::DeserializeOwned>(v: &Value, name: &str) -> T {
    let h = v["hpke"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["name"] == name)
        .unwrap_or_else(|| panic!("{name}"));
    serde_json::from_str(h["plaintext"].as_str().unwrap()).unwrap()
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|p| p.as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn names_targets_lookups_and_saves() {
    let v = load();
    let s = &v["key_projects"];
    assert_eq!(s["global"], apikey::GLOBAL);
    assert_eq!(s["max_project"], apikey::MAX_PROJECT);
    assert_eq!(s["max_projects"], apikey::MAX_PROJECTS);
    for n in s["names"].as_array().unwrap() {
        let name = n["name"].as_str().unwrap();
        assert_eq!(apikey::valid_project(name), n["ok"] == true, "{name:?}");
    }
    for p in s["same"].as_array().unwrap() {
        let (a, b) = (p["a"].as_str().unwrap(), p["b"].as_str().unwrap());
        assert_eq!(apikey::same_project(a, b), p["same"] == true, "{p}");
    }
    for t in s["targets"].as_array().unwrap() {
        let target = t["target"].as_str().unwrap();
        let parsed = SecretTarget::parse(target);
        assert_eq!(parsed.is_ok(), t["ok"] == true, "{target:?}");
        if let Ok(p) = parsed {
            assert_eq!(p.service.as_deref(), t["service"].as_str(), "{target}");
            assert_eq!(p.variable.as_deref(), t["variable"].as_str(), "{target}");
            assert_eq!(p.project.as_deref(), t["project"].as_str(), "{target}");
            assert_eq!(p.global, t["global"] == true, "{target}");
        }
    }
    let keys: Vec<(Option<String>, String, Vec<String>)> = s["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| {
            (
                k["service"].as_str().map(str::to_owned),
                k["variable"].as_str().unwrap().to_owned(),
                strings(&k["projects"]),
            )
        })
        .collect();
    let names: Vec<KeyNames> = keys
        .iter()
        .map(|(service, variable, projects)| KeyNames {
            service: service.as_deref(),
            variable: Some(variable),
            projects,
        })
        .collect();
    let lookups = s["lookups"].as_array().unwrap();
    for from in ["project", "global"] {
        assert!(lookups.iter().any(|l| l["from"] == from));
    }
    assert!(lookups.iter().any(|l| l["from"].is_null()));
    for l in lookups {
        let target = SecretTarget::parse(l["target"].as_str().unwrap()).unwrap();
        let found = apikey::lookup(&target, l["project"].as_str(), &names);
        let from: Option<KeyFrom> = serde_json::from_value(l["from"].clone()).unwrap();
        assert_eq!(found.as_ref().map(|f| f.from), from, "{l}");
        let want: Vec<usize> = serde_json::from_value(l["keys"].clone()).unwrap();
        assert_eq!(found.map(|f| f.keys).unwrap_or_default(), want, "{l}");
    }
    for save in s["saves"].as_array().unwrap() {
        let got = apikey::saved_key(
            save["service"].as_str(),
            save["variable"].as_str().unwrap(),
            &strings(&save["projects"]),
            &names,
        );
        assert_eq!(got, save["updates"].as_u64().map(|i| i as usize), "{save}");
    }
}

#[test]
fn requests_and_answers() {
    let v = load();
    for name in [
        "request_secret_project",
        "request_secret_global",
        "request_secret_project_target",
        "request_bundle_project",
        "request_bundle_project_session",
        "request_save_secret_projects",
    ] {
        let r: Request = plaintext(&v, name);
        nodkey_proto::client::check_request(&r).unwrap_or_else(|e| panic!("{name}: {e}"));
    }
    let r: Request = plaintext(&v, "request_secret_project");
    assert_eq!(r.project.as_deref(), Some("sparrow"));
    let a: Answer = plaintext(&v, "answer_secret_project");
    let key = a.secret.unwrap();
    assert_eq!(key.from, Some(KeyFrom::Project));
    assert_eq!(key.project.as_deref(), Some("Sparrow"));
    let a: Answer = plaintext(&v, "answer_secret_project_global");
    assert_eq!(a.secret.unwrap().from, Some(KeyFrom::Global));
    let a: Answer = plaintext(&v, "answer_secret_project_chosen");
    assert_eq!(a.secret.unwrap().from, Some(KeyFrom::Chosen));

    let r: Request = plaintext(&v, "request_secret_global");
    assert!(SecretTarget::parse(&r.target).unwrap().global);
    let r: Request = plaintext(&v, "request_secret_project_target");
    assert_eq!(r.project, None);
    assert_eq!(
        SecretTarget::parse(&r.target).unwrap().project.as_deref(),
        Some("otter")
    );

    let bundle: Request = plaintext(&v, "request_bundle_project");
    assert_eq!(bundle.kind, Kind::Bundle);
    assert_eq!(bundle.bundle.unwrap().items.len(), 3);
    let answer: Answer = plaintext(&v, "answer_bundle_project");
    let from: Vec<Option<KeyFrom>> = answer
        .items
        .unwrap()
        .iter()
        .map(|i| i.secret.as_ref().unwrap().from)
        .collect();
    assert_eq!(
        from,
        [
            Some(KeyFrom::Project),
            Some(KeyFrom::Global),
            Some(KeyFrom::Project)
        ]
    );
    let plan: Answer = plaintext(&v, "answer_bundle_project_session");
    assert!(
        plan.items.unwrap()[0]
            .secret
            .as_ref()
            .unwrap()
            .value
            .is_none()
    );

    let save: Request = plaintext(&v, "request_save_secret_projects");
    assert_eq!(save.save_secret.unwrap().projects, ["Sparrow"]);
    let list: Answer = plaintext(&v, "answer_list_with_key_projects");
    let secrets = list.secrets.unwrap();
    assert_eq!(secrets[1].projects, ["Otter", "Heron"]);
    assert!(secrets[2].projects.is_empty());
}
