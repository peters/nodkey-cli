use super::*;

fn s(list: &[&str]) -> Vec<String> {
    list.iter().map(|p| p.to_string()).collect()
}

#[test]
fn project_names() {
    for ok in [
        "Sparrow",
        "sparrow",
        "Otter app",
        "otter.example",
        "Bådbygger",
        "a",
    ] {
        assert!(valid_project(ok), "{ok}");
    }
    for bad in [
        "",
        " Sparrow",
        "Sparrow ",
        "a/b",
        "a,b",
        "a\nb",
        "global",
        "Global",
        &"p".repeat(MAX_PROJECT + 1),
    ] {
        assert!(!valid_project(bad), "{bad:?}");
    }
    assert!(valid_project(&"p".repeat(MAX_PROJECT)));
    assert!(same_project("sparrow", "Sparrow"));
    assert!(same_project("BÅDBYGGER", "Bådbygger"));
    assert!(!same_project("Sparrow", "Otter"));
    assert!(same_projects(
        &s(&["Sparrow", "Otter"]),
        &s(&["otter", "SPARROW"])
    ));
    assert!(!same_projects(&s(&["Sparrow"]), &s(&["Sparrow", "Otter"])));
    assert!(same_projects(&[], &[]));
    assert!(!same_projects(&[], &s(&["Sparrow"])));
}

#[test]
fn targets_with_projects() {
    let t = |s: &str| SecretTarget::parse(s);
    let sparrow = t("sparrow/OPENAI_API_KEY").unwrap();
    assert_eq!(sparrow.project.as_deref(), Some("sparrow"));
    assert_eq!(sparrow.service, None);
    assert_eq!(sparrow.variable.as_deref(), Some("OPENAI_API_KEY"));
    assert_eq!(sparrow.to_target(), "sparrow/OPENAI_API_KEY");
    let global = t("Global/OPENAI_API_KEY").unwrap();
    assert!(global.global);
    assert_eq!(global.project, None);
    assert_eq!(global.to_target(), "global/OPENAI_API_KEY");
    assert_eq!(
        t("Otter app/ADMIN_TOKEN").unwrap().project.as_deref(),
        Some("Otter app")
    );
    // A dot or `localhost` makes the first part a service.
    assert_eq!(
        t("otter.example/KEY").unwrap().service.as_deref(),
        Some("otter.example")
    );
    assert_eq!(
        t("localhost/DEV_TOKEN").unwrap().service.as_deref(),
        Some("localhost")
    );
    for bad in [
        "sparrow/",
        "global/",
        "global/a-b",
        "/KEY",
        "a,b/KEY",
        "a\tb/KEY",
    ] {
        assert!(t(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn the_lookup() {
    let keys = [
        (None, "OPENAI_API_KEY", s(&["Sparrow"])),
        (None, "OPENAI_API_KEY", s(&["Otter", "Heron"])),
        (Some("openai.com"), "OPENAI_API_KEY", s(&[])),
        (None, "ADMIN_TOKEN", s(&["Sparrow"])),
        (None, "GITHUB_TOKEN", s(&[])),
        (None, "GITHUB_TOKEN", s(&[])),
    ];
    let names: Vec<KeyNames> = keys
        .iter()
        .map(|(service, variable, projects)| KeyNames {
            service: *service,
            variable: Some(variable),
            projects,
        })
        .collect();
    let find = |target: &str, project: Option<&str>| {
        lookup(&SecretTarget::parse(target).unwrap(), project, &names).map(|f| (f.from, f.keys))
    };
    use KeyFrom::{Global, Project};
    assert_eq!(
        find("OPENAI_API_KEY", Some("sparrow")),
        Some((Project, vec![0]))
    );
    assert_eq!(
        find("OPENAI_API_KEY", Some("HERON")),
        Some((Project, vec![1]))
    );
    assert_eq!(
        find("OPENAI_API_KEY", Some("Puffin")),
        Some((Global, vec![2]))
    );
    assert_eq!(find("OPENAI_API_KEY", None), Some((Global, vec![2])));
    assert_eq!(
        find("global/OPENAI_API_KEY", Some("Sparrow")),
        Some((Global, vec![2]))
    );
    assert_eq!(
        find("otter/OPENAI_API_KEY", Some("Sparrow")),
        Some((Project, vec![1]))
    );
    assert_eq!(
        find("openai.com/OPENAI_API_KEY", Some("Sparrow")),
        Some((Global, vec![2]))
    );
    assert_eq!(
        find("ADMIN_TOKEN", Some("Sparrow")),
        Some((Project, vec![3]))
    );
    assert_eq!(find("ADMIN_TOKEN", Some("Otter")), None);
    assert_eq!(find("ADMIN_TOKEN", None), None);
    assert_eq!(
        find("GITHUB_TOKEN", Some("Sparrow")),
        Some((Global, vec![4, 5]))
    );

    let saved = |service: Option<&str>, variable: &str, projects: &[&str]| {
        saved_key(service, variable, &s(projects), &names)
    };
    assert_eq!(saved(None, "openai_api_key", &["sparrow"]), Some(0));
    assert_eq!(saved(None, "OPENAI_API_KEY", &["Heron", "Otter"]), Some(1));
    assert_eq!(saved(None, "OPENAI_API_KEY", &["Otter"]), None);
    assert_eq!(saved(Some("openai.com"), "OPENAI_API_KEY", &[]), Some(2));
    assert_eq!(saved(None, "OPENAI_API_KEY", &[]), None);
    assert_eq!(saved(None, "GITHUB_TOKEN", &[]), Some(4));
}

#[test]
fn request_project() {
    let mut r: Request = serde_json::from_value(serde_json::json!({
        "v": 1, "request_id": "r", "kind": "secret", "target": "OPENAI_API_KEY",
        "reason": "Run the tests", "agent": "a", "ts": 1, "project": "sparrow"
    }))
    .unwrap();
    assert!(crate::client::check_request(&r).is_ok());
    r.project = Some("global".into());
    assert!(
        crate::client::check_request(&r)
            .unwrap_err()
            .contains("not a project name")
    );
    r.project = Some("Sparrow".into());
    r.kind = Kind::Code;
    r.target = "github.com".into();
    assert!(
        crate::client::check_request(&r)
            .unwrap_err()
            .contains("names a project")
    );
    r.kind = Kind::Bundle;
    r.target = String::new();
    let items = |kind: Kind| crate::BundleRequest {
        items: vec![crate::BundleItem {
            id: "1".into(),
            kind,
            target: "OPENAI_API_KEY".into(),
        }],
        follow_up: None,
        session: None,
    };
    r.bundle = Some(items(Kind::Secret));
    assert!(crate::client::check_request(&r).is_ok());
    r.bundle = Some(items(Kind::Code));
    assert!(crate::client::check_request(&r).is_err());
}
