use super::*;

fn strings(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

fn wanted(name: &str, target: &str) -> Wanted {
    Wanted {
        name: name.into(),
        target: target.into(),
    }
}

#[test]
fn options_and_command() {
    let p = plan(
        &strings(&[
            "--secret",
            "OPENAI_API_KEY",
            "--secret=EXAMPLE_TOKEN=https://api.example.com/v1",
            "--secret",
            "global/GITHUB_TOKEN",
            "--secret",
            "Otter/ADMIN_TOKEN",
            "--reason",
            "Run the tests",
            "--",
            "npm",
            "test",
            "--secret",
            "--",
        ]),
        None,
    )
    .unwrap();
    assert_eq!(
        p.wanted,
        [
            wanted("OPENAI_API_KEY", "OPENAI_API_KEY"),
            wanted("EXAMPLE_TOKEN", "api.example.com/EXAMPLE_TOKEN"),
            wanted("GITHUB_TOKEN", "global/GITHUB_TOKEN"),
            wanted("ADMIN_TOKEN", "Otter/ADMIN_TOKEN"),
        ]
    );
    assert_eq!(p.project, None);
    assert_eq!(p.reason(), "Run the tests");
    assert_eq!(p.command, ["npm", "test", "--secret", "--"]);

    for (bad, want) in [
        (&["--secret", "A", "--reason", "x"][..], "then -- and the"),
        (
            &["--secret", "A", "--reason", "x", "--"][..],
            "then -- and the",
        ),
        (&["--reason", "x", "--", "ls"][..], "--secret NAME"),
        (
            &["--secret", "A-B", "--reason", "x", "--", "ls"][..],
            "variable name",
        ),
        (
            &[
                "--secret",
                "A",
                "--secret",
                "A=x.example",
                "--reason",
                "x",
                "--",
                "ls",
            ][..],
            "twice",
        ),
        (
            &["--secret", "A", "--reason", "x", "extra", "--", "ls"][..],
            "options before",
        ),
        (
            &["--secret", "A", "--reason", "x", "--field", "v", "--", "ls"][..],
            "--field",
        ),
        (
            &["--secret", "A=not a host", "--reason", "x", "--", "ls"][..],
            "not a service",
        ),
        (
            &["--secret", "global/A=x.example", "--", "ls"][..],
            "takes no service",
        ),
        (&["--secret", "a,b/A", "--", "ls"][..], "project name"),
        (
            &["--secret", "A", "--project", "a/b", "--", "ls"][..],
            "not a project name",
        ),
    ] {
        let err = plan(&strings(bad), None).err().unwrap_or_default();
        assert!(err.contains(want), "{bad:?}: {err}");
    }
    let many: Vec<String> = (0..11)
        .flat_map(|i| ["--secret".to_owned(), format!("K{i}")])
        .chain(strings(&["--reason", "x", "--", "ls"]))
        .collect();
    assert!(plan(&many, None).err().unwrap().contains("at most 10"));
}

#[test]
fn keys_from_the_file() {
    let file = KeyFile {
        project: Some("sparrow".into()),
        secrets: strings(&["OPENAI_API_KEY", "ADMIN_TOKEN", "global/GITHUB_TOKEN"]),
        ..KeyFile::default()
    };
    let p = plan(&strings(&["--", "npm", "test"]), Some(&file)).unwrap();
    assert_eq!(p.project.as_deref(), Some("sparrow"));
    assert_eq!(
        p.wanted,
        [
            wanted("OPENAI_API_KEY", "OPENAI_API_KEY"),
            wanted("ADMIN_TOKEN", "ADMIN_TOKEN"),
            wanted("GITHUB_TOKEN", "global/GITHUB_TOKEN"),
        ]
    );
    assert_eq!(p.reason(), "Run npm test");

    // --secret adds a key or replaces one with the same name; --project wins.
    let p = plan(
        &strings(&[
            "--secret",
            "EXAMPLE_TOKEN",
            "--secret",
            "ADMIN_TOKEN=admin.example.com",
            "--project",
            "Otter",
            "--",
            "ls",
        ]),
        Some(&file),
    )
    .unwrap();
    assert_eq!(p.project.as_deref(), Some("Otter"));
    let names: Vec<&str> = p.wanted.iter().map(|w| w.target.as_str()).collect();
    assert_eq!(
        names,
        [
            "OPENAI_API_KEY",
            "global/GITHUB_TOKEN",
            "EXAMPLE_TOKEN",
            "admin.example.com/ADMIN_TOKEN"
        ]
    );
    let p = plan(&strings(&["--project", "global", "--", "ls"]), Some(&file)).unwrap();
    assert_eq!(p.project, None);
    let empty = KeyFile {
        project: Some("sparrow".into()),
        ..KeyFile::default()
    };
    assert!(
        plan(&strings(&["--", "ls"]), Some(&empty))
            .unwrap_err()
            .contains(".nodkey")
    );
    let long: Vec<String> = ["--", "echo"]
        .iter()
        .map(|s| s.to_string())
        .chain(std::iter::repeat_n("word".to_owned(), 100))
        .collect();
    let reason = plan(&long, Some(&file)).unwrap().reason();
    assert!(reason.ends_with(" ...") && reason.chars().count() == 204);
}
