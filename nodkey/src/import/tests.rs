use super::*;
use nodkey_proto::vectors::import::{CHROME_CSV, SAMPLES};

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = crate::test_dir(tag);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn reads_a_regular_file_once() {
    let dir = scratch("import-read");
    let path = dir.join("Chrome Passwords.csv");
    std::fs::write(&path, CHROME_CSV).unwrap();
    let e = file::read(path.to_str().unwrap()).unwrap();
    assert_eq!(&e.bytes[..], CHROME_CSV);
    assert_eq!(e.name, "Chrome Passwords.csv");

    let empty = dir.join("empty.csv");
    std::fs::write(&empty, b"").unwrap();
    let (code, _) = file::read(empty.to_str().unwrap()).err().unwrap();
    assert_eq!(code, Some(import::errors::IMPORT_UNREADABLE));

    let big = dir.join("big.csv");
    std::fs::write(&big, vec![b'a'; import::MAX_FILE + 1]).unwrap();
    let (code, message) = file::read(big.to_str().unwrap()).err().unwrap();
    assert_eq!(code, Some(import::errors::TOO_LARGE));
    assert!(message.contains("1 MiB"));
    std::fs::write(&big, vec![b'a'; import::MAX_FILE]).unwrap();
    assert!(file::read(big.to_str().unwrap()).is_ok());

    assert_eq!(file::read(dir.to_str().unwrap()).err().unwrap().0, None);
    assert_eq!(
        file::read(dir.join("missing.csv").to_str().unwrap())
            .err()
            .unwrap()
            .0,
        None
    );
    #[cfg(unix)]
    {
        let link = dir.join("link.csv");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        let (code, message) = file::read(link.to_str().unwrap()).err().unwrap();
        assert_eq!(code, None);
        assert!(message.contains("is a link"));
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn wipes_only_the_file_it_read() {
    let dir = scratch("import-wipe");
    let path = dir.join("export.csv");
    std::fs::write(&path, CHROME_CSV).unwrap();
    let e = file::read(path.to_str().unwrap()).unwrap();
    e.wipe().unwrap();
    assert!(!path.exists());

    // Replaced by another file after it was read: left alone.
    std::fs::write(&path, CHROME_CSV).unwrap();
    let e = file::read(path.to_str().unwrap()).unwrap();
    std::fs::remove_file(&path).unwrap();
    std::fs::write(
        &path,
        b"name,url,username,password\nother,https://other.example,alex,x\n",
    )
    .unwrap();
    assert!(e.wipe().unwrap_err().contains("changed"));
    assert!(path.exists());

    // Gone already: an error, nothing else is touched.
    std::fs::remove_file(&path).unwrap();
    assert!(e.wipe().is_err());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn names_for_the_phone() {
    use std::path::Path;
    assert_eq!(
        display_name(Path::new("/a/b/Chrome Passwords.csv")),
        "Chrome Passwords.csv"
    );
    assert_eq!(display_name(Path::new("bad\nname.csv")), "bad_name.csv");
    assert_eq!(display_name(Path::new("/")), "export");
    let long = "a".repeat(300) + ".csv";
    assert_eq!(
        display_name(Path::new(&long)).chars().count(),
        import::MAX_FILE_NAME
    );
}

#[test]
fn local_refusals() {
    let by_name = |name: &str| {
        let s = SAMPLES.iter().find(|s| s.name == name).unwrap();
        detect::detect(s.bytes)
    };
    assert!(refuse_locally(&by_name("chrome_csv")).is_none());
    assert!(refuse_locally(&by_name("plain_text")).is_none());
    assert!(
        refuse_locally(&by_name("zip_archive"))
            .unwrap()
            .contains("zip")
    );
    assert!(
        refuse_locally(&by_name("bitwarden_json_encrypted"))
            .unwrap()
            .contains("encrypted")
    );
    let header_only = detect::detect(b"name,url,username,password,note\n");
    assert!(refuse_locally(&header_only).unwrap().contains("no login"));
    assert_eq!(
        describe(&by_name("chrome_csv")),
        "2 logins and 0 codes; 1 row without a password or code (left out)"
    );
    assert!(check_source("Chrome, profile Default").is_ok());
    assert!(check_source(" ").is_err());
    assert!(check_source(&"s".repeat(81)).is_err());
    assert!(check_source("a\nb").is_err());
}

#[test]
fn exit_codes() {
    let code = |v: Value| exit_code(&v);
    use serde_json::json;
    assert_eq!(code(json!({"decision": "staged"})), 0);
    assert_eq!(code(json!({"sent": false, "dry_run": true})), 0);
    assert_eq!(code(json!({"decision": "denied"})), DENIED);
    assert_eq!(code(json!({"decision": "expired"})), EXPIRED);
    assert_eq!(
        code(json!({"decision": "denied", "error": "paused"})),
        PAUSED
    );
    for (error, exit) in [
        ("no_passcode", 10),
        ("import_closed", 11),
        ("window_full", 12),
        ("import_unreadable", 13),
        ("too_large", 14),
        ("bad_import", 1),
    ] {
        assert_eq!(
            code(json!({"decision": "denied", "error": error})),
            exit,
            "{error}"
        );
    }
    assert_eq!(code(json!({"sent": false, "error": "too_large"})), 14);
    assert_eq!(code(json!({"decision": "approved"})), 1);
}

#[test]
fn messages_name_no_value() {
    let mut a = Answer::decision("r", Decision::Staged);
    a.import = Some(ImportCounts {
        found: 2,
        new: 2,
        merged: 0,
        duplicates: 0,
        conflicts: 0,
        skipped: 1,
        logins: Some(2),
        codes: Some(0),
        files: Some(1),
        until: Some(nodkey_proto::unix_now() + 600),
    });
    let m = message(&a, "Test iPhone", "Chrome Passwords.csv");
    assert!(
        m.contains("2 entries (2 logins, 0 codes): 2 new, 0 merged") && m.contains("1 of 20 files"),
        "{m}"
    );
    assert!(m.contains("1 row left out"), "{m}");
    assert!(m.contains("10 more minutes"), "{m}");
    for error in import::errors::IN_ORDER {
        let mut a = Answer::decision("r", Decision::Denied);
        a.error = Some(error.into());
        assert_ne!(
            message(&a, "Test iPhone", "x.csv"),
            crate::outcome::MISFIT,
            "{error}"
        );
    }
    let mut closed = Answer::decision("r", Decision::Denied);
    closed.error = Some(import::errors::IMPORT_CLOSED.into());
    assert!(message(&closed, "Test iPhone", "x.csv").contains("Settings"));
}
