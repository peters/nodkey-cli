//! Import vectors (peters/nodkey#130): an `import` request for a Chrome export (plain and signed),
//! the sealed file (`nodkey/v1/import`), the `staged` answer and each refusal, and the `import`
//! section: the limits, the formats, which requests pass the checks, and what `detect` reads from
//! the invented samples.

use serde_json::{Value, json};

use super::{Ctx, Side, label_id, pairing::signed_vector, request, to_json};
use crate::{
    Answer, Decision, ImportCounts, ImportFormat, ImportRequest, Kind, Purpose, import,
    signed::Direction,
};

pub use super::import_samples::{CHROME_CSV, SAMPLES, Sample};

/// The file name and source of the vectors' import request.
pub const FILE_NAME: &str = "Chrome Passwords.csv";
pub const SOURCE: &str = "Chrome, profile Default";

/// The vectors' `import` request: the Chrome sample, with its hint.
pub fn import_request(rid: &str) -> crate::Request {
    let mut r = request(
        rid,
        Kind::Import,
        "",
        "Move the passwords saved in Chrome into Nodkey",
        None,
    );
    r.import = Some(ImportRequest::new(
        FILE_NAME,
        CHROME_CSV,
        Some(ImportFormat::ChromeCsv),
        SOURCE,
    ));
    r
}

/// Adds the HPKE vectors and returns the `import` section and the signed request.
pub(super) fn add(ctx: &mut Ctx, agent: &Side, phone: &Side) -> (Value, Value) {
    let rid = label_id("nodkey/v1/vectors/request/import");
    let r = import_request(&rid);
    ctx.seal(
        "request_import",
        Purpose::Request,
        "agent",
        phone,
        format!("{rid}{}", agent.id),
        &to_json(&r),
        true,
    );
    ctx.seal(
        "import_file",
        Purpose::Import,
        "agent",
        phone,
        format!("{rid}{}", agent.id),
        CHROME_CSV,
        false,
    );
    let (signed, plain) = signed_vector(
        "request_import_signed",
        "request_import_signed",
        Direction::Request,
        agent,
        agent,
        phone,
        &to_json(&r),
    );
    ctx.seal(
        "request_import_signed",
        Purpose::Request,
        "agent",
        phone,
        format!("{rid}{}", agent.id),
        &plain,
        true,
    );

    let mut staged = Answer::decision(&rid, Decision::Staged);
    staged.import = Some(ImportCounts {
        found: 2,
        new: 2,
        merged: 0,
        duplicates: 0,
        conflicts: 0,
        skipped: 1,
        logins: Some(2),
        codes: Some(0),
        files: Some(1),
        until: Some(super::TS + import::WINDOW_SECONDS),
    });
    let mut answers = vec![("answer_import_staged", staged)];
    for (name, error) in [
        ("answer_import_closed", import::errors::IMPORT_CLOSED),
        ("answer_import_window_full", import::errors::WINDOW_FULL),
        ("answer_import_too_large", import::errors::TOO_LARGE),
        ("answer_import_bad_import", import::errors::BAD_IMPORT),
        (
            "answer_import_unreadable",
            import::errors::IMPORT_UNREADABLE,
        ),
        ("answer_import_no_passcode", import::errors::NO_PASSCODE),
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
            format!("{rid}{}", phone.id),
            &to_json(a),
            true,
        );
    }
    (section(&r), signed)
}

fn section(r: &crate::Request) -> Value {
    let ok = serde_json::to_value(r.import.as_ref().expect("import")).expect("json");
    let with = |key: &str, value: Value| {
        let mut v = ok.clone();
        v[key] = value;
        v
    };
    let without = |key: &str| {
        let mut v = ok.clone();
        v.as_object_mut().expect("object").remove(key);
        v
    };
    let bad = Some(import::errors::BAD_IMPORT);
    let checks: Vec<(&str, Value, Option<&str>)> = vec![
        ("chrome", ok.clone(), None),
        ("no_hint", without("format_hint"), None),
        ("unknown_hint", with("format_hint", json!("edge_csv")), None),
        ("largest", with("size", json!(import::MAX_FILE)), None),
        (
            "too_large",
            with("size", json!(import::MAX_FILE + 1)),
            Some(import::errors::TOO_LARGE),
        ),
        ("empty_file", with("size", json!(0)), bad),
        (
            "folder_in_name",
            with("file_name", json!("Downloads/Chrome Passwords.csv")),
            bad,
        ),
        (
            "backslash_in_name",
            with("file_name", json!("C:\\Users\\alex\\Passwords.csv")),
            bad,
        ),
        ("blank_name", with("file_name", json!(" ")), bad),
        ("long_name", with("file_name", json!("a".repeat(121))), bad),
        (
            "longest_name",
            with("file_name", json!("a".repeat(120))),
            None,
        ),
        ("short_hash", with("sha256", json!("abc")), bad),
        ("blank_source", with("source", json!("")), bad),
        ("long_source", with("source", json!("s".repeat(81))), bad),
        (
            "control_in_source",
            with("source", json!("Chrome\nprofile")),
            bad,
        ),
    ];
    let checks: Vec<Value> = checks
        .into_iter()
        .map(|(name, import, error)| json!({"name": name, "import": import, "error": error}))
        .collect();
    let samples: Vec<Value> = SAMPLES
        .iter()
        .map(|s| {
            let (format, found, logins, codes, skipped, encrypted, archive) = s.expect;
            let mut v = json!({
                "name": s.name,
                "content_b64u": crate::b64u::encode(s.bytes),
                "format": format.as_str(),
                "found": found, "logins": logins, "codes": codes, "skipped": skipped,
                "encrypted": encrypted, "archive": archive,
            });
            if let Ok(text) = std::str::from_utf8(s.bytes) {
                v["content"] = json!(text);
            }
            v
        })
        .collect();
    json!({
        "limits": {
            "attachment_max": import::ATTACHMENT_MAX,
            "max_file": import::MAX_FILE,
            "max_file_name": import::MAX_FILE_NAME,
            "max_source": import::MAX_SOURCE,
            "window_files": import::WINDOW_FILES,
            "window_seconds": import::WINDOW_SECONDS,
            "file_wait": import::FILE_WAIT,
        },
        "formats": ImportFormat::ALL.iter().map(|f| f.as_str()).collect::<Vec<_>>(),
        "errors": [
            import::errors::NO_PASSCODE, import::errors::IMPORT_CLOSED, import::errors::WINDOW_FULL,
            import::errors::TOO_LARGE, import::errors::BAD_IMPORT, import::errors::IMPORT_UNREADABLE,
        ],
        "request": "request_import",
        "file": "import_file",
        "file_sha256": import::file_sha256(CHROME_CSV),
        "checks": checks,
        "detect": samples,
    })
}
