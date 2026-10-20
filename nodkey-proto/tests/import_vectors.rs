//! Checks the import vectors in `vectors/v1.json`: the request describes the sealed file, the
//! checks decide the same way as `ImportRequest::check`, `detect` reads each sample the same way,
//! and the answers carry counts or a refusal, never a secret.

use nodkey_proto::{
    Answer, Decision, ImportFormat, ImportRequest, Kind, Request, b64u, import, import::detect,
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

fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap_or_else(|| panic!("{key}"))
}

#[test]
fn request_and_file() {
    let v = load();
    let sec = &v["import"];
    let r: Request =
        parse_plaintext(text(hpke(&v, text(sec, "request")), "plaintext").as_bytes()).unwrap();
    assert_eq!(r.kind, Kind::Import);
    assert_eq!(r.target, "");
    nodkey_proto::client::check_request(&r).unwrap();
    let i = r.import.unwrap();
    let file = b64u::decode(text(hpke(&v, text(sec, "file")), "plaintext_b64u")).unwrap();
    assert!(i.matches(&file));
    assert_eq!(i.sha256, text(sec, "file_sha256"));
    assert_eq!(i.format_hint, Some(detect::detect(&file).format));
    // The file opens with the phone's key, as the import purpose only.
    let phone_sk: [u8; 32] = b64u::decode_array(text(&v["keys"]["phone"], "kem_sk")).unwrap();
    let agent_id = text(&v["keys"]["agent"], "id");
    let body = b64u::decode(text(hpke(&v, "import_file"), "body_b64u")).unwrap();
    assert_eq!(
        &*import::open_file(&phone_sk, &r.request_id, agent_id, &body).unwrap(),
        &file[..]
    );
    assert!(nodkey_proto::seal::open_attachment_body(&phone_sk, b"", &body).is_err());
    // The signed request is the same request.
    let signed: Value = v["signed"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == "request_import_signed")
        .unwrap()
        .clone();
    assert_eq!(
        text(&signed, "body"),
        text(hpke(&v, "request_import"), "plaintext")
    );
}

#[test]
fn checks_decide_the_same() {
    let v = load();
    for c in v["import"]["checks"].as_array().unwrap() {
        let name = text(c, "name");
        let r: ImportRequest = serde_json::from_value(c["import"].clone()).unwrap();
        let got = r.check().err().map(|(code, _)| code);
        assert_eq!(got, c["error"].as_str(), "{name}");
    }
}

#[test]
fn detect_reads_the_samples() {
    let v = load();
    let sec = &v["import"];
    let formats: Vec<&str> = sec["formats"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f.as_str().unwrap())
        .collect();
    assert_eq!(formats.len(), ImportFormat::ALL.len());
    for s in sec["detect"].as_array().unwrap() {
        let name = text(s, "name");
        let bytes = b64u::decode(text(s, "content_b64u")).unwrap();
        if let Some(t) = s["content"].as_str() {
            assert_eq!(t.as_bytes(), &bytes[..], "{name}");
        }
        let d = detect::detect(&bytes);
        assert_eq!(d.format.as_str(), text(s, "format"), "{name}");
        assert!(formats.contains(&d.format.as_str()));
        let n = |k: &str| s[k].as_u64().unwrap() as u32;
        assert_eq!(
            (d.found, d.logins, d.codes, d.skipped),
            (n("found"), n("logins"), n("codes"), n("skipped")),
            "{name}"
        );
        assert_eq!(d.encrypted, s["encrypted"].as_bool().unwrap(), "{name}");
        assert_eq!(d.archive, s["archive"].as_bool().unwrap(), "{name}");
    }
}

#[test]
fn answers_carry_counts_or_a_refusal() {
    let v = load();
    let sec = &v["import"];
    let errors: Vec<&str> = sec["errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e.as_str().unwrap())
        .collect();
    let mut refusals = 0;
    for h in v["hpke"].as_array().unwrap() {
        let name = text(h, "name");
        if !name.starts_with("answer_import") {
            continue;
        }
        let a: Answer = parse_plaintext(text(h, "plaintext").as_bytes()).unwrap();
        assert!(a.password.is_none() && a.code.is_none() && a.account.is_none());
        match a.decision {
            Decision::Staged => {
                let c = a.import.unwrap();
                assert_eq!(c.found, c.new + c.merged + c.duplicates, "{name}");
                assert!(c.conflicts <= c.new);
                let (logins, codes) = (c.logins.unwrap(), c.codes.unwrap());
                assert!(c.found >= logins.max(codes) && c.found <= logins + codes);
                assert!(c.files.unwrap() <= sec["limits"]["window_files"].as_u64().unwrap() as u32);
                assert!(a.error.is_none());
            }
            Decision::Denied => {
                assert!(errors.contains(&a.error.as_deref().unwrap()), "{name}");
                assert!(a.import.is_none());
                refusals += 1;
            }
            other => panic!("{name}: {other:?}"),
        }
    }
    assert_eq!(refusals, errors.len());
    let l = &sec["limits"];
    assert_eq!(l["max_file"].as_u64().unwrap() as usize, import::MAX_FILE);
    assert_eq!(
        l["attachment_max"].as_u64().unwrap() as usize,
        import::ATTACHMENT_MAX
    );
}
