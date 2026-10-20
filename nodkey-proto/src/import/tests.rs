use super::{detect::detect, *};
use crate::{
    Answer, Decision, Kind, client,
    keys::x25519_public,
    messages::parse_plaintext,
    vectors::import::{CHROME_CSV, SAMPLES, import_request},
};

#[test]
fn formats_read_tolerantly() {
    for f in ImportFormat::ALL {
        let text = serde_json::to_string(&f).unwrap();
        assert_eq!(text, format!("\"{}\"", f.as_str()));
        assert_eq!(serde_json::from_str::<ImportFormat>(&text).unwrap(), f);
    }
    let later: ImportFormat = serde_json::from_str("\"edge_csv\"").unwrap();
    assert_eq!(later, ImportFormat::Unknown);
    assert_eq!(ImportFormat::default(), ImportFormat::Unknown);
}

#[test]
fn limits_fit_the_relay() {
    assert_eq!(MAX_FILE, 1_048_528);
    assert_eq!(MAX_FILE + ENC_LEN + TAG_LEN, ATTACHMENT_MAX);
}

#[test]
fn request_rules() {
    let ok = ImportRequest::new("Chrome Passwords.csv", CHROME_CSV, None, "Chrome");
    assert_eq!(ok.check(), Ok(()));
    assert!(ok.matches(CHROME_CSV));
    assert!(!ok.matches(b"name,url,username,password\n"));
    let code = |r: ImportRequest| r.check().unwrap_err().0;
    let mut r = ok.clone();
    r.size = MAX_FILE as u64 + 1;
    assert_eq!(code(r), errors::TOO_LARGE);
    for name in ["", " ", "a/b.csv", "a\\b.csv", "a\u{7}.csv"] {
        let mut r = ok.clone();
        r.file_name = name.into();
        assert_eq!(code(r), errors::BAD_IMPORT, "{name:?}");
    }
    let mut r = ok.clone();
    r.size = 0;
    assert_eq!(code(r), errors::BAD_IMPORT);
    let mut r = ok.clone();
    r.sha256 = "A".repeat(43) + "A";
    assert_eq!(code(r), errors::BAD_IMPORT);
    let mut r = ok.clone();
    r.source = "x".repeat(MAX_SOURCE + 1);
    assert_eq!(code(r), errors::BAD_IMPORT);
    let mut r = ok;
    r.source = "x".repeat(MAX_SOURCE);
    r.file_name = "é".repeat(MAX_FILE_NAME);
    assert_eq!(r.check(), Ok(()));
}

#[test]
fn whole_request_rules() {
    let rid = crate::random_id();
    let r = import_request(&rid);
    assert_eq!(client::check_request(&r), Ok(()));
    let mut bad = r.clone();
    bad.target = "example.com".into();
    assert!(client::check_request(&bad).is_err());
    let mut bad = r.clone();
    bad.import = None;
    assert!(client::check_request(&bad).is_err());
    let mut bad = r.clone();
    bad.session_id = Some(crate::random_id());
    assert!(client::check_request(&bad).is_err());
    let mut bad = r.clone();
    bad.attachment = Some(client::attachment_info(
        crate::ImageType::Png,
        &crate::vectors::PNG,
        None,
    ));
    assert!(client::check_request(&bad).is_err());
    let mut bad = r.clone();
    bad.kind = Kind::List;
    assert!(client::check_request(&bad).is_err());
    let mut bad = r;
    bad.reason = String::new();
    assert!(client::check_request(&bad).is_err());
}

#[test]
fn the_file_opens_only_as_an_import() {
    let sk = [7u8; 32];
    let pk = x25519_public(&sk);
    let body = seal_file("rid", "aid", &pk, CHROME_CSV).unwrap();
    assert_eq!(body.len(), CHROME_CSV.len() + ENC_LEN + TAG_LEN);
    assert_eq!(&*open_file(&sk, "rid", "aid", &body).unwrap(), CHROME_CSV);
    assert!(open_file(&sk, "rix", "aid", &body).is_err());
    assert!(crate::seal::open_attachment_body(&sk, b"ridaid", &body).is_err());
    let picture = client::seal_attachment("rid", "aid", &pk, CHROME_CSV).unwrap();
    assert!(open_file(&sk, "rid", "aid", &picture).is_err());
}

#[test]
fn a_staged_answer_reads() {
    let text = r#"{"v":1,"request_id":"r","decision":"staged","import":{"found":4,"new":3,"merged":1,
        "duplicates":0,"conflicts":0,"skipped":1}}"#;
    let a: Answer = parse_plaintext(text.as_bytes()).unwrap();
    assert_eq!(a.decision, Decision::Staged);
    let counts = a.import.unwrap();
    assert_eq!((counts.found, counts.new, counts.merged), (4, 3, 1));
    assert_eq!(
        (counts.logins, counts.files, counts.until),
        (None, None, None)
    );
}

#[test]
fn detect_reads_every_sample() {
    for s in SAMPLES {
        let d = detect(s.bytes);
        let got = (
            d.format,
            d.found,
            d.logins,
            d.codes,
            d.skipped,
            d.encrypted,
            d.archive,
        );
        assert_eq!(got, s.expect, "{}", s.name);
    }
}

#[test]
fn detect_never_fails() {
    // Cut every sample at every length, and some odd bytes: a result, never a panic.
    for s in SAMPLES {
        for n in 0..=s.bytes.len() {
            let d = detect(&s.bytes[..n]);
            assert!(d.found <= d.logins + d.codes);
        }
    }
    for odd in [
        &b"\"unterminated,"[..],
        b",,,\n,,,",
        b"\r\r\r",
        b"\xff\xfe\x00",
        b"{",
        b"[1,2]",
    ] {
        let _ = detect(odd);
    }
    const ALPHABET: &[u8] = b",\"\n\ra{}otpauth://";
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut noise = vec![0u8; 4096];
    for _ in 0..64 {
        for b in noise.iter_mut() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *b = ALPHABET[(state % ALPHABET.len() as u64) as usize];
        }
        let _ = detect(&noise);
    }
}
