//! End to end: the `nodkey` command line against the in-process fake relay.

mod common;

use nodkey_fake_relay as fake_relay;

use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Output, Stdio},
};

use fake_relay::Mode;
use nodkey_proto::{
    PasskeyOp, b64u,
    passkey::{build_client_data_json, check_client_data},
    webauthn,
};
use serde_json::{Value, json};

struct Cli {
    relay: std::net::SocketAddr,
    dir: PathBuf,
}

impl Cli {
    fn new(relay: std::net::SocketAddr) -> Self {
        let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("nodkey-cli-{}", nodkey_proto::random_id()));
        Cli { relay, dir }
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nodkey"));
        c.args(args)
            .env("NODKEY_AGENT_DIR", &self.dir)
            .env("NODKEY_KEYSTORE", "file")
            .env("NODKEY_RELAY", format!("http://{}", self.relay))
            .env("NODKEY_REQUEST_TIMEOUT", "3")
            .env_remove("NODKEY_AGENT")
            .env_remove("CLAUDECODE")
            .env_remove("CODEX_SANDBOX")
            .env_remove("CODEX_SANDBOX_NETWORK_DISABLED")
            .env("TMPDIR", env!("CARGO_TARGET_TMPDIR"));
        c
    }

    fn run(&self, args: &[&str]) -> Output {
        common::output(&mut self.command(args), args)
    }

    /// `nodkey webauthn --agent claude-code` with `input` on stdin: the one JSON line on stdout
    /// and the exit code.
    fn webauthn(&self, input: &str) -> (Value, i32) {
        let mut child = self
            .command(&["webauthn", "--agent", "claude-code"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("run nodkey");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        assert_eq!(
            text.lines().count(),
            1,
            "one JSON line: {text}{}",
            stderr(&out)
        );
        (
            serde_json::from_str(&text).unwrap(),
            out.status.code().unwrap(),
        )
    }
}

impl Drop for Cli {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn pair_then_ask_from_the_terminal() {
    let (fake, addr) = fake_relay::start(1);
    let cli = Cli::new(addr);

    let out = cli.run(&["code", "github.com", "--reason", "Merge PR #4"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(stderr(&out).contains("not paired"), "{}", stderr(&out));

    let out = cli.run(&["pair"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    assert!(
        text.contains("K7P-2QX") && text.contains("Terminal @ "),
        "{text}"
    );
    assert!(
        text.contains(&format!("Paired with {}", fake_relay::PHONE_NAME)),
        "{text}"
    );
    let id: Value = serde_json::from_slice(
        &std::fs::read(cli.dir.join("agents/terminal/identity.json")).unwrap(),
    )
    .unwrap();
    assert!(text.contains(&fake.check_for(id["agent_id"].as_str().unwrap())));

    // One field only, for scripts.
    let out = cli.run(&[
        "code",
        "github.com",
        "--reason",
        "Merge PR #4",
        "--field",
        "code",
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), format!("{}\n", fake_relay::CODE));
    assert!(stderr(&out).contains("Waiting for your answer"));

    // The whole answer as JSON.
    let out = cli.run(&[
        "login",
        "vg.no",
        "--reason",
        "Read the paper",
        "--model",
        "m1",
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["decision"], "approved");
    assert_eq!(v["username"], fake_relay::USERNAME);
    assert_eq!(v["password"], fake_relay::PASSWORD);
    let seen = fake.seen();
    let last = &seen.last().unwrap().request;
    assert_eq!(last.client.as_ref().unwrap().model.as_deref(), Some("m1"));
    assert!(last.agent.starts_with("Terminal @ "), "{}", last.agent);

    let out = cli.run(&["accounts"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("GitHub  alex  github.com  code"),
        "{}",
        stdout(&out)
    );

    // Several items at once.
    let out = cli.run(&[
        "credentials",
        "login:chatgpt.com",
        "code:deny.example",
        "--reason",
        "Two sign-ins",
        "--follow-up",
        "300",
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        (v["approved"].as_u64(), v["of"].as_u64()),
        (Some(1), Some(2))
    );
    assert_eq!(v["items"][0]["password"], fake_relay::PASSWORD);
    assert_eq!(v["items"][1]["decision"], "denied");

    let out = cli.run(&["cleanup", "--ip-only", "--reason", "Old routers"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    assert!(
        text.contains("3 saved logins were moved") && text.contains("192.168.1.1"),
        "{text}"
    );

    fake.set_mode(Mode::Deny);
    let out = cli.run(&["code", "github.com", "--reason", "Again", "--field", "code"]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(stdout(&out), "");
    assert!(stderr(&out).contains("denied"), "{}", stderr(&out));

    fake.set_mode(Mode::Silent);
    let out = cli.run(&["code", "github.com", "--reason", "Nobody home"]);
    assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));

    let out = cli.run(&["agents"]);
    assert!(stdout(&out).starts_with("terminal"), "{}", stdout(&out));
    assert!(
        stdout(&out).contains("keys in the file identity.json"),
        "{}",
        stdout(&out)
    );
    let out = cli.run(&["agents", "--json"]);
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["agents"][0]["keys"], "file");
    let out = cli.run(&["phones", "--json"]);
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["phones"][0]["name"], fake_relay::PHONE_NAME);

    // Another agent has its own identity and is not paired.
    let out = cli.run(&["phones", "--agent", "codex"]);
    assert!(stdout(&out).contains("Codex @ ") && stdout(&out).contains("not paired"));

    let out = cli.run(&["unpair", fake_relay::PHONE_NAME]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(fake.left(), [id["agent_id"].as_str().unwrap()]);
}

#[test]
fn bad_arguments_exit_64() {
    let cli = Cli::new("127.0.0.1:9".parse().unwrap());
    for args in [
        &["code"][..],
        &["code", "github.com"],
        &["cleanup", "--reason", "x"],
        &["credentials", "--reason", "x"],
        &["credentials", "vg.no", "--reason", "x"],
        &["login", "a", "--reason", "x", "--bogus"],
        &["frobnicate"],
        &["phones", "--agent", "Not Valid"],
        &["webauthn", "--bogus"],
        &["webauthn", "extra"],
        &["webauthn", "--agent", "Not Valid"],
    ] {
        let out = cli.run(args);
        assert_eq!(out.status.code(), Some(64), "{args:?}: {}", stderr(&out));
        if args[0] == "webauthn" {
            let v: Value = serde_json::from_slice(&out.stdout).unwrap();
            assert_eq!(v["status"], "error", "{args:?}");
        }
    }
    let out = cli.run(&["--version"]);
    assert!(stdout(&out).starts_with("nodkey "));
    let out = cli.run(&["skill"]);
    assert!(stdout(&out).contains("name: nodkey"));
}

// Passkeys: `nodkey webauthn` against the fake phone, which holds a test passkey for
// `webauthn.io` and makes new ones. Signatures are checked with real ES256.

const ORIGIN: &str = "https://webauthn.io";

fn bytes(v: &Value, k: &str) -> Vec<u8> {
    b64u::decode(
        v[k].as_str()
            .unwrap_or_else(|| panic!("{k} missing in {v}")),
    )
    .unwrap()
}

fn client_data(op: PasskeyOp, origin: &str) -> String {
    let mut challenge = [0u8; 32];
    nodkey_proto::random_bytes(&mut challenge);
    build_client_data_json(op, &b64u::encode(&challenge), origin)
}

fn get(rp_id: &str, cd: &str, allow: &[&str]) -> String {
    json!({
        "version": 1, "op": "get", "rp_id": rp_id, "origin": ORIGIN,
        "client_data_json": b64u::encode(cd.as_bytes()), "allow_credentials": allow,
        "user_verification": "preferred",
        "reason": "Sign in to webauthn.io in a browser panel",
        "requester": {"app": "Horizon", "agent": "Claude Code"},
    })
    .to_string()
}

fn create(cd: &str, user_id: &[u8], algorithms: &[i64], exclude: &[&str]) -> String {
    json!({
        "version": 1, "op": "create", "rp_id": "webauthn.io", "origin": ORIGIN,
        "client_data_json": b64u::encode(cd.as_bytes()), "rp_name": "WebAuthn.io",
        "user": {"id": b64u::encode(user_id), "name": "sam@example.com", "display_name": "Sam"},
        "algorithms": algorithms, "exclude_credentials": exclude, "resident_key": "required",
        "user_verification": "required",
    })
    .to_string()
}

#[test]
fn create_then_sign_in_with_a_passkey() {
    let (fake, addr) = fake_relay::start(1);
    let cli = Cli::new(addr);
    let out = cli.run(&["pair", "--agent", "claude-code"]);
    assert!(out.status.success(), "{}", stderr(&out));

    // A new passkey: the attested authenticator data holds the returned key and credential id.
    let user_id = [42u8; 16];
    let cd = client_data(PasskeyOp::Create, ORIGIN);
    let (made, code) = cli.webauthn(&create(&cd, &user_id, &[-7, -257], &[]));
    assert_eq!(code, 0, "{made}");
    assert_eq!(made["status"], "ok");
    assert_eq!(made["public_key_algorithm"], -7);
    assert_eq!(made["transports"], json!(["internal", "hybrid"]));
    let credential = made["credential_id"].as_str().unwrap().to_owned();
    let public_key = webauthn::key_from_spki(&bytes(&made, "public_key")).unwrap();
    let auth = bytes(&made, "authenticator_data");
    assert_eq!(
        auth,
        webauthn::authenticator_data(
            "webauthn.io",
            Some((&bytes(&made, "credential_id"), &public_key))
        )
    );
    assert_eq!(
        bytes(&made, "attestation_object"),
        webauthn::attestation_object(&auth)
    );
    let seen = fake.seen();
    let sent = &seen.last().unwrap().request;
    assert_eq!(sent.kind, nodkey_proto::Kind::Passkey);
    assert_eq!(sent.target, "webauthn.io");
    assert_eq!(sent.reason, "Create a passkey for webauthn.io");
    assert!(sent.agent.starts_with("Claude Code @ "), "{}", sent.agent);

    // Sign in with it: the signature verifies with the key from create, over this client data.
    let cd = client_data(PasskeyOp::Get, ORIGIN);
    let (signed, code) = cli.webauthn(&get("webauthn.io", &cd, &[&credential]));
    assert_eq!(code, 0, "{signed}");
    assert_eq!(signed["credential_id"], credential.as_str());
    assert_eq!(bytes(&signed, "user_handle"), user_id);
    let auth = bytes(&signed, "authenticator_data");
    assert_eq!(auth, webauthn::authenticator_data("webauthn.io", None));
    let signature = bytes(&signed, "signature");
    webauthn::verify(&public_key, &auth, cd.as_bytes(), &signature).unwrap();
    assert!(webauthn::verify(&public_key, &auth, b"{}", &signature).is_err());
    let seen = fake.seen();
    let sent = &seen.last().unwrap().request;
    assert_eq!(sent.reason, "Sign in to webauthn.io in a browser panel");
    let client = sent.client.as_ref().unwrap();
    assert_eq!(client.app.as_deref(), Some("Horizon (Claude Code)"));
    let p = sent.passkey.as_ref().unwrap();
    assert_eq!(
        check_client_data(
            PasskeyOp::Get,
            "webauthn.io",
            &b64u::decode(p.client_data_json()).unwrap()
        )
        .unwrap()
        .origin,
        ORIGIN
    );

    // The phone's test passkey (the vectors' key) signs too.
    let test = fake
        .passkeys()
        .into_iter()
        .find(|p| p.user_name == fake_relay::passkeys::USER_NAME)
        .unwrap();
    let cd = client_data(PasskeyOp::Get, ORIGIN);
    let (signed, code) = cli.webauthn(&get("webauthn.io", &cd, &[&test.credential_id]));
    assert_eq!(code, 0, "{signed}");
    let key = webauthn::key_from_spki(&b64u::decode(&test.public_key).unwrap()).unwrap();
    webauthn::verify(
        &key,
        &bytes(&signed, "authenticator_data"),
        cd.as_bytes(),
        &bytes(&signed, "signature"),
    )
    .unwrap();

    // Refusals.
    let cd = client_data(PasskeyOp::Get, "https://example.com");
    let none = json!({
        "version": 1, "op": "get", "rp_id": "example.com", "origin": "https://example.com",
        "client_data_json": b64u::encode(cd.as_bytes()),
    });
    let (v, code) = cli.webauthn(&none.to_string());
    assert_eq!((v["status"].as_str(), code), (Some("not_found"), 2), "{v}");
    let cd = client_data(PasskeyOp::Create, ORIGIN);
    let (v, code) = cli.webauthn(&create(&cd, &user_id, &[-7], &[&credential]));
    assert_eq!((v["status"].as_str(), code), (Some("excluded"), 2), "{v}");
    let (v, code) = cli.webauthn(&create(&cd, &user_id, &[-257], &[]));
    assert_eq!((v["status"].as_str(), code), (Some("denied"), 2), "{v}");
    assert_eq!(v["error"], "unsupported_algorithm");

    fake.set_mode(Mode::Deny);
    let cd = client_data(PasskeyOp::Get, ORIGIN);
    let (v, code) = cli.webauthn(&get("webauthn.io", &cd, &[]));
    assert_eq!((v["status"].as_str(), code), (Some("denied"), 2), "{v}");
    fake.set_mode(Mode::Silent);
    let (v, code) = cli.webauthn(&get("webauthn.io", &cd, &[]));
    assert_eq!((v["status"].as_str(), code), (Some("expired"), 3), "{v}");

    // Bad input never reaches the phone.
    let before = fake.seen().len();
    let other = client_data(PasskeyOp::Get, "https://www.webauthn.io");
    let mut mismatch: Value = serde_json::from_str(&get("webauthn.io", &other, &[])).unwrap();
    mismatch["origin"] = json!(ORIGIN);
    for input in [
        mismatch.to_string(),
        get(
            "webauthn.io",
            &client_data(PasskeyOp::Get, "http://webauthn.io"),
            &[],
        ),
        get("webauthn.io", &client_data(PasskeyOp::Create, ORIGIN), &[]),
        "not json".to_owned(),
        json!({"version": 2}).to_string(),
    ] {
        let (v, code) = cli.webauthn(&input);
        assert_eq!(
            (v["status"].as_str(), code),
            (Some("error"), 64),
            "{input}: {v}"
        );
    }
    assert_eq!(fake.seen().len(), before);
}

#[test]
fn not_paired_is_an_error() {
    let (_fake, addr) = fake_relay::start(1);
    let cli = Cli::new(addr);
    let cd = client_data(PasskeyOp::Get, ORIGIN);
    let (v, code) = cli.webauthn(&get("webauthn.io", &cd, &[]));
    assert_eq!((v["status"].as_str(), code), (Some("error"), 1), "{v}");
    assert!(v["message"].as_str().unwrap().contains("not paired"), "{v}");
}

/// `extensions.prf` with `eval` (`first`, and `second` when given).
fn with_prf(request: &str, first: &[u8], second: Option<&[u8]>) -> String {
    let mut v: Value = serde_json::from_str(request).unwrap();
    let mut eval = json!({"first": b64u::encode(first)});
    if let Some(second) = second {
        eval["second"] = json!(b64u::encode(second));
    }
    v["extensions"] = json!({"prf": {"eval": eval}});
    v.to_string()
}

#[test]
fn prf_gives_the_same_key_for_the_same_salt() {
    use nodkey_proto::{prf, vectors::prf::cred_random};
    let (fake, addr) = fake_relay::start(1);
    let cli = Cli::new(addr);
    let out = cli.run(&["pair", "--agent", "claude-code"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let expected = |salt: &[u8]| b64u::encode(&*prf::evaluate(&cred_random(), salt));

    // A new passkey with PRF; the output for the salt comes at once.
    let cd = client_data(PasskeyOp::Create, ORIGIN);
    let (made, code) = cli.webauthn(&with_prf(
        &create(&cd, &[9; 16], &[-7], &[]),
        b"salt one",
        None,
    ));
    assert_eq!(code, 0, "{made}");
    let prf_made = &made["clientExtensionResults"]["prf"];
    assert_eq!(prf_made["enabled"], true, "{made}");
    assert_eq!(prf_made["results"]["first"], expected(b"salt one"));
    let credential = made["credential_id"].as_str().unwrap().to_owned();
    let sent = fake.seen().last().unwrap().request.clone();
    assert!(sent.passkey.unwrap().prf().is_some());

    // Sign in twice with the same salt: the same output. Another salt: another output.
    let unlock = |salt: &[u8], second: Option<&[u8]>| {
        let cd = client_data(PasskeyOp::Get, ORIGIN);
        let (v, code) = cli.webauthn(&with_prf(
            &get("webauthn.io", &cd, &[&credential]),
            salt,
            second,
        ));
        assert_eq!(code, 0, "{v}");
        v["clientExtensionResults"]["prf"]["results"].clone()
    };
    let one = unlock(b"salt one", None);
    assert_eq!(one, unlock(b"salt one", None));
    assert_eq!(one["first"], expected(b"salt one"));
    assert!(one.get("second").is_none());
    let two = unlock(b"salt two", Some(b"salt one"));
    assert_ne!(two["first"], one["first"]);
    assert_eq!(two["second"], one["first"]);
    let sent = fake.seen().last().unwrap().request.clone();
    assert_eq!(sent.reason, "Sign in to webauthn.io in a browser panel");

    // Without a reason the phone gets "Unlock a key for ...".
    let cd = client_data(PasskeyOp::Get, ORIGIN);
    let mut v: Value = serde_json::from_str(&with_prf(
        &get("webauthn.io", &cd, &[&credential]),
        b"x",
        None,
    ))
    .unwrap();
    v.as_object_mut().unwrap().remove("reason");
    let (_, code) = cli.webauthn(&v.to_string());
    assert_eq!(code, 0);
    let sent = fake.seen().last().unwrap().request.clone();
    assert_eq!(sent.reason, "Unlock a key for webauthn.io");

    // The test passkey is from before PRF support: prf_unsupported, at once.
    let test = fake
        .passkeys()
        .into_iter()
        .find(|p| p.user_name == fake_relay::passkeys::USER_NAME)
        .unwrap();
    assert!(!test.prf);
    let cd = client_data(PasskeyOp::Get, ORIGIN);
    let (v, code) = cli.webauthn(&with_prf(
        &get("webauthn.io", &cd, &[&test.credential_id]),
        b"salt one",
        None,
    ));
    assert_eq!(
        (v["status"].as_str(), code),
        (Some("prf_unsupported"), 2),
        "{v}"
    );
    assert_eq!(v["error"], "prf_unsupported");

    // The help documents the contract.
    let out = cli.run(&["webauthn", "--help"]);
    let help = stdout(&out);
    for part in [
        "evalByCredential",
        "clientExtensionResults",
        "RP ID rule",
        "\".\" + rp_id",
    ] {
        assert!(help.contains(part), "{part}");
    }
}

#[test]
fn a_session_signs_in_without_uv_and_required_asks_with_face_id() {
    let (fake, addr) = fake_relay::start(1);
    let cli = Cli::new(addr);
    assert!(
        cli.run(&["pair", "--agent", "claude-code"])
            .status
            .success()
    );
    let out = cli.run(&[
        "credentials",
        "passkey:webauthn.io",
        "--session",
        "15",
        "--reason",
        "Sign in to webauthn.io a few times",
        "--agent",
        "claude-code",
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    let key =
        webauthn::key_from_spki(&b64u::decode(&fake.passkeys()[0].public_key).unwrap()).unwrap();

    // The session answers by itself, even when the user would say no: no Face ID, so no UV.
    fake.set_mode(Mode::Deny);
    let cd = client_data(PasskeyOp::Get, ORIGIN);
    let (signed, code) = cli.webauthn(&get("webauthn.io", &cd, &[]));
    assert_eq!(code, 0, "{signed}");
    let auth = bytes(&signed, "authenticator_data");
    assert_eq!(auth[32], 0x19);
    assert_eq!(auth, webauthn::authenticator_data_without_uv("webauthn.io"));
    webauthn::verify(&key, &auth, cd.as_bytes(), &bytes(&signed, "signature")).unwrap();

    // A site that requires user verification is asked with Face ID, never by the session.
    let required = |cd: &str| {
        let mut v: Value = serde_json::from_str(&get("webauthn.io", cd, &[])).unwrap();
        v["user_verification"] = json!("required");
        v.to_string()
    };
    let (v, code) = cli.webauthn(&required(&client_data(PasskeyOp::Get, ORIGIN)));
    assert_eq!((code, v["status"].as_str()), (2, Some("denied")), "{v}");
    fake.set_mode(Mode::Approve);
    let cd = client_data(PasskeyOp::Get, ORIGIN);
    let (signed, code) = cli.webauthn(&required(&cd));
    assert_eq!(code, 0, "{signed}");
    let auth = bytes(&signed, "authenticator_data");
    assert_eq!(auth[32], 0x1d);
    webauthn::verify(&key, &auth, cd.as_bytes(), &bytes(&signed, "signature")).unwrap();
}
