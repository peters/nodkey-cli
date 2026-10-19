//! End to end: a phone without a passcode. `nodkey webauthn` gets `no_passcode` for a passkey
//! request that needs user verification or PRF, and an answer without UV for any other one.

mod common;

use nodkey_fake_relay as fake_relay;

use std::path::PathBuf;

use nodkey_proto::{PasskeyOp, b64u, passkey::build_client_data_json, webauthn};
use serde_json::{Value, json};

const ORIGIN: &str = "https://webauthn.io";

struct Cli {
    relay: std::net::SocketAddr,
    dir: PathBuf,
}

impl Cli {
    fn command(&self, args: &[&str]) -> std::process::Command {
        let mut c = std::process::Command::new(env!("CARGO_BIN_EXE_nodkey"));
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

    /// `nodkey webauthn --agent horizon` with `input` on stdin: the JSON result and exit code.
    fn webauthn(&self, input: &Value) -> (Value, i32) {
        let args = ["webauthn", "--agent", "horizon"];
        let out = common::output_with_input(&mut self.command(&args), input.to_string().as_bytes());
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
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

fn request(op: PasskeyOp, uv: &str, extra: Value) -> Value {
    let mut challenge = [0u8; 32];
    nodkey_proto::random_bytes(&mut challenge);
    let cd = build_client_data_json(op, &b64u::encode(&challenge), ORIGIN);
    let mut v = json!({
        "version": 1, "op": if op == PasskeyOp::Get { "get" } else { "create" },
        "rp_id": "webauthn.io", "origin": ORIGIN, "client_data_json": b64u::encode(cd.as_bytes()),
        "user_verification": uv, "requester": {"app": "Horizon", "agent": "Claude Code"},
    });
    if op == PasskeyOp::Create {
        v["rp_name"] = json!("WebAuthn.io");
        v["user"] =
            json!({"id": b64u::encode(b"sam"), "name": "sam@example.com", "display_name": "Sam"});
        v["algorithms"] = json!([-7]);
    }
    for (k, val) in extra.as_object().unwrap() {
        v[k] = val.clone();
    }
    v
}

/// The flags byte of a result's authenticator data.
fn flags(v: &Value) -> u8 {
    b64u::decode(v["authenticator_data"].as_str().unwrap()).unwrap()[32]
}

#[test]
fn passkeys_on_a_phone_without_a_passcode() {
    let (fake, addr) = fake_relay::start(1);
    let cli = Cli {
        relay: addr,
        dir: std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("nodkey-passcode-{}", nodkey_proto::random_id())),
    };
    let out = common::output(&mut cli.command(&["pair", "--agent", "horizon"]), &["pair"]);
    assert!(out.status.success());
    *fake.passcode.lock().unwrap() = false;

    // Refused at once: the phone cannot verify the user.
    let prf = json!({"extensions": {"prf": {"eval": {"first": b64u::encode(b"salt")}}}});
    for input in [
        request(PasskeyOp::Get, "required", json!({})),
        request(PasskeyOp::Create, "required", json!({})),
        request(PasskeyOp::Get, "preferred", prf),
    ] {
        let (v, code) = cli.webauthn(&input);
        assert_eq!((v["status"].as_str(), code), (Some("denied"), 2), "{v}");
        assert_eq!(v["error"], "no_passcode");
        assert!(
            v["message"]
                .as_str()
                .unwrap()
                .contains("Face ID & Passcode")
        );
    }

    // Anything else is answered without UV.
    let (v, code) = cli.webauthn(&request(PasskeyOp::Create, "preferred", json!({})));
    assert_eq!(code, 0, "{v}");
    assert_eq!(flags(&v), webauthn::FLAGS_WITHOUT_UV | webauthn::FLAG_AT);
    let (v, code) = cli.webauthn(&request(PasskeyOp::Get, "preferred", json!({})));
    assert_eq!(code, 0, "{v}");
    assert_eq!(flags(&v), webauthn::FLAGS_WITHOUT_UV);

    // With a passcode the same get is verified.
    *fake.passcode.lock().unwrap() = true;
    let (v, _) = cli.webauthn(&request(PasskeyOp::Get, "preferred", json!({})));
    assert_eq!(flags(&v), webauthn::FLAGS);
}
