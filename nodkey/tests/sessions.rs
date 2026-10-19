//! End to end: a task session from the command line against the in-process fake relay. One plan
//! approved once covers later codes and logins for its items, even when the user would deny; a code
//! about to run out is replaced by the next one; `end-session` and an ended session both stop it.

mod common;

use nodkey_fake_relay as fake_relay;

use std::{
    path::PathBuf,
    process::{Command, Output},
};

use fake_relay::{Mode, sessions::NEXT_CODE};
use nodkey_proto::Kind;
use serde_json::Value;

struct Cli {
    relay: std::net::SocketAddr,
    dir: PathBuf,
}

impl Cli {
    fn new(relay: std::net::SocketAddr) -> Self {
        let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("nodkey-sessions-{}", nodkey_proto::random_id()));
        Cli { relay, dir }
    }

    fn run(&self, args: &[&str]) -> Output {
        common::output(
            Command::new(env!("CARGO_BIN_EXE_nodkey"))
                .args(args)
                .env("NODKEY_AGENT_DIR", &self.dir)
                .env("NODKEY_KEYSTORE", "file")
                .env("NODKEY_RELAY", format!("http://{}", self.relay))
                .env("NODKEY_REQUEST_TIMEOUT", "3")
                .env_remove("NODKEY_AGENT")
                .env_remove("CLAUDECODE")
                .env_remove("CODEX_SANDBOX")
                .env_remove("CODEX_SANDBOX_NETWORK_DISABLED")
                .env("TMPDIR", env!("CARGO_TARGET_TMPDIR")),
            args,
        )
    }

    fn json(&self, args: &[&str]) -> (Value, i32) {
        let out = self.run(args);
        let v = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
        (v, out.status.code().unwrap())
    }

    fn session_file(&self) -> PathBuf {
        self.dir.join("agents/terminal/session.json")
    }
}

impl Drop for Cli {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn one_plan_covers_the_task() {
    let (fake, addr) = fake_relay::start(1);
    let cli = Cli::new(addr);
    assert!(cli.run(&["pair"]).status.success());

    // The plan: a login and a code on one site, for 30 minutes.
    let (v, code) = cli.json(&[
        "credentials",
        "login:accounts.example.com",
        "code:accounts.example.com",
        "--session",
        "30",
        "--reason",
        "Upload the release",
    ]);
    assert_eq!(code, 0, "{v}");
    let id = v["session"]["id"].as_str().expect("a session").to_owned();
    assert_eq!(v["items"][0]["lease"]["kind"], "session");
    assert!(v["message"].as_str().unwrap().contains("end_session"));
    assert!(cli.session_file().exists());
    let plan = fake.seen().last().unwrap().request.clone();
    assert_eq!(plan.bundle.as_ref().unwrap().session, Some(1800));

    // The user would deny now, but the session answers for the approved items.
    fake.set_mode(Mode::Deny);
    let (v, code) = cli.json(&["code", "accounts.example.com", "--reason", "Step two"]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["code"], fake_relay::CODE);
    let asked = fake.seen().last().unwrap().request.clone();
    assert_eq!(asked.session_id.as_deref(), Some(id.as_str()));
    let (v, code) = cli.json(&["login", "accounts.example.com", "--reason", "Logged out"]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["password"], fake_relay::PASSWORD);

    // Anything outside the plan is asked as usual.
    let (_, code) = cli.json(&["code", "github.com", "--reason", "Not in the plan"]);
    assert_eq!(code, 2);

    // A code with 3 seconds left: the tool waits and hands on the next one.
    fake.sessions.lock().unwrap().seconds_left = 3;
    let started = std::time::Instant::now();
    let (v, code) = cli.json(&["code", "accounts.example.com", "--reason", "Fresh code"]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["code"], NEXT_CODE);
    assert!(v["seconds_left"].as_u64().unwrap() >= 25, "{v}");
    assert!(started.elapsed().as_secs() >= 3);
    fake.sessions.lock().unwrap().seconds_left = 17;
    assert_eq!(fake.sessions.lock().unwrap().list[0].used, 3);

    // The agent ends it: the phone forgets it, and so does the agent.
    let out = cli.run(&["end-session", "--reason", "Done"]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("over"));
    assert!(!cli.session_file().exists());
    assert!(fake.sessions.lock().unwrap().list.is_empty());
    let ended = fake.seen().last().unwrap().request.clone();
    assert_eq!(ended.kind, Kind::SessionEnd);
    let (_, code) = cli.json(&["code", "accounts.example.com", "--reason", "After"]);
    assert_eq!(code, 2, "asked again, and the user denies");
    assert!(fake.seen().last().unwrap().request.session_id.is_none());
    let out = cli.run(&["end-session"]);
    assert!(String::from_utf8_lossy(&out.stderr).contains("No task session"));
}

#[test]
fn an_ended_session_is_forgotten_and_passkeys_need_one() {
    let (fake, addr) = fake_relay::start(1);
    let cli = Cli::new(addr);
    assert!(cli.run(&["pair"]).status.success());
    let (v, _) = cli.json(&[
        "credentials",
        "code:accounts.example.com",
        "passkey:github.com",
        "--session",
        "15",
        "--reason",
        "Sign in twice",
    ]);
    assert!(v["session"]["id"].is_string(), "{v}");
    assert!(
        v["items"][1]["code"].is_null(),
        "a passkey item holds no secret"
    );

    // The user stopped the session on the phone.
    fake.sessions.lock().unwrap().list.clear();
    fake.set_mode(Mode::Deny);
    let (_, code) = cli.json(&["code", "accounts.example.com", "--reason", "Again"]);
    assert_eq!(code, 2);
    assert!(!cli.session_file().exists(), "session_ended: forgotten");

    // A passkey item without a session is refused before anything is sent.
    let before = fake.seen().len();
    let out = cli.run(&["credentials", "passkey:github.com", "--reason", "x"]);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("need a session"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(fake.seen().len(), before);
    let out = cli.run(&[
        "credentials",
        "code:x.example",
        "--session",
        "45",
        "--reason",
        "x",
    ]);
    assert_eq!(out.status.code(), Some(64));
}
