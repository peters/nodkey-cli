//! End to end: the agent limit from the command line against the in-process fake relay. The phone
//! asks with the warning (the answer still gives the login, with `quota_warning`), a plan starts no
//! session then and a running one ends, and a paused agent exits with 4 and says why.

mod common;

use nodkey_fake_relay as fake_relay;

use std::{
    path::PathBuf,
    process::{Command, Output},
};

use fake_relay::quota::{FakeQuota, QuotaState};
use serde_json::Value;

struct Cli {
    relay: std::net::SocketAddr,
    dir: PathBuf,
}

impl Cli {
    fn new(relay: std::net::SocketAddr) -> Self {
        let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("nodkey-quota-{}", nodkey_proto::random_id()));
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
                .env("TMPDIR", env!("CARGO_TARGET_TMPDIR")),
            args,
        )
    }

    fn json(&self, args: &[&str]) -> (Value, i32, String) {
        let out = self.run(args);
        let v = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
        let err = String::from_utf8_lossy(&out.stderr).into_owned();
        (v, out.status.code().unwrap(), err)
    }
}

impl Drop for Cli {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn set(fake: &fake_relay::Fake, state: QuotaState, new_today: u32, burst: bool) {
    *fake.quota.lock().unwrap() = FakeQuota {
        state,
        new_today,
        limit: 10,
        burst,
    };
}

#[test]
fn the_warning_still_answers_and_stops_sessions() {
    let (fake, addr) = fake_relay::start(1);
    let cli = Cli::new(addr);
    assert!(cli.run(&["pair"]).status.success());

    // A plan while all is well starts a session.
    let (v, code, _) = cli.json(&[
        "credentials",
        "login:accounts.example.com",
        "--session",
        "15",
        "--reason",
        "Upload the release",
    ]);
    assert_eq!(code, 0, "{v}");
    assert!(v["session"]["id"].is_string());

    // Above the limit: the user approves with the warning; the session no longer answers.
    set(&fake, QuotaState::Warning, 12, false);
    let (v, code, _) = cli.json(&["login", "accounts.example.com", "--reason", "Logged out"]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["password"], fake_relay::PASSWORD);
    assert_eq!(v["error"], "quota_warning");
    assert_eq!(v["quota"]["new_today"], 12);
    assert_eq!(v["quota"]["limit"], 10);
    let message = v["message"].as_str().unwrap();
    assert!(message.contains("12 in the last 24 hours"), "{message}");
    assert!(message.contains("do not retry in a loop"), "{message}");
    assert!(v["lease"]["kind"] != "session", "{v}");
    assert!(fake.sessions.lock().unwrap().list.is_empty());

    // A plan now is asked as a bundle without a session.
    let (v, code, _) = cli.json(&[
        "credentials",
        "login:accounts.example.com",
        "code:github.com",
        "--session",
        "30",
        "--reason",
        "Compare the notes",
    ]);
    assert_eq!(code, 0, "{v}");
    assert!(v["session"].is_null(), "{v}");
    assert_eq!(v["error"], "quota_warning");
    assert!(
        v["message"]
            .as_str()
            .unwrap()
            .contains("did not start a task session because of the limit notice")
    );

    // The burst rule, and a denial after the warning.
    set(&fake, QuotaState::Warning, 6, true);
    fake.set_mode(fake_relay::Mode::Deny);
    let (v, code, _) = cli.json(&["code", "github.com", "--reason", "One more"]);
    assert_eq!(code, 2, "{v}");
    assert_eq!(v["quota"]["burst"], true);
    assert!(v["message"].as_str().unwrap().contains("in a short time"));

    // Not counted: the warning leaves a list of accounts alone.
    fake.set_mode(fake_relay::Mode::Approve);
    let (v, code, _) = cli.json(&["accounts", "--json"]);
    assert_eq!(code, 0, "{v}");
    assert!(v["error"].is_null(), "{v}");
}

#[test]
fn a_paused_agent_exits_with_4_and_says_why() {
    let (fake, addr) = fake_relay::start(1);
    let cli = Cli::new(addr);
    assert!(cli.run(&["pair"]).status.success());

    set(&fake, QuotaState::Paused, 25, false);
    let (v, code, err) = cli.json(&["login", "vg.no", "--reason", "Read the article"]);
    assert_eq!(code, 4, "{v}");
    assert_eq!(v["decision"], "denied");
    assert_eq!(v["error"], "paused");
    assert_eq!(v["quota"]["new_today"], 25);
    assert!(v.get("password").is_none());
    assert!(err.contains("Nodkey paused this agent"), "{err}");
    assert!(err.contains("resume this agent under Agents"), "{err}");
    let (v, code, _) = cli.json(&["credentials", "code:github.com", "--reason", "x"]);
    assert_eq!((code, v["error"].as_str()), (4, Some("paused")), "{v}");

    set(&fake, QuotaState::PausedByUser, 0, false);
    let (v, code, err) = cli.json(&["code", "github.com", "--reason", "Merge PR #42"]);
    assert_eq!(code, 4, "{v}");
    assert!(v.get("quota").is_none(), "{v}");
    assert!(err.contains("The user has paused this agent"), "{err}");
    let (v, code, _) = cli.json(&[
        "suggest",
        "renderfarm.example",
        "--kind",
        "federated",
        "--provider",
        "google",
        "--reason",
        "Signed in with Google",
    ]);
    assert_eq!((code, v["decision"].as_str()), (4, Some("rejected")), "{v}");

    // The user resumes the agent.
    set(&fake, QuotaState::Off, 0, false);
    let (v, code, _) = cli.json(&["code", "github.com", "--reason", "Merge PR #42"]);
    assert_eq!(code, 0, "{v}");
    assert!(v["error"].is_null());
}
