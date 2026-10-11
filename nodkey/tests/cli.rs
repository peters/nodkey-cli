//! End to end: the `nodkey` command line against the in-process fake relay.

use nodkey_fake_relay as fake_relay;

use std::{
    path::PathBuf,
    process::{Command, Output},
};

use fake_relay::Mode;
use serde_json::Value;

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

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_nodkey"))
            .args(args)
            .env("NODKEY_AGENT_DIR", &self.dir)
            .env("NODKEY_RELAY", format!("http://{}", self.relay))
            .env("NODKEY_REQUEST_TIMEOUT", "3")
            .env_remove("NODKEY_AGENT")
            .env("TMPDIR", env!("CARGO_TARGET_TMPDIR"))
            .output()
            .expect("run nodkey")
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
        &["login", "a", "--reason", "x", "--bogus"],
        &["frobnicate"],
        &["phones", "--agent", "Not Valid"],
    ] {
        let out = cli.run(args);
        assert_eq!(out.status.code(), Some(64), "{args:?}: {}", stderr(&out));
    }
    let out = cli.run(&["--version"]);
    assert!(stdout(&out).starts_with("nodkey "));
    let out = cli.run(&["skill"]);
    assert!(stdout(&out).contains("name: nodkey"));
}
