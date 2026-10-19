//! End to end: websites against the in-process fake relay. Every approved login and code names
//! the sites it may be filled on (`fill_only_on`): the account's own, or for an account the user
//! picked by hand, the site that was asked for. A task session covers the approved item's website
//! (any host of it), never a look-alike.

use nodkey_fake_relay as fake_relay;

use std::{
    path::PathBuf,
    process::{Command, Output},
};

use fake_relay::{FakeAccount, Mode};
use nodkey_proto::MatchKind;
use serde_json::{Value, json};

struct Cli {
    relay: std::net::SocketAddr,
    dir: PathBuf,
}

impl Cli {
    fn new(relay: std::net::SocketAddr) -> Self {
        let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("nodkey-sites-{}", nodkey_proto::random_id()));
        Cli { relay, dir }
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_nodkey"))
            .args(args)
            .env("NODKEY_AGENT_DIR", &self.dir)
            .env("NODKEY_KEYSTORE", "file")
            .env("NODKEY_RELAY", format!("http://{}", self.relay))
            .env("NODKEY_REQUEST_TIMEOUT", "3")
            .env_remove("NODKEY_AGENT")
            .env("TMPDIR", env!("CARGO_TARGET_TMPDIR"))
            .output()
            .expect("run nodkey")
    }

    fn json(&self, args: &[&str]) -> (Value, i32) {
        let out = self.run(args);
        let v = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
        (v, out.status.code().unwrap())
    }
}

impl Drop for Cli {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn results_say_where_to_fill() {
    let (fake, addr) = fake_relay::start(1);
    let cli = Cli::new(addr);
    assert!(cli.run(&["pair"]).status.success());

    // The phone found the account for the site asked for: its website, every host of it.
    let (v, code) = cli.json(&["login", "login.vg.no", "--reason", "Read the article"]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["match"], "direct");
    assert_eq!(v["fill_only_on"], json!(["vg.no"]));
    assert!(v["message"].as_str().unwrap().contains("vg.no or below"));

    // Picked by hand for sora.com: only there, whatever the account's own sites are.
    *fake.account.lock().unwrap() = Some(FakeAccount {
        site: Some("openai.com".into()),
        sites: Some(vec!["chatgpt.com".into()]),
        match_kind: Some(MatchKind::Chosen),
    });
    let (v, _) = cli.json(&["login", "https://sora.com/login", "--reason", "Sign in"]);
    assert_eq!(v["fill_only_on"], json!(["sora.com"]));
    assert!(v["message"].as_str().unwrap().contains("picked it by hand"));

    // An account saved for another website (an older phone matched by name): the agent is told
    // the account's own site, so it stops on the page it asked for.
    *fake.account.lock().unwrap() = Some(FakeAccount {
        site: Some("github.com".into()),
        sites: None,
        match_kind: Some(MatchKind::Direct),
    });
    let (v, _) = cli.json(&["code", "github.xyz", "--reason", "Merge"]);
    assert_eq!(v["fill_only_on"], json!(["github.com"]));

    // A code account without a website, picked for github.com.
    *fake.account.lock().unwrap() = Some(FakeAccount {
        site: None,
        sites: None,
        match_kind: Some(MatchKind::Chosen),
    });
    let (v, _) = cli.json(&["code", "github.com/alex", "--reason", "Merge"]);
    assert_eq!(v["fill_only_on"], json!(["github.com"]));
    let (v, _) = cli.json(&["code", "GitHub", "--reason", "Merge"]);
    assert!(v.get("fill_only_on").is_none(), "{v}");
}

#[test]
fn a_session_covers_the_website_not_a_look_alike() {
    let (fake, addr) = fake_relay::start(1);
    let cli = Cli::new(addr);
    assert!(cli.run(&["pair"]).status.success());
    let (v, code) = cli.json(&[
        "credentials",
        "login:accounts.example.com",
        "--session",
        "15",
        "--reason",
        "Upload the release",
    ]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["items"][0]["fill_only_on"], json!(["example.com"]));

    // The user would deny now: only what the session covers goes through.
    fake.set_mode(Mode::Deny);
    let (v, code) = cli.json(&["login", "login.example.com", "--reason", "Logged out"]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["lease"]["kind"], "session");
    for other in [
        "example.com.evil.test",
        "example.co",
        "alice.github.io",
        "Example",
    ] {
        let (_, code) = cli.json(&["login", other, "--reason", "Look-alike"]);
        assert_eq!(code, 2, "{other} is asked as usual, and the user denies");
    }
}
