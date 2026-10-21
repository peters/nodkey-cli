//! End to end: a new password (peters/nodkey#131). `nodkey generate` and the MCP tool
//! `create_login` against the fake phone: the phone makes a password by the page's rules, saves it
//! first and gives it with the user name as confirmed; stdout holds only the password. Refusals:
//! `bad_rules`, `no_passcode`, `not_allowed`, `save_failed`, denied and paused, each with its exit
//! code. A task session never covers it.

mod common;

use nodkey_fake_relay as fake_relay;

use std::{
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    process::{Command, Output, Stdio},
};

use fake_relay::{
    Mode,
    generate::FakeGenerate,
    quota::{FakeQuota, QuotaState},
};
use nodkey_proto::{Kind, Saved, generate::Rules};
use serde_json::{Value, json};

const RULES: &str =
    "minlength: 12; required: lower; required: upper; required: digit; allowed: [-_.!];";

struct Cli {
    relay: std::net::SocketAddr,
    dir: PathBuf,
}

impl Cli {
    fn new(relay: std::net::SocketAddr) -> Self {
        let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("nodkey-generate-{}", nodkey_proto::random_id()));
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

fn set(fake: &fake_relay::Fake, f: impl FnOnce(&mut FakeGenerate)) {
    f(&mut fake.generate.lock().unwrap());
}

fn signup(extra: &[&'static str]) -> Vec<&'static str> {
    let mut args = vec![
        "generate",
        "--site",
        "https://accounts.example.com/signup?invite=abc123",
        "--user",
        "alex@example.com",
        "--title",
        "Example Cloud",
        "--rules",
        RULES,
        "--max",
        "64",
        "--reason",
        "Sign up for Example Cloud, as you asked",
    ];
    args.extend_from_slice(extra);
    args
}

#[test]
fn generate_from_the_terminal() {
    let (fake, addr) = fake_relay::start(1);
    let cli = Cli::new(addr);
    assert!(cli.run(&["pair"]).status.success());

    // Approved: stdout is the password and nothing else; stderr names the login and the site.
    let out = cli.run(&signup(&[]));
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let printed = stdout(&out);
    let password = printed.strip_suffix('\n').expect("one line");
    assert!(!password.contains('\n') && !password.is_empty());
    let rules = Rules {
        passwordrules: Some(RULES.into()),
        max_length: Some(64),
        ..Rules::default()
    };
    assert!(rules.fits(password), "{password}");
    let note = stderr(&out);
    assert!(note.contains("saved the login alex@example.com on accounts.example.com"));
    assert!(note.contains("only on example.com"), "{note}");
    assert!(!note.contains(password));

    // The phone saw the page without its query, and saved the password before it answered.
    let sent = fake.seen().last().unwrap().request.clone();
    assert_eq!(sent.kind, Kind::Generate);
    assert_eq!(sent.target, "accounts.example.com");
    assert!(sent.session_id.is_none() && sent.attachment.is_none());
    let g = sent.generate.unwrap();
    assert_eq!(
        g.url.as_deref(),
        Some("https://accounts.example.com/signup")
    );
    assert_eq!(g.rules.unwrap(), rules);
    assert!(!g.change);
    let made = fake.generate.lock().unwrap().made.clone();
    assert_eq!(made.len(), 1);
    assert_eq!(
        (made[0].saved, made[0].password.as_str()),
        (Saved::Added, password)
    );
    assert_eq!(made[0].title, "Example Cloud");

    // A password change for the same user on the same website updates that login; the old
    // password stays on the phone.
    let out = cli.run(&[
        "generate",
        "--site",
        "example.com",
        "--user",
        "ALEX@example.com",
        "--change",
        "--json",
        "--reason",
        "Change the password you asked me to change",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let v: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v["saved"], "updated");
    assert_eq!(v["account"]["site"], "accounts.example.com");
    assert_eq!(v["fill_only_on"], json!(["example.com"]));
    assert!(stderr(&out).contains("old one stays"));
    let made = fake.generate.lock().unwrap().made.clone();
    assert_eq!(made[1].old_password.as_deref(), Some(password));
    assert_eq!(v["password"], made[1].password);
    assert!(
        fake.seen()
            .last()
            .unwrap()
            .request
            .generate
            .as_ref()
            .unwrap()
            .change
    );

    // The user corrects the user name on the phone: the answer carries theirs.
    set(&fake, |g| g.username = Some("alex.k@example.com".into()));
    let out = cli.run(&signup(&["--json"]));
    let v: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(
        (v["username"].as_str(), v["saved"].as_str()),
        (Some("alex.k@example.com"), Some("added"))
    );
    set(&fake, |g| g.username = None);
}

#[test]
fn generate_refusals_and_exit_codes() {
    let (fake, addr) = fake_relay::start(1);
    let cli = Cli::new(addr);
    assert!(cli.run(&["pair"]).status.success());
    let refused = |args: &[&str], code: i32, error: &str| {
        let out = cli.run(args);
        assert_eq!(out.status.code(), Some(code), "{}", stderr(&out));
        assert!(stdout(&out).is_empty(), "stdout: {}", stdout(&out));
        let mut json = args.to_vec();
        json.push("--json");
        let v: Value = serde_json::from_slice(&cli.run(&json).stdout).unwrap();
        assert_eq!(
            v["error"].as_str(),
            (!error.is_empty()).then_some(error),
            "{v}"
        );
        assert!(v["password"].is_null());
        stderr(&out)
    };

    // Rules no password can meet: the phone refuses before it asks.
    let note = refused(
        &[
            "generate",
            "--site",
            "example.com",
            "--min",
            "30",
            "--max",
            "10",
        ],
        15,
        "bad_rules",
    );
    assert!(note.contains("rules"));
    refused(
        &[
            "generate",
            "--site",
            "example.com",
            "--rules",
            "allowed: [ ]",
        ],
        15,
        "bad_rules",
    );

    // The user says no.
    fake.set_mode(Mode::Deny);
    let note = refused(&signup(&[]), 2, "");
    assert!(note.contains("did not make"));
    fake.set_mode(Mode::Approve);

    // A phone without a passcode never makes one.
    *fake.passcode.lock().unwrap() = false;
    let note = refused(&signup(&[]), 10, "no_passcode");
    assert!(note.contains("Face ID & Passcode"));
    *fake.passcode.lock().unwrap() = true;

    // An agent paired for codes only gets no password.
    set(&fake, |g| g.codes_only = true);
    refused(&signup(&[]), 2, "not_allowed");
    set(&fake, |g| g.codes_only = false);

    // The phone could not save: nothing is given.
    set(&fake, |g| g.save_fails = true);
    let note = refused(&signup(&[]), 1, "save_failed");
    assert!(note.contains("nothing changed"));
    set(&fake, |g| g.save_fails = false);

    // A paused agent.
    *fake.quota.lock().unwrap() = FakeQuota {
        state: QuotaState::PausedByUser,
        ..FakeQuota::default()
    };
    refused(&signup(&[]), 4, "paused");
    *fake.quota.lock().unwrap() = FakeQuota::default();
    assert!(fake.generate.lock().unwrap().made.is_empty());

    // Bad arguments never reach the phone.
    let before = fake.seen().len();
    for args in [
        vec!["generate"],
        vec!["generate", "--site", "GitHub"],
        vec!["generate", "--site", "example.com", "--min", "ten"],
        vec!["generate", "example.com"],
    ] {
        assert_eq!(cli.run(&args).status.code(), Some(64), "{args:?}");
    }
    assert_eq!(fake.seen().len(), before);
}

#[test]
fn a_task_session_never_covers_a_new_password() {
    let (fake, addr) = fake_relay::start(1);
    let cli = Cli::new(addr);
    assert!(cli.run(&["pair"]).status.success());
    let out = cli.run(&[
        "credentials",
        "login:accounts.example.com",
        "--session",
        "15",
        "--reason",
        "Set up the account",
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    // The user would deny now: the session does not answer for a new password.
    fake.set_mode(Mode::Deny);
    let out = cli.run(&signup(&[]));
    assert_eq!(out.status.code(), Some(2));
    let sent = fake.seen().last().unwrap().request.clone();
    assert_eq!(sent.kind, Kind::Generate);
    assert!(sent.session_id.is_none());
}

#[test]
fn create_login_over_mcp() {
    let (fake, addr) = fake_relay::start(1);
    let cli = Cli::new(addr);
    assert!(cli.run(&["pair", "--agent", "e2e"]).status.success());
    let mut child = cli
        .command(&["mcp", "--agent", "e2e"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let mut id = 0;
    let mut rpc = |method: &str, params: Value| -> Value {
        id += 1;
        let msg = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        writeln!(stdin, "{msg}").unwrap();
        loop {
            let mut line = String::new();
            assert!(out.read_line(&mut line).unwrap() > 0);
            let v: Value = serde_json::from_str(&line).unwrap();
            if v["id"] == json!(id) {
                return v;
            }
        }
    };
    rpc(
        "initialize",
        json!({"protocolVersion": "2025-06-18", "capabilities": {},
               "clientInfo": {"name": "e2e", "version": "1"}}),
    );
    let tools = rpc("tools/list", json!({}));
    let tool = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "create_login")
        .unwrap()
        .clone();
    let description = tool["description"].as_str().unwrap();
    assert!(description.contains("only when the user asked you to sign up"));
    assert!(description.contains("Never store, log or repeat it"));
    assert_eq!(tool["inputSchema"]["required"], json!(["site", "reason"]));

    let mut call = |args: Value| -> (Value, bool) {
        let r = rpc(
            "tools/call",
            json!({"name": "create_login", "arguments": args}),
        );
        let text = r["result"]["content"][0]["text"].as_str().unwrap();
        (
            serde_json::from_str(text).unwrap_or(json!({ "text": text })),
            r["result"]["isError"] == true,
        )
    };
    let (v, error) = call(json!({
        "site": "https://accounts.example.com/signup",
        "username": "alex@example.com",
        "rules": {"passwordrules": RULES, "max_length": 64},
        "reason": "Sign up for Example Cloud, as you asked",
        "model": "test-model",
    }));
    assert!(!error, "{v}");
    assert_eq!(
        (v["decision"].as_str(), v["saved"].as_str()),
        (Some("approved"), Some("added"))
    );
    assert_eq!(v["username"], "alex@example.com");
    assert_eq!(v["fill_only_on"], json!(["example.com"]));
    let password = v["password"].as_str().unwrap();
    assert!(
        Rules {
            passwordrules: Some(RULES.into()),
            ..Rules::default()
        }
        .fits(password)
    );
    assert!(v["message"].as_str().unwrap().contains("Do not store"));
    let sent = fake.seen().last().unwrap().request.clone();
    assert_eq!(sent.client.unwrap().model.as_deref(), Some("test-model"));

    // A passwordrules string works as rules; impossible rules are refused by the phone.
    let (v, error) = call(
        json!({"site": "example.com", "rules": "maxlength: 2; required: upper; required: lower; required: digit", "reason": "Sign up"}),
    );
    assert!(!error);
    assert_eq!(
        (v["decision"].as_str(), v["error"].as_str()),
        (Some("denied"), Some("bad_rules"))
    );
    assert!(v["password"].is_null());

    // Mistakes in the call are tool errors and never reach the phone.
    let before = fake.seen().len();
    for args in [
        json!({"site": "example.com"}),
        json!({"site": "GitHub", "reason": "Sign up"}),
        json!({"site": "example.com", "rules": {"minlength": 8}, "reason": "Sign up"}),
        json!({"site": "example.com", "change": "yes", "reason": "Sign up"}),
    ] {
        let (v, error) = call(args.clone());
        assert!(error, "{args}: {v}");
    }
    assert_eq!(fake.seen().len(), before);
    drop(call);
    drop(rpc);
    let _ = child.kill();
    let _ = child.wait();
}
