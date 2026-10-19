//! End to end: API keys. `nodkey run --secret`, `nodkey secret save`, key items in a task plan and
//! the `request_secret`, `save_secret` and `list_accounts` MCP tools against the in-process fake
//! relay, whose phone holds two test keys (`OPENAI_API_KEY` for openai.com, `EXAMPLE_TOKEN` for
//! api.example.com).

use nodkey_fake_relay as fake_relay;

use std::{
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    process::{Command, Output, Stdio},
};

use fake_relay::{Mode, quota::FakeQuota, quota::QuotaState};
use nodkey_proto::Kind;
use serde_json::{Value, json};

const OPENAI: &str = "sk-test-0000";
const EXAMPLE: &str = "tok-test-1111";

struct Cli {
    relay: std::net::SocketAddr,
    dir: PathBuf,
}

impl Cli {
    fn new(relay: std::net::SocketAddr) -> Self {
        let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("nodkey-secrets-{}", nodkey_proto::random_id()));
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
            .env_remove("OPENAI_API_KEY")
            .env_remove("EXAMPLE_TOKEN")
            .env("TMPDIR", env!("CARGO_TARGET_TMPDIR"));
        c
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command(args).output().expect("run nodkey")
    }

    fn run_with_stdin(&self, args: &[&str], input: &str) -> Output {
        let mut child = self
            .command(args)
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
        child.wait_with_output().unwrap()
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

/// A child command that prints the variables `names` (joined by `|`) and exits with `code`.
fn printer(names: &[&str], code: u8) -> Vec<String> {
    if cfg!(windows) {
        let shown: Vec<String> = names.iter().map(|n| format!("$env:{n}")).collect();
        vec![
            "powershell".into(),
            "-NoProfile".into(),
            "-Command".into(),
            format!("Write-Output ({}); exit {code}", shown.join(" + '|' + ")),
        ]
    } else {
        let shown: Vec<String> = names.iter().map(|n| format!("${n}")).collect();
        vec![
            "sh".into(),
            "-c".into(),
            format!("printf '%s\\n' \"{}\"; exit {code}", shown.join("|")),
        ]
    }
}

fn run_args<'a>(secrets: &'a [&'a str], child: &'a [String]) -> Vec<&'a str> {
    let mut args = vec!["run"];
    for s in secrets {
        args.extend(["--secret", s]);
    }
    args.extend(["--reason", "Run the tests that call the API", "--"]);
    args.extend(child.iter().map(String::as_str));
    args
}

#[test]
fn run_puts_keys_only_into_the_command() {
    let (fake, addr) = fake_relay::start(1);
    let cli = Cli::new(addr);
    assert!(cli.run(&["pair"]).status.success());

    // One key: one `secret` request; the command sees it, nodkey never prints it.
    let child = printer(&["OPENAI_API_KEY"], 0);
    let out = cli.run(&run_args(&["OPENAI_API_KEY"], &child));
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stdout(&out).trim(), OPENAI);
    assert!(!stderr(&out).contains(OPENAI));
    let seen = fake.seen().pop().unwrap().request;
    assert_eq!(
        (seen.kind, seen.target.as_str()),
        (Kind::Secret, "OPENAI_API_KEY")
    );

    // The command's exit code is passed on.
    let child = printer(&["OPENAI_API_KEY"], 7);
    let out = cli.run(&run_args(&["OPENAI_API_KEY"], &child));
    assert_eq!(out.status.code(), Some(7));

    // Two keys: one bundle, one approval; a key may name its service, also as a URL.
    let child = printer(&["OPENAI_API_KEY", "EXAMPLE_TOKEN"], 0);
    let out = cli.run(&run_args(
        &["OPENAI_API_KEY", "EXAMPLE_TOKEN=https://api.example.com/v1"],
        &child,
    ));
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stdout(&out).trim(), format!("{OPENAI}|{EXAMPLE}"));
    let seen = fake.seen().pop().unwrap().request;
    assert_eq!(seen.kind, Kind::Bundle);
    let items = seen.bundle.unwrap().items;
    assert_eq!(items[1].target, "api.example.com/EXAMPLE_TOKEN");
    assert!(items.iter().all(|i| i.kind == Kind::Secret));

    // A missing command: 127, after the keys came.
    let out = cli.run(&run_args(
        &["OPENAI_API_KEY"],
        &["nodkey-test-no-such-command".to_owned()],
    ));
    assert_eq!(out.status.code(), Some(127), "{}", stderr(&out));
}

#[test]
fn run_starts_nothing_when_the_phone_refuses() {
    let (fake, addr) = fake_relay::start(1);
    let cli = Cli::new(addr);
    assert!(cli.run(&["pair"]).status.success());
    let child = printer(&["OPENAI_API_KEY"], 0);

    let out = cli.run(&run_args(&["MISSING_KEY"], &child));
    assert_eq!(out.status.code(), Some(2));
    assert!(stdout(&out).is_empty(), "the command did not run");
    assert!(stderr(&out).contains("no such key"), "{}", stderr(&out));

    let out = cli.run(&run_args(&["OPENAI_API_KEY", "MISSING_KEY"], &child));
    assert_eq!(out.status.code(), Some(2));
    assert!(stdout(&out).is_empty());
    assert!(stderr(&out).contains("MISSING_KEY: "), "{}", stderr(&out));

    fake.set_mode(Mode::Deny);
    let out = cli.run(&run_args(&["OPENAI_API_KEY"], &child));
    assert_eq!(out.status.code(), Some(2));
    assert!(stdout(&out).is_empty());

    fake.set_mode(Mode::Silent);
    let out = cli.run(&run_args(&["OPENAI_API_KEY"], &child));
    assert_eq!(out.status.code(), Some(3));
    assert!(stdout(&out).is_empty());

    fake.set_mode(Mode::Approve);
    *fake.quota.lock().unwrap() = FakeQuota {
        state: QuotaState::PausedByUser,
        new_today: 0,
        limit: 10,
        burst: false,
    };
    let out = cli.run(&run_args(&["OPENAI_API_KEY"], &child));
    assert_eq!(out.status.code(), Some(4));
    assert!(stdout(&out).is_empty());

    // Bad options never reach the phone.
    let before = fake.seen().len();
    let out = cli.run(&["run", "--secret", "OPENAI-KEY", "--reason", "x", "--", "ls"]);
    assert_eq!(out.status.code(), Some(64));
    let out = cli.run(&["run", "--secret", "OPENAI_API_KEY", "--reason", "x"]);
    assert_eq!(out.status.code(), Some(64));
    assert_eq!(fake.seen().len(), before);
}

#[test]
fn a_plan_with_a_key_covers_later_runs() {
    let (fake, addr) = fake_relay::start(1);
    let cli = Cli::new(addr);
    assert!(cli.run(&["pair"]).status.success());

    let out = cli.run(&[
        "credentials",
        "login:accounts.example.com",
        "secret:openai.com/OPENAI_API_KEY",
        "--session",
        "15",
        "--reason",
        "Release the new version",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let v: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v["items"][1]["kind"], "secret");
    assert_eq!(v["items"][1]["secret"]["variable"], "OPENAI_API_KEY");
    assert!(
        v["items"][1]["secret"].get("value").is_none(),
        "a plan item has no value"
    );
    assert!(!stdout(&out).contains(OPENAI));

    // Denied from now on, but the session covers the key.
    fake.set_mode(Mode::Deny);
    let child = printer(&["OPENAI_API_KEY"], 0);
    let out = cli.run(&run_args(&["OPENAI_API_KEY=openai.com"], &child));
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stdout(&out).trim(), OPENAI);
    let seen = fake.seen().pop().unwrap().request;
    assert!(seen.session_id.is_some());
    assert_eq!(fake.sessions.lock().unwrap().list[0].used, 1);

    // Another key is asked as usual (and denied).
    let out = cli.run(&run_args(&["EXAMPLE_TOKEN"], &child));
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn save_reads_the_key_from_stdin() {
    let (fake, addr) = fake_relay::start(1);
    let cli = Cli::new(addr);
    assert!(cli.run(&["pair"]).status.success());
    let save = [
        "secret",
        "save",
        "NEW_TOKEN",
        "--service",
        "https://www.new.example.com/settings",
        "--title",
        "New example",
        "--expires",
        "2027-01-31",
        "--reason",
        "Save the token I just made",
    ];

    let out = cli.run_with_stdin(&save, "tok-test-2222\n");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let v: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v["saved"], "added");
    assert!(!stdout(&out).contains("tok-test-2222") && !stderr(&out).contains("tok-test-2222"));
    let seen = fake.seen().pop().unwrap();
    assert_eq!(seen.request.kind, Kind::SaveSecret);
    assert_eq!(seen.request.target, "new.example.com/NEW_TOKEN");
    assert_eq!(seen.saved_secret.as_deref(), Some("tok-test-2222"));
    let s = seen.request.save_secret.unwrap();
    assert_eq!(s.title.as_deref(), Some("New example"));
    assert_eq!(s.expires, Some(1_801_353_600));
    let keys = fake.secrets.lock().unwrap().clone();
    assert!(keys.iter().any(|k| k.value == "tok-test-2222"));

    let out = cli.run_with_stdin(&save, "tok-test-2222\r\n");
    let v: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v["saved"], "unchanged");
    let out = cli.run_with_stdin(&save, "tok-test-3333");
    let v: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v["saved"], "updated");

    // Never from the arguments, never empty.
    let before = fake.seen().len();
    let out = cli.run_with_stdin(&save, "\n");
    assert_eq!(out.status.code(), Some(64));
    let out = cli.run_with_stdin(
        &[
            "secret",
            "save",
            "NEW_TOKEN",
            "tok-test-4444",
            "--reason",
            "x",
        ],
        "x",
    );
    assert_eq!(out.status.code(), Some(64));
    let out = cli.run_with_stdin(&["secret", "save", "NEW-TOKEN", "--reason", "x"], "x");
    assert_eq!(out.status.code(), Some(64));
    assert_eq!(fake.seen().len(), before);
}

/// A small MCP client over the real `nodkey mcp`.
struct Mcp {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
    next: u64,
}

impl Mcp {
    fn start(cli: &Cli) -> Self {
        let mut child = cli
            .command(&["mcp", "--agent", "claude-code"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("start nodkey mcp");
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let mut m = Mcp {
            child,
            stdin,
            stdout,
            next: 1,
        };
        m.rpc(
            "initialize",
            json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}),
        );
        m
    }

    fn rpc(&mut self, method: &str, params: Value) -> Value {
        let id = self.next;
        self.next += 1;
        let msg = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        writeln!(self.stdin, "{msg}").unwrap();
        self.stdin.flush().unwrap();
        loop {
            let mut line = String::new();
            assert!(self.stdout.read_line(&mut line).unwrap() > 0);
            let v: Value = serde_json::from_str(&line).unwrap();
            if v["id"] == json!(id) {
                return v;
            }
        }
    }

    fn tool(&mut self, name: &str, args: Value) -> (Value, bool) {
        let r = self.rpc("tools/call", json!({"name": name, "arguments": args}));
        let text = r["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_owned();
        let parsed = serde_json::from_str(&text).unwrap_or(Value::String(text));
        (parsed, r["result"]["isError"].as_bool().unwrap())
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn mcp_tools_for_keys() {
    let (fake, addr) = fake_relay::start(1);
    let cli = Cli::new(addr);
    assert!(
        cli.run(&["pair", "--agent", "claude-code"])
            .status
            .success()
    );
    let mut mcp = Mcp::start(&cli);

    let (v, err) = mcp.tool(
        "request_secret",
        json!({"service": "https://api.openai.com", "reason": "Call the API once"}),
    );
    assert!(!err, "{v}");
    assert_eq!(v["secret"]["value"], OPENAI);
    assert!(
        v["message"]
            .as_str()
            .unwrap()
            .contains("nodkey run --secret")
    );
    assert_eq!(fake.seen().pop().unwrap().request.target, "api.openai.com");

    let (v, err) = mcp.tool("request_secret", json!({"reason": "x"}));
    assert!(err && v.to_string().contains("name the key"), "{v}");

    let (v, err) = mcp.tool(
        "save_secret",
        json!({"variable": "NEW_TOKEN", "service": "new.example.com", "value": "tok-test-5555",
               "expires": "2027-01-31", "reason": "Save the token I just made"}),
    );
    assert!(!err, "{v}");
    assert_eq!(v["saved"], "added");
    assert!(!v.to_string().contains("tok-test-5555"));
    assert_eq!(
        fake.seen().pop().unwrap().saved_secret.as_deref(),
        Some("tok-test-5555")
    );

    let (v, err) = mcp.tool("list_accounts", json!({}));
    assert!(!err, "{v}");
    let names: Vec<&str> = v["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["variable"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["OPENAI_API_KEY", "EXAMPLE_TOKEN", "NEW_TOKEN"]);
    assert!(!v.to_string().contains(OPENAI));
    assert!(v["message"].as_str().unwrap().contains("by name only"));

    let tools = mcp.rpc("tools/list", json!({}));
    let list = tools["result"]["tools"].as_array().unwrap();
    for name in ["request_secret", "save_secret"] {
        assert!(list.iter().any(|t| t["name"] == name), "{name}");
    }
}
