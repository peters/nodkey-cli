//! End to end: sign-in methods against the in-process fake relay. A login for a site signed in
//! to with Google carries the method and the Google login as `via`; answers carry the second step
//! order; `nodkey suggest` and the `suggest_sign_in_method` tool queue a suggestion (and the phone
//! rejects too many); `nodkey sms-code` and `request_sms_code` wait for an SMS the test delivers.

use nodkey_fake_relay as fake_relay;

use std::{
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    process::{Command, Output, Stdio},
    time::Duration,
};

use fake_relay::{
    Mode,
    signin::{GOOGLE_SITE, GOOGLE_USER, Sms},
};
use nodkey_proto::{Kind, Provider, SignInKind, SuggestOutcome};
use serde_json::{Value, json};

struct Cli {
    relay: std::net::SocketAddr,
    dir: PathBuf,
}

impl Cli {
    fn new(relay: std::net::SocketAddr) -> Self {
        let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("nodkey-signin-{}", nodkey_proto::random_id()));
        Cli { relay, dir }
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nodkey"));
        c.args(args)
            .env("NODKEY_AGENT_DIR", &self.dir)
            .env("NODKEY_RELAY", format!("http://{}", self.relay))
            .env("NODKEY_REQUEST_TIMEOUT", "3")
            .env_remove("NODKEY_AGENT")
            .env("TMPDIR", env!("CARGO_TARGET_TMPDIR"));
        c
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command(args).output().expect("run nodkey")
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

fn deliver(fake: &fake_relay::Fake, sms: Sms) {
    fake.signin.lock().unwrap().sms = Some(sms);
}

#[test]
fn login_answers_carry_the_method_via_and_second_step() {
    let (_fake, addr) = fake_relay::start(1);
    let cli = Cli::new(addr);
    assert!(cli.run(&["pair"]).status.success());

    let (v, code) = cli.json(&["login", GOOGLE_SITE, "--reason", "Start the render job"]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["method"]["kind"], "federated");
    assert_eq!(v["method"]["provider"], "google");
    assert!(
        v.get("password").is_none(),
        "the site has no login of its own"
    );
    assert_eq!(v["via"]["username"], GOOGLE_USER);
    assert_eq!(v["via"]["password"], fake_relay::PASSWORD);
    assert_eq!(v["via"]["code"], fake_relay::CODE);
    // Only Google's sign-in host, not every google.com page.
    assert_eq!(v["via"]["fill_only_on"], json!(["accounts.google.com"]));
    assert_eq!(v["second_step"]["prefer"], json!(["passkey", "totp"]));
    let message = v["message"].as_str().unwrap();
    assert!(message.contains("never on the target"), "{message}");
    assert!(message.contains("Try another way"), "{message}");

    let (v, _) = cli.json(&["login", "vg.no", "--reason", "Read the article"]);
    assert_eq!(v["method"]["kind"], "password");
    assert_eq!(v["password"], fake_relay::PASSWORD);
    assert!(v.get("via").is_none());
    assert_eq!(v["fill_only_on"], json!(["vg.no"]));

    let (v, _) = cli.json(&["login", "mail.example.com", "--reason", "Read the invoice"]);
    assert_eq!(v["method"]["kind"], "email_code");
    assert!(v["message"].as_str().unwrap().contains("newest mail"));

    let (v, _) = cli.json(&["code", "github.com", "--reason", "Merge PR #42"]);
    assert_eq!(v["second_step"]["avoid"], json!(["app_prompt", "sms"]));
    assert!(v.get("method").is_none());

    // A bundle item for the Google site carries the same.
    let (v, code) = cli.json(&[
        "credentials",
        &format!("login:{GOOGLE_SITE}"),
        "code:github.com",
        "--reason",
        "Render and publish",
    ]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(
        v["items"][0]["via"]["fill_only_on"],
        json!(["accounts.google.com"])
    );
    assert_eq!(v["items"][1]["fill_only_on"], json!(["github.com"]));
    assert_eq!(v["items"][1]["second_step"]["prefer"][0], "passkey");
    assert!(v["message"].as_str().unwrap().contains("fill_only_on"));
}

#[test]
fn suggestions_are_queued_without_face_id_and_limited() {
    let (fake, addr) = fake_relay::start(1);
    let cli = Cli::new(addr);
    assert!(cli.run(&["pair"]).status.success());
    // The user would deny: a suggestion does not ask them.
    fake.set_mode(Mode::Deny);

    let (v, code) = cli.json(&[
        "suggest",
        "https://www.Renderfarm.example/login",
        "--kind",
        "federated",
        "--provider",
        "google",
        "--reason",
        "Signed in with Google; Nodkey had no method for this site",
    ]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["decision"], "queued");
    let seen = fake.seen().last().unwrap().request.clone();
    assert_eq!(seen.kind, Kind::Suggest);
    assert_eq!(seen.target, "renderfarm.example");
    let s = seen.suggest.unwrap();
    assert_eq!(s.method.provider, Some(Provider::Google));
    assert_eq!(s.method.certainty, Some(nodkey_proto::Certainty::Seen));
    assert_eq!(s.method.source, Some(nodkey_proto::MethodSource::Agent));
    assert_eq!(s.outcome, SuggestOutcome::SignedIn);

    // Another provider by its own name, and a method that failed.
    let (v, code) = cli.json(&[
        "suggest",
        "tools.example.com",
        "--kind",
        "federated",
        "--provider",
        "Okta",
        "--reason",
        "Signed in with the company's Okta",
    ]);
    assert_eq!(code, 0, "{v}");
    let (v, code) = cli.json(&[
        "suggest",
        "mail.example.com",
        "--kind",
        "password",
        "--outcome",
        "failed",
        "--reason",
        "The password did not work; the site sends a code by e-mail now",
    ]);
    assert_eq!(code, 0, "{v}");
    let queued = fake.signin.lock().unwrap().suggestions.clone();
    assert_eq!(queued.len(), 3);
    assert_eq!(
        queued[1].suggest.method.provider_name.as_deref(),
        Some("Okta")
    );
    assert_eq!(queued[2].suggest.outcome, SuggestOutcome::Failed);
    assert_eq!(queued[2].suggest.method.certainty, None);
    assert_eq!(queued[2].suggest.method.kind, SignInKind::Password);

    // Bad suggestions are refused before anything is sent.
    let before = fake.seen().len();
    for args in [
        &[
            "suggest",
            "renderfarm.example",
            "--kind",
            "federated",
            "--reason",
            "x",
        ][..],
        &[
            "suggest",
            "renderfarm.example",
            "--kind",
            "magic",
            "--reason",
            "x",
        ][..],
        &[
            "suggest",
            "not a site",
            "--kind",
            "password",
            "--reason",
            "x",
        ][..],
        &[
            "suggest",
            "renderfarm.example",
            "--kind",
            "sms",
            "--mailbox",
            "alex@example.com",
            "--reason",
            "x",
        ][..],
        &["suggest", "renderfarm.example", "--kind", "password"][..],
    ] {
        let out = cli.run(args);
        assert_ne!(out.status.code(), Some(0), "{args:?}");
    }
    assert_eq!(fake.seen().len(), before);

    // Five per hour: the sixth is rejected.
    for i in 0..2 {
        let (v, code) = cli.json(&[
            "suggest",
            &format!("site{i}.example.com"),
            "--kind",
            "passkey",
            "--reason",
            "Signed in with a passkey",
        ]);
        assert_eq!(code, 0, "{v}");
    }
    let (v, code) = cli.json(&[
        "suggest",
        "site9.example.com",
        "--kind",
        "passkey",
        "--reason",
        "Signed in with a passkey",
    ]);
    assert_eq!(code, 2, "{v}");
    assert_eq!(v["decision"], "rejected");
    assert_eq!(v["error"], "rate_limited");
}

#[test]
fn sms_codes_wait_for_the_message() {
    let (fake, addr) = fake_relay::start(1);
    let cli = Cli::new(addr);
    assert!(cli.run(&["pair"]).status.success());

    let child = cli
        .command(&[
            "sms-code",
            "account.example.com",
            "--reason",
            "The site sent a sign-in code by SMS",
            "--wait",
            "60",
            "--field",
            "code",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(1500));
    deliver(
        &fake,
        Sms {
            text: Some("Your Example code is 482913. Do not share it.".into()),
            expire: false,
        },
    );
    let out = child.wait_with_output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "482913");
    let seen = fake.seen().last().unwrap().request.clone();
    assert_eq!(seen.kind, Kind::SmsCode);
    assert_eq!(seen.wait_seconds, Some(60));

    deliver(
        &fake,
        Sms {
            text: None,
            expire: true,
        },
    );
    let (v, code) = cli.json(&["sms-code", "account.example.com", "--reason", "Code by SMS"]);
    assert_eq!(code, 3, "{v}");
    assert!(v["message"].as_str().unwrap().contains("Shortcuts"));

    let out = cli.run(&[
        "sms-code",
        "account.example.com",
        "--reason",
        "x",
        "--wait",
        "301",
    ]);
    assert_eq!(out.status.code(), Some(64));
}

/// The MCP tools: one `nodkey mcp` process, one request per line.
#[test]
fn mcp_tools_for_suggestions_and_sms_codes() {
    let (fake, addr) = fake_relay::start(1);
    let cli = Cli::new(addr);
    // Pair the MCP profile from the command line, then talk MCP with that profile.
    assert!(
        cli.run(&["pair", "--agent", "claude-code"])
            .status
            .success()
    );
    let mut child = cli
        .command(&["mcp", "--agent", "claude-code"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut call = |id: u64, name: &str, args: Value| -> Value {
        let msg = json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
                         "params": {"name": name, "arguments": args}});
        writeln!(stdin, "{msg}").unwrap();
        loop {
            let mut line = String::new();
            assert!(stdout.read_line(&mut line).unwrap() > 0);
            let v: Value = serde_json::from_str(&line).unwrap();
            if v["id"] == json!(id) {
                let text = v["result"]["content"][0]["text"].as_str().unwrap();
                return serde_json::from_str(text).unwrap();
            }
        }
    };
    let v = call(
        1,
        "suggest_sign_in_method",
        json!({"target": "renderfarm.example", "kind": "federated", "provider": "google",
               "outcome": "signed_in", "reason": "Signed in with Google"}),
    );
    assert_eq!(v["decision"], "queued", "{v}");
    let v = call(
        2,
        "suggest_sign_in_method",
        json!({"target": "renderfarm.example", "kind": "federated", "outcome": "signed_in", "reason": "x"}),
    );
    assert!(v["error"].as_str().unwrap().contains("provider"), "{v}");

    deliver(
        &fake,
        Sms {
            text: Some("123456 is your code".into()),
            expire: false,
        },
    );
    let v = call(
        3,
        "request_sms_code",
        json!({"target": "account.example.com", "reason": "Code by SMS", "wait_seconds": 30}),
    );
    assert_eq!(v["decision"], "approved", "{v}");
    assert_eq!(v["code"], "123456");
    let v = call(
        4,
        "request_sms_code",
        json!({"target": "account.example.com", "reason": "Code by SMS", "wait_seconds": 10}),
    );
    assert!(v["error"].as_str().unwrap().contains("30 to 300"), "{v}");
    drop(stdin);
    let _ = child.kill();
    let _ = child.wait();
}
