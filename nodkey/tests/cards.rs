//! End to end: payment cards. `nodkey pay`, `nodkey card-fill` and the `request_payment` MCP tool
//! against the in-process fake relay, whose phone holds the test card 4242 4242 4242 4242 and
//! answers by the user's card settings (on/off, full numbers on/off, limit per purchase).

mod common;

use nodkey_fake_relay as fake_relay;

use std::{
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    process::{Command, Output, Stdio},
};

use fake_relay::{Mode, cards::FakeCards};
use nodkey_proto::{CardMode, Kind, Money};
use serde_json::{Value, json};

struct Cli {
    relay: std::net::SocketAddr,
    dir: PathBuf,
}

impl Cli {
    fn new(relay: std::net::SocketAddr) -> Self {
        let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("nodkey-cards-{}", nodkey_proto::random_id()));
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

    fn pair(&self, agent: &str) {
        let out = self.run(&["pair", "--agent", agent]);
        assert!(out.status.success(), "{}", stderr(&out));
    }

    /// `nodkey card-fill --agent claude-code` with `input` on stdin: the JSON line and exit code.
    fn card_fill(&self, input: &Value) -> (Value, i32) {
        let mut child = self
            .command(&["card-fill", "--agent", "claude-code"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("run nodkey");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.to_string().as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        let text = stdout(&out);
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

fn set_cards(fake: &fake_relay::Shared, enabled: bool, reveal: bool, limit: Option<&str>) {
    *fake.cards.lock().unwrap() = FakeCards {
        enabled,
        reveal,
        limit: limit.map(|v| Money::parse(v, "NOK").unwrap()),
    };
}

const PAY: [&str; 7] = [
    "pay",
    "shop.example.com",
    "499",
    "NOK",
    "--reason",
    "Buy the 2 m USB-C cable you asked for",
    "--reveal",
];

#[test]
fn pay_from_the_terminal() {
    let (fake, addr) = fake_relay::start(1);
    let cli = Cli::new(addr);
    cli.pair("terminal");

    let out = cli.run(&PAY);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let v: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v["decision"], "approved");
    assert_eq!(v["card"]["number"], fake_relay::cards::CARD_NUMBER);
    assert_eq!(
        v["card"]["approved_amount"],
        json!({"value": "499", "currency": "NOK"})
    );
    assert!(v["message"].as_str().unwrap().contains("ONE purchase"));
    let seen = fake.seen().pop().unwrap().request;
    assert_eq!(seen.kind, Kind::Card);
    let card = seen.card.unwrap();
    assert_eq!(
        (card.mode, card.merchant.as_str()),
        (CardMode::Reveal, "shop.example.com")
    );
    assert_eq!(card.amount.unwrap().value, "499");

    let mut field = PAY.to_vec();
    field.extend(["--field", "cvc"]);
    let out = cli.run(&field);
    assert_eq!(stdout(&out).trim(), fake_relay::cards::CARD_CVC);

    // Refusals the phone gives without asking, each with its own exit code.
    let over = cli.run(&[
        "pay",
        "shop.example.com",
        "12999",
        "NOK",
        "--reason",
        "A TV",
        "--reveal",
    ]);
    assert_eq!(over.status.code(), Some(5), "{}", stderr(&over));
    assert!(stderr(&over).contains("never split"), "{}", stderr(&over));
    assert!(!stdout(&over).contains(fake_relay::cards::CARD_NUMBER));
    set_cards(&fake, true, false, Some("1000"));
    assert_eq!(cli.run(&PAY).status.code(), Some(6));
    set_cards(&fake, false, true, None);
    assert_eq!(cli.run(&PAY).status.code(), Some(7));
    set_cards(&fake, true, true, None);
    fake.set_mode(Mode::Deny);
    let denied = cli.run(&PAY);
    assert_eq!(denied.status.code(), Some(2));
    assert!(stderr(&denied).contains("denied the payment"));
    fake.set_mode(Mode::Silent);
    assert_eq!(cli.run(&PAY).status.code(), Some(3));

    // Checked before anything is sent.
    let before = fake.seen().len();
    let missing = cli.run(&["pay", "shop.example.com", "--reason", "x", "--reveal"]);
    assert_eq!(missing.status.code(), Some(64));
    assert!(stderr(&missing).contains("amount_missing"));
    let no_reveal = cli.run(&PAY[..6]);
    assert_eq!(no_reveal.status.code(), Some(64));
    assert!(stderr(&no_reveal).contains("--reveal"));
    assert_eq!(
        cli.run(&[
            "pay",
            "s.example",
            "1 000",
            "NOK",
            "--reason",
            "x",
            "--reveal"
        ])
        .status
        .code(),
        Some(64)
    );
    assert_eq!(fake.seen().len(), before);
}

fn fill(extra: Value) -> Value {
    let mut v = json!({
        "version": 1, "merchant": "shop.example.com", "origin": "https://www.shop.example.com",
        "amount": {"value": "499.00", "currency": "NOK"},
        "page_total": {"value": "499,00", "currency": "NOK"}, "total_source": "page",
        "reason": "Buy the 2 m USB-C cable you asked for",
        "requester": {"app": "Horizon", "agent": "Claude Code"},
    });
    for (k, val) in extra.as_object().unwrap() {
        v[k] = val.clone();
    }
    v
}

#[test]
fn a_browser_host_fills_a_card() {
    let (fake, addr) = fake_relay::start(1);
    let cli = Cli::new(addr);
    cli.pair("claude-code");

    let (v, code) = cli.card_fill(&fill(json!({})));
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["status"], "ok");
    assert_eq!(v["card"]["number"], fake_relay::cards::CARD_NUMBER);
    assert_eq!(v["card"]["cvc"], fake_relay::cards::CARD_CVC);
    assert_eq!(
        v["approved_amount"],
        json!({"value": "499.00", "currency": "NOK"})
    );
    let summary = v["summary"].as_str().unwrap();
    assert!(
        summary.contains("Visa \u{b7}\u{b7}\u{b7}\u{b7}4242") && summary.contains("499.00 NOK")
    );
    assert!(!summary.contains(fake_relay::cards::CARD_NUMBER));
    let seen = fake.seen().pop().unwrap();
    let card = seen.request.card.unwrap();
    assert_eq!(card.mode, CardMode::Fill);
    assert_eq!(card.origin.as_deref(), Some("https://www.shop.example.com"));
    assert_eq!(card.page_total.unwrap().value, "499.00");
    assert_eq!(
        seen.request.client.unwrap().app.as_deref(),
        Some("Horizon (Claude Code)")
    );

    // The page shows more than the amount: refused here, nothing goes to the phone.
    let before = fake.seen().len();
    let (v, code) = cli.card_fill(&fill(
        json!({"page_total": {"value": "4999", "currency": "NOK"}}),
    ));
    assert_eq!(
        (code, v["status"].as_str()),
        (8, Some("total_mismatch")),
        "{v}"
    );
    let (v, code) = cli.card_fill(&fill(json!({"origin": "https://shop.example.com.evil.io"})));
    assert_eq!(code, 64, "{v}");
    let (v, code) = cli.card_fill(&fill(json!({"amount": null})));
    assert_eq!(
        (code, v["error"].as_str()),
        (64, Some("amount_missing")),
        "{v}"
    );
    let (_, code) = cli.card_fill(&fill(json!({"number": "4242424242424242"})));
    assert_eq!(code, 64);
    assert_eq!(fake.seen().len(), before);

    // The phone's refusals.
    let (v, code) = cli.card_fill(&fill(json!({
        "amount": {"value": "12999", "currency": "NOK"}, "page_total": null, "total_source": null
    })));
    assert_eq!((code, v["status"].as_str()), (5, Some("over_limit")), "{v}");
    set_cards(&fake, false, false, None);
    let (v, code) = cli.card_fill(&fill(json!({})));
    assert_eq!((code, v["status"].as_str()), (7, Some("cards_off")), "{v}");
    // Fill works with full numbers off: the number goes to the host, not the model.
    set_cards(&fake, true, false, None);
    assert_eq!(cli.card_fill(&fill(json!({}))).1, 0);
    fake.set_mode(Mode::Deny);
    assert_eq!(cli.card_fill(&fill(json!({}))).1, 2);
}

#[test]
fn request_payment_over_mcp() {
    let (fake, addr) = fake_relay::start(1);
    let cli = Cli::new(addr);
    cli.pair("claude-code");
    let mut child = cli
        .command(&["mcp", "--agent", "claude-code"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let mut rpc = |id: u64, method: &str, params: Value| -> Value {
        writeln!(
            stdin,
            "{}",
            json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
        )
        .unwrap();
        stdin.flush().unwrap();
        loop {
            let mut line = String::new();
            assert!(
                out.read_line(&mut line).unwrap() > 0,
                "server closed stdout"
            );
            let v: Value = serde_json::from_str(&line).unwrap();
            if v["id"] == json!(id) {
                return v;
            }
        }
    };
    rpc(
        1,
        "initialize",
        json!({"protocolVersion": "2025-06-18", "capabilities": {},
                                "clientInfo": {"name": "e2e", "version": "1"}}),
    );
    let tools = rpc(2, "tools/list", json!({}));
    let pay = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "request_payment")
        .expect("request_payment is listed")
        .clone();
    assert!(
        pay["description"]
            .as_str()
            .unwrap()
            .starts_with("Spends the user's money.")
    );
    assert_eq!(pay["annotations"]["destructiveHint"], true);
    assert_eq!(
        pay["inputSchema"]["required"],
        json!(["merchant", "amount", "currency", "reason"])
    );

    let call = |args: Value| json!({"name": "request_payment", "arguments": args});
    let r = rpc(
        3,
        "tools/call",
        call(json!({
            "merchant": "shop.example.com", "amount": "499.00", "currency": "NOK",
            "reason": "Buy the 2 m USB-C cable you asked for", "model": "claude-opus-5-5"
        })),
    );
    let v: Value =
        serde_json::from_str(r["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(v["decision"], "approved", "{v}");
    assert_eq!(v["card"]["last4"], "4242");
    assert_eq!(
        fake.seen().pop().unwrap().request.card.unwrap().mode,
        CardMode::Reveal
    );

    set_cards(&fake, true, false, Some("1000"));
    let r = rpc(
        4,
        "tools/call",
        call(json!({
            "merchant": "shop.example.com", "amount": 499, "currency": "NOK", "reason": "Buy the cable"
        })),
    );
    let v: Value =
        serde_json::from_str(r["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(
        (v["decision"].as_str(), v["error"].as_str()),
        (Some("denied"), Some("reveal_off"))
    );
    assert!(v.get("card").is_none());

    let r = rpc(
        5,
        "tools/call",
        call(json!({"merchant": "shop.example.com", "reason": "Buy"})),
    );
    assert_eq!(r["result"]["isError"], true, "{r}");
    drop(stdin);
    let _ = child.wait();
}

#[test]
fn accounts_list_cards_without_numbers() {
    let (fake, addr) = fake_relay::start(1);
    let cli = Cli::new(addr);
    cli.pair("terminal");
    let out = cli.run(&["accounts"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("Card  Test Visa  visa \u{b7}\u{b7}\u{b7}\u{b7}4242"),
        "{}",
        stdout(&out)
    );
    set_cards(&fake, false, false, None);
    let out = cli.run(&["accounts", "--json"]);
    let v: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert!(v.get("cards").is_none());
    assert!(!stdout(&out).contains(fake_relay::cards::CARD_NUMBER));
}
