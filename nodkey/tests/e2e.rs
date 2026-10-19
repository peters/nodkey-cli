//! End to end: the real `nodkey mcp` over stdio against the in-process fake relay.

use nodkey_fake_relay as fake_relay;

use std::{
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    time::{Duration, Instant},
};

use fake_relay::Mode;
use serde_json::{Value, json};

struct Client {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
    notifications: Vec<Value>,
    dir: PathBuf,
}

impl Client {
    fn start(relay: std::net::SocketAddr, extra_env: &[(&str, &str)]) -> Self {
        // Under the target directory, never the system temp dir.
        let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("nodkey-e2e-{}", nodkey_proto::random_id()));
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_nodkey"));
        cmd.arg("mcp")
            .env_remove("NODKEY_AGENT")
            .env("NODKEY_AGENT_DIR", &dir)
            .env("NODKEY_KEYSTORE", "file")
            .env("NODKEY_RELAY", format!("http://{relay}"))
            .env("TMPDIR", env!("CARGO_TARGET_TMPDIR"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().expect("start nodkey mcp");
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let mut c = Client {
            child,
            stdin,
            stdout,
            next_id: 1,
            notifications: Vec::new(),
            dir,
        };
        let init = c.rpc(
            "initialize",
            json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "e2e", "version": "1"}}),
        );
        assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
        c.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
        c
    }

    /// The agent's own folder: the client says it is "e2e", so the profile is `e2e`.
    fn agent_dir(&self) -> PathBuf {
        self.dir.join("agents").join("e2e")
    }

    fn send(&mut self, v: &Value) {
        writeln!(self.stdin, "{v}").unwrap();
        self.stdin.flush().unwrap();
    }

    fn rpc(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        loop {
            let mut line = String::new();
            assert!(
                self.stdout.read_line(&mut line).unwrap() > 0,
                "server closed stdout"
            );
            let v: Value = serde_json::from_str(&line).expect("one JSON message per line");
            assert_eq!(v["jsonrpc"], "2.0");
            if v["id"] == json!(id) {
                return v;
            }
            assert!(v.get("method").is_some(), "unexpected message {v}");
            self.notifications.push(v);
        }
    }

    /// Calls a tool; returns (parsed JSON text, isError).
    fn tool(&mut self, name: &str, args: Value) -> (Value, bool) {
        self.tool_with_meta(name, args, None)
    }

    fn tool_with_meta(&mut self, name: &str, args: Value, token: Option<&str>) -> (Value, bool) {
        let mut params = json!({"name": name, "arguments": args});
        if let Some(t) = token {
            params["_meta"] = json!({"progressToken": t});
        }
        let r = self.rpc("tools/call", params);
        let result = &r["result"];
        assert_eq!(result["content"][0]["type"], "text", "{r}");
        let text = result["content"][0]["text"].as_str().unwrap();
        (
            serde_json::from_str(text).expect("tool text is JSON"),
            result["isError"].as_bool().unwrap(),
        )
    }

    fn pair(&mut self, fake: &fake_relay::Fake) -> Value {
        let (start, err) = self.tool("pair", json!({"name": "E2E agent"}));
        assert!(!err, "{start}");
        let code = start["code"].as_str().unwrap().to_owned();
        assert_eq!(code, "K7P-2QX");
        assert_eq!(start["agent_name"], "E2E agent");
        let (done, err) = self.tool("pair", json!({"code": code.to_lowercase()}));
        assert!(!err, "{done}");
        let identity: Value =
            serde_json::from_slice(&std::fs::read(self.agent_dir().join("identity.json")).unwrap())
                .unwrap();
        let agent_id = identity["agent_id"].as_str().unwrap();
        assert_eq!(done["check"], fake.check_for(agent_id));
        assert_eq!(done["phone"], fake_relay::PHONE_NAME);
        assert_eq!(done["phone_id"], fake.phone_id.as_str());
        assert!(
            fake.lookups() >= 1,
            "the phone looks up the agent's keys before it claims"
        );
        done
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn pair_request_answer_with_attachment() {
    // The phone claims on the second poll, so the agent sees one 204 first.
    let (fake, addr) = fake_relay::start(2);
    let mut c = Client::start(addr, &[]);

    // Not paired yet.
    let (e, err) = c.tool(
        "request_code",
        json!({"target": "github.com", "reason": "Merge PR #42"}),
    );
    assert!(err);
    assert!(e["error"].as_str().unwrap().contains("pair"), "{e}");

    c.pair(&fake);
    let (phones, err) = c.tool("list_phones", json!({}));
    assert!(!err);
    assert_eq!(phones["phones"].as_array().unwrap().len(), 1);
    assert_eq!(phones["phones"][0]["name"], fake_relay::PHONE_NAME);

    // A code.
    let (r, err) = c.tool(
        "request_code",
        json!({"target": "github.com/alex", "reason": "Merge PR #42", "model": "claude-opus-5-5", "effort": "high"}),
    );
    assert!(!err, "{r}");
    assert_eq!(r["decision"], "approved");
    assert_eq!(r["code"], fake_relay::CODE);
    assert_eq!(r["seconds_left"], 17);
    assert_eq!(r["account"]["issuer"], "GitHub");

    // A login with a screenshot.
    let shot = c.dir.join("login.png");
    std::fs::write(&shot, nodkey_proto::vectors::PNG).unwrap();
    let (r, err) = c.tool(
        "request_login",
        json!({"target": "vg.no", "reason": "Sign in to read the article", "image_path": shot.to_str().unwrap()}),
    );
    assert!(!err, "{r}");
    assert_eq!(r["decision"], "approved");
    assert_eq!(r["username"], fake_relay::USERNAME);
    assert_eq!(r["password"], fake_relay::PASSWORD);
    assert!(r.get("attachment_warning").is_none(), "{r}");

    // The account list.
    let (r, err) = c.tool("list_accounts", json!({}));
    assert!(!err, "{r}");
    assert_eq!(r["accounts"][0]["issuer"], "GitHub");

    // Clean-up insights: counts and anonymous groups, passed on with how to use them.
    let (r, err) = c.tool("cleanup_insights", json!({"reason": "Suggest rules"}));
    assert!(!err, "{r}");
    assert_eq!(r["decision"], "approved");
    assert_eq!(r["insights"]["total"], 712);
    assert_eq!(r["insights"]["sites"][0]["group"], "d_3fa9c21b07e4");
    assert!(r["message"].as_str().unwrap().contains("cleanup_logins"));
    assert!(r.get("accounts").is_none());

    // What the phone saw.
    let seen = fake.seen();
    assert_eq!(seen.len(), 4);
    assert_eq!(seen[3].request.kind, nodkey_proto::Kind::Insights);
    assert_eq!(seen[0].request.kind, nodkey_proto::Kind::Code);
    assert_eq!(seen[0].request.target, "github.com/alex");
    assert_eq!(seen[0].request.reason, "Merge PR #42");
    let client = seen[0].request.client.clone().expect("who is asking");
    assert_eq!(client.app.as_deref(), Some("e2e"));
    assert_eq!(client.app_version.as_deref(), Some("1"));
    assert_eq!(client.model.as_deref(), Some("claude-opus-5-5"));
    assert_eq!(client.effort.as_deref(), Some("high"));
    assert_eq!(
        client.mcp_version.as_deref(),
        Some(env!("CARGO_PKG_VERSION"))
    );
    assert!(client.os.is_some());
    assert!(
        seen[1].request.client.as_ref().unwrap().model.is_none(),
        "model only when reported"
    );
    assert_eq!(seen[0].request.agent, "E2E agent");
    assert!(seen[0].attachment.is_none());
    assert_eq!(seen[0].announced, None);
    assert_eq!(seen[1].announced, Some(true));
    let att = seen[1]
        .request
        .attachment
        .as_ref()
        .expect("attachment described");
    assert_eq!(att.kind, nodkey_proto::ImageType::Png);
    assert_eq!(att.bytes, 76);
    assert_eq!(att.caption.as_deref(), Some("login.png"));
    assert_eq!(
        seen[1].attachment.as_deref(),
        Some(&nodkey_proto::vectors::PNG[..])
    );
    assert_eq!(seen[2].request.kind, nodkey_proto::Kind::List);

    // Nothing from the phone was written to disk.
    for entry in std::fs::read_dir(c.agent_dir()).unwrap() {
        let path = entry.unwrap().path();
        let bytes = std::fs::read(&path).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            !text.contains(fake_relay::PASSWORD) && !text.contains(fake_relay::CODE),
            "{}",
            path.display()
        );
        #[cfg(unix)]
        if path.extension().is_some_and(|e| e == "json") {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    // Unpair tells the relay, then forgets the phone locally.
    let (r, err) = c.tool("unpair", json!({"phone": fake_relay::PHONE_NAME}));
    assert!(!err, "{r}");
    assert!(r.get("relay_warning").is_none(), "{r}");
    let identity: Value =
        serde_json::from_slice(&std::fs::read(c.agent_dir().join("identity.json")).unwrap())
            .unwrap();
    assert_eq!(fake.left(), [identity["agent_id"].as_str().unwrap()]);
    let (phones, _) = c.tool("list_phones", json!({}));
    assert_eq!(phones["phones"], json!([]));
    let (_, err) = c.tool(
        "request_code",
        json!({"target": "github.com", "reason": "x"}),
    );
    assert!(err);
}

#[test]
fn denied_request() {
    let (fake, addr) = fake_relay::start(1);
    let mut c = Client::start(addr, &[]);
    c.pair(&fake);
    fake.set_mode(Mode::Deny);
    let (r, err) = c.tool(
        "request_login",
        json!({"target": "vg.no", "reason": "Read the article"}),
    );
    assert!(!err, "{r}");
    assert_eq!(r["decision"], "denied");
    assert!(r.get("password").is_none() && r.get("username").is_none());
    assert!(r["message"].as_str().unwrap().contains("denied"));
}

#[test]
fn unanswered_request_times_out_with_progress() {
    let (fake, addr) = fake_relay::start(1);
    let mut c = Client::start(addr, &[("NODKEY_REQUEST_TIMEOUT", "2")]);
    c.pair(&fake);
    fake.set_mode(Mode::Silent);
    let t = Instant::now();
    let (r, err) = c.tool_with_meta(
        "request_code",
        json!({"target": "github.com", "reason": "Merge"}),
        Some("tok-1"),
    );
    assert!(!err, "{r}");
    assert_eq!(r["decision"], "expired");
    assert!(r.get("code").is_none());
    assert!(
        t.elapsed() < Duration::from_secs(15),
        "took {:?}",
        t.elapsed()
    );
    assert!(
        c.notifications
            .iter()
            .any(|n| n["method"] == "notifications/progress"
                && n["params"]["progressToken"] == "tok-1"),
        "{:?}",
        c.notifications
    );
}

#[test]
fn oversized_and_wrong_images_are_rejected_before_sending() {
    let (fake, addr) = fake_relay::start(1);
    let mut c = Client::start(addr, &[]);
    c.pair(&fake);
    let big = c.dir.join("big.jpg");
    let mut data = vec![0xff, 0xd8, 0xff, 0xe0];
    data.resize(1024 * 1024 + 1, 0);
    std::fs::write(&big, &data).unwrap();
    let (r, err) = c.tool(
        "request_code",
        json!({"target": "github.com", "reason": "Merge", "image_path": big.to_str().unwrap()}),
    );
    assert!(err);
    assert!(r["error"].as_str().unwrap().contains("1 MiB"), "{r}");
    let txt = c.dir.join("note.txt");
    std::fs::write(&txt, b"hello").unwrap();
    let (r, err) = c.tool(
        "request_code",
        json!({"target": "github.com", "reason": "Merge", "image_path": txt.to_str().unwrap()}),
    );
    assert!(err);
    assert!(
        r["error"].as_str().unwrap().contains("PNG, JPEG or GIF"),
        "{r}"
    );
    assert!(fake.seen().is_empty(), "nothing reached the phone");
}

#[test]
fn stdio_framing_handshake_and_tools_list() {
    let (_fake, addr) = fake_relay::start(1);
    let mut c = Client::start(addr, &[]);
    let r = c.rpc("ping", json!({}));
    assert_eq!(r["result"], json!({}));
    let r = c.rpc("tools/list", json!({}));
    let tools = r["result"]["tools"].as_array().unwrap();
    let names: Vec<_> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    for want in [
        "pair",
        "list_phones",
        "unpair",
        "request_code",
        "request_login",
        "list_accounts",
    ] {
        assert!(names.contains(&want), "{want} missing");
    }
    for t in tools
        .iter()
        .filter(|t| t["name"].as_str().unwrap().starts_with("request_"))
    {
        let d = t["description"].as_str().unwrap();
        assert!(
            d.contains("The user approves") && d.contains("reason"),
            "{d}"
        );
        assert!(t["inputSchema"]["properties"]["image_path"].is_object());
    }
    let r = c.rpc("tools/call", json!({"name": "nope", "arguments": {}}));
    assert_eq!(r["error"]["code"], -32602);
}

#[test]
fn request_gone_at_the_relay_is_expired() {
    let (fake, addr) = fake_relay::start(1);
    let mut c = Client::start(addr, &[]);
    c.pair(&fake);
    fake.set_mode(Mode::Gone);
    let (r, err) = c.tool(
        "request_code",
        json!({"target": "github.com", "reason": "Merge"}),
    );
    assert!(!err, "{r}");
    assert_eq!(r["decision"], "expired");
}

#[test]
fn unreachable_relay_is_a_tool_error() {
    // Nothing listens on port 9 (discard) on loopback in the test environment.
    let addr: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
    let mut c = Client::start(addr, &[]);
    let (r, err) = c.tool("pair", json!({}));
    assert!(err);
    assert!(r["error"].as_str().unwrap().contains("relay"), "{r}");
    // The identity was still made, named after the client.
    let identity: Value =
        serde_json::from_slice(&std::fs::read(c.agent_dir().join("identity.json")).unwrap())
            .unwrap();
    assert!(
        identity["name"].as_str().unwrap().starts_with("e2e @ "),
        "{identity}"
    );
}

#[test]
fn attachment_too_large_at_the_relay_still_sends_the_request() {
    let (fake, addr) = fake_relay::start(1);
    *fake.attachment_limit.lock().unwrap() = 64;
    let mut c = Client::start(addr, &[]);
    c.pair(&fake);
    let shot = c.dir.join("login.png");
    std::fs::write(&shot, nodkey_proto::vectors::PNG).unwrap();
    let (r, err) = c.tool(
        "request_code",
        json!({"target": "github.com", "reason": "Merge", "image_path": shot.to_str().unwrap()}),
    );
    assert!(!err, "{r}");
    assert_eq!(r["decision"], "approved");
    assert!(
        r["attachment_warning"]
            .as_str()
            .unwrap()
            .contains("too large"),
        "{r}"
    );
    let seen = fake.seen();
    assert_eq!(seen[0].announced, Some(true));
    assert!(seen[0].attachment.is_none());
}

#[test]
fn cleanup_logins_moves_the_matches_and_refuses_an_empty_filter() {
    let (fake, addr) = fake_relay::start(1);
    let mut c = Client::start(addr, &[]);
    c.pair(&fake);

    // An empty filter never leaves this computer.
    for filter in [json!({}), json!({"ip_only": false, "username": "  "})] {
        let (r, err) = c.tool(
            "cleanup_logins",
            json!({"filter": filter, "reason": "Tidy up"}),
        );
        assert!(err, "{r}");
        assert!(
            r["error"]
                .as_str()
                .unwrap()
                .contains("at least one criterion"),
            "{r}"
        );
    }
    let (r, err) = c.tool("cleanup_logins", json!({"filter": {"ip_only": true}}));
    assert!(
        err && r["error"].as_str().unwrap().contains("reason"),
        "{r}"
    );
    assert!(fake.seen().is_empty(), "nothing reached the phone");

    // Site is an IP address: the router, the printer and the NAS.
    let (r, err) = c.tool(
        "cleanup_logins",
        json!({"filter": {"ip_only": true}, "reason": "Remove logins for old router addresses"}),
    );
    assert!(!err, "{r}");
    assert_eq!(r["decision"], "approved");
    assert_eq!(r["moved"], 3);
    let titles: Vec<_> = r["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["title"].as_str().unwrap())
        .collect();
    assert_eq!(titles, ["Router", "Printer", "NAS"]);
    assert_eq!(r["accounts"][0]["name"], "admin");
    assert_eq!(r["accounts"][0]["site"], "192.168.1.1");
    assert!(
        r.get("password").is_none() && r.get("lease").is_none(),
        "{r}"
    );
    assert!(r["message"].as_str().unwrap().contains("Recently deleted"));

    // One old user name, with a date as text.
    let (r, err) = c.tool(
        "cleanup_logins",
        json!({"filter": {"username": "alex@old-company.example", "last_used_before": "2025-01-01"},
               "reason": "The user left the old company"}),
    );
    assert!(!err, "{r}");
    assert_eq!(r["moved"], 1);
    assert_eq!(r["accounts"][0]["site"], "mail.old-company.example");

    // Nothing matches: approved, nothing moved.
    let (r, err) = c.tool(
        "cleanup_logins",
        json!({"filter": {"username": "nobody@example.com"}, "reason": "Tidy up"}),
    );
    assert!(!err, "{r}");
    assert_eq!(r["decision"], "approved");
    assert_eq!(r["moved"], 0);

    // What the phone saw: kind cleanup, no target, the filter as given.
    let seen = fake.seen();
    assert_eq!(seen.len(), 3);
    assert!(
        seen.iter()
            .all(|s| s.request.kind == nodkey_proto::Kind::Cleanup)
    );
    assert_eq!(seen[0].request.target, "");
    assert_eq!(
        seen[0].request.reason,
        "Remove logins for old router addresses"
    );
    let f = seen[0].request.filter.as_ref().unwrap();
    assert_eq!(f.ip_only, Some(true));
    assert!(f.username.is_none() && f.last_used_before.is_none());
    let f = seen[1].request.filter.as_ref().unwrap();
    assert_eq!(f.username.as_deref(), Some("alex@old-company.example"));
    assert_eq!(f.last_used_before, Some(1_735_689_600));

    // The user says no: nothing moved.
    fake.set_mode(Mode::Deny);
    let (r, err) = c.tool(
        "cleanup_logins",
        json!({"filter": {"domain": "old-company.example"}, "reason": "Tidy up"}),
    );
    assert!(!err, "{r}");
    assert_eq!(r["decision"], "denied");
    assert!(
        r.get("moved").is_none() && r.get("accounts").is_none(),
        "{r}"
    );
    assert!(r["message"].as_str().unwrap().contains("Nothing was moved"));
}

#[test]
fn request_credentials_answers_item_by_item() {
    let (fake, addr) = fake_relay::start(1);
    let mut c = Client::start(addr, &[]);
    c.pair(&fake);
    let items = json!([
        {"kind": "login", "target": "chatgpt.com"},
        {"kind": "code", "target": "github.com/alex"},
        {"kind": "code", "target": "deny.example"}
    ]);
    let (r, err) = c.tool(
        "request_credentials",
        json!({"items": items, "reason": "Sign in to ChatGPT and GitHub", "follow_up_seconds": 300}),
    );
    assert!(!err, "{r}");
    assert_eq!(r["decision"], "approved");
    assert_eq!(
        (r["approved"].as_u64(), r["of"].as_u64()),
        (Some(2), Some(3))
    );
    assert_eq!(r["items"][0]["target"], "chatgpt.com");
    assert_eq!(r["items"][0]["password"], fake_relay::PASSWORD);
    assert_eq!(r["items"][1]["code"], fake_relay::CODE);
    assert_eq!(r["items"][2]["decision"], "denied");
    assert!(r["items"][2].get("code").is_none());
    let seen = fake.seen();
    let bundle = seen[0]
        .request
        .bundle
        .clone()
        .expect("the items reached the phone");
    assert_eq!(seen[0].request.kind, nodkey_proto::Kind::Bundle);
    assert_eq!(seen[0].request.target, "");
    assert_eq!(bundle.follow_up, Some(300));
    assert_eq!(
        bundle
            .items
            .iter()
            .map(|i| i.id.as_str())
            .collect::<Vec<_>>(),
        ["1", "2", "3"]
    );
}
