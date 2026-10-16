//! MCP over stdio: newline-delimited JSON-RPC 2.0, protocol version 2025-06-18.
//!
//! Handles `initialize`, `ping`, `tools/list`, `tools/call`, `notifications/initialized` and
//! `notifications/cancelled`. Tool calls run concurrently, so a `ping` is answered while a request
//! waits for the user; progress notifications are sent when the client passes a `progressToken`.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use nodkey_proto::Kind;
use serde_json::{Map, Value, json};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt},
    sync::mpsc,
    task::{AbortHandle, JoinSet},
};
use zeroize::Zeroizing;

use crate::{
    agent::{Agent, Text},
    filter::cleanup_filter,
    profile::Profile,
    tools::{TOOL_NAMES, tools},
};

/// The protocol version this server implements.
pub const PROTOCOL_VERSION: &str = "2025-06-18";
/// Older versions whose tool features are identical for this server; echoed when asked for.
const COMPATIBLE: [&str; 3] = [PROTOCOL_VERSION, "2025-03-26", "2024-11-05"];

const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;

const INSTRUCTIONS: &str = "Nodkey keeps the user's one-time codes and passwords on their iPhone. These tools ask \
the phone for one code or one login at a time; the user approves or denies every request on their iPhone (or a \
lease they set answers for them), so a call can wait up to 2 minutes. Always pass a short, honest reason that \
explains what you are about to do. Use what you get only for that task and never store or repeat secrets. \
cleanup_logins proposes moving old saved logins to Recently deleted; the user sees the list and confirms, and \
nothing is deleted for good. request_payment spends the user's money: use it only for a purchase the user asked \
for, with the exact amount, and never split a purchase to get under their limit. If no phone is paired, use the \
pair tool first.";

/// Shared server state.
pub struct Server {
    agent: Agent,
    out: mpsc::UnboundedSender<Zeroizing<String>>,
    /// True when no `--agent` was given: the profile follows the client from `initialize`.
    auto_profile: bool,
    running: Mutex<HashMap<String, AbortHandle>>,
}

/// Serves MCP on `input`/`output` until `input` ends, then lets running calls finish. With
/// `auto_profile`, the agent's profile follows the client that connects (Claude Code, Codex, ...).
pub async fn serve<R, W>(agent: Agent, auto_profile: bool, input: R, output: W)
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (tx, mut rx) = mpsc::unbounded_channel::<Zeroizing<String>>();
    let writer = tokio::spawn(async move {
        let mut output = output;
        while let Some(line) = rx.recv().await {
            if output.write_all(line.as_bytes()).await.is_err()
                || output.write_all(b"\n").await.is_err()
                || output.flush().await.is_err()
            {
                break;
            }
        }
    });
    let server = Arc::new(Server {
        agent,
        out: tx,
        auto_profile,
        running: Mutex::new(HashMap::new()),
    });

    let mut tasks = JoinSet::new();
    let mut lines = input.lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let line = Zeroizing::new(line);
        if line.trim().is_empty() {
            continue;
        }
        server.handle_line(&line, &mut tasks);
        // Reap finished calls so the set does not grow.
        while tasks.try_join_next().is_some() {}
    }
    while tasks.join_next().await.is_some() {}
    drop(server);
    let _ = writer.await;
}

fn response(id: &Value, result: Value) -> Zeroizing<String> {
    Zeroizing::new(json!({"jsonrpc": "2.0", "id": id, "result": result}).to_string())
}

fn error(id: &Value, code: i64, message: &str) -> Zeroizing<String> {
    Zeroizing::new(
        json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
            .to_string(),
    )
}

/// A tool result as text content.
fn tool_result(id: &Value, text: &str, is_error: bool) -> Zeroizing<String> {
    // Built by hand so the secret-bearing text is copied once into a wiped buffer.
    let mut s = Zeroizing::new(String::with_capacity(text.len() + 128));
    s.push_str(r#"{"jsonrpc":"2.0","id":"#);
    s.push_str(&id.to_string());
    s.push_str(r#","result":{"content":[{"type":"text","text":""#);
    escape_into(text, &mut s);
    s.push('"');
    s.push_str(r#"}],"isError":"#);
    s.push_str(if is_error { "true" } else { "false" });
    s.push_str("}}");
    s
}

/// JSON string escaping without an intermediate allocation.
fn escape_into(text: &str, out: &mut String) {
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
}

impl Server {
    fn send(&self, msg: Zeroizing<String>) {
        let _ = self.out.send(msg);
    }

    fn handle_line(self: &Arc<Self>, line: &str, tasks: &mut JoinSet<()>) {
        let msg: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => return self.send(error(&Value::Null, PARSE_ERROR, "Parse error")),
        };
        let Value::Object(mut obj) = msg else {
            return self.send(error(
                &Value::Null,
                INVALID_REQUEST,
                "Expected a JSON-RPC object (batches are not supported)",
            ));
        };
        let id = obj.remove("id");
        let Some(method) = obj.get("method").and_then(Value::as_str).map(str::to_owned) else {
            // A response to something we never sent, or garbage: ignore responses, reject the rest.
            if id.is_some() && !obj.contains_key("result") && !obj.contains_key("error") {
                self.send(error(
                    id.as_ref().unwrap_or(&Value::Null),
                    INVALID_REQUEST,
                    "Missing method",
                ));
            }
            return;
        };
        if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            if let Some(id) = &id {
                self.send(error(id, INVALID_REQUEST, "jsonrpc must be \"2.0\""));
            }
            return;
        }
        let params = match obj.remove("params") {
            Some(Value::Object(p)) => p,
            None | Some(Value::Null) => Map::new(),
            Some(_) => {
                if let Some(id) = &id {
                    self.send(error(id, INVALID_PARAMS, "params must be an object"));
                }
                return;
            }
        };

        let Some(id) = id else {
            return self.notification(&method, &params);
        };
        match method.as_str() {
            "initialize" => self.send(response(&id, self.initialize(&params))),
            "ping" => self.send(response(&id, json!({}))),
            "tools/list" => self.send(response(&id, json!({ "tools": tools() }))),
            "tools/call" => {
                let Some(name) = params
                    .get("name")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                else {
                    return self.send(error(&id, INVALID_PARAMS, "tools/call needs a tool name"));
                };
                if !TOOL_NAMES.contains(&name.as_str()) {
                    return self.send(error(&id, INVALID_PARAMS, &format!("Unknown tool: {name}")));
                }
                let args = match params.get("arguments") {
                    Some(Value::Object(a)) => a.clone(),
                    None | Some(Value::Null) => Map::new(),
                    Some(_) => {
                        return self.send(error(
                            &id,
                            INVALID_PARAMS,
                            "arguments must be an object",
                        ));
                    }
                };
                let token = params
                    .get("_meta")
                    .and_then(|m| m.get("progressToken"))
                    .cloned();
                let key = id.to_string();
                let server = Arc::clone(self);
                let task_key = key.clone();
                let handle = tasks.spawn(async move {
                    let (text, is_error) = match server.call(&name, &args, token).await {
                        Ok(t) => (t, false),
                        Err(e) => (Zeroizing::new(json!({ "error": e }).to_string()), true),
                    };
                    server.running.lock().expect("lock").remove(&task_key);
                    server.send(tool_result(&id, &text, is_error));
                });
                self.running.lock().expect("lock").insert(key, handle);
            }
            _ => self.send(error(
                &id,
                METHOD_NOT_FOUND,
                &format!("Method not found: {method}"),
            )),
        }
    }

    fn notification(&self, method: &str, params: &Map<String, Value>) {
        if method == "notifications/cancelled"
            && let Some(id) = params.get("requestId")
            && let Some(handle) = self.running.lock().expect("lock").remove(&id.to_string())
        {
            handle.abort();
        }
        // notifications/initialized and anything else need no action.
    }

    fn initialize(&self, params: &Map<String, Value>) -> Value {
        if let Some(info) = params.get("clientInfo") {
            let field = |k: &str| {
                info.get(k)
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|n| !n.is_empty())
            };
            let name = field("title")
                .or_else(|| field("name"))
                .map(|n| n.chars().take(40).collect::<String>());
            let version = info
                .get("version")
                .and_then(Value::as_str)
                .map(|v| v.chars().take(40).collect::<String>());
            let mut client = self.agent.client.lock().expect("lock");
            client.app = name;
            client.app_version = version;
            if self.auto_profile
                && let Some(id) = field("name")
            {
                *self.agent.profile.lock().expect("lock") =
                    Profile::from_client(id, field("title"));
            }
        }
        let requested = params
            .get("protocolVersion")
            .and_then(Value::as_str)
            .unwrap_or(PROTOCOL_VERSION);
        let version = if COMPATIBLE.contains(&requested) {
            requested
        } else {
            PROTOCOL_VERSION
        };
        json!({
            "protocolVersion": version,
            "capabilities": { "tools": { "listChanged": false } },
            "serverInfo": { "name": "nodkey", "title": "Nodkey", "version": env!("CARGO_PKG_VERSION") },
            "instructions": INSTRUCTIONS,
        })
    }

    fn progress_fn(&self, token: Option<Value>) -> impl Fn(u64, u64, &str) + Send + Sync + use<> {
        let out = self.out.clone();
        move |done: u64, total: u64, message: &str| {
            if let Some(token) = &token {
                let n = json!({
                    "jsonrpc": "2.0",
                    "method": "notifications/progress",
                    "params": { "progressToken": token, "progress": done, "total": total, "message": message },
                });
                let _ = out.send(Zeroizing::new(n.to_string()));
            }
        }
    }

    async fn call(
        &self,
        name: &str,
        args: &Map<String, Value>,
        token: Option<Value>,
    ) -> Result<Text, String> {
        let progress = self.progress_fn(token);
        let a = &self.agent;
        match name {
            "pair" => match opt_str(args, "code")? {
                Some(code) => a.pair_finish(code, &progress).await,
                None => a.pair_start(opt_str(args, "name")?).await,
            },
            "list_phones" => a.list_phones(),
            "unpair" => a.unpair(req_str(args, "phone")?).await,
            "request_code" | "request_login" => {
                let kind = if name == "request_code" {
                    Kind::Code
                } else {
                    Kind::Login
                };
                a.request(
                    kind,
                    req_str(args, "target")?,
                    req_str(args, "reason")?,
                    opt_str(args, "image_path")?,
                    opt_str(args, "phone")?,
                    reported(args)?,
                    &progress,
                )
                .await
            }
            "request_credentials" => {
                let (wanted, follow_up, session) = crate::bundle::from_args(args)?;
                a.credentials(
                    wanted,
                    req_str(args, "reason")?,
                    follow_up,
                    session,
                    opt_str(args, "image_path")?,
                    opt_str(args, "phone")?,
                    reported(args)?,
                    &progress,
                )
                .await
            }
            "request_payment" => {
                let (merchant, amount) = crate::card::from_args(args)?;
                a.pay(
                    &merchant,
                    amount,
                    req_str(args, "reason")?,
                    opt_str(args, "image_path")?,
                    opt_str(args, "phone")?,
                    reported(args)?,
                    &progress,
                )
                .await
            }
            "cleanup_logins" => {
                let filter = cleanup_filter(args)?;
                a.cleanup(
                    filter,
                    req_str(args, "reason")?,
                    opt_str(args, "phone")?,
                    reported(args)?,
                    &progress,
                )
                .await
            }
            "cleanup_insights" => {
                let reason = opt_str(args, "reason")?
                    .unwrap_or("Suggest clean-up rules without seeing names");
                a.request(
                    Kind::Insights,
                    "",
                    reason,
                    None,
                    opt_str(args, "phone")?,
                    reported(args)?,
                    &progress,
                )
                .await
            }
            "end_session" => {
                a.end_session(opt_str(args, "reason")?, reported(args)?, &progress)
                    .await
            }
            "list_accounts" => {
                let reason = opt_str(args, "reason")?.unwrap_or("See which accounts I may ask for");
                a.request(
                    Kind::List,
                    "",
                    reason,
                    None,
                    opt_str(args, "phone")?,
                    reported(args)?,
                    &progress,
                )
                .await
            }
            _ => Err(format!("Unknown tool: {name}")),
        }
    }
}

/// The optional `model` and `effort` a tool call reports, for the phone's history.
fn reported(args: &Map<String, Value>) -> Result<crate::agent::Reported<'_>, String> {
    Ok(crate::agent::Reported {
        model: opt_str(args, "model")?,
        effort: opt_str(args, "effort")?,
    })
}

fn opt_str<'a>(args: &'a Map<String, Value>, key: &str) -> Result<Option<&'a str>, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.trim().is_empty() => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(format!("{key} must be a string")),
    }
}

fn req_str<'a>(args: &'a Map<String, Value>, key: &str) -> Result<&'a str, String> {
    opt_str(args, key)?.ok_or_else(|| format!("{key} is required"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{agent::Timing, store::Home};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    fn agent(dir: &std::path::Path) -> Agent {
        Agent {
            home: Ok(Home::at(dir)),
            profile: std::sync::Mutex::new(Profile::named("test").unwrap()),
            relay: crate::relay::Relay::new("http://127.0.0.1:9").map_err(|e| e.to_string()),
            timing: Timing::default(),
            client: std::sync::Mutex::new(Default::default()),
        }
    }

    async fn session(lines: &[&str]) -> Vec<Value> {
        let (client, server_io) = tokio::io::duplex(64 * 1024);
        let (server_read, server_write) = tokio::io::split(server_io);
        let dir = crate::test_dir("mcp");
        let srv = tokio::spawn(serve(
            agent(&dir),
            true,
            BufReader::new(server_read),
            server_write,
        ));
        let (client_read, mut client_write) = tokio::io::split(client);
        for l in lines {
            client_write.write_all(l.as_bytes()).await.unwrap();
            client_write.write_all(b"\n").await.unwrap();
        }
        client_write.shutdown().await.unwrap();
        drop(client_write);
        let mut out = Vec::new();
        let mut reader = BufReader::new(client_read).lines();
        while let Some(l) = reader.next_line().await.unwrap() {
            out.push(serde_json::from_str(&l).unwrap());
        }
        srv.await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        out
    }

    #[tokio::test]
    async fn handshake_list_and_errors() {
        let out = session(&[
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test-client","version":"1"}}}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
            r#"{"jsonrpc":"2.0","id":"p","method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":3,"method":"nope"}"#,
            r#"not json"#,
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"missing_tool"}}"#,
            r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"list_phones","arguments":{}}}"#,
            r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"request_code","arguments":{"target":"github.com"}}}"#,
            r#"[{"jsonrpc":"2.0","id":7,"method":"ping"}]"#,
        ])
        .await;
        let by_id = |id: Value| {
            out.iter()
                .find(|m| m["id"] == id)
                .unwrap_or_else(|| panic!("no reply to {id}"))
        };
        let init = &by_id(json!(1))["result"];
        assert_eq!(init["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(init["serverInfo"]["name"], "nodkey");
        assert!(init["capabilities"]["tools"].is_object());
        let tools = by_id(json!(2))["result"]["tools"]
            .as_array()
            .unwrap()
            .clone();
        let names: Vec<_> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(
            names,
            [
                "request_code",
                "request_login",
                "request_credentials",
                "end_session",
                "request_payment",
                "cleanup_insights",
                "list_accounts",
                "cleanup_logins",
                "pair",
                "list_phones",
                "unpair"
            ]
        );
        for t in &tools {
            assert_eq!(t["inputSchema"]["type"], "object");
        }
        assert!(
            tools[0]["description"]
                .as_str()
                .unwrap()
                .contains("The user approves")
        );
        assert!(
            tools[0]["description"]
                .as_str()
                .unwrap()
                .contains("explain the reason")
        );
        assert_eq!(by_id(json!("p"))["result"], json!({}));
        assert_eq!(by_id(json!(3))["error"]["code"], METHOD_NOT_FOUND);
        assert!(
            out.iter()
                .any(|m| m["error"]["code"] == PARSE_ERROR && m["id"].is_null())
        );
        assert_eq!(by_id(json!(4))["error"]["code"], INVALID_PARAMS);
        let phones = &by_id(json!(5))["result"];
        assert_eq!(phones["isError"], false);
        let text: Value =
            serde_json::from_str(phones["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(text["phones"], json!([]));
        let missing = &by_id(json!(6))["result"];
        assert_eq!(missing["isError"], true);
        assert!(
            missing["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("reason is required")
        );
        assert!(out.iter().any(|m| m["error"]["code"] == INVALID_REQUEST));
        // notifications get no reply: 10 lines, 9 replies.
        assert_eq!(out.len(), 9);
    }

    #[tokio::test]
    async fn older_protocol_versions_are_echoed() {
        let out = session(&[r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}"#]).await;
        assert_eq!(out[0]["result"]["protocolVersion"], "2025-03-26");
        let out = session(&[r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}"#]).await;
        assert_eq!(out[0]["result"]["protocolVersion"], PROTOCOL_VERSION);
    }

    #[test]
    fn tool_result_escaping() {
        let s = tool_result(&json!(7), "a\"b\\c\nd\u{1}é", true);
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["id"], 7);
        assert_eq!(v["result"]["content"][0]["type"], "text");
        assert_eq!(v["result"]["content"][0]["text"], "a\"b\\c\nd\u{1}é");
        assert_eq!(v["result"]["isError"], true);
    }
}
