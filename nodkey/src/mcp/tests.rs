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
            "request_sms_code",
            "request_secret",
            "save_secret",
            "suggest_sign_in_method",
            "end_session",
            "request_payment",
            "cleanup_insights",
            "list_accounts",
            "cleanup_logins",
            "import_file",
            "create_login",
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
    let text: Value = serde_json::from_str(phones["content"][0]["text"].as_str().unwrap()).unwrap();
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
