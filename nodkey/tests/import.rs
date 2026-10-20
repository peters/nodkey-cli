//! End to end: moving in. `nodkey import` and the MCP tool `import_file` send an invented Chrome
//! export to the fake phone's import window, print only counts, and delete the file after the
//! phone staged it; without an open window the phone refuses with `import_closed`.

mod common;

use nodkey_fake_relay as fake_relay;

use std::{
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use fake_relay::imports::{OpenWindow, StagedFile, Window};
use nodkey_proto::{
    Kind, import,
    vectors::import::{CHROME_CSV, SAMPLES},
};
use serde_json::{Value, json};

/// Every password in the samples starts like this; no output may hold it.
const SECRET_MARK: &str = "test-password";

struct Cli {
    relay: std::net::SocketAddr,
    dir: PathBuf,
    files: PathBuf,
}

impl Cli {
    fn new(relay: std::net::SocketAddr) -> Self {
        let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("nodkey-import-{}", nodkey_proto::random_id()));
        let files = root.join("Downloads");
        std::fs::create_dir_all(&files).unwrap();
        Cli {
            relay,
            dir: root.join("agent"),
            files,
        }
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nodkey"));
        c.args(args)
            .env("NODKEY_AGENT_DIR", &self.dir)
            .env("NODKEY_KEYSTORE", "file")
            .env("NODKEY_RELAY", format!("http://{}", self.relay))
            .env("NODKEY_REQUEST_TIMEOUT", "5")
            .env_remove("NODKEY_AGENT")
            .env_remove("CLAUDECODE")
            .env_remove("CODEX_SANDBOX")
            .env_remove("CODEX_SANDBOX_NETWORK_DISABLED")
            .env("TMPDIR", env!("CARGO_TARGET_TMPDIR"));
        c
    }

    /// A file in the scratch Downloads folder.
    fn export(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.files.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    /// `nodkey import FILE --json ...`: the result and the exit code. Neither stdout nor stderr
    /// holds a password from the file.
    fn import(&self, path: &Path, extra: &[&str]) -> (Value, i32) {
        let mut args = vec!["import", path.to_str().unwrap(), "--json"];
        args.extend_from_slice(extra);
        let out = common::output(&mut self.command(&args), &args);
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(!stdout.contains(SECRET_MARK) && !stderr.contains(SECRET_MARK));
        let v = serde_json::from_str(&stdout).unwrap_or_else(|_| panic!("{stdout}\n{stderr}"));
        (v, out.status.code().unwrap())
    }
}

impl Drop for Cli {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.dir.parent().unwrap());
    }
}

fn open_window(fake: &fake_relay::Fake, agent_id: Option<&str>) {
    *fake.import.lock().unwrap() = Some(Window::open(OpenWindow {
        agent_id: agent_id.map(str::to_owned),
        seconds: None,
    }));
}

fn imports_seen(fake: &fake_relay::Fake) -> usize {
    fake.seen()
        .iter()
        .filter(|s| s.request.kind == Kind::Import)
        .count()
}

#[test]
fn import_a_chrome_export() {
    let (fake, addr) = fake_relay::start(1);
    let cli = Cli::new(addr);
    let out = common::output(&mut cli.command(&["pair"]), &["pair"]);
    assert!(out.status.success(), "{out:?}");
    let path = cli.export("Chrome Passwords.csv", CHROME_CSV);

    // A dry run reads the file and sends nothing.
    let (v, code) = cli.import(&path, &["--dry-run"]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(
        (v["sent"].as_bool(), v["dry_run"].as_bool()),
        (Some(false), Some(true))
    );
    assert_eq!(
        v["detected"],
        json!({"format": "chrome_csv", "found": 2, "logins": 2, "codes": 0, "skipped": 1})
    );
    assert!(path.exists() && v["deleted"] == false);
    assert_eq!(imports_seen(&fake), 0);

    // Without an open window the phone refuses, and the file stays.
    let (v, code) = cli.import(&path, &[]);
    assert_eq!(
        (code, v["error"].as_str()),
        (11, Some("import_closed")),
        "{v}"
    );
    assert!(v["message"].as_str().unwrap().contains("Settings"));
    assert!(path.exists() && v["still_at"].is_string());

    // A window for another agent is not this agent's.
    open_window(&fake, Some(&nodkey_proto::random_id()));
    let (v, code) = cli.import(&path, &[]);
    assert_eq!(
        (code, v["error"].as_str()),
        (11, Some("import_closed")),
        "{v}"
    );

    // With a window: staged, counts only, and the export is gone.
    open_window(&fake, None);
    let (v, code) = cli.import(&path, &["--source", "Chrome, profile Default"]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["decision"], "staged");
    let counts = &v["import"];
    assert_eq!(
        (
            &counts["found"],
            &counts["new"],
            &counts["duplicates"],
            &counts["skipped"],
            &counts["files"]
        ),
        (&json!(2), &json!(2), &json!(0), &json!(1), &json!(1))
    );
    assert_eq!(v["deleted"], true);
    assert!(!path.exists());
    let seen = fake.seen();
    let sent = seen
        .iter()
        .rfind(|s| s.request.kind == Kind::Import)
        .unwrap();
    let info = sent.request.import.as_ref().unwrap();
    assert_eq!(info.file_name, "Chrome Passwords.csv");
    assert_eq!(info.source, "Chrome, profile Default");
    assert_eq!(
        info.format_hint,
        Some(nodkey_proto::ImportFormat::ChromeCsv)
    );
    assert_eq!(sent.announced, Some(true));
    assert_eq!(sent.attachment.as_deref(), Some(CHROME_CSV));
    assert!(sent.signed);

    // The same file again: duplicates of the first; with --keep it stays.
    let path = cli.export("Chrome Passwords.csv", CHROME_CSV);
    let (v, code) = cli.import(&path, &["--keep"]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(
        (&v["import"]["new"], &v["import"]["duplicates"]),
        (&json!(0), &json!(2))
    );
    assert!(path.exists() && v["deleted"] == false);
    let window = fake.import.lock().unwrap().clone().unwrap();
    assert_eq!(window.files.len(), 2);
    assert_eq!(window.files[0].source, "Chrome, profile Default");

    // Refused before sending: an encrypted export and one above 1 MiB.
    let before = imports_seen(&fake);
    let encrypted = SAMPLES
        .iter()
        .find(|s| s.name == "bitwarden_json_encrypted")
        .unwrap();
    let locked = cli.export("bitwarden.json", encrypted.bytes);
    let (v, code) = cli.import(&locked, &[]);
    assert_eq!(
        (code, v["error"].as_str()),
        (13, Some("import_unreadable")),
        "{v}"
    );
    assert!(
        v["message"]
            .as_str()
            .unwrap()
            .contains("without a password")
    );
    let big = cli.export("big.csv", &vec![b'a'; import::MAX_FILE + 1]);
    let (v, code) = cli.import(&big, &[]);
    assert_eq!((code, v["error"].as_str()), (14, Some("too_large")), "{v}");
    assert!(locked.exists() && big.exists());
    assert_eq!(imports_seen(&fake), before);

    // A full window, then a phone without a passcode.
    {
        let mut w = fake.import.lock().unwrap();
        let w = w.as_mut().unwrap();
        let first: StagedFile = w.files[0].clone();
        w.files.resize(import::WINDOW_FILES as usize, first);
    }
    let (v, code) = cli.import(&path, &[]);
    assert_eq!(
        (code, v["error"].as_str()),
        (12, Some("window_full")),
        "{v}"
    );
    *fake.passcode.lock().unwrap() = false;
    let (v, code) = cli.import(&path, &[]);
    assert_eq!(
        (code, v["error"].as_str()),
        (10, Some("no_passcode")),
        "{v}"
    );
    assert!(path.exists());
}

#[test]
fn import_over_mcp() {
    let (fake, addr) = fake_relay::start(1);
    let cli = Cli::new(addr);
    let out = common::output(&mut cli.command(&["pair", "--agent", "e2e"]), &["pair"]);
    assert!(out.status.success(), "{out:?}");
    let path = cli.export("passwords.csv", CHROME_CSV);

    let mut child = cli
        .command(&["mcp"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut id = 0;
    let mut rpc = |method: &str, params: Value| -> Value {
        id += 1;
        let msg = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        writeln!(stdin, "{msg}").unwrap();
        loop {
            let mut line = String::new();
            assert!(stdout.read_line(&mut line).unwrap() > 0);
            assert!(!line.contains(SECRET_MARK));
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
        .find(|t| t["name"] == "import_file")
        .unwrap()
        .clone();
    assert!(tool["description"].as_str().unwrap().contains("NEVER read"));
    assert_eq!(tool["inputSchema"]["required"], json!(["path"]));

    let mut call = |args: Value| -> Value {
        let r = rpc(
            "tools/call",
            json!({"name": "import_file", "arguments": args}),
        );
        serde_json::from_str(r["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
    };
    let file = path.to_str().unwrap();
    let v = call(json!({"path": file, "dry_run": true}));
    assert_eq!(
        (v["sent"].as_bool(), &v["detected"]["logins"]),
        (Some(false), &json!(2))
    );
    let v = call(json!({"path": file}));
    assert_eq!(v["error"], "import_closed", "{v}");
    assert!(path.exists());

    open_window(&fake, None);
    let v = call(
        json!({"path": file, "source": "Chrome", "reason": "Move the Chrome passwords into Nodkey"}),
    );
    assert_eq!(
        (v["decision"].as_str(), v["deleted"].as_bool()),
        (Some("staged"), Some(true)),
        "{v}"
    );
    assert_eq!(v["import"]["found"], 2);
    assert!(!path.exists());
    let seen = fake.seen();
    let sent = seen
        .iter()
        .rfind(|s| s.request.kind == Kind::Import)
        .unwrap();
    assert_eq!(sent.request.reason, "Move the Chrome passwords into Nodkey");
    drop(call);
    drop(rpc);
    let _ = child.kill();
    let _ = child.wait();
}
