//! End to end: keys by project. A `.nodkey` file in a repository (found from a folder below it),
//! `nodkey run -- <command>` asking for its keys in one request in its project, `--project` and
//! `--secret`, `global/NAME`, a task plan in a project, `nodkey secret save` for the file's project
//! and the `request_secret`, `save_secret` and `list_accounts` MCP tools, against the in-process
//! fake relay. Test values only.

use nodkey_fake_relay as fake_relay;

use std::{
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

use fake_relay::{Mode, secrets::FakeKey};
use nodkey_proto::Kind;
use serde_json::{Value, json};

const SPARROW_OPENAI: &str = "sk-test-sparrow-0000";
const GLOBAL_OPENAI: &str = "sk-test-global-0000";
const SPARROW_ADMIN: &str = "adm-test-2222";
const GLOBAL_GITHUB: &str = "ghp-test-3333";
const OTTER_OPENAI: &str = "sk-test-otter-0000";

struct Cli {
    relay: std::net::SocketAddr,
    dir: PathBuf,
}

impl Cli {
    fn new(relay: std::net::SocketAddr) -> Self {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("nodkey-projects-{}", nodkey_proto::random_id()));
        std::fs::create_dir_all(&dir).unwrap();
        Cli { relay, dir }
    }

    /// A repository with a `.nodkey` file and a folder two levels below it.
    fn repo(&self, file: &str) -> PathBuf {
        let repo = self.dir.join("repo");
        std::fs::create_dir_all(repo.join("src/bin")).unwrap();
        std::fs::write(repo.join(".nodkey"), file).unwrap();
        repo.join("src/bin")
    }

    fn command(&self, args: &[&str], cwd: &Path) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nodkey"));
        c.args(args)
            .current_dir(cwd)
            .env("NODKEY_AGENT_DIR", self.dir.join("agent"))
            .env("NODKEY_KEYSTORE", "file")
            .env("NODKEY_RELAY", format!("http://{}", self.relay))
            .env("NODKEY_REQUEST_TIMEOUT", "3")
            .env_remove("NODKEY_AGENT")
            .env("TMPDIR", env!("CARGO_TARGET_TMPDIR"));
        for name in ["OPENAI_API_KEY", "ADMIN_TOKEN", "GITHUB_TOKEN"] {
            c.env_remove(name);
        }
        c
    }

    fn run(&self, args: &[&str], cwd: &Path) -> Output {
        self.command(args, cwd).output().expect("run nodkey")
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

/// A child command that prints the variables `names`, joined by `|`.
fn printer(names: &[&str]) -> Vec<String> {
    if cfg!(windows) {
        let shown: Vec<String> = names.iter().map(|n| format!("$env:{n}")).collect();
        vec![
            "powershell".into(),
            "-NoProfile".into(),
            "-Command".into(),
            format!("Write-Output ({})", shown.join(" + '|' + ")),
        ]
    } else {
        let shown: Vec<String> = names.iter().map(|n| format!("${n}")).collect();
        vec![
            "sh".into(),
            "-c".into(),
            format!("printf '%s\\n' \"{}\"", shown.join("|")),
        ]
    }
}

fn with<'a>(head: &[&'a str], child: &'a [String]) -> Vec<&'a str> {
    let mut args = head.to_vec();
    args.push("--");
    args.extend(child.iter().map(String::as_str));
    args
}

fn key(variable: &str, value: &str, projects: &[&str]) -> FakeKey {
    FakeKey {
        title: variable.into(),
        service: None,
        variable: Some(variable.into()),
        value: value.into(),
        projects: projects.iter().map(|p| p.to_string()).collect(),
    }
}

fn keys() -> Vec<FakeKey> {
    vec![
        key("OPENAI_API_KEY", SPARROW_OPENAI, &["Sparrow"]),
        key("OPENAI_API_KEY", OTTER_OPENAI, &["Otter"]),
        key("OPENAI_API_KEY", GLOBAL_OPENAI, &[]),
        key("ADMIN_TOKEN", SPARROW_ADMIN, &["Sparrow"]),
        key("GITHUB_TOKEN", GLOBAL_GITHUB, &[]),
    ]
}

const FILE: &str = "# Keys for the tests (names only)\n\
                    project = \"sparrow\"\n\
                    secrets = [\n  \"OPENAI_API_KEY\",\n  \"ADMIN_TOKEN\",\n  \"GITHUB_TOKEN\",\n]\n";

#[test]
fn run_asks_for_the_keys_of_the_nodkey_file() {
    let (fake, addr) = fake_relay::start(1);
    *fake.secrets.lock().unwrap() = keys();
    let cli = Cli::new(addr);
    let below = cli.repo(FILE);
    assert!(cli.run(&["pair"], &cli.dir).status.success());
    let names = ["OPENAI_API_KEY", "ADMIN_TOKEN", "GITHUB_TOKEN"];
    let child = printer(&names);

    // Every key of the file in one bundle with the project; the project's key, else the global.
    let out = cli.run(&with(&["run"], &child), &below);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(
        stdout(&out).trim(),
        format!("{SPARROW_OPENAI}|{SPARROW_ADMIN}|{GLOBAL_GITHUB}")
    );
    let err = stderr(&out);
    assert!(
        err.contains(
            "OPENAI_API_KEY from Sparrow, ADMIN_TOKEN from Sparrow, GITHUB_TOKEN (global)"
        ),
        "{err}"
    );
    assert!(!err.contains(SPARROW_OPENAI));
    let seen = fake.seen().pop().unwrap().request;
    assert_eq!(seen.kind, Kind::Bundle);
    assert_eq!(seen.project.as_deref(), Some("sparrow"));
    assert!(seen.reason.starts_with("Run "), "{}", seen.reason);
    // Which file named the keys: on stderr, and in the reason the phone shows.
    assert!(
        err.contains("nodkey: using ") && err.contains("repo/.nodkey: OPENAI_API_KEY"),
        "{err}"
    );
    assert!(seen.reason.ends_with("repo/.nodkey)"), "{}", seen.reason);
    assert!(seen.reason.contains(" (keys named in "), "{}", seen.reason);
    let targets: Vec<String> = seen
        .bundle
        .unwrap()
        .items
        .into_iter()
        .map(|i| i.target)
        .collect();
    assert_eq!(targets, names);

    // --project asks in another project; a key it lacks is not given.
    let out = cli.run(&with(&["run", "--project", "Otter"], &child), &below);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(stdout(&out).is_empty(), "the command did not run");
    assert!(stderr(&out).contains("ADMIN_TOKEN: "), "{}", stderr(&out));

    // --secret adds a key; global/NAME takes only the global key; one key is one request.
    let one = printer(&["OPENAI_API_KEY"]);
    std::fs::write(cli.dir.join("repo/.nodkey"), "project = \"sparrow\"\n").unwrap();
    let out = cli.run(
        &with(&["run", "--secret", "global/OPENAI_API_KEY"], &one),
        &below,
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stdout(&out).trim(), GLOBAL_OPENAI);
    let seen = fake.seen().pop().unwrap().request;
    assert_eq!(
        (seen.kind, seen.target.as_str(), seen.project.as_deref()),
        (Kind::Secret, "global/OPENAI_API_KEY", Some("sparrow"))
    );
    let out = cli.run(&with(&["run", "--secret", "OPENAI_API_KEY"], &one), &below);
    assert_eq!(stdout(&out).trim(), SPARROW_OPENAI, "{}", stderr(&out));
    let out = cli.run(
        &with(
            &["run", "--secret", "OPENAI_API_KEY", "--project", "global"],
            &one,
        ),
        &below,
    );
    assert_eq!(stdout(&out).trim(), GLOBAL_OPENAI, "{}", stderr(&out));
    assert_eq!(fake.seen().pop().unwrap().request.project, None);

    // Without a .nodkey file and without --secret there is nothing to ask for.
    std::fs::remove_file(cli.dir.join("repo/.nodkey")).unwrap();
    let before = fake.seen().len();
    let out = cli.run(&with(&["run"], &one), &below);
    assert_eq!(out.status.code(), Some(64));
    assert!(stderr(&out).contains(".nodkey"), "{}", stderr(&out));
    // A file with a value in it is refused before anything is sent.
    std::fs::write(
        cli.dir.join("repo/.nodkey"),
        "secrets = [\"OPENAI_API_KEY=sk-test-0000\"]\n",
    )
    .unwrap();
    let out = cli.run(&with(&["run"], &one), &below);
    assert_eq!(out.status.code(), Some(64));
    assert!(stderr(&out).contains("never a value"), "{}", stderr(&out));
    assert_eq!(fake.seen().len(), before);
}

/// A `.nodkey` that everyone may change is not the user's own: passed over, said on stderr, and
/// nothing is asked for.
#[cfg(unix)]
#[test]
fn a_nodkey_file_everyone_may_change_is_ignored() {
    use std::os::unix::fs::PermissionsExt;
    let (fake, addr) = fake_relay::start(1);
    let cli = Cli::new(addr);
    let below = cli.repo(FILE);
    assert!(cli.run(&["pair"], &cli.dir).status.success());
    let file = cli.dir.join("repo/.nodkey");
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).unwrap();
    let before = fake.seen().len();
    let out = cli.run(&with(&["run"], &printer(&["OPENAI_API_KEY"])), &below);
    assert_eq!(out.status.code(), Some(64), "{}", stderr(&out));
    let err = stderr(&out);
    assert!(
        err.contains("ignoring ") && err.contains("everyone may change it"),
        "{err}"
    );
    assert_eq!(fake.seen().len(), before);
}

#[test]
fn a_plan_in_a_project_covers_later_runs() {
    let (fake, addr) = fake_relay::start(1);
    *fake.secrets.lock().unwrap() = keys();
    let cli = Cli::new(addr);
    let below = cli.repo("project = \"sparrow\"\nsecrets = [\"OPENAI_API_KEY\"]\n");
    assert!(cli.run(&["pair"], &cli.dir).status.success());
    let out = cli.run(
        &[
            "credentials",
            "secret:sparrow/OPENAI_API_KEY",
            "--session",
            "15",
            "--reason",
            "Release the new version",
        ],
        &below,
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let v: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v["items"][0]["secret"]["from"], "project");
    assert!(v["items"][0]["secret"].get("value").is_none());

    fake.set_mode(Mode::Deny);
    let child = printer(&["OPENAI_API_KEY"]);
    let out = cli.run(&with(&["run"], &child), &below);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stdout(&out).trim(), SPARROW_OPENAI);
    assert_eq!(fake.sessions.lock().unwrap().list[0].used, 1);
    // The global key is another key: asked as usual (and denied).
    let out = cli.run(&with(&["run", "--project", "global"], &child), &below);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
}

#[test]
fn save_uses_the_project_of_the_file() {
    let (fake, addr) = fake_relay::start(1);
    *fake.secrets.lock().unwrap() = keys();
    let cli = Cli::new(addr);
    let below = cli.repo(FILE);
    assert!(cli.run(&["pair"], &cli.dir).status.success());
    let save = |extra: &[&str], value: &str| {
        let mut args = vec!["secret", "save", "OPENAI_API_KEY", "--reason", "Save it"];
        args.extend(extra);
        let mut child = cli
            .command(&args, &below)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(value.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    };

    let out = save(&[], "sk-test-sparrow-1111");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(stderr(&out).contains("for the project sparrow"));
    let v: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v["saved"], "updated", "the Sparrow key gets the new value");
    let s = fake.seen().pop().unwrap().request.save_secret.unwrap();
    assert_eq!(s.projects, ["sparrow"]);

    let out = save(&["--project", "Otter,Heron"], "sk-test-shared-1111");
    let v: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v["saved"], "added", "{}", stderr(&out));
    let out = save(&["--project", "global"], GLOBAL_OPENAI);
    let v: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v["saved"], "unchanged", "{}", stderr(&out));

    let keys = fake.secrets.lock().unwrap().clone();
    assert_eq!(keys[0].value, "sk-test-sparrow-1111");
    assert_eq!(keys.last().unwrap().projects, ["Otter", "Heron"]);

    let out = cli.run(&["accounts"], &below);
    assert!(
        stdout(&out).contains("OPENAI_API_KEY  Otter, Heron"),
        "{}",
        stdout(&out)
    );
    assert!(stdout(&out).contains("GITHUB_TOKEN  global"));
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
            .command(&["mcp", "--agent", "claude-code"], &cli.dir)
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
fn mcp_tools_take_projects() {
    let (fake, addr) = fake_relay::start(1);
    *fake.secrets.lock().unwrap() = keys();
    let cli = Cli::new(addr);
    assert!(
        cli.run(&["pair", "--agent", "claude-code"], &cli.dir)
            .status
            .success()
    );
    let mut mcp = Mcp::start(&cli);

    let (v, err) = mcp.tool(
        "request_secret",
        json!({"variable": "OPENAI_API_KEY", "project": "otter", "reason": "Call the API once"}),
    );
    assert!(!err, "{v}");
    assert_eq!(v["secret"]["value"], OTTER_OPENAI);
    assert_eq!(v["secret"]["from"], "project");
    assert_eq!(v["secret"]["project"], "Otter");
    assert!(v["message"].as_str().unwrap().contains("project Otter"));
    let seen = fake.seen().pop().unwrap().request;
    assert_eq!(
        (seen.target.as_str(), seen.project.as_deref()),
        ("OPENAI_API_KEY", Some("otter"))
    );
    let (v, err) = mcp.tool(
        "request_secret",
        json!({"variable": "OPENAI_API_KEY", "project": "Puffin", "reason": "Call the API once"}),
    );
    assert!(!err, "{v}");
    assert_eq!(v["secret"]["value"], GLOBAL_OPENAI);
    assert_eq!(v["secret"]["from"], "global");
    let (v, err) = mcp.tool(
        "request_secret",
        json!({"variable": "OPENAI_API_KEY", "project": "a/b", "reason": "x"}),
    );
    assert!(err && v.to_string().contains("not a project name"), "{v}");

    let (v, err) = mcp.tool(
        "save_secret",
        json!({"variable": "NEW_TOKEN", "value": "tok-test-5555", "projects": ["Sparrow", "Otter"],
               "reason": "Save the token I just made"}),
    );
    assert!(!err, "{v}");
    assert_eq!(v["saved"], "added");
    let s = fake.seen().pop().unwrap().request.save_secret.unwrap();
    assert_eq!(s.projects, ["Sparrow", "Otter"]);
    let (v, err) = mcp.tool(
        "save_secret",
        json!({"variable": "NEW_TOKEN", "value": "x", "projects": "Sparrow", "reason": "x"}),
    );
    assert!(
        err && v.to_string().contains("list of project names"),
        "{v}"
    );

    let (v, err) = mcp.tool("list_accounts", json!({}));
    assert!(!err, "{v}");
    let secrets = v["secrets"].as_array().unwrap();
    assert_eq!(secrets[0]["projects"], json!(["Sparrow"]));
    assert!(secrets[2].get("projects").is_none(), "a global key");
    assert_eq!(secrets[5]["projects"], json!(["Sparrow", "Otter"]));
    assert!(v["message"].as_str().unwrap().contains("global key"));
}
