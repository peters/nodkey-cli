//! The Secret Service (GNOME Keyring, KWallet) through `secret-tool` from libsecret. One item per
//! agent with the attributes `service=nodkey-agent` and `agent_id=<id>`. The keys go to
//! `secret-tool store` on stdin and come back from `secret-tool lookup` on stdout, never in argv.

use std::{
    ffi::OsString,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use nodkey_proto::b64u;
use zeroize::Zeroizing;

use super::{Backend, Location, SERVICE};

/// How long one `secret-tool` call may take. Long enough for the person to unlock the keyring
/// when the desktop asks.
const TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) struct SecretTool {
    program: PathBuf,
    /// Arguments before the command (tests run a script through `sh`).
    pre: Vec<OsString>,
}

/// `name` in a folder of `PATH`, if it is there.
fn find(name: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

impl SecretTool {
    /// `secret-tool` when it is on `PATH` and there is a session bus to reach the service.
    pub(crate) fn available() -> Option<Self> {
        let bus = std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some_and(|v| !v.is_empty())
            || std::env::var_os("XDG_RUNTIME_DIR")
                .is_some_and(|d| Path::new(&d).join("bus").exists());
        bus.then(|| find("secret-tool"))
            .flatten()
            .map(|program| SecretTool {
                program,
                pre: Vec::new(),
            })
    }

    /// `secret-tool` from `PATH`, to read keys that are already there.
    pub(crate) fn from_path() -> Self {
        SecretTool {
            program: find("secret-tool").unwrap_or_else(|| "secret-tool".into()),
            pre: Vec::new(),
        }
    }

    /// A stand-in program, for tests.
    #[cfg(test)]
    pub(crate) fn with_program(program: PathBuf, pre: Vec<OsString>) -> Self {
        SecretTool { program, pre }
    }

    /// Runs `secret-tool args`, gives it `input` on stdin and returns its stdout.
    fn run(&self, args: &[&str], input: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
        let mut child = Command::new(&self.program)
            .args(&self.pre)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("cannot start secret-tool: {e}"))?;
        if let Some(mut stdin) = child.stdin.take() {
            // A program that does not read its input ends the pipe; its exit status says more.
            let _ = stdin.write_all(input);
        }
        let deadline = Instant::now() + TIMEOUT;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20))
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "secret-tool did not answer within {} s",
                        TIMEOUT.as_secs()
                    ));
                }
                Err(e) => return Err(format!("secret-tool: {e}")),
            }
        };
        let mut out = Zeroizing::new(Vec::new());
        if let Some(mut stdout) = child.stdout.take() {
            stdout
                .read_to_end(&mut out)
                .map_err(|e| format!("secret-tool: {e}"))?;
        }
        if status.success() {
            return Ok(out);
        }
        let mut err = String::new();
        if let Some(mut stderr) = child.stderr.take() {
            let _ = stderr.read_to_string(&mut err);
        }
        let err = err.trim();
        Err(if err.is_empty() {
            format!("secret-tool {} failed ({status})", args[0])
        } else {
            format!("secret-tool {}: {err}", args[0])
        })
    }
}

impl Backend for SecretTool {
    fn location(&self) -> Location {
        Location::SecretService
    }

    fn put(&self, agent_id: &str, label: &str, secret: &[u8]) -> Result<Option<String>, String> {
        let text = Zeroizing::new(b64u::encode(secret));
        let args = [
            "store", "--label", label, "service", SERVICE, "agent_id", agent_id,
        ];
        self.run(&args, text.as_bytes()).map(|_| None)
    }

    fn get(&self, agent_id: &str, _sealed: Option<&str>) -> Result<Zeroizing<Vec<u8>>, String> {
        let out = self
            .run(&["lookup", "service", SERVICE, "agent_id", agent_id], b"")
            .map_err(|e| {
                if e.contains("failed (exit status: 1)") {
                    "the item for this agent is not in the keyring".to_owned()
                } else {
                    e
                }
            })?;
        let text = std::str::from_utf8(&out).map_err(|_| "the keyring item is not text")?;
        if text.trim().is_empty() {
            return Err("the item for this agent is not in the keyring".into());
        }
        b64u::decode(text.trim())
            .map(Zeroizing::new)
            .map_err(|e| e.to_string())
    }

    fn delete(&self, agent_id: &str) {
        let _ = self.run(&["clear", "service", SERVICE, "agent_id", agent_id], b"");
    }
}
