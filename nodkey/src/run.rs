//! API keys on the command line. `nodkey run --secret NAME[=SERVICE] ... -- <command> [args]` asks
//! the phone for the keys, puts each one only into the environment of the command it starts,
//! never prints them and exits with the command's exit code. `nodkey secret save NAME` reads the
//! value of a new key from stdin (never from the arguments) and asks the phone to keep it.

use std::{io::IsTerminal, process::ExitCode};

use nodkey_proto::{Answer, BundleItem, BundleRequest, Decision, Kind, apikey};
use zeroize::Zeroizing;

use crate::{
    agent::{Agent, Reported, new_request},
    cli::{Args, DENIED, EXPIRED, PAUSED, agent_for, fail, usage_error},
    secret::{NewKey, refusal},
    store::select_phone,
};

/// When the command cannot start: not found, or found but not runnable (as shells do).
const NOT_FOUND: u8 = 127;
const CANNOT_RUN: u8 = 126;

/// One `--secret` option: the variable name in the command's environment and the target the
/// phone matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wanted {
    pub name: String,
    pub target: String,
}

impl Wanted {
    /// `NAME` or `NAME=SERVICE` (the service as a host or a URL).
    pub fn parse(text: &str) -> Result<Wanted, String> {
        let (name, service) = match text.split_once('=') {
            Some((n, s)) => (n.trim(), Some(s)),
            None => (text.trim(), None),
        };
        if !apikey::valid_variable(name) {
            return Err(format!(
                "--secret {text:?}: give NAME or NAME=SERVICE, NAME a variable name like OPENAI_API_KEY"
            ));
        }
        Ok(Wanted {
            name: name.to_owned(),
            target: crate::secret::target(Some(name), service)?,
        })
    }
}

/// Splits `nodkey run` arguments: the `--secret` options, the other options and the command after
/// `--`.
pub fn split(rest: &[String]) -> Result<(Vec<Wanted>, Args, Vec<String>), String> {
    let usage = "nodkey run takes --secret NAME[=SERVICE] (one or more), --reason TEXT, then -- and the \
                 command, e.g. nodkey run --secret OPENAI_API_KEY --reason \"Run the tests\" -- npm test";
    let at = rest.iter().position(|a| a == "--").ok_or(usage)?;
    let command = rest[at + 1..].to_vec();
    if command.is_empty() {
        return Err(usage.into());
    }
    let mut wanted = Vec::new();
    let mut others = Vec::new();
    let mut it = rest[..at].iter();
    while let Some(arg) = it.next() {
        let value = match arg.strip_prefix("--secret") {
            Some("") => it.next().ok_or("--secret needs a value")?.clone(),
            Some(v) if v.starts_with('=') => v[1..].to_owned(),
            _ => {
                others.push(arg.clone());
                continue;
            }
        };
        let w = Wanted::parse(&value)?;
        if wanted.iter().any(|x: &Wanted| x.name == w.name) {
            return Err(format!("--secret {} is given twice", w.name));
        }
        wanted.push(w);
    }
    if wanted.is_empty() {
        return Err(usage.into());
    }
    if wanted.len() > nodkey_proto::bundle::MAX_ITEMS {
        return Err(format!(
            "at most {} keys in one run",
            nodkey_proto::bundle::MAX_ITEMS
        ));
    }
    let args = Args::parse(&others)?;
    args.only("run", &["reason", "phone", "model", "effort"])?;
    args.positionals("run", 0, "options before --, and the command after it")?;
    args.value("reason")
        .ok_or("nodkey run needs --reason: say in one sentence what the command does")?;
    Ok((wanted, args, command))
}

/// What the phone gave: every key, or why not and the exit code.
pub enum Fetched {
    Keys(Vec<(String, Zeroizing<String>)>),
    Refused { message: String, code: u8 },
}

fn exit_code(a: &Answer) -> u8 {
    match a.decision {
        _ if crate::outcome::is_paused(a) => PAUSED,
        Decision::Denied | Decision::Rejected => DENIED,
        Decision::Expired => EXPIRED,
        _ => 1,
    }
}

fn refused(a: &Answer) -> Fetched {
    let message = match a.decision {
        Decision::Expired => "The request expired on the phone without an answer.".to_owned(),
        _ => refusal(a),
    };
    Fetched::Refused {
        message,
        code: exit_code(a),
    }
}

fn expired(agent: &Agent) -> Fetched {
    Fetched::Refused {
        message: format!(
            "No answer from the phone within {} s. The command did not run.",
            agent.timing.request.as_secs()
        ),
        code: EXPIRED,
    }
}

impl Agent {
    /// Asks the phone for the keys `nodkey run` needs: one request for one key, or while a task
    /// session runs (each key request in it may go through); else one bundle, one approval.
    pub async fn fetch_keys(
        &self,
        wanted: &[Wanted],
        reason: &str,
        phone: Option<&str>,
        reported: Reported<'_>,
        progress: crate::agent::Progress<'_>,
    ) -> Result<Fetched, String> {
        let in_session = self.store().ok().is_some_and(|store| {
            let phones = store.phones().unwrap_or_default();
            select_phone(&phones, phone).is_ok_and(|p| {
                crate::session::running(&store).is_some_and(|s| s.phone_id == p.phone_id)
            })
        });
        let mut keys = Vec::new();
        if wanted.len() == 1 || in_session {
            for w in wanted {
                let request =
                    new_request(Kind::Secret, &w.target, reason, self.client_for(reported));
                let ex = self.exchange(request, None, phone, progress).await?;
                let Some(a) = ex.answer else {
                    return Ok(expired(self));
                };
                note_limit(&a);
                match a.secret.and_then(|s| s.value) {
                    Some(v) if a.decision == Decision::Approved => {
                        keys.push((w.name.clone(), Zeroizing::new(v.expose().to_owned())));
                    }
                    _ => return Ok(refused(&Answer { secret: None, ..a })),
                }
            }
            return Ok(Fetched::Keys(keys));
        }
        let mut request = new_request(Kind::Bundle, "", reason, self.client_for(reported));
        request.bundle = Some(BundleRequest {
            items: wanted
                .iter()
                .enumerate()
                .map(|(i, w)| BundleItem {
                    id: (i + 1).to_string(),
                    kind: Kind::Secret,
                    target: w.target.clone(),
                })
                .collect(),
            follow_up: None,
            session: None,
        });
        let ex = self.exchange(request, None, phone, progress).await?;
        let Some(mut a) = ex.answer else {
            return Ok(expired(self));
        };
        note_limit(&a);
        let items = a.items.take().unwrap_or_default();
        if a.decision != Decision::Approved {
            return Ok(refused(&a));
        }
        for (i, w) in wanted.iter().enumerate() {
            let id = (i + 1).to_string();
            let item = items.iter().find(|x| x.id == id);
            match item.and_then(|x| x.secret.as_ref()?.value.as_ref()) {
                Some(v) if item.is_some_and(|x| x.decision == Decision::Approved) => {
                    keys.push((w.name.clone(), Zeroizing::new(v.expose().to_owned())));
                }
                _ => {
                    let mut one = Answer::decision(&a.request_id, Decision::Denied);
                    one.error = item.and_then(|x| x.error.clone());
                    let Fetched::Refused { message, code } = refused(&one) else {
                        unreachable!()
                    };
                    return Ok(Fetched::Refused {
                        message: format!("{}: {message}", w.name),
                        code,
                    });
                }
            }
        }
        Ok(Fetched::Keys(keys))
    }
}

/// Tells the user on stderr when the phone asked with the agent limit notice.
fn note_limit(a: &Answer) {
    let note = crate::outcome::limit_note(a);
    if !note.is_empty() {
        eprintln!("nodkey:{note}");
    }
}

/// Prints `note` on stderr once, the first time a wait reports progress.
fn waiting(note: String) -> impl Fn(u64, u64, &str) + Send + Sync {
    let shown = std::sync::atomic::AtomicBool::new(false);
    move |_, _, _| {
        if !shown.swap(true, std::sync::atomic::Ordering::Relaxed) {
            eprintln!("{note}");
        }
    }
}

fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())
}

/// `nodkey run`.
pub fn main(rest: &[String]) -> ExitCode {
    let (wanted, args, command) = match split(rest) {
        Ok(parts) => parts,
        Err(e) => return usage_error(&e),
    };
    let agent = match agent_for(&args) {
        Ok(a) => a,
        Err(e) => return usage_error(&e),
    };
    let runtime = match runtime() {
        Ok(rt) => rt,
        Err(e) => return fail(&e),
    };
    let reported = Reported {
        model: args.value("model"),
        effort: args.value("effort"),
    };
    let names: Vec<&str> = wanted.iter().map(|w| w.name.as_str()).collect();
    let progress = waiting(format!(
        "Waiting for your answer in Nodkey on your iPhone for {} (up to {} s) ...",
        names.join(", "),
        agent.timing.request.as_secs()
    ));
    let fetched = runtime.block_on(agent.fetch_keys(
        &wanted,
        args.value("reason").unwrap_or_default(),
        args.value("phone"),
        reported,
        &progress,
    ));
    drop(runtime);
    match fetched {
        Ok(Fetched::Keys(keys)) => spawn(&command, keys),
        Ok(Fetched::Refused { message, code }) => {
            eprintln!("nodkey: {message} The command did not run.");
            ExitCode::from(code)
        }
        Err(e) => fail(&format!("{e} The command did not run.")),
    }
}

/// Starts `command` with the keys in its environment, waits, and passes its exit code on.
fn spawn(command: &[String], keys: Vec<(String, Zeroizing<String>)>) -> ExitCode {
    let mut cmd = std::process::Command::new(&command[0]);
    cmd.args(&command[1..]);
    for (name, value) in &keys {
        cmd.env(name, value.as_str());
    }
    let child = cmd.spawn();
    drop(cmd);
    drop(keys);
    let status = match child {
        Ok(mut child) => child.wait(),
        Err(e) => {
            eprintln!("nodkey: cannot run {:?}: {e}", command[0]);
            return ExitCode::from(if e.kind() == std::io::ErrorKind::NotFound {
                NOT_FOUND
            } else {
                CANNOT_RUN
            });
        }
    };
    match status {
        Ok(s) => match s.code() {
            Some(code) => ExitCode::from((code & 0xff) as u8),
            None => ExitCode::from(signal_code(&s)),
        },
        Err(e) => fail(&format!("waiting for the command failed: {e}")),
    }
}

/// 128 + the signal that ended the command, as shells report it.
#[cfg(unix)]
fn signal_code(s: &std::process::ExitStatus) -> u8 {
    use std::os::unix::process::ExitStatusExt;
    s.signal().map_or(1, |sig| (128 + sig.clamp(0, 127)) as u8)
}

#[cfg(not(unix))]
fn signal_code(_: &std::process::ExitStatus) -> u8 {
    1
}

/// `nodkey secret save NAME [--service HOST] [--title TEXT] [--notes TEXT] [--expires DATE]
/// --reason TEXT`: the value comes from stdin.
pub fn secret_main(rest: &[String]) -> ExitCode {
    let parsed = (|| -> Result<(NewKey, Args), String> {
        let usage = "nodkey secret save NAME [--service HOST] --reason TEXT, with the key on stdin";
        let (Some("save"), Some(tail)) = (rest.first().map(String::as_str), rest.get(1..)) else {
            return Err(usage.into());
        };
        let args = Args::parse(tail)?;
        args.only(
            "secret save",
            &[
                "service", "title", "notes", "expires", "reason", "phone", "model", "effort",
            ],
        )?;
        args.positionals("secret save", 1, "one NAME, e.g. OPENAI_API_KEY")?;
        args.value("reason")
            .ok_or("nodkey secret save needs --reason: say in one sentence what the key is for")?;
        let expires = args
            .value("expires")
            .map(|v| crate::secret::expires(Some(&serde_json::Value::String(v.to_owned()))))
            .transpose()?
            .flatten();
        let key = NewKey {
            variable: args.positional[0].clone(),
            service: args.value("service").map(str::to_owned),
            title: args.value("title").map(str::to_owned),
            notes: args.value("notes").map(str::to_owned),
            expires,
        };
        crate::secret::target(Some(&key.variable), key.service.as_deref())?;
        Ok((key, args))
    })();
    let (key, args) = match parsed {
        Ok(p) => p,
        Err(e) => return usage_error(&e),
    };
    let value = match read_value() {
        Ok(v) => v,
        Err(e) => return usage_error(&e),
    };
    let agent = match agent_for(&args) {
        Ok(a) => a,
        Err(e) => return usage_error(&e),
    };
    let runtime = match runtime() {
        Ok(rt) => rt,
        Err(e) => return fail(&e),
    };
    let progress = waiting(format!(
        "Waiting for you to save the key in Nodkey on your iPhone (up to {} s) ...",
        agent.timing.request.as_secs()
    ));
    let reported = Reported {
        model: args.value("model"),
        effort: args.value("effort"),
    };
    let result = runtime.block_on(agent.save_secret(
        key,
        value,
        args.value("reason").unwrap_or_default(),
        args.value("phone"),
        reported,
        &progress,
    ));
    match result
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).map_err(|e| e.to_string()))
    {
        Ok(v) => {
            let code = crate::commands::exit_for(&v);
            eprintln!("nodkey: {}", v["message"].as_str().unwrap_or_default());
            println!(
                "{}",
                serde_json::to_string_pretty(&v).expect("serializable")
            );
            ExitCode::from(code)
        }
        Err(e) => fail(&e),
    }
}

/// The key from stdin, without the line break at its end.
fn read_value() -> Result<Zeroizing<String>, String> {
    use std::io::Read;
    if std::io::stdin().is_terminal() {
        eprintln!("Paste the key, then press Enter and Ctrl-D (Ctrl-Z and Enter on Windows):");
    }
    let mut value = Zeroizing::new(String::new());
    std::io::stdin()
        .read_to_string(&mut value)
        .map_err(|e| format!("cannot read the key from stdin: {e}"))?;
    let end = value.trim_end_matches(['\r', '\n']).len();
    value.truncate(end);
    if value.trim().is_empty() {
        return Err("no key on stdin; pipe it in, e.g. from your clipboard tool".into());
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn options_and_command() {
        let (wanted, args, command) = split(&strings(&[
            "--secret",
            "OPENAI_API_KEY",
            "--secret=EXAMPLE_TOKEN=https://api.example.com/v1",
            "--reason",
            "Run the tests",
            "--",
            "npm",
            "test",
            "--secret",
            "--",
        ]))
        .unwrap();
        assert_eq!(
            wanted,
            [
                Wanted {
                    name: "OPENAI_API_KEY".into(),
                    target: "OPENAI_API_KEY".into()
                },
                Wanted {
                    name: "EXAMPLE_TOKEN".into(),
                    target: "api.example.com/EXAMPLE_TOKEN".into()
                }
            ]
        );
        assert_eq!(args.value("reason"), Some("Run the tests"));
        assert_eq!(command, ["npm", "test", "--secret", "--"]);

        for (bad, want) in [
            (&["--secret", "A", "--reason", "x"][..], "then -- and the"),
            (
                &["--secret", "A", "--reason", "x", "--"][..],
                "then -- and the",
            ),
            (&["--reason", "x", "--", "ls"][..], "--secret NAME"),
            (&["--secret", "A", "--", "ls"][..], "--reason"),
            (
                &["--secret", "A-B", "--reason", "x", "--", "ls"][..],
                "variable name",
            ),
            (
                &[
                    "--secret",
                    "A",
                    "--secret",
                    "A=x.example",
                    "--reason",
                    "x",
                    "--",
                    "ls",
                ][..],
                "twice",
            ),
            (
                &["--secret", "A", "--reason", "x", "extra", "--", "ls"][..],
                "options before",
            ),
            (
                &["--secret", "A", "--reason", "x", "--field", "v", "--", "ls"][..],
                "--field",
            ),
            (
                &["--secret", "A=not a host", "--reason", "x", "--", "ls"][..],
                "not a service",
            ),
        ] {
            let err = split(&strings(bad)).err().unwrap_or_default();
            assert!(err.contains(want), "{bad:?}: {err}");
        }
        let many: Vec<String> = (0..11)
            .flat_map(|i| ["--secret".to_owned(), format!("K{i}")])
            .chain(strings(&["--reason", "x", "--", "ls"]))
            .collect();
        assert!(split(&many).err().unwrap().contains("at most 10"));
    }
}
