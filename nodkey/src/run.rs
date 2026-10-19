//! API keys on the command line. `nodkey run [--secret NAME[=SERVICE]]... [--project NAME] --
//! <command> [args]` asks the phone for the keys, puts each one only into the environment of the
//! command it starts, never prints them and exits with the command's exit code. It asks for the
//! keys the nearest `.nodkey` file lists, in its project (`keyfile.rs`); `--secret` adds keys and
//! `--project` names another project (`global`: only the global keys).

use std::process::ExitCode;

use nodkey_proto::{
    Answer, BundleItem, BundleRequest, Decision, Kind, SecretAnswer, SecretTarget,
    apikey::{self, KeyFrom},
};
use zeroize::Zeroizing;

use crate::{
    agent::{Agent, Reported, new_request},
    cli::{Args, DENIED, EXPIRED, PAUSED, agent_for, fail, usage_error},
    keyfile::{self, KeyFile},
    secret::refusal,
    store::select_phone,
};

/// When the command cannot start: not found, or found but not runnable (as shells do).
const NOT_FOUND: u8 = 127;
const CANNOT_RUN: u8 = 126;

/// One key: the variable name in the command's environment and the target the phone matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wanted {
    pub name: String,
    pub target: String,
}

impl Wanted {
    /// `NAME`, `NAME=SERVICE` (the service as a host or a URL), `global/NAME` (only the global
    /// key) or `project/NAME` (another project's key).
    pub fn parse(text: &str) -> Result<Wanted, String> {
        let (left, service) = match text.split_once('=') {
            Some((n, s)) => (n.trim(), Some(s)),
            None => (text.trim(), None),
        };
        let usage = || {
            format!(
                "--secret {text:?}: give NAME, NAME=SERVICE, global/NAME or project/NAME, NAME a variable name like \
                 OPENAI_API_KEY"
            )
        };
        if left.contains('/') {
            if service.is_some() {
                return Err(format!(
                    "--secret {text:?}: a project or global key takes no service"
                ));
            }
            let t = SecretTarget::parse(left).map_err(|e| format!("--secret {text:?}: {e}"))?;
            let name = t.variable.clone().ok_or_else(usage)?;
            return Ok(Wanted {
                name,
                target: t.to_target(),
            });
        }
        if !apikey::valid_variable(left) {
            return Err(usage());
        }
        Ok(Wanted {
            name: left.to_owned(),
            target: crate::secret::target(Some(left), service)?,
        })
    }
}

/// What `nodkey run` does: the keys, the project they are asked in, the other options and the
/// command.
#[derive(Debug)]
pub struct Plan {
    pub wanted: Vec<Wanted>,
    pub project: Option<String>,
    pub args: Args,
    pub command: Vec<String>,
}

impl Plan {
    /// `--reason`, or the command itself ("Run npm test").
    pub fn reason(&self) -> String {
        if let Some(r) = self.args.value("reason") {
            return r.to_owned();
        }
        let line = format!("Run {}", self.command.join(" "));
        let max = 200;
        match line.char_indices().nth(max) {
            Some((at, _)) => format!("{} ...", &line[..at]),
            None => line,
        }
    }
}

/// Splits `nodkey run` arguments: the `--secret` options, the other options and the command after
/// `--`. `file` is the nearest `.nodkey` file: its keys come first (a `--secret` with the same
/// name replaces one), and its project unless `--project` names another.
pub fn plan(rest: &[String], file: Option<&KeyFile>) -> Result<Plan, String> {
    let usage = "nodkey run takes options (--secret NAME[=SERVICE], --project NAME, --reason TEXT), then -- \
                 and the command, e.g. nodkey run --secret OPENAI_API_KEY --reason \"Run the tests\" -- npm test";
    let at = rest.iter().position(|a| a == "--").ok_or(usage)?;
    let command = rest[at + 1..].to_vec();
    if command.is_empty() {
        return Err(usage.into());
    }
    let mut options: Vec<Wanted> = Vec::new();
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
        if options.iter().any(|x| x.name == w.name) {
            return Err(format!("--secret {} is given twice", w.name));
        }
        options.push(w);
    }
    let args = Args::parse(&others)?;
    args.only("run", &["reason", "project", "phone", "model", "effort"])?;
    args.positionals("run", 0, "options before --, and the command after it")?;
    let mut wanted: Vec<Wanted> = file
        .iter()
        .flat_map(|f| &f.secrets)
        .map(|t| Wanted {
            name: keyfile::variable(t).to_owned(),
            target: t.clone(),
        })
        .collect();
    for w in options {
        wanted.retain(|x| x.name != w.name);
        wanted.push(w);
    }
    if wanted.is_empty() {
        return Err(
            "nodkey run needs the keys to ask for: a .nodkey file in this folder or one above it (project = \"NAME\" \
             and secrets = [\"OPENAI_API_KEY\"]), or --secret NAME[=SERVICE]"
                .into(),
        );
    }
    if wanted.len() > nodkey_proto::bundle::MAX_ITEMS {
        return Err(format!(
            "at most {} keys in one run",
            nodkey_proto::bundle::MAX_ITEMS
        ));
    }
    let project = match args.value("project") {
        Some(p) => crate::secret::project(Some(p))?,
        None => file.and_then(|f| f.project.clone()),
    };
    Ok(Plan {
        wanted,
        project,
        args,
        command,
    })
}

/// What the phone gave: every key and where each came from ("OPENAI_API_KEY from Sparrow"), or why
/// not and the exit code.
pub enum Fetched {
    Keys {
        keys: Vec<(String, Zeroizing<String>)>,
        from: Vec<String>,
    },
    Refused {
        message: String,
        code: u8,
    },
}

/// Where a key came from, for stderr; empty when the app does not say.
fn source(name: &str, key: &SecretAnswer) -> Option<String> {
    match (key.from?, key.project.as_deref()) {
        (KeyFrom::Project, Some(p)) => Some(format!("{name} from {p}")),
        (KeyFrom::Project, None) => Some(format!("{name} from the project")),
        (KeyFrom::Global, _) => Some(format!("{name} (global)")),
        (KeyFrom::Chosen, _) => Some(format!("{name} (picked by hand)")),
    }
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
    /// Asks the phone for the keys `nodkey run` needs, in `project`: one request for one key, or
    /// while a task session runs (each key request in it may go through); else one bundle, one
    /// approval.
    #[allow(clippy::too_many_arguments)]
    pub async fn fetch_keys(
        &self,
        wanted: &[Wanted],
        project: Option<&str>,
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
        let (mut keys, mut from) = (Vec::new(), Vec::new());
        if wanted.len() == 1 || in_session {
            for w in wanted {
                let mut request =
                    new_request(Kind::Secret, &w.target, reason, self.client_for(reported));
                request.project = project.map(str::to_owned);
                let ex = self.exchange(request, None, phone, progress).await?;
                let Some(a) = ex.answer else {
                    return Ok(expired(self));
                };
                note_limit(&a);
                match &a.secret {
                    Some(s) if a.decision == Decision::Approved && s.value.is_some() => {
                        let v = s.value.as_ref().expect("checked");
                        keys.push((w.name.clone(), Zeroizing::new(v.expose().to_owned())));
                        from.extend(source(&w.name, s));
                    }
                    _ => return Ok(refused(&Answer { secret: None, ..a })),
                }
            }
            return Ok(Fetched::Keys { keys, from });
        }
        let mut request = new_request(Kind::Bundle, "", reason, self.client_for(reported));
        request.project = project.map(str::to_owned);
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
            let key = item.and_then(|x| x.secret.as_ref());
            match key.and_then(|k| k.value.as_ref()) {
                Some(v) if item.is_some_and(|x| x.decision == Decision::Approved) => {
                    keys.push((w.name.clone(), Zeroizing::new(v.expose().to_owned())));
                    from.extend(key.and_then(|k| source(&w.name, k)));
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
        Ok(Fetched::Keys { keys, from })
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
pub(crate) fn waiting(note: String) -> impl Fn(u64, u64, &str) + Send + Sync {
    let shown = std::sync::atomic::AtomicBool::new(false);
    move |_, _, _| {
        if !shown.swap(true, std::sync::atomic::Ordering::Relaxed) {
            eprintln!("{note}");
        }
    }
}

pub(crate) fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())
}

/// The nearest `.nodkey` file from the current folder up, if there is one.
fn nearest_file() -> Result<Option<KeyFile>, String> {
    let dir = std::env::current_dir().map_err(|e| format!("no current folder: {e}"))?;
    keyfile::find(&dir).map(|p| keyfile::read(&p)).transpose()
}

/// `nodkey run`.
pub fn main(rest: &[String]) -> ExitCode {
    let plan = match nearest_file().and_then(|file| plan(rest, file.as_ref())) {
        Ok(p) => p,
        Err(e) => return usage_error(&e),
    };
    let agent = match agent_for(&plan.args) {
        Ok(a) => a,
        Err(e) => return usage_error(&e),
    };
    let runtime = match runtime() {
        Ok(rt) => rt,
        Err(e) => return fail(&e),
    };
    let reported = Reported {
        model: plan.args.value("model"),
        effort: plan.args.value("effort"),
    };
    let names: Vec<&str> = plan.wanted.iter().map(|w| w.name.as_str()).collect();
    let progress = waiting(format!(
        "Waiting for your answer in Nodkey on your iPhone for {}{} (up to {} s) ...",
        names.join(", "),
        plan.project
            .as_deref()
            .map(|p| format!(" in {p}"))
            .unwrap_or_default(),
        agent.timing.request.as_secs()
    ));
    let fetched = runtime.block_on(agent.fetch_keys(
        &plan.wanted,
        plan.project.as_deref(),
        &plan.reason(),
        plan.args.value("phone"),
        reported,
        &progress,
    ));
    drop(runtime);
    match fetched {
        Ok(Fetched::Keys { keys, from }) => {
            if !from.is_empty() {
                eprintln!("nodkey: {}.", from.join(", "));
            }
            spawn(&plan.command, keys)
        }
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

#[cfg(test)]
mod tests;
