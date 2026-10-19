//! The command line. Each command is one request with the terminal's own identity
//! ("Terminal @ my-laptop"), or another agent's with `--agent`. Results go to stdout (JSON, one
//! field with `--field`, or plain text); waiting notes and errors go to stderr.

use std::{collections::HashMap, process::ExitCode};

use serde_json::{Map, Value, json};

use crate::{
    agent::Agent,
    profile::{self, Profile},
    relay::{self, DEFAULT_RELAY},
    store::Home,
};

pub use crate::usage::USAGE;

pub(crate) const DENIED: u8 = 2;
pub(crate) const EXPIRED: u8 = 3;
/// The agent is paused (`error: paused`), by the user or by its limit.
pub(crate) const PAUSED: u8 = 4;
const BAD_ARGS: u8 = 64;

const VALUE_FLAGS: [&str; 28] = [
    "service",
    "project",
    "title",
    "notes",
    "expires",
    "agent",
    "kind",
    "provider",
    "mailbox",
    "outcome",
    "wait",
    "follow-up",
    "session",
    "relay",
    "name",
    "reason",
    "image",
    "field",
    "phone",
    "model",
    "effort",
    "query",
    "username",
    "domain",
    "group",
    "last-used-before",
    "added-before",
    "password-changed-before",
];
const BOOL_FLAGS: [&str; 6] = [
    "json",
    "ip-only",
    "never-used",
    "remove",
    "dry-run",
    "reveal",
];

/// Parsed arguments: positionals and `--flag [value]`.
#[derive(Debug, Default)]
pub struct Args {
    pub positional: Vec<String>,
    values: HashMap<String, String>,
    flags: Vec<String>,
}

impl Args {
    pub fn parse(raw: &[String]) -> Result<Self, String> {
        let mut a = Args::default();
        let mut it = raw.iter();
        while let Some(arg) = it.next() {
            let Some(flag) = arg.strip_prefix("--") else {
                a.positional.push(arg.clone());
                continue;
            };
            let (name, inline) = match flag.split_once('=') {
                Some((n, v)) => (n, Some(v.to_owned())),
                None => (flag, None),
            };
            if VALUE_FLAGS.contains(&name) {
                let value = match inline {
                    Some(v) => v,
                    None => it.next().ok_or(format!("--{name} needs a value"))?.clone(),
                };
                if a.values.insert(name.to_owned(), value).is_some() {
                    return Err(format!("--{name} is given twice"));
                }
            } else if BOOL_FLAGS.contains(&name) && inline.is_none() {
                a.flags.push(name.to_owned());
            } else {
                return Err(format!("unknown option --{name}"));
            }
        }
        Ok(a)
    }

    pub fn value(&self, name: &str) -> Option<&str> {
        self.values
            .get(name)
            .map(String::as_str)
            .filter(|v| !v.trim().is_empty())
    }

    pub fn flag(&self, name: &str) -> bool {
        self.flags.iter().any(|f| f == name)
    }

    /// Fails on options that `command` does not take.
    pub(crate) fn only(&self, command: &str, allowed: &[&str]) -> Result<(), String> {
        let global = ["agent", "relay", "json"];
        for name in self.values.keys().chain(&self.flags) {
            if !allowed.contains(&name.as_str()) && !global.contains(&name.as_str()) {
                return Err(format!("nodkey {command} does not take --{name}"));
            }
        }
        Ok(())
    }

    pub(crate) fn positionals(&self, command: &str, n: usize, what: &str) -> Result<(), String> {
        if self.positional.len() != n {
            return Err(format!("nodkey {command} takes {what}"));
        }
        Ok(())
    }
}

/// Runs the command line with the arguments after the program name.
pub fn main(raw: Vec<String>) -> ExitCode {
    let Some((command, rest)) = raw.split_first() else {
        eprint!("{USAGE}");
        return ExitCode::from(BAD_ARGS);
    };
    match command.as_str() {
        "-h" | "--help" | "help" => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        "-V" | "--version" | "version" => {
            println!("nodkey {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        _ => {}
    }
    let before_command = rest.split(|a| a == "--").next().unwrap_or_default();
    let help = before_command.iter().any(|a| a == "-h" || a == "--help");
    match command.as_str() {
        "run" if !help => return crate::run::main(rest),
        "secret" if !help => return crate::secret::save::main(rest),
        _ => {}
    }
    if rest.iter().any(|a| a == "-h" || a == "--help") {
        if command == "webauthn" {
            print!("{}", crate::webauthn::HELP);
            return ExitCode::SUCCESS;
        }
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let args = match Args::parse(rest) {
        Ok(a) => a,
        Err(e) if command == "webauthn" => return crate::webauthn::bad_input(&e),
        Err(e) if command == "card-fill" => return crate::cardfill::bad_input(&e),
        Err(e) if command == "login-fill" => return crate::loginfill::bad_input(&e),
        Err(e) => return usage_error(&e),
    };
    if std::env::var_os("NODKEY_DEBUG").is_none() && command != "mcp" {
        relay::LOG_PUSH.store(false, std::sync::atomic::Ordering::Relaxed);
    }
    let result = match command.as_str() {
        "mcp" => return mcp(&args),
        "setup" => {
            return match crate::setup::main(&args) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => fail(&e),
            };
        }
        "skill" => {
            print!("{}", crate::SKILL);
            return ExitCode::SUCCESS;
        }
        "webauthn" => return crate::webauthn::main(&args, agent(&args, profile::TERMINAL)),
        "card-fill" => return crate::cardfill::main(&args, host_agent(&args)),
        "login-fill" => return crate::loginfill::main(&args, agent(&args, profile::TERMINAL)),
        "pair" | "code" | "login" | "credentials" | "pay" | "accounts" | "insights" | "cleanup"
        | "phones" | "unpair" | "agents" | "end-session" => check(command, &args),
        "suggest" | "sms-code" => crate::signin::check_cli(command, &args),
        other => Err(format!("unknown command {other:?}; see nodkey --help")),
    };
    if let Err(e) = result {
        return usage_error(&e);
    }
    let agent = match agent(&args, profile::TERMINAL) {
        Ok(a) => a,
        Err(e) => return usage_error(&e),
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => return fail(&e.to_string()),
    };
    match runtime.block_on(crate::commands::run(command, &args, &agent)) {
        Ok(code) => ExitCode::from(code),
        Err(e) => fail(&e),
    }
}

pub(crate) fn usage_error(e: &str) -> ExitCode {
    eprintln!("nodkey: {e}\nRun `nodkey --help` for the commands.");
    ExitCode::from(BAD_ARGS)
}

pub(crate) fn fail(e: &str) -> ExitCode {
    eprintln!("nodkey: {e}");
    ExitCode::FAILURE
}

/// Checks the options and positionals of a command before anything is sent.
fn check(command: &str, a: &Args) -> Result<(), String> {
    let request = ["reason", "image", "field", "phone", "model", "effort"];
    let cleanup = [
        "reason",
        "phone",
        "model",
        "effort",
        "query",
        "username",
        "domain",
        "group",
        "last-used-before",
        "added-before",
        "password-changed-before",
        "ip-only",
        "never-used",
    ];
    match command {
        "pair" => a
            .only(command, &["name"])
            .and(a.positionals(command, 0, "no arguments")),
        "code" | "login" => {
            a.only(command, &request)?;
            a.positionals(command, 1, "one TARGET, e.g. github.com/alex")?;
            a.value("reason")
                .map(|_| ())
                .ok_or_else(|| format!("nodkey {command} needs --reason: say in one sentence why"))
        }
        "credentials" => {
            a.only(
                command,
                &[
                    "reason",
                    "image",
                    "phone",
                    "model",
                    "effort",
                    "follow-up",
                    "session",
                ],
            )?;
            if a.positional.is_empty() {
                return Err(
                    "nodkey credentials takes one or more ITEMs, e.g. login:chatgpt.com code:github.com/alex"
                        .into(),
                );
            }
            credential_items(a)?;
            a.value("reason").map(|_| ()).ok_or_else(|| {
                "nodkey credentials needs --reason: say in one sentence why".to_owned()
            })
        }
        "pay" => {
            a.only(
                command,
                &[
                    "reason", "image", "field", "phone", "model", "effort", "reveal",
                ],
            )?;
            crate::card::payment(a).map(|_| ())
        }
        "accounts" | "insights" => a
            .only(command, &["reason", "phone", "model", "effort"])
            .and(a.positionals(command, 0, "no arguments")),
        "cleanup" => {
            a.only(command, &cleanup)?;
            a.positionals(command, 0, "filter options, not arguments")?;
            a.value("reason")
                .map(|_| ())
                .ok_or_else(|| "nodkey cleanup needs --reason".to_owned())?;
            cleanup_filter(a).map(|_| ())
        }
        "phones" | "agents" => a
            .only(command, &[])
            .and(a.positionals(command, 0, "no arguments")),
        "unpair" => a
            .only(command, &[])
            .and(a.positionals(command, 1, "one PHONE")),
        "end-session" => a
            .only(command, &["reason", "model", "effort"])
            .and(a.positionals(command, 0, "no arguments")),
        _ => Ok(()),
    }
}

/// The terminal's agent for these arguments (or `--agent`, or `$NODKEY_AGENT`), for commands that
/// parse their own arguments. Push notes stay quiet unless `NODKEY_DEBUG` is set.
pub(crate) fn agent_for(a: &Args) -> Result<Agent, String> {
    if std::env::var_os("NODKEY_DEBUG").is_none() {
        relay::LOG_PUSH.store(false, std::sync::atomic::Ordering::Relaxed);
    }
    agent(a, profile::TERMINAL)
}

/// The browser host's own profile for `card-fill`, named with `--agent` and never an agent's: an
/// agent that can run commands must not get the card under its own profile.
fn host_agent(a: &Args) -> Result<Agent, String> {
    let why = "card-fill runs only under the browser host's own profile, for example --agent horizon. \
               Pair the host once with `nodkey pair --agent horizon` and turn cards on for it in Nodkey; \
               an agent's own profile cannot fill cards, because an agent that can run commands could read \
               the card";
    match a.value("agent").map(|s| s.trim().to_ascii_lowercase()) {
        None => Err(format!("{why}.")),
        Some(slug) if profile::is_agent(&slug) => Err(format!("{why} ({slug} is an agent).")),
        Some(_) => agent(a, profile::TERMINAL),
    }
}

/// The agent for these arguments: `--agent`, else `$NODKEY_AGENT`, else the agent whose shell
/// runs this command ([`profile::calling_agent`]), else `default_profile`.
fn agent(a: &Args, default_profile: &str) -> Result<Agent, String> {
    let env_agent = std::env::var("NODKEY_AGENT").ok();
    let slug = a
        .value("agent")
        .or(env_agent.as_deref().filter(|s| !s.trim().is_empty()))
        .or_else(|| profile::calling_agent(|name| std::env::var(name).ok()))
        .unwrap_or(default_profile);
    let profile = Profile::named(slug)?;
    let home = Home::from_env().map_err(|e| e.to_string());
    let relay = relay_url(a.value("relay"), home.as_ref().ok());
    Ok(Agent::new(home, profile, &relay))
}

/// `--relay`, else `NODKEY_RELAY`, else `relay` in `config.json`, else the default.
pub fn relay_url(arg: Option<&str>, home: Option<&Home>) -> String {
    arg.map(str::to_owned)
        .or_else(|| {
            std::env::var("NODKEY_RELAY")
                .ok()
                .filter(|r| !r.trim().is_empty())
        })
        .or_else(|| home.and_then(|h| h.configured_relay().ok().flatten()))
        .unwrap_or_else(|| DEFAULT_RELAY.to_owned())
}

/// `nodkey mcp`: the MCP server on stdio. Without `--agent` the profile follows the client.
fn mcp(a: &Args) -> ExitCode {
    if let Err(e) = a
        .only("mcp", &[])
        .and(a.positionals("mcp", 0, "no arguments"))
    {
        return usage_error(&e);
    }
    let fixed = a.value("agent").is_some()
        || std::env::var("NODKEY_AGENT").is_ok_and(|s| !s.trim().is_empty());
    let agent = match agent(a, profile::UNKNOWN_MCP) {
        Ok(agent) => agent,
        Err(e) => return usage_error(&e),
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => return fail(&e.to_string()),
    };
    runtime.block_on(async {
        let stdin = tokio::io::BufReader::new(tokio::io::stdin());
        crate::mcp::serve(agent, !fixed, stdin, tokio::io::stdout()).await;
    });
    ExitCode::SUCCESS
}

/// The items, follow-up window and session length of `nodkey credentials`, checked by the same
/// rules as the tool.
pub(crate) fn credential_items(a: &Args) -> Result<crate::bundle::Plan, String> {
    let wanted = a
        .positional
        .iter()
        .map(|p| crate::bundle::Wanted::parse(p))
        .collect::<Result<Vec<_>, _>>()?;
    let follow_up = a
        .value("follow-up")
        .map(|v| {
            v.trim()
                .parse::<u32>()
                .map_err(|_| "--follow-up takes whole seconds (120-600)".to_owned())
        })
        .transpose()?;
    let session = a
        .value("session")
        .map(|v| {
            v.trim()
                .parse::<u64>()
                .map_err(|_| "--session takes minutes: 15, 30 or 60".to_owned())
                .and_then(crate::bundle::session_seconds)
        })
        .transpose()?;
    Ok((wanted, follow_up, session))
}

/// The clean-up filter from the command line, checked by the same rules as the MCP tool.
pub(crate) fn cleanup_filter(a: &Args) -> Result<nodkey_proto::CleanupFilter, String> {
    let mut filter = Map::new();
    for key in ["query", "username", "domain", "group"] {
        if let Some(v) = a.value(key) {
            filter.insert(key.to_owned(), json!(v));
        }
    }
    for key in ["ip-only", "never-used"] {
        if a.flag(key) {
            filter.insert(key.replace('-', "_"), json!(true));
        }
    }
    for key in [
        "last-used-before",
        "added-before",
        "password-changed-before",
    ] {
        if let Some(v) = a.value(key) {
            let value = match v.trim().parse::<u64>() {
                Ok(n) => json!(n),
                Err(_) => json!(v),
            };
            filter.insert(key.replace('-', "_"), value);
        }
    }
    let mut args = Map::new();
    args.insert("filter".to_owned(), Value::Object(filter));
    crate::filter::cleanup_filter(&args).map_err(|e| e.replace("filter.", "--").replace('_', "-"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Result<Args, String> {
        Args::parse(&list.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn parsing() {
        let a = args(&[
            "github.com",
            "--reason",
            "Merge #4",
            "--field=code",
            "--json",
        ])
        .unwrap();
        assert_eq!(a.positional, ["github.com"]);
        assert_eq!(a.value("reason"), Some("Merge #4"));
        assert_eq!(a.value("field"), Some("code"));
        assert!(a.flag("json") && !a.flag("remove"));
        assert!(args(&["--reason"]).is_err());
        assert!(args(&["--nope"]).is_err());
        assert!(args(&["--json=1"]).is_err());
        assert!(args(&["--reason", "a", "--reason", "b"]).is_err());
    }

    #[test]
    fn checks_before_sending() {
        let ok = |c: &str, l: &[&str]| check(c, &args(l).unwrap());
        assert!(ok("code", &["github.com", "--reason", "x"]).is_ok());
        assert!(
            ok("code", &["github.com"])
                .unwrap_err()
                .contains("--reason")
        );
        assert!(ok("code", &["a", "b", "--reason", "x"]).is_err());
        assert!(ok("login", &["vg.no", "--reason", "x", "--ip-only"]).is_err());
        assert!(
            ok(
                "credentials",
                &["login:vg.no", "code:github.com", "--reason", "x"]
            )
            .is_ok()
        );
        assert!(
            ok("credentials", &["--reason", "x"])
                .unwrap_err()
                .contains("ITEM")
        );
        assert!(ok("credentials", &["vg.no", "--reason", "x"]).is_err());
        assert!(
            ok("credentials", &["login:vg.no"])
                .unwrap_err()
                .contains("--reason")
        );
        assert!(
            ok(
                "credentials",
                &["login:vg.no", "--reason", "x", "--follow-up", "soon"]
            )
            .is_err()
        );
        assert!(ok("phones", &["--json"]).is_ok());
        assert!(ok("unpair", &[]).is_err());
        assert!(
            ok("cleanup", &["--reason", "x"])
                .unwrap_err()
                .contains("at least one")
        );
        assert!(ok("cleanup", &["--ip-only"]).is_err());
        assert!(
            ok(
                "cleanup",
                &["--ip-only", "--reason", "x", "--last-used-before", "soon"]
            )
            .unwrap_err()
            .contains("--last-used-before")
        );
    }

    #[test]
    fn cleanup_flags() {
        let f = cleanup_filter(
            &args(&[
                "--ip-only",
                "--query",
                "*.old-company.example",
                "--last-used-before",
                "2022-01-01",
                "--added-before",
                "1700000000",
            ])
            .unwrap(),
        )
        .unwrap();
        assert_eq!(f.ip_only, Some(true));
        assert_eq!(f.query.as_deref(), Some("*.old-company.example"));
        assert_eq!(f.last_used_before, Some(1_640_995_200));
        assert_eq!(f.added_before, Some(1_700_000_000));
    }
}
