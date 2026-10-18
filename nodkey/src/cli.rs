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

pub const USAGE: &str = "\
nodkey: ask Nodkey on your iPhone for one-time codes and logins

Usage:
  nodkey pair [--name NAME]                pair this agent with your iPhone (once)
  nodkey code TARGET --reason TEXT         one one-time code
  nodkey login TARGET --reason TEXT        user name and password (and a code if it has one)
  nodkey credentials ITEM... --reason TEXT up to 10 logins and codes in one request (JSON);
                                           ITEM is login:TARGET, code:TARGET or passkey:SITE
                                           (passkey items need --session)
  nodkey end-session [--reason TEXT]       end this agent's task session (from --session)
  nodkey sms-code TARGET --reason TEXT [--wait SECS] [--image FILE]
                                           a code the site sent by SMS, passed to Nodkey by your
                                           Shortcuts automation (wait 30-300 s, default 120)
  nodkey suggest SITE --kind KIND [--provider NAME] [--mailbox ADDR] [--outcome failed]
                   --reason TEXT           propose a sign-in method for your suggestion list
                                           (KIND: password, federated, passkey, email_code, sso,
                                           sms; no Face ID, nothing secret)
  nodkey pay MERCHANT AMOUNT CURRENCY --reason TEXT --reveal
                                           the full payment card for ONE purchase (spends money;
                                           only when the user turned full card numbers on for
                                           this agent); e.g. nodkey pay shop.example.com 499 NOK
  nodkey accounts [--reason TEXT]          the accounts this agent may ask for (no secrets)
  nodkey insights [--reason TEXT]          anonymous clean-up numbers (JSON)
  nodkey cleanup FILTER... --reason TEXT   propose moving old saved logins to Recently deleted
  nodkey phones                            the phones this agent is paired with
  nodkey unpair PHONE                      leave a phone (phone name or id)
  nodkey agents                            the agents paired on this computer
  nodkey webauthn [--phone PHONE]          sign in with a passkey or make one: one JSON request
                                           on stdin, one JSON result on stdout (for browser hosts)
  nodkey card-fill [--phone PHONE]         a card for a browser host to fill a checkout form: one
                                           JSON request on stdin, one JSON result on stdout
  nodkey mcp                               run the MCP server on stdio
  nodkey setup [--remove] [--dry-run]      add (or remove) the MCP server and skill in your agents
  nodkey skill                             print the agent skill

TARGET is a site or issuer, optionally with /account: github.com/alex, vg.no, GitHub.

Options for code and login:
  --reason TEXT    why, in one sentence; shown on your lock screen (required)
  --image FILE     a PNG, JPEG or GIF (at most 1 MiB) shown in the notification
  --field NAME     print only this field (code, username, password, seconds_left, ...)
  --phone PHONE    which phone, when this agent is paired with more than one
  --model NAME     --effort LEVEL   shown in the history on the phone

Options for credentials: --reason, --image, --phone, --model, --effort as above, and
  --session MIN     a task session: for 15, 30 or 60 minutes, codes, logins and passkey
                    sign-ins for the approved items go through without asking again
  --follow-up SECS  without a session: how long a fresh code for an approved item follows
                    without asking (120-600)

Options for pay: --reason, --image, --field (number, cvc, exp_month, ...), --phone, --model,
  --effort as above, and --reveal (required: the card number is printed). Without a browser
  host nothing can fill the card for you; the user decides on the iPhone every time.

Clean-up filter (every one you give must hold; at least one):
  --ip-only  --never-used  --query PATTERN  --username NAME  --domain DOMAIN  --group ID
  --last-used-before DATE  --added-before DATE  --password-changed-before DATE
  PATTERN and NAME take * and ?; DATE is YYYY-MM-DD or Unix seconds.

Global options:
  --agent NAME     which agent identity to use (default: terminal; also $NODKEY_AGENT)
  --relay URL      the relay (default: $NODKEY_RELAY, else relay in config.json, else
                   https://relay.nodkey.app)
  --json           print JSON for accounts, cleanup, phones, agents, unpair and pair
  -h, --help       -V, --version

Exit codes: 0 approved, queued or done, 1 error, 2 denied or rejected, 3 expired (no answer),
4 paused (the user or the agent limit paused this agent; resume it under Agents), 64 bad arguments;
pay and card-fill: 5 over the user's limit, 6 full card numbers off, 7 cards off or no card,
8 the page total is higher than the amount.
Environment: NODKEY_AGENT_DIR (default ~/.config/nodkey-agent), NODKEY_REQUEST_TIMEOUT (120 s),
NODKEY_PAIR_TIMEOUT (300 s), NODKEY_DEBUG.
";

pub(crate) const DENIED: u8 = 2;
pub(crate) const EXPIRED: u8 = 3;
/// The agent is paused (`error: paused`), by the user or by its limit.
pub(crate) const PAUSED: u8 = 4;
const BAD_ARGS: u8 = 64;

const VALUE_FLAGS: [&str; 23] = [
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
    if rest.iter().any(|a| a == "-h" || a == "--help") {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let args = match Args::parse(rest) {
        Ok(a) => a,
        Err(e) if command == "webauthn" => return crate::webauthn::bad_input(&e),
        Err(e) if command == "card-fill" => return crate::cardfill::bad_input(&e),
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
        "card-fill" => return crate::cardfill::main(&args, agent(&args, profile::TERMINAL)),
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

fn usage_error(e: &str) -> ExitCode {
    eprintln!("nodkey: {e}\nRun `nodkey --help` for the commands.");
    ExitCode::from(BAD_ARGS)
}

fn fail(e: &str) -> ExitCode {
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

/// The agent for these arguments: `--agent`, else `$NODKEY_AGENT`, else `default_profile`.
fn agent(a: &Args, default_profile: &str) -> Result<Agent, String> {
    let env_agent = std::env::var("NODKEY_AGENT").ok();
    let slug = a
        .value("agent")
        .or(env_agent.as_deref().filter(|s| !s.trim().is_empty()))
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
