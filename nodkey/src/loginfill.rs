//! `nodkey login-fill`: the command a browser host (Horizon) calls to fill a sign-in form with a
//! login from the phone, so the password goes to the host and not into the model's conversation.
//! It reads one JSON request on stdin and writes one JSON result on stdout, also when it fails
//! (waiting notes go to stderr). The host fills the form and gives the model only `summary`. The
//! login comes out only when the page's origin is on its `fill_only_on`. See
//! docs/agent-protocol.md, "The login fill command".

use std::{io::Read, process::ExitCode};

use nodkey_proto::{Account, Decision, Kind, Secret, site};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    agent::{Agent, Exchanged, Text, new_request, text},
    cli::{Args, DENIED, EXPIRED},
};

const BAD_INPUT: u8 = 64;
const PAUSED: u8 = 4;
/// Largest request read from stdin.
const MAX_INPUT: u64 = 16 * 1024;

/// The JSON a host sends on stdin.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    version: u8,
    /// The sign-in page's origin, as the host saw the frame (never from the page or the model).
    origin: String,
    /// The site and account to ask for (`vg.no`, `github.com/alex`); the origin's host when absent.
    target: Option<String>,
    reason: Option<String>,
    requester: Option<Requester>,
}

/// Who asks, as the host says (self-reported; shown in the phone's history).
#[derive(Debug, Default, Deserialize)]
struct Requester {
    app: Option<String>,
    agent: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
struct Checked {
    origin: String,
    target: String,
    reason: String,
    app: Option<String>,
}

/// Reads and checks the input.
fn parse(bytes: &[u8]) -> Result<Checked, String> {
    let input: Input = serde_json::from_slice(bytes).map_err(|e| format!("bad request: {e}"))?;
    if input.version != 1 {
        return Err(format!("unsupported version {}", input.version));
    }
    let origin = input.origin.trim().to_owned();
    let host = match origin.split_once("://") {
        Some(("https", _)) | Some(("http", _)) => site::host(&origin),
        _ => None,
    }
    .ok_or("origin must be the page's origin, for example https://www.vg.no")?;
    let target = match input.target.as_deref().map(str::trim) {
        Some(t) if !t.is_empty() => t.to_owned(),
        _ => host.clone(),
    };
    let reason = match input.reason.as_deref().map(str::trim) {
        Some(r) if !r.is_empty() => r.to_owned(),
        _ => format!("Sign in to {host}"),
    };
    let r = input.requester.unwrap_or_default();
    let app = match (r.app, r.agent) {
        (Some(app), Some(agent)) => Some(format!("{app} ({agent})")),
        (app, agent) => app.or(agent),
    };
    Ok(Checked {
        origin,
        target,
        reason,
        app,
    })
}

fn failure(status: &str, message: &str, error: Option<&str>) -> Text {
    let mut v = json!({"version": 1, "status": status, "message": message});
    if let Some(e) = error {
        v["error"] = json!(e);
    }
    text(&v)
}

/// An approved result; serialized straight into a wiped buffer.
#[derive(Serialize)]
struct Filled<'a> {
    version: u8,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<&'a Secret>,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<&'a Secret>,
    #[serde(skip_serializing_if = "Option::is_none")]
    seconds_left: Option<u32>,
    account: &'a Account,
    fill_only_on: &'a [String],
    summary: String,
}

/// The result and exit code for what came back from the phone.
fn result(checked: &Checked, ex: &Exchanged) -> (Text, u8) {
    let Some(answer) = &ex.answer else {
        let msg = format!("No answer from {} in time.", ex.phone);
        return (failure("expired", &msg, None), EXPIRED);
    };
    let error = answer.error.as_deref();
    match answer.decision {
        Decision::Approved => {
            let (Some(account), Some(sites)) = (
                answer.account.as_ref(),
                crate::outcome::fill_only_on(answer, Kind::Login, &checked.target),
            ) else {
                let msg = "The phone approved but named no website for the login; nothing to fill.";
                return (failure("error", msg, None), 1);
            };
            if !site::may_fill(&checked.origin, &sites) {
                let msg = format!(
                    "The login is saved for {}, not for {}; nothing to fill.",
                    sites.join(" or "),
                    checked.origin
                );
                return (failure("wrong_site", &msg, None), 1);
            }
            if answer.password.is_none() && answer.code.is_none() {
                let msg = "The phone sent no password or code for this login; nothing to fill.";
                return (failure("error", msg, None), 1);
            }
            let name = answer.username.as_deref().unwrap_or(&account.name);
            let mut summary = format!(
                "filled: the login {name} on {}. Ask again for the next sign-in.",
                sites.join(" or ")
            );
            if error == Some(nodkey_proto::quota::errors::QUOTA_WARNING) {
                summary.push_str(
                    " The user saw a notice about many new logins and codes today; ask for fewer.",
                );
            }
            let filled = Filled {
                version: 1,
                status: "ok",
                username: answer.username.as_deref(),
                password: answer.password.as_ref(),
                code: answer.code.as_ref(),
                seconds_left: answer.seconds_left,
                account,
                fill_only_on: &sites,
                summary,
            };
            (text(&filled), 0)
        }
        Decision::Queued | Decision::Rejected | Decision::Staged => {
            (failure("error", crate::outcome::MISFIT, None), 1)
        }
        Decision::Expired => (
            failure("expired", "The request expired on the phone.", error),
            EXPIRED,
        ),
        Decision::Denied => match error {
            Some("unsupported_kind" | "unsupported_version") => (
                failure(
                    "error",
                    "Nodkey on the iPhone is too old for this request; update the app.",
                    error,
                ),
                1,
            ),
            Some("paused") => (
                failure(
                    "denied",
                    "This agent is paused in Nodkey (by the user or by its limit); the user can resume it under Agents.",
                    error,
                ),
                PAUSED,
            ),
            _ => (
                failure("denied", "The user denied the login.", error),
                DENIED,
            ),
        },
    }
}

async fn run(agent: &Agent, phone: Option<&str>, checked: Checked) -> (Text, u8) {
    let client = nodkey_proto::ClientInfo {
        app: checked.app.clone(),
        ..agent.client.lock().expect("lock").clone()
    };
    let request = new_request(Kind::Login, &checked.target, &checked.reason, client);
    let shown = std::sync::atomic::AtomicBool::new(false);
    let note = format!(
        "Waiting for your answer in Nodkey on your iPhone (up to {} s) ...",
        agent.timing.request.as_secs()
    );
    let progress = move |_: u64, _: u64, _: &str| {
        if !shown.swap(true, std::sync::atomic::Ordering::Relaxed) {
            eprintln!("{note}");
        }
    };
    match agent.exchange(request, None, phone, &progress).await {
        Ok(ex) => result(&checked, &ex),
        Err(e) => (failure("error", &e, None), 1),
    }
}

/// `nodkey login-fill [--agent PROFILE] [--phone PHONE]`.
pub fn main(args: &Args, agent: Result<Agent, String>) -> ExitCode {
    let (v, code) = match prepare(args, agent) {
        Err(msg) => (failure("error", &msg, None), BAD_INPUT),
        Ok((agent, checked)) => match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt.block_on(run(&agent, args.value("phone"), checked)),
            Err(e) => (failure("error", &e.to_string(), None), 1),
        },
    };
    println!("{}", v.as_str());
    ExitCode::from(code)
}

/// Bad arguments: the JSON result and exit code 64.
pub fn bad_input(message: &str) -> ExitCode {
    println!("{}", failure("error", message, None).as_str());
    ExitCode::from(BAD_INPUT)
}

fn prepare(args: &Args, agent: Result<Agent, String>) -> Result<(Agent, Checked), String> {
    if !args.positional.is_empty() {
        return Err("nodkey login-fill takes no arguments; it reads the request on stdin".into());
    }
    args.only("login-fill", &["phone"])?;
    // Read the request before the profile check, so a refused host can always write it.
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(MAX_INPUT + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read stdin: {e}"))?;
    let agent = agent?;
    if bytes.len() as u64 > MAX_INPUT {
        return Err("the request is larger than 16 KiB".into());
    }
    Ok((agent, parse(&bytes)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing() {
        let c = parse(br#"{"version":1,"origin":"https://www.vg.no"}"#).unwrap();
        assert_eq!(c.target, "www.vg.no");
        assert_eq!(c.reason, "Sign in to www.vg.no");
        let c = parse(
            br#"{"version":1,"origin":"https://github.com","target":"github.com/alex",
                 "reason":"Merge PR #42","requester":{"app":"Horizon","agent":"Claude Code"}}"#,
        )
        .unwrap();
        assert_eq!(c.target, "github.com/alex");
        assert_eq!(c.app.as_deref(), Some("Horizon (Claude Code)"));
        assert!(parse(br#"{"version":1,"origin":"vg.no"}"#).is_err());
        assert!(parse(br#"{"version":1,"origin":"javascript:alert(1)"}"#).is_err());
        assert!(
            parse(br#"{"version":1,"origin":"https://vg.no","password":"x"}"#)
                .unwrap_err()
                .contains("unknown field")
        );
        assert!(parse(br#"{"version":2,"origin":"https://vg.no"}"#).is_err());
    }
}
