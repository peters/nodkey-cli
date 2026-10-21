//! A new password for a sign-up or a password change (docs/agent-protocol.md, "Making a
//! password"): `nodkey generate` and the MCP tool `create_login`.
//!
//! The phone makes the password by the page's rules, saves it before it answers and gives it for
//! this one sign-up, with the user name as the user confirmed it. The password only passes through
//! memory on its way into the tool result or stdout; nothing here stores it.

use std::io::Write;

use nodkey_proto::{
    Account, Answer, ClientInfo, Decision, GenerateRequest, Kind, Quota, Saved, Secret,
    generate::{self, Rules, errors},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{
    agent::{Agent, Progress, Reported, Text, new_request, text},
    cli::{Args, DENIED, EXPIRED, PAUSED},
    outcome::{MISFIT, OLD_PROTOCOL, is_paused, paused},
};

/// Exit codes of `nodkey generate` beyond the common ones (docs/agent-protocol.md).
pub const NO_PASSCODE_EXIT: u8 = 10;
pub const BAD_RULES_EXIT: u8 = 15;

/// What `nodkey generate` and `create_login` ask for.
#[derive(Debug, Clone, Default)]
pub struct NewLogin<'a> {
    /// The page's address or host.
    pub site: &'a str,
    pub username: Option<&'a str>,
    pub title: Option<&'a str>,
    pub rules: Rules,
    /// The page changes the password of an existing account.
    pub change: bool,
    pub reason: Option<&'a str>,
    pub image: Option<&'a str>,
    pub phone: Option<&'a str>,
}

impl NewLogin<'_> {
    /// The request's target and its `generate` part, checked as the phone checks them.
    pub fn request(&self) -> Result<(String, GenerateRequest), String> {
        let (target, url) = generate::page(self.site).ok_or_else(|| {
            format!(
                "{:?} is not a website; give the page's address or host, e.g. \
                 https://accounts.example.com/signup",
                self.site.trim()
            )
        })?;
        let clean = |s: Option<&str>| {
            s.map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
        };
        let g = GenerateRequest {
            url,
            username: clean(self.username),
            title: clean(self.title),
            change: self.change,
            rules: (!self.rules.is_empty()).then(|| self.rules.clone()),
        };
        g.check(&target)?;
        Ok((target, g))
    }
}

/// What `create_login` returns, and what `nodkey generate --json` prints.
#[derive(Serialize, Deserialize)]
pub struct Outcome {
    pub decision: Decision,
    pub request_id: String,
    pub phone: String,
    pub target: String,
    /// `added` (a new login) or `updated` (an existing login got the new password).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saved: Option<Saved>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<Account>,
    /// The user name as the user confirmed it on the phone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<Secret>,
    /// The only sites where the password may be filled (or below them).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fill_only_on: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota: Option<Quota>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attachment_warning: Option<String>,
    pub message: String,
}

/// What a refusal means, for the model and the user.
fn refusal(a: &Answer) -> String {
    match a.error.as_deref() {
        _ if is_paused(a) => paused(a),
        Some("unsupported_version" | "unsupported_kind") => {
            format!("{OLD_PROTOCOL} (Making a password needs a newer Nodkey on the iPhone.)")
        }
        Some(errors::NO_PASSCODE) => {
            "The iPhone has no passcode, so Nodkey cannot verify who approves a new password and \
             refused. The user can set one in Settings \u{2192} Face ID & Passcode; do not ask again \
             until they did."
                .into()
        }
        Some(errors::NOT_ALLOWED) => {
            "This agent may not get passwords (it is paired for codes only). The user can change \
             that under Agents in Nodkey."
                .into()
        }
        Some(errors::BAD_RULES) => {
            "The phone says no password can meet the page's rules (passwordrules, length, pattern). \
             Check the rules you sent against the page; if they are right, tell the user, who can \
             choose a password in Nodkey by hand."
                .into()
        }
        Some(errors::BAD_GENERATE) => "The phone refused the request as malformed.".into(),
        Some(errors::SAVE_FAILED) => {
            "The phone could not save a new password, so it gave none and nothing changed. Fill \
             nothing; tell the user."
                .into()
        }
        _ => "The user did not make a new password. Do not ask again unless they say so.".into(),
    }
}

/// The result for the phone's answer to a request for `target`.
fn outcome(a: Answer, target: &str, phone: &str) -> Result<Outcome, String> {
    generate::check_answer(&a).map_err(|why| {
        format!("The phone's answer was not used: {why}. Ask the user to look at Nodkey on their iPhone.")
    })?;
    let mut out = Outcome {
        decision: a.decision,
        request_id: a.request_id.clone(),
        phone: phone.to_owned(),
        target: target.to_owned(),
        saved: None,
        account: None,
        username: None,
        password: None,
        fill_only_on: None,
        error: a.error.clone(),
        quota: a.quota.clone(),
        attachment_warning: None,
        message: String::new(),
    };
    out.message = match a.decision {
        Decision::Approved => {
            let sites = generate::fill_only_on(target);
            let login = match a.saved {
                Some(Saved::Updated) => format!(
                    "saved it in the existing login on {phone} (the old password stays on the iPhone \
                     for {} days)",
                    generate::KEEP_OLD_DAYS
                ),
                _ => format!("saved it as a new login on {phone}"),
            };
            let message = format!(
                "The user approved. Nodkey made a new password and {login}. Use username (the user may \
                 have corrected it on the phone) and fill the password only into the new password field \
                 and its confirm field, on a page whose host is {} or below; check the address bar \
                 first, and if the page is elsewhere, stop and tell the user. Do not store, log or repeat \
                 the password: Nodkey keeps it. The page may still refuse it; then tell the user, who \
                 finds the password in Nodkey.",
                sites.join(" or ")
            );
            out.saved = a.saved;
            out.account = a.account;
            out.username = a.username;
            out.password = a.password;
            out.fill_only_on = Some(sites);
            message
        }
        Decision::Denied => refusal(&a),
        Decision::Expired => {
            "The request expired on the phone without an answer. No password was made; ask the user \
             before trying again."
                .into()
        }
        Decision::Queued | Decision::Rejected | Decision::Staged => MISFIT.into(),
    };
    Ok(out)
}

impl Agent {
    /// Asks the phone to make, save and give a new password for `new.site`, and waits for the
    /// answer. Never covered by a lease or a task session: the user approves each one.
    pub async fn create_login(
        &self,
        new: NewLogin<'_>,
        reported: Reported<'_>,
        progress: Progress<'_>,
    ) -> Result<Text, String> {
        let (target, g) = new.request()?;
        let default_reason = if g.change {
            format!("Change the password on {target}")
        } else {
            format!("Make a password to sign up on {target}")
        };
        let client = ClientInfo {
            model: reported.model.map(str::to_owned),
            effort: reported.effort.map(str::to_owned),
            ..self.client.lock().expect("lock").clone()
        };
        let reason = new.reason.unwrap_or(&default_reason);
        let mut request = new_request(Kind::Generate, &target, reason, client);
        request.generate = Some(g);
        let ex = self
            .exchange(request, new.image, new.phone, progress)
            .await?;
        let answer = ex
            .answer
            .unwrap_or_else(|| Answer::decision(&ex.request_id, Decision::Expired));
        let mut out = outcome(answer, &target, &ex.phone)?;
        out.attachment_warning = ex.attachment_warning;
        Ok(text(&out))
    }
}

/// The exit code of a result (docs/agent-protocol.md, "Making a password").
pub fn exit_code(out: &Outcome) -> u8 {
    match (out.decision, out.error.as_deref()) {
        (_, Some("paused")) => PAUSED,
        (_, Some(errors::NO_PASSCODE)) => NO_PASSCODE_EXIT,
        (_, Some(errors::BAD_RULES)) => BAD_RULES_EXIT,
        (_, Some(errors::BAD_GENERATE | errors::SAVE_FAILED)) => 1,
        (Decision::Approved, _) => 0,
        (Decision::Denied, _) => DENIED,
        (Decision::Expired, _) => EXPIRED,
        _ => 1,
    }
}

/// The rules from the command line: `--rules`, `--min`, `--max`, `--pattern`.
fn cli_rules(a: &Args) -> Result<Rules, String> {
    let number = |flag: &str| {
        a.value(flag)
            .map(|v| {
                v.trim()
                    .parse::<u32>()
                    .map_err(|_| format!("--{flag} takes a whole number of characters"))
            })
            .transpose()
    };
    Ok(Rules {
        passwordrules: a.value("rules").map(str::to_owned),
        min_length: number("min")?,
        max_length: number("max")?,
        pattern: a.value("pattern").map(str::to_owned),
    })
}

fn cli_login(a: &Args) -> Result<NewLogin<'_>, String> {
    Ok(NewLogin {
        site: a
            .value("site")
            .ok_or("nodkey generate needs --site: the page's address or host")?,
        username: a.value("user"),
        title: a.value("title"),
        rules: cli_rules(a)?,
        change: a.flag("change"),
        reason: a.value("reason"),
        image: a.value("image"),
        phone: a.value("phone"),
    })
}

/// Checks the options of `nodkey generate` before anything is sent.
pub fn check_cli(a: &Args) -> Result<(), String> {
    a.only(
        "generate",
        &[
            "site", "user", "title", "rules", "min", "max", "pattern", "change", "reason", "image",
            "phone", "model", "effort",
        ],
    )?;
    a.positionals("generate", 0, "options, not arguments: --site URL")?;
    cli_login(a)?.request().map(|_| ())
}

/// `nodkey generate`: the password alone on stdout and one line on stderr (`--json`: the whole
/// result on stdout); returns the exit code.
pub async fn run_cli(a: &Args, agent: &Agent, reported: Reported<'_>) -> Result<u8, String> {
    let note = std::sync::atomic::AtomicBool::new(false);
    let progress = |_: u64, _: u64, _: &str| {
        if !note.swap(true, std::sync::atomic::Ordering::Relaxed) {
            eprintln!(
                "Waiting for you to make the password in Nodkey on your iPhone (up to {} s) ...",
                agent.timing.request.as_secs()
            );
        }
    };
    let result = agent
        .create_login(cli_login(a)?, reported, &progress)
        .await?;
    let out: Outcome =
        serde_json::from_str(&result).map_err(|e| format!("unexpected result: {e}"))?;
    drop(result);
    let code = exit_code(&out);
    if a.flag("json") {
        println!("{}", text(&out).as_str());
    } else if let (0, Some(password)) = (code, &out.password) {
        let mut stdout = std::io::stdout().lock();
        stdout
            .write_all(password.expose().as_bytes())
            .and_then(|()| stdout.write_all(b"\n"))
            .and_then(|()| stdout.flush())
            .map_err(|e| format!("cannot write the password: {e}"))?;
    }
    if code == 0 {
        eprintln!("nodkey: {}", summary(&out));
    } else {
        eprintln!("nodkey: {}", out.message);
    }
    Ok(code)
}

/// One line for stderr about an approved password: the login and where to fill it.
fn summary(out: &Outcome) -> String {
    let name = out.username.as_deref().filter(|n| !n.is_empty());
    let site = out
        .account
        .as_ref()
        .and_then(|a| a.site.as_deref())
        .unwrap_or(&out.target);
    let login = match name {
        Some(n) => format!("the login {n} on {site}"),
        None => format!("a login without user name on {site}"),
    };
    let what = match out.saved {
        Some(Saved::Updated) => format!(
            "{login} has the new password in Nodkey on {} (the old one stays there for {} days)",
            out.phone,
            generate::KEEP_OLD_DAYS
        ),
        _ => format!("saved {login} in Nodkey on {}", out.phone),
    };
    let sites = out.fill_only_on.as_deref().unwrap_or_default().join(" or ");
    format!("{what}. Fill the password only on {sites}.")
}

/// The MCP tool `create_login`.
pub async fn call(
    agent: &Agent,
    args: &Map<String, Value>,
    reported: Reported<'_>,
    progress: Progress<'_>,
) -> Result<Text, String> {
    use crate::mcp::{opt_str, req_str};
    let change = match args.get("change") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return Err("change must be true or false".into()),
    };
    let rules = match args.get("rules") {
        None | Some(Value::Null) => Rules::default(),
        Some(Value::String(s)) => Rules {
            passwordrules: Some(s.clone()),
            ..Rules::default()
        },
        Some(Value::Object(m)) => {
            let known = ["passwordrules", "min_length", "max_length", "pattern"];
            if let Some(k) = m.keys().find(|k| !known.contains(&k.as_str())) {
                return Err(format!(
                    "rules has no {k}; it takes passwordrules, min_length, max_length and pattern"
                ));
            }
            serde_json::from_value(Value::Object(m.clone())).map_err(|e| {
                format!("rules is {{passwordrules?, min_length?, max_length?, pattern?}}: {e}")
            })?
        }
        Some(_) => return Err("rules is an object or a passwordrules string".into()),
    };
    let new = NewLogin {
        site: req_str(args, "site")?,
        username: opt_str(args, "username")?,
        title: opt_str(args, "title")?,
        rules,
        change,
        reason: Some(req_str(args, "reason")?),
        image: opt_str(args, "image_path")?,
        phone: opt_str(args, "phone")?,
    };
    agent.create_login(new, reported, progress).await
}

#[cfg(test)]
mod tests;
