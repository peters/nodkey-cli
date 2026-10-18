//! Sign-in methods on the agent side (docs/agent-protocol.md, "Sign-in methods"): what a result
//! says about `method`, `via` and `second_step`, the `suggest_sign_in_method` tool and
//! `nodkey suggest`, and the `request_sms_code` tool and `nodkey sms-code`.

use std::time::Duration;

use nodkey_proto::{
    Account, Answer, Certainty, ClientInfo, Decision, Kind, MethodSource, Provider,
    SecondStepOrder, SignInKind, SignInMethod, SuggestOutcome, Suggestion, Via, client, signin,
};
use serde::Serialize;
use serde_json::{Map, Value};

use crate::{
    agent::{Agent, Progress, Reported, Text, new_request, text},
    cli::Args,
    outcome::{OLD_PROTOCOL, Outcome, paused},
};

/// The provider login as a result shows it, with the only sites where it may be filled.
#[derive(Serialize)]
pub struct ViaOut<'a> {
    account: &'a Account,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    seconds_left: Option<u32>,
    /// Fill this login only on these sites or below them, never on the target site.
    fill_only_on: Vec<String>,
}

/// `via` for a result; `None` without a method to tell where it may be filled.
pub fn via_out<'a>(method: Option<&SignInMethod>, via: Option<&'a Via>) -> Option<ViaOut<'a>> {
    let via = via?;
    let fill_only_on = signin::via_sites(method?, via);
    Some(ViaOut {
        account: &via.account,
        username: via.username.as_deref(),
        password: via.password.as_ref().map(|p| p.expose()),
        code: via.code.as_ref().map(|c| c.expose()),
        seconds_left: via.seconds_left,
        fill_only_on,
    })
}

/// What the model should do with the method, the provider login and the second step order of an
/// approved answer; empty when the answer has none of them.
pub fn notes(
    method: Option<&SignInMethod>,
    via: Option<&Via>,
    order: Option<&SecondStepOrder>,
) -> String {
    let mut m = String::new();
    match (method, via) {
        (Some(method), Some(via)) => {
            let provider = method.provider_label().unwrap_or_default();
            let sites = signin::via_sites(method, via).join(", ");
            m.push_str(&format!(
                " The user signs in to this site with {provider}: choose \"Sign in with {provider}\" there. via is \
                 the {provider} login: fill it only on {provider}'s own pages ({sites} or below), never on the target \
                 site; if the target site itself asks for the {provider} password, stop and tell the user."
            ));
        }
        (Some(method), None) if method.kind == SignInKind::Federated => {
            let provider = method.provider_label().unwrap_or_default();
            m.push_str(&format!(
                " The user signs in to this site with {provider}. If {provider}'s page asks for its login, ask for it \
                 with request_login on {provider}'s own site."
            ));
        }
        (Some(method), _) => m.push_str(match method.kind {
            SignInKind::Passkey => " The user signs in to this site with a passkey: use the passkey option first.",
            SignInKind::EmailCode => {
                " The site sends a code by e-mail: read only the newest mail from that site (the last 5 minutes) with \
                 your own mail tool if you have one (method.mailbox is the address); else ask the user for the code."
            }
            SignInKind::Sso => " The user signs in to this site with the company's single sign-on.",
            SignInKind::Sms => {
                " The site sends a code by SMS: use request_sms_code only when the site offers nothing better."
            }
            _ => "",
        }),
        (None, _) => {}
    }
    if let Some(order) = order {
        let words = |steps: &[nodkey_proto::SecondStep]| {
            steps
                .iter()
                .filter_map(|s| {
                    serde_json::to_value(s)
                        .ok()
                        .and_then(|v| v.as_str().map(str::to_owned))
                })
                .collect::<Vec<_>>()
                .join(", ")
        };
        m.push_str(&format!(
            " At a second step, choose in this order: {} (passkey = a Nodkey passkey, totp = a Nodkey code: \
             via.code on the provider's page, else request_code); avoid {} and pick \"Try another way\" when the site offers them first.",
            if order.prefer.is_empty() { "what the site offers".to_owned() } else { words(&order.prefer) },
            if order.avoid.is_empty() { "nothing".to_owned() } else { words(&order.avoid) },
        ));
    }
    m
}

/// How much longer than a usual request the agent waits for this one: an `sms_code` request
/// stays at the relay for its envelope's `ttl`.
pub fn extra_wait(request: &nodkey_proto::Request) -> Duration {
    let ttl = client::relay_ttl(request).map_or(0, u64::from);
    Duration::from_secs(ttl.saturating_sub(120))
}

/// A suggestion from the tool's or command's words: `kind`, `provider` (a known name or the
/// provider's own, e.g. Okta), `mailbox` and `outcome`.
pub fn suggestion(
    kind: &str,
    provider: Option<&str>,
    mailbox: Option<&str>,
    outcome: &str,
) -> Result<Suggestion, String> {
    let kind: SignInKind = serde_json::from_value(Value::String(kind.trim().replace('-', "_")))
        .map_err(|_| {
            format!("kind {kind:?} must be password, federated, passkey, email_code, sso or sms")
        })?;
    let outcome = match outcome.trim() {
        "signed_in" | "signed-in" => SuggestOutcome::SignedIn,
        "failed" => SuggestOutcome::Failed,
        other => return Err(format!("outcome {other:?} must be signed_in or failed")),
    };
    let mut method = SignInMethod::new(kind);
    if let Some(name) = provider.map(str::trim).filter(|p| !p.is_empty()) {
        let p = Provider::parse(name);
        method.provider = Some(p);
        if p == Provider::Other && !name.eq_ignore_ascii_case("other") {
            method.provider_name = Some(name.to_owned());
        }
    }
    method.mailbox = mailbox
        .map(str::trim)
        .filter(|m| !m.is_empty())
        .map(str::to_owned);
    method.certainty = (outcome == SuggestOutcome::SignedIn).then_some(Certainty::Seen);
    method.source = Some(MethodSource::Agent);
    let s = Suggestion { method, outcome };
    s.check()?;
    Ok(s)
}

/// What `suggest_sign_in_method` returns.
#[derive(Serialize)]
struct SuggestOutcomeOut<'a> {
    decision: Decision,
    request_id: &'a str,
    phone: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
    message: String,
}

fn suggest_message(a: &Answer) -> String {
    match (a.decision, a.error.as_deref()) {
        (Decision::Queued, _) => {
            "The suggestion is in the user's list in Nodkey; they accept it with one tap. \
            Do not send it again."
                .into()
        }
        (Decision::Rejected, Some(signin::errors::RATE_LIMITED)) => format!(
            "The phone takes at most {} suggestions per hour ({} per day) from this agent. Do not retry now; \
             it is fine to skip this suggestion.",
            signin::SUGGEST_PER_HOUR,
            signin::SUGGEST_PER_DAY
        ),
        (Decision::Rejected | Decision::Denied, Some("paused")) => paused(a),
        (_, Some("unsupported_kind")) => {
            "Nodkey on the iPhone does not know suggestions yet (the app is older). \
            Nothing to do; do not retry."
                .into()
        }
        (_, Some("unsupported_version")) => OLD_PROTOCOL.into(),
        (Decision::Rejected, _) => "The phone did not take the suggestion. Do not retry it.".into(),
        (Decision::Expired, _) => {
            "The phone did not answer in time. Do not retry the suggestion.".into()
        }
        _ => "The phone did not take the suggestion. Do not retry it.".into(),
    }
}

impl Agent {
    /// Sends a `suggest` request: a sign-in method for the user's suggestion list. No Face ID; the
    /// phone answers at once with `queued` or `rejected`.
    #[allow(clippy::too_many_arguments)]
    pub async fn suggest(
        &self,
        target: &str,
        suggestion: Suggestion,
        reason: &str,
        phone_selector: Option<&str>,
        reported: Reported<'_>,
        progress: Progress<'_>,
    ) -> Result<Text, String> {
        let site = signin::site(target).ok_or_else(|| {
            format!("target {target:?} is not a website; give the site's host, e.g. example.com")
        })?;
        let mut request = new_request(Kind::Suggest, &site, reason, self.client_for(reported));
        request.suggest = Some(suggestion);
        let ex = self
            .exchange(request, None, phone_selector, progress)
            .await?;
        let expired = Answer::decision(&ex.request_id, Decision::Expired);
        let a = ex.answer.as_ref().unwrap_or(&expired);
        Ok(text(&SuggestOutcomeOut {
            decision: a.decision,
            request_id: &ex.request_id,
            phone: &ex.phone,
            error: a.error.as_deref(),
            message: suggest_message(a),
        }))
    }

    /// Sends an `sms_code` request and waits for the code that the user's Shortcuts automation
    /// passes to Nodkey, approved with Face ID.
    #[allow(clippy::too_many_arguments)]
    pub async fn sms_code(
        &self,
        target: &str,
        reason: &str,
        wait_seconds: Option<u32>,
        image_path: Option<&str>,
        phone_selector: Option<&str>,
        reported: Reported<'_>,
        progress: Progress<'_>,
    ) -> Result<Text, String> {
        let mut request = new_request(Kind::SmsCode, target, reason, self.client_for(reported));
        request.wait_seconds = wait_seconds;
        let total = self.timing.request + extra_wait(&request);
        let ex = self
            .exchange(request, image_path, phone_selector, progress)
            .await?;
        Ok(text(&match &ex.answer {
            Some(a) => Outcome::from_answer(a, Kind::SmsCode, &ex.phone, None),
            None => Outcome::expired(&ex.request_id, &ex.phone, total, None)
                .with_message(SMS_EXPIRED.into()),
        }))
    }

    /// The client info for a request, with the model and effort a call reports.
    fn client_for(&self, reported: Reported<'_>) -> ClientInfo {
        ClientInfo {
            model: reported.model.map(str::to_owned),
            effort: reported.effort.map(str::to_owned),
            ..self.client.lock().expect("lock").clone()
        }
    }
}

/// The message of an `sms_code` request that got no code.
pub const SMS_EXPIRED: &str = "No SMS code reached Nodkey in time. The user may not have the Shortcuts \
    automation that passes codes to Nodkey (\"Send code to Nodkey\"), or the SMS came before the request. Ask the \
    user to type the code, or to ask the site for a new one; do not loop.";

/// Runs `suggest_sign_in_method` and `request_sms_code` for the MCP server.
pub async fn call(
    agent: &Agent,
    name: &str,
    args: &Map<String, Value>,
    reported: Reported<'_>,
    progress: Progress<'_>,
) -> Result<Text, String> {
    use crate::mcp::{opt_str, req_str};
    let phone = opt_str(args, "phone")?;
    if name == "request_sms_code" {
        let wait = match args.get("wait_seconds") {
            None | Some(Value::Null) => None,
            Some(v) => Some(
                v.as_u64()
                    .and_then(|n| u32::try_from(n).ok())
                    .ok_or("wait_seconds must be a whole number of seconds")?,
            ),
        };
        return agent
            .sms_code(
                req_str(args, "target")?,
                req_str(args, "reason")?,
                wait,
                opt_str(args, "image_path")?,
                phone,
                reported,
                progress,
            )
            .await;
    }
    let s = suggestion(
        req_str(args, "kind")?,
        opt_str(args, "provider")?,
        opt_str(args, "mailbox")?,
        req_str(args, "outcome")?,
    )?;
    agent
        .suggest(
            req_str(args, "target")?,
            s,
            req_str(args, "reason")?,
            phone,
            reported,
            progress,
        )
        .await
}

/// The options of `nodkey suggest` and `nodkey sms-code`, checked before anything is sent.
pub fn check_cli(command: &str, a: &Args) -> Result<(), String> {
    let common = ["reason", "phone", "model", "effort"];
    if command == "sms-code" {
        a.only(
            command,
            &[&common[..], &["wait", "field", "image"]].concat(),
        )?;
        a.positionals(command, 1, "one TARGET, e.g. account.example.com")?;
        sms_wait(a)?;
    } else {
        a.only(
            command,
            &[&common[..], &["kind", "provider", "mailbox", "outcome"]].concat(),
        )?;
        a.positionals(command, 1, "one SITE, e.g. example.com")?;
        cli_suggestion(a)?;
    }
    a.value("reason")
        .map(|_| ())
        .ok_or_else(|| format!("nodkey {command} needs --reason: say in one sentence why"))
}

fn cli_suggestion(a: &Args) -> Result<Suggestion, String> {
    let kind = a.value("kind").ok_or(
        "nodkey suggest needs --kind (password, federated, passkey, email_code, sso or sms)",
    )?;
    suggestion(
        kind,
        a.value("provider"),
        a.value("mailbox"),
        a.value("outcome").unwrap_or("signed_in"),
    )
}

fn sms_wait(a: &Args) -> Result<Option<u32>, String> {
    a.value("wait")
        .map(|w| {
            w.trim()
                .parse::<u32>()
                .ok()
                .filter(|&n| signin::sms_wait(Some(n)).is_some())
                .ok_or_else(|| {
                    format!(
                        "--wait must be {} to {} seconds",
                        signin::SMS_WAIT_MIN,
                        signin::SMS_WAIT_MAX
                    )
                })
        })
        .transpose()
}

/// `nodkey suggest` and `nodkey sms-code`: the result as JSON (or one field), and the exit code.
pub async fn run_cli(
    command: &str,
    a: &Args,
    agent: &Agent,
    reported: Reported<'_>,
) -> Result<(Value, u8), String> {
    let quiet = |_: u64, _: u64, _: &str| {};
    let target = &a.positional[0];
    let reason = a.value("reason").unwrap_or_default();
    let text = if command == "sms-code" {
        eprintln!("Waiting for the SMS code and your answer in Nodkey on your iPhone ...");
        agent
            .sms_code(
                target,
                reason,
                sms_wait(a)?,
                a.value("image"),
                a.value("phone"),
                reported,
                &quiet,
            )
            .await?
    } else {
        agent
            .suggest(
                target,
                cli_suggestion(a)?,
                reason,
                a.value("phone"),
                reported,
                &quiet,
            )
            .await?
    };
    let v: Value = serde_json::from_str(&text).map_err(|e| format!("unexpected result: {e}"))?;
    let code = crate::commands::exit_for(&v);
    Ok((v, code))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suggestions_from_words() {
        let s = suggestion("federated", Some("Okta"), None, "signed-in").unwrap();
        assert_eq!(s.method.provider, Some(Provider::Other));
        assert_eq!(s.method.provider_name.as_deref(), Some("Okta"));
        assert_eq!(s.method.certainty, Some(Certainty::Seen));
        let s = suggestion("email-code", None, Some("alex@example.com"), "failed").unwrap();
        assert_eq!(s.method.kind, SignInKind::EmailCode);
        assert_eq!(s.method.certainty, None);
        assert!(suggestion("federated", Some("other"), None, "signed_in").is_err());
        assert!(suggestion("federated", None, None, "signed_in").is_err());
        assert!(suggestion("password", None, None, "maybe").is_err());
        assert!(suggestion("magic", None, None, "signed_in").is_err());
    }

    #[test]
    fn notes_for_the_model() {
        let google = SignInMethod::federated(Provider::Google, None);
        let via = Via {
            account: Account {
                issuer: "Google".into(),
                name: "alex@example.com".into(),
                site: Some("accounts.google.com".into()),
                sites: None,
            },
            username: Some("alex@example.com".into()),
            password: None,
            code: None,
            seconds_left: None,
            next_code: None,
            next_seconds_left: None,
        };
        let n = notes(Some(&google), Some(&via), None);
        assert!(n.contains("google.com or below") && n.contains("never on the target site"));
        let n = notes(Some(&google), None, None);
        assert!(n.contains("request_login on Google's own site"));
        let n = notes(None, None, Some(&SecondStepOrder::default()));
        assert!(n.contains("passkey, totp") && n.contains("avoid app_prompt, sms"));
        assert!(notes(None, None, None).is_empty());
        assert!(via_out(None, Some(&via)).is_none());
    }
}
