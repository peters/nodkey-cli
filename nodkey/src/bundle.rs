//! Bundles: several codes and logins in one request (the `request_credentials` tool and
//! `nodkey credentials`), approved by the user in one go, item by item. With a session length the
//! bundle is a task plan: it may also name passkeys, and the session covers later requests for the
//! approved items (see [`crate::session`]).

use nodkey_proto::{
    Account, Answer, BundleItem, BundleItemAnswer, BundleRequest, ClientInfo, Decision, Kind,
    Lease, MatchKind, SessionInfo, site,
};
use serde::Serialize;

use crate::{
    agent::{Agent, Progress, Reported, Text, new_request, text},
    outcome::{OLD_PROTOCOL, Outcome, is_paused, limit_note, paused},
};

/// One code, login or passkey an agent wants: `kind` and `target`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wanted {
    pub kind: Kind,
    pub target: String,
}

impl Wanted {
    /// `login:chatgpt.com` or `code:github.com/alex` (the command line's form).
    pub fn parse(text: &str) -> Result<Self, String> {
        let (kind, target) = text.split_once(':').ok_or_else(|| {
            format!("{text:?}: give each item as login:TARGET, code:TARGET, secret:TARGET or passkey:SITE")
        })?;
        Ok(Wanted {
            kind: kind_named(kind)?,
            target: target.trim().to_owned(),
        })
    }
}

/// `code`, `login`, `secret` or `passkey`.
pub fn kind_named(name: &str) -> Result<Kind, String> {
    match name.trim() {
        "code" => Ok(Kind::Code),
        "login" => Ok(Kind::Login),
        "passkey" => Ok(Kind::Passkey),
        "secret" => Ok(Kind::Secret),
        other => Err(format!(
            "{other:?} is not an item kind; a bundle holds code, login, secret and (with a session) passkey items"
        )),
    }
}

/// The session length in seconds for `minutes` (15, 30 or 60).
pub fn session_seconds(minutes: u64) -> Result<u32, String> {
    u32::try_from(minutes)
        .ok()
        .and_then(nodkey_proto::session::length_for_minutes)
        .ok_or_else(|| "session_minutes must be 15, 30 or 60".to_owned())
}

/// What a `request_credentials` call or `nodkey credentials` asks for: the items, the follow-up
/// window and the session length (seconds).
pub type Plan = (Vec<Wanted>, Option<u32>, Option<u32>);

/// The `items`, `follow_up_seconds` and `session_minutes` (as seconds) of a
/// `request_credentials` call.
pub fn from_args(args: &serde_json::Map<String, serde_json::Value>) -> Result<Plan, String> {
    let items = args.get("items").and_then(|v| v.as_array()).ok_or(
        "items is required: a list of {\"kind\": \"login\", \"code\" or \"passkey\", \"target\": \"...\"}",
    )?;
    let mut wanted = Vec::new();
    for item in items {
        let obj = item
            .as_object()
            .ok_or("each item is an object with kind and target")?;
        if let Some(key) = obj
            .keys()
            .find(|k| !["kind", "target"].contains(&k.as_str()))
        {
            return Err(format!(
                "unknown item field {key:?}; an item has kind and target"
            ));
        }
        let field = |key: &str| {
            obj.get(key)
                .and_then(|v| v.as_str())
                .ok_or(format!("each item needs {key} (a string)"))
        };
        wanted.push(Wanted {
            kind: kind_named(field("kind")?)?,
            target: field("target")?.trim().to_owned(),
        });
    }
    let follow_up = match args.get("follow_up_seconds") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => Some(
            v.as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or("follow_up_seconds must be a whole number of seconds")?,
        ),
    };
    let session = match args.get("session_minutes") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => Some(session_seconds(
            v.as_u64().ok_or("session_minutes must be 15, 30 or 60")?,
        )?),
    };
    Ok((wanted, follow_up, session))
}

impl Agent {
    /// Asks for several codes and logins at once and waits for the user's answer. Items are
    /// numbered "1", "2", ... in the order given. `session`: seconds of a task session to start.
    /// `image_path`: a picture for the notification.
    #[allow(clippy::too_many_arguments)]
    pub async fn credentials(
        &self,
        wanted: Vec<Wanted>,
        reason: &str,
        follow_up: Option<u32>,
        session: Option<u32>,
        image_path: Option<&str>,
        phone_selector: Option<&str>,
        reported: Reported<'_>,
        progress: Progress<'_>,
    ) -> Result<Text, String> {
        let bundle = BundleRequest {
            items: wanted
                .into_iter()
                .enumerate()
                .map(|(i, w)| BundleItem {
                    id: (i + 1).to_string(),
                    kind: w.kind,
                    target: w.target.trim().to_owned(),
                })
                .collect(),
            follow_up,
            session,
        };
        bundle.check()?;
        let client = ClientInfo {
            model: reported.model.map(str::to_owned),
            effort: reported.effort.map(str::to_owned),
            ..self.client.lock().expect("lock").clone()
        };
        let mut request = new_request(Kind::Bundle, "", reason, client);
        request.bundle = Some(bundle);
        let asked = request.bundle.clone();
        let ex = self
            .exchange(request, image_path, phone_selector, progress)
            .await?;
        Ok(text(
            &match &ex.answer {
                Some(answer) => serde_json::to_value(outcome(
                    answer,
                    asked.as_ref(),
                    &ex.phone,
                    ex.attachment_warning.clone(),
                )),
                None => serde_json::to_value(Outcome::expired(
                    &ex.request_id,
                    &ex.phone,
                    self.timing.request,
                    ex.attachment_warning.clone(),
                )),
            }
            .map_err(|e| e.to_string())?,
        ))
    }
}

/// What `request_credentials` returns.
#[derive(Serialize)]
pub struct BundleOutcome<'a> {
    decision: Decision,
    request_id: &'a str,
    phone: &'a str,
    /// How many items the user approved, of how many asked.
    approved: usize,
    of: usize,
    items: Vec<ItemOutcome<'a>>,
    /// The task session the approval started: later requests for approved items go through.
    #[serde(skip_serializing_if = "Option::is_none")]
    session: Option<&'a SessionInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attachment_warning: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
    /// With `quota_warning`, or `paused` by the agent limit: the count behind it.
    #[serde(skip_serializing_if = "Option::is_none")]
    quota: Option<&'a nodkey_proto::Quota>,
    message: String,
}

#[derive(Serialize)]
struct ItemOutcome<'a> {
    id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<Kind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<&'a str>,
    decision: Decision,
    #[serde(skip_serializing_if = "Option::is_none")]
    account: Option<&'a Account>,
    #[serde(rename = "match", skip_serializing_if = "Option::is_none")]
    match_kind: Option<MatchKind>,
    /// A login or code item: the only sites where it may be filled (or below them).
    #[serde(skip_serializing_if = "Option::is_none")]
    fill_only_on: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    seconds_left: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<&'a nodkey_proto::SignInMethod>,
    #[serde(skip_serializing_if = "Option::is_none")]
    via: Option<crate::signin::ViaOut<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    second_step: Option<&'a nodkey_proto::SecondStepOrder>,
    /// A `secret` item: the key (without its value in a task plan).
    #[serde(skip_serializing_if = "Option::is_none")]
    secret: Option<&'a nodkey_proto::SecretAnswer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lease: Option<&'a Lease>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
}

/// The tool result for a bundle answer, with each item's target from the request.
pub fn outcome<'a>(
    a: &'a Answer,
    asked: Option<&'a BundleRequest>,
    phone: &'a str,
    attachment_warning: Option<String>,
) -> BundleOutcome<'a> {
    let items: Vec<ItemOutcome> = a
        .items
        .iter()
        .flatten()
        .map(|i: &BundleItemAnswer| {
            let wanted = asked.and_then(|b| b.items.iter().find(|w| w.id == i.id));
            let fill_only_on = wanted
                .filter(|w| {
                    i.decision == Decision::Approved && matches!(w.kind, Kind::Code | Kind::Login)
                })
                .zip(i.account.as_ref())
                .map(|(w, account)| site::fill_only_on(&w.target, account, i.match_kind))
                .filter(|sites| !sites.is_empty());
            ItemOutcome {
                id: &i.id,
                kind: wanted.map(|w| w.kind),
                target: wanted.map(|w| w.target.as_str()),
                decision: i.decision,
                account: i.account.as_ref(),
                match_kind: i.match_kind,
                fill_only_on,
                code: i.code.as_ref().map(|c| c.expose()),
                seconds_left: i.seconds_left,
                username: i.username.as_deref(),
                password: i.password.as_ref().map(|p| p.expose()),
                method: i.method.as_ref(),
                via: crate::signin::via_out(i.method.as_ref(), i.via.as_ref()),
                second_step: i.second_step.as_ref(),
                secret: i
                    .secret
                    .as_ref()
                    .filter(|_| i.decision == Decision::Approved),
                lease: i.lease.as_ref(),
                error: i.error.as_deref(),
            }
        })
        .collect();
    let approved = items
        .iter()
        .filter(|i| i.decision == Decision::Approved)
        .count();
    let of = asked.map_or(items.len(), |b| b.items.len());
    let chosen = items
        .iter()
        .any(|i| i.match_kind == Some(MatchKind::Chosen));
    let message = match a.decision {
        Decision::Approved => {
            let mut m = format!(
                "The user approved {approved} of {of} items. Use each item's credentials only for its own sign-in; \
                 do not store, log or repeat them. Codes are valid for their seconds_left; for a while after the \
                 approval a fresh code for an approved item is answered without asking (request_code with the \
                 same target)."
            );
            if approved < of {
                m.push_str(" Items with decision denied were left out; do not ask for them again unless the user says so.");
            }
            if chosen {
                m.push_str(" Items with match chosen: the account is not saved for that site, and the user picked it \
                    by hand for it.");
            }
            if items.iter().any(|i| i.fill_only_on.is_some()) {
                m.push_str(" Fill each login or code only on a page whose host is in its fill_only_on or below; check \
                    the address bar first, and if the page is elsewhere, stop and tell the user.");
            }
            if items.iter().any(|i| i.method.is_some() || i.via.is_some()) {
                m.push_str(" An item's method says how the user signs in to its site; fill an item's via (the provider \
                    login) only on its fill_only_on sites, never on the item's own site.");
            }
            if items.iter().any(|i| i.secret.is_some()) {
                m.push_str(" A secret item carries its key in secret.value (in a task session it has no value: \
                    later nodkey run --secret calls for it go through without asking). Never put a key in a file, a \
                    commit or a chat message; prefer nodkey run --secret, so a key never enters this conversation.");
            }
            if let Some(info) = &a.session {
                let minutes = info.until.saturating_sub(nodkey_proto::unix_now()).div_ceil(60);
                m.push_str(&format!(
                    " A task session runs for about {minutes} more minutes: request_code, request_login and passkey \
                     sign-ins and keys (nodkey run --secret) for the approved items go through without asking the \
                     user again. Call end_session \
                     when the task is done."
                ));
            } else if asked.is_some_and(|b| b.session.is_some()) && a.quota.is_some() {
                m.push_str(" The phone did not start a task session because of the limit notice; each later request is asked.");
            } else if asked.is_some_and(|b| b.session.is_some()) {
                m.push_str(" The phone did not start a task session (its app may be older); ask as usual for anything else.");
            }
            m
        }
        Decision::Denied if a.error.as_deref() == Some("bad_bundle") => {
            "The phone could not read this bundle. Its Nodkey app may be older than task sessions (passkey items, \
             more than 6 items) or than keys (secret items): ask the user to update Nodkey, or ask for at most 6 \
             code and login items."
                .to_owned()
        }
        Decision::Denied if is_paused(a) => paused(a),
        Decision::Denied
            if matches!(
                a.error.as_deref(),
                Some("unsupported_version" | "unsupported_kind")
            ) =>
        {
            OLD_PROTOCOL.to_owned()
        }
        Decision::Denied => {
            "The user denied the request. Do not ask again for the same things unless they say so."
                .to_owned()
        }
        Decision::Expired => "The request expired on the phone without an answer.".to_owned(),
        Decision::Queued | Decision::Rejected => crate::outcome::MISFIT.to_owned(),
    } + &limit_note(a);
    BundleOutcome {
        decision: a.decision,
        request_id: &a.request_id,
        phone,
        approved,
        of,
        items,
        session: a.session.as_ref(),
        attachment_warning,
        error: a.error.as_deref(),
        quota: a.quota.as_ref(),
        message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::text;
    use nodkey_proto::Secret;

    #[test]
    fn wanted_items() {
        assert_eq!(
            Wanted::parse("login:chatgpt.com").unwrap(),
            Wanted {
                kind: Kind::Login,
                target: "chatgpt.com".into()
            }
        );
        assert_eq!(
            Wanted::parse("code: github.com/alex").unwrap().kind,
            Kind::Code
        );
        assert!(Wanted::parse("chatgpt.com").is_err());
        assert!(
            Wanted::parse("list:x")
                .unwrap_err()
                .contains("code, login, secret and")
        );
        assert_eq!(
            Wanted::parse("passkey:github.com").unwrap().kind,
            Kind::Passkey
        );
    }

    #[test]
    fn tool_arguments() {
        let args = |v: serde_json::Value| v.as_object().unwrap().clone();
        let (wanted, follow, session) = from_args(&args(serde_json::json!({
            "items": [{"kind": "login", "target": " chatgpt.com "}], "follow_up_seconds": 300
        })))
        .unwrap();
        assert_eq!(wanted[0].target, "chatgpt.com");
        assert_eq!(follow, Some(300));
        assert_eq!(session, None);
        let (wanted, _, session) = from_args(&args(serde_json::json!({
            "items": [{"kind": "passkey", "target": "github.com"}], "session_minutes": 60
        })))
        .unwrap();
        assert_eq!(wanted[0].kind, Kind::Passkey);
        assert_eq!(session, Some(3600));
        for (bad, want) in [
            (serde_json::json!({}), "items is required"),
            (
                serde_json::json!({"items": [{"kind": "list", "target": "x"}]}),
                "code, login, secret and",
            ),
            (serde_json::json!({"items": [{"kind": "code"}]}), "target"),
            (
                serde_json::json!({"items": [{"kind": "code", "target": "x", "site": "y"}]}),
                "unknown item field",
            ),
            (
                serde_json::json!({"items": [], "follow_up_seconds": "soon"}),
                "whole number",
            ),
            (
                serde_json::json!({"items": [], "session_minutes": 45}),
                "15, 30 or 60",
            ),
        ] {
            assert!(from_args(&args(bad)).unwrap_err().contains(want), "{want}");
        }
    }

    #[test]
    fn outcome_counts_and_targets() {
        let asked = BundleRequest {
            items: vec![
                BundleItem {
                    id: "1".into(),
                    kind: Kind::Login,
                    target: "chatgpt.com".into(),
                },
                BundleItem {
                    id: "2".into(),
                    kind: Kind::Code,
                    target: "github.com".into(),
                },
            ],
            follow_up: None,
            session: None,
        };
        let mut a = Answer::decision("rid", Decision::Approved);
        let mut login = BundleItemAnswer::decision("1", Decision::Approved);
        login.username = Some("alex@example.com".into());
        login.password = Some(Secret::new("pw"));
        login.match_kind = Some(MatchKind::Chosen);
        a.items = Some(vec![
            login,
            BundleItemAnswer::decision("2", Decision::Denied),
        ]);
        let v: serde_json::Value =
            serde_json::from_str(&text(&outcome(&a, Some(&asked), "P", None))).unwrap();
        assert_eq!(v["approved"], 1);
        assert_eq!(v["of"], 2);
        assert_eq!(v["items"][0]["target"], "chatgpt.com");
        assert_eq!(v["items"][0]["kind"], "login");
        assert_eq!(v["items"][0]["password"], "pw");
        assert_eq!(v["items"][0]["match"], "chosen");
        assert_eq!(v["items"][1]["decision"], "denied");
        let message = v["message"].as_str().unwrap();
        assert!(
            message.contains("1 of 2")
                && message.contains("left out")
                && message.contains("by hand")
        );

        let mut paused = Answer::decision("rid", Decision::Denied);
        paused.error = Some("paused".into());
        let v: serde_json::Value =
            serde_json::from_str(&text(&outcome(&paused, Some(&asked), "P", None))).unwrap();
        assert_eq!(v["approved"], 0);
        assert!(v["message"].as_str().unwrap().contains("paused"));
    }
}
