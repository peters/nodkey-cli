//! Bundles: several codes and logins in one request (the `request_credentials` tool and
//! `nodkey credentials`), approved by the user in one go, item by item.

use nodkey_proto::{
    Account, Answer, BundleItem, BundleItemAnswer, BundleRequest, ClientInfo, Decision, Kind,
    Lease, MatchKind,
};
use serde::Serialize;

use crate::{
    agent::{Agent, Progress, Reported, Text, new_request, text},
    outcome::{OLD_PROTOCOL, Outcome, PAUSED},
};

/// One code or login an agent wants: `kind` (`code` or `login`) and `target`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wanted {
    pub kind: Kind,
    pub target: String,
}

impl Wanted {
    /// `login:chatgpt.com` or `code:github.com/alex` (the command line's form).
    pub fn parse(text: &str) -> Result<Self, String> {
        let (kind, target) = text
            .split_once(':')
            .ok_or_else(|| format!("{text:?}: give each item as login:TARGET or code:TARGET"))?;
        Ok(Wanted {
            kind: kind_named(kind)?,
            target: target.trim().to_owned(),
        })
    }
}

/// `code` or `login`.
pub fn kind_named(name: &str) -> Result<Kind, String> {
    match name.trim() {
        "code" => Ok(Kind::Code),
        "login" => Ok(Kind::Login),
        other => Err(format!(
            "{other:?} is not an item kind; a bundle holds code and login items"
        )),
    }
}

/// The `items` and `follow_up_seconds` of a `request_credentials` call.
pub fn from_args(
    args: &serde_json::Map<String, serde_json::Value>,
) -> Result<(Vec<Wanted>, Option<u32>), String> {
    let items = args.get("items").and_then(|v| v.as_array()).ok_or(
        "items is required: a list of {\"kind\": \"login\" or \"code\", \"target\": \"...\"}",
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
    Ok((wanted, follow_up))
}

impl Agent {
    /// Asks for several codes and logins at once and waits for the user's answer. Items are
    /// numbered "1", "2", ... in the order given. `image_path`: a picture for the notification.
    #[allow(clippy::too_many_arguments)]
    pub async fn credentials(
        &self,
        wanted: Vec<Wanted>,
        reason: &str,
        follow_up: Option<u32>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    attachment_warning: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    seconds_left: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<&'a str>,
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
            ItemOutcome {
                id: &i.id,
                kind: wanted.map(|w| w.kind),
                target: wanted.map(|w| w.target.as_str()),
                decision: i.decision,
                account: i.account.as_ref(),
                match_kind: i.match_kind,
                code: i.code.as_ref().map(|c| c.expose()),
                seconds_left: i.seconds_left,
                username: i.username.as_deref(),
                password: i.password.as_ref().map(|p| p.expose()),
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
                m.push_str(" Items with match chosen: nothing matched that site and the user picked the account by hand.");
            }
            m
        }
        Decision::Denied if a.error.as_deref() == Some("paused") => PAUSED.to_owned(),
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
    };
    BundleOutcome {
        decision: a.decision,
        request_id: &a.request_id,
        phone,
        approved,
        of,
        items,
        attachment_warning,
        error: a.error.as_deref(),
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
                .contains("code and login")
        );
    }

    #[test]
    fn tool_arguments() {
        let args = |v: serde_json::Value| v.as_object().unwrap().clone();
        let (wanted, follow) = from_args(&args(serde_json::json!({
            "items": [{"kind": "login", "target": " chatgpt.com "}], "follow_up_seconds": 300
        })))
        .unwrap();
        assert_eq!(wanted[0].target, "chatgpt.com");
        assert_eq!(follow, Some(300));
        for (bad, want) in [
            (serde_json::json!({}), "items is required"),
            (
                serde_json::json!({"items": [{"kind": "list", "target": "x"}]}),
                "code and login",
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
