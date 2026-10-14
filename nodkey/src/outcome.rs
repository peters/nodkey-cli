//! The JSON a request returns: the decision, what the phone sent and a message for the model.

use std::time::Duration;

use nodkey_proto::{Account, AccountEntry, Answer, CardEntry, Decision, Kind, Lease, MatchKind};
use serde::Serialize;

/// What a request tool returns.
#[derive(Serialize)]
pub struct Outcome<'a> {
    decision: Decision,
    request_id: &'a str,
    phone: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    account: Option<&'a Account>,
    /// How the phone found the account: `direct`, `alias` (an extra website) or `chosen` (by hand).
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
    accounts: Option<Accounts<'a>>,
    /// `list_accounts`: the cards this agent may use (no numbers), when cards are on for it.
    #[serde(skip_serializing_if = "Option::is_none")]
    cards: Option<&'a [CardEntry]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    moved: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lease: Option<&'a Lease>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attachment_warning: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    insights: Option<&'a serde_json::Value>,
    /// Why the phone refused without asking (`paused`, `empty_filter`, `unsupported_version`, ...).
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
    message: String,
}

/// The `accounts` of a result: account names for `list_accounts`, or the logins a clean-up moved
/// (title, user name and site; no code or password flags, they mean nothing there).
#[derive(Serialize)]
#[serde(untagged)]
enum Accounts<'a> {
    Names(&'a [AccountEntry]),
    Moved(Vec<MovedLogin<'a>>),
}

#[derive(Serialize)]
struct MovedLogin<'a> {
    title: &'a str,
    name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    site: Option<&'a str>,
}

/// The phone refused without asking because the user paused this agent (or all agents).
/// How to read and use clean-up insights.
const INSIGHTS: &str = "The user approved. These are counts and anonymous groups only: sites (d_…) share a site, \
    usernames (u_…) share a user name; spread is how many user names or sites, years are when last used or added. \
    Propose clean-up rules to the user from these numbers (e.g. a large group unused for years, logins for IP \
    addresses or test hosts) and wait for them to choose. To act on a group, call cleanup_logins with \
    {\"group\": \"<id>\"}; the phone shows them the real site or user name before anything moves.";

pub(crate) const OLD_PROTOCOL: &str = "The phone could not read this request: Nodkey on the iPhone and this nodkey \
    speak different protocol versions. Update both (the app from the App Store, nodkey with its installer) \
    and try again.";

/// Added to the message when the user picked the account by hand.
const CHOSEN: &str = " No saved account matched the site you asked for, so the user picked this one by hand \
    (account.site may differ). Use it for this sign-in only.";

pub(crate) const PAUSED: &str = "The user has paused this agent in Nodkey, so the phone refused without asking. \
    Do not retry; tell them, and they can resume it under Agents.";

impl<'a> Outcome<'a> {
    pub fn from_answer(
        a: &'a Answer,
        kind: Kind,
        phone: &'a str,
        attachment_warning: Option<String>,
    ) -> Self {
        if kind == Kind::Cleanup {
            return Self::from_cleanup(a, phone);
        }
        let mut message = match a.decision {
            Decision::Approved if a.password.is_some() => {
                "The user approved. Use these credentials for this sign-in only; do not store, log or repeat them."
            }
            Decision::Approved if a.code.is_some() => {
                "The user approved. Use the code right away (it is valid for seconds_left more seconds); do not store it."
            }
            Decision::Approved if kind == Kind::Insights => INSIGHTS,
            Decision::Approved => "The user approved.",
            Decision::Denied if a.error.as_deref() == Some("paused") => PAUSED,
            Decision::Denied
                if matches!(
                    a.error.as_deref(),
                    Some("unsupported_version" | "unsupported_kind")
                ) =>
            {
                OLD_PROTOCOL
            }
            Decision::Denied => {
                "The user denied the request. Do not ask again for the same thing unless they say so."
            }
            Decision::Expired => "The request expired on the phone without an answer.",
        }
        .to_owned();
        if a.decision == Decision::Approved && a.match_kind == Some(MatchKind::Chosen) {
            message.push_str(CHOSEN);
        }
        Outcome {
            decision: a.decision,
            request_id: &a.request_id,
            phone,
            account: a.account.as_ref(),
            match_kind: a.match_kind,
            code: a.code.as_ref().map(|c| c.expose()),
            seconds_left: a.seconds_left,
            username: a.username.as_deref(),
            password: a.password.as_ref().map(|p| p.expose()),
            accounts: a.accounts.as_deref().map(Accounts::Names),
            cards: a.cards.as_deref().filter(|_| kind == Kind::List),
            moved: None,
            lease: a.lease.as_ref(),
            attachment_warning,
            insights: a.insights.as_ref().filter(|_| kind == Kind::Insights),
            error: a.error.as_deref(),
            message,
        }
    }

    /// A clean-up answer: how many logins were moved and which (names only).
    fn from_cleanup(a: &'a Answer, phone: &'a str) -> Self {
        let moved = a.moved.unwrap_or(0);
        let message = match a.decision {
            Decision::Approved if moved == 0 => {
                "No saved login on the phone matched the filter, so nothing was moved.".to_owned()
            }
            Decision::Approved => format!(
                "The user confirmed. {moved} saved login{} moved to Recently deleted on their iPhone; they can \
                 restore them there for 30 days. Nothing was deleted for good.",
                if moved == 1 { " was" } else { "s were" }
            ),
            Decision::Denied if a.error.as_deref() == Some("paused") => PAUSED.to_owned(),
            Decision::Denied if matches!(a.error.as_deref(), Some("unsupported_version" | "unsupported_kind")) => {
                OLD_PROTOCOL.to_owned()
            }
            Decision::Denied if a.error.as_deref() == Some("empty_filter") => {
                "The phone refused the request because the filter had no criterion. Nothing was moved."
                    .to_owned()
            }
            Decision::Denied => {
                "The user denied the clean-up. Nothing was moved; do not ask again for the same thing unless they say so."
                    .to_owned()
            }
            Decision::Expired => {
                "The request expired on the phone without an answer. Nothing was moved.".to_owned()
            }
        };
        let accounts = a
            .accounts
            .as_deref()
            .filter(|_| a.decision == Decision::Approved)
            .map(|list| {
                Accounts::Moved(
                    list.iter()
                        .map(|e| MovedLogin {
                            title: &e.issuer,
                            name: &e.name,
                            site: e.site.as_deref(),
                        })
                        .collect(),
                )
            });
        Outcome {
            decision: a.decision,
            request_id: &a.request_id,
            phone,
            account: None,
            match_kind: None,
            code: None,
            seconds_left: None,
            username: None,
            password: None,
            accounts,
            cards: None,
            moved: (a.decision == Decision::Approved).then_some(moved),
            lease: None,
            attachment_warning: None,
            insights: None,
            error: a.error.as_deref(),
            message,
        }
    }

    pub fn expired(
        request_id: &'a str,
        phone: &'a str,
        after: Duration,
        attachment_warning: Option<String>,
    ) -> Self {
        Outcome {
            decision: Decision::Expired,
            request_id,
            phone,
            account: None,
            match_kind: None,
            code: None,
            seconds_left: None,
            username: None,
            password: None,
            accounts: None,
            cards: None,
            moved: None,
            lease: None,
            attachment_warning,
            insights: None,
            error: None,
            message: format!(
                "No answer from the phone within {} s. The user may be away from their iPhone; ask them before trying again.",
                after.as_secs()
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::text;
    use serde_json::json;

    #[test]
    fn outcome_messages() {
        let mut a = Answer::decision("rid", Decision::Approved);
        a.code = Some(nodkey_proto::Secret::new("123456"));
        a.seconds_left = Some(20);
        let t = text(&Outcome::from_answer(&a, Kind::Code, "Test iPhone", None));
        let v: serde_json::Value = serde_json::from_str(&t).unwrap();
        assert_eq!(v["code"], "123456");
        assert_eq!(v["decision"], "approved");
        assert_eq!(v["phone"], "Test iPhone");
        assert!(v.get("password").is_none());
        let t = text(&Outcome::expired(
            "rid",
            "P",
            Duration::from_secs(120),
            None,
        ));
        assert!(t.contains("120 s"));
    }

    #[test]
    fn chosen_account_and_extra_websites() {
        let mut a = Answer::decision("rid", Decision::Approved);
        a.username = Some("alex@example.com".into());
        a.password = Some(nodkey_proto::Secret::new("pw"));
        a.account = Some(Account {
            issuer: "OpenAI".into(),
            name: "alex@example.com".into(),
            site: Some("openai.com".into()),
            sites: Some(vec!["chatgpt.com".into()]),
        });
        a.match_kind = Some(MatchKind::Chosen);
        let v: serde_json::Value =
            serde_json::from_str(&text(&Outcome::from_answer(&a, Kind::Login, "P", None))).unwrap();
        assert_eq!(v["match"], "chosen");
        assert_eq!(v["account"]["sites"], json!(["chatgpt.com"]));
        assert!(
            v["message"]
                .as_str()
                .unwrap()
                .contains("picked this one by hand")
        );
        a.match_kind = Some(MatchKind::Alias);
        let v: serde_json::Value =
            serde_json::from_str(&text(&Outcome::from_answer(&a, Kind::Login, "P", None))).unwrap();
        assert_eq!(v["match"], "alias");
        assert!(!v["message"].as_str().unwrap().contains("by hand"));
    }

    #[test]
    fn cleanup_outcomes() {
        let mut a = Answer::decision("rid", Decision::Approved);
        a.moved = Some(2);
        a.accounts = Some(vec![
            AccountEntry {
                issuer: "192.168.1.1".into(),
                name: "admin".into(),
                site: Some("192.168.1.1".into()),
                has_code: false,
                has_password: true,
                sites: None,
            },
            AccountEntry {
                issuer: "Printer".into(),
                name: "demo".into(),
                site: None,
                has_code: false,
                has_password: true,
                sites: None,
            },
        ]);
        let v: serde_json::Value =
            serde_json::from_str(&text(&Outcome::from_answer(&a, Kind::Cleanup, "P", None)))
                .unwrap();
        assert_eq!(v["moved"], 2);
        assert_eq!(
            v["accounts"],
            json!([{"title": "192.168.1.1", "name": "admin", "site": "192.168.1.1"}, {"title": "Printer", "name": "demo"}])
        );
        assert!(v["message"].as_str().unwrap().contains("Recently deleted"));

        a.moved = Some(0);
        a.accounts = Some(vec![]);
        let v: serde_json::Value =
            serde_json::from_str(&text(&Outcome::from_answer(&a, Kind::Cleanup, "P", None)))
                .unwrap();
        assert_eq!(v["moved"], 0);
        assert!(v["message"].as_str().unwrap().contains("nothing was moved"));

        let mut refused = Answer::decision("rid", Decision::Denied);
        refused.error = Some("empty_filter".into());
        let v: serde_json::Value = serde_json::from_str(&text(&Outcome::from_answer(
            &refused,
            Kind::Cleanup,
            "P",
            None,
        )))
        .unwrap();
        assert_eq!(v["decision"], "denied");
        assert!(v.get("moved").is_none() && v.get("accounts").is_none());
        assert!(v["message"].as_str().unwrap().contains("no criterion"));
    }
}
