//! The JSON a request returns: the decision, what the phone sent and a message for the model.

use std::time::Duration;

use nodkey_proto::{
    Account, AccountEntry, Answer, CardEntry, Decision, Kind, Lease, MatchKind, Quota,
    SecondStepOrder, SignInMethod, quota, site,
};
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
    /// `code`/`login`: the only sites where the login or code may be filled (or below them).
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
    /// `login`: how the user signs in to the site, when the phone knows.
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<&'a SignInMethod>,
    /// `login` with "Sign in with ...": the provider login and where it may be filled.
    #[serde(skip_serializing_if = "Option::is_none")]
    via: Option<crate::signin::ViaOut<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    second_step: Option<&'a SecondStepOrder>,
    #[serde(skip_serializing_if = "Option::is_none")]
    accounts: Option<Accounts<'a>>,
    /// `list_accounts`: the cards this agent may use (no numbers), when cards are on for it.
    #[serde(skip_serializing_if = "Option::is_none")]
    cards: Option<&'a [CardEntry]>,
    /// `list_accounts`: the names of the keys this agent may ask for (never a value).
    #[serde(skip_serializing_if = "Option::is_none")]
    secrets: Option<&'a [nodkey_proto::SecretEntry]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    moved: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lease: Option<&'a Lease>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attachment_warning: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    insights: Option<&'a serde_json::Value>,
    /// Why the phone refused without asking (`paused`, `empty_filter`, `unsupported_version`, ...),
    /// or `quota_warning`: the phone asked with the agent limit warning.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
    /// With `quota_warning`, or `paused` by the agent limit: the count behind it.
    #[serde(skip_serializing_if = "Option::is_none")]
    quota: Option<&'a Quota>,
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

/// How to read and use clean-up insights.
const INSIGHTS: &str = "The user approved. These are counts and anonymous groups only: sites (d_…) share a site, \
    usernames (u_…) share a user name; spread is how many user names or sites, years are when last used or added. \
    Propose clean-up rules to the user from these numbers (e.g. a large group unused for years, logins for IP \
    addresses or test hosts) and wait for them to choose. To act on a group, call cleanup_logins with \
    {\"group\": \"<id>\"}; the phone shows them the real site or user name before anything moves.";

/// Why the phone gives no cards or keys: it has no passcode (`no_passcode`).
pub(crate) const NO_PASSCODE: &str = "The phone has no passcode, so Nodkey hands out no cards or keys. The user can \
    set one in Settings \u{2192} Face ID & Passcode on the iPhone; do not ask again until they did.";

pub(crate) const OLD_PROTOCOL: &str = "The phone could not read this request: Nodkey on the iPhone and this nodkey \
    speak different protocol versions. Update both (the app from the App Store, nodkey with its installer) \
    and try again.";

/// Added to a list result with key names.
const KEYS: &str = " secrets lists the API keys this agent may ask for, by name only, with their projects (none: a \
    global key every project may use). To use one, run `nodkey run --secret VARIABLE[=SERVICE] -- <command>` (with \
    --project NAME, or in a repository with a .nodkey file): the key goes into the command's environment and never \
    into this conversation.";

/// Added to the message when the user picked the account by hand.
const CHOSEN: &str = " The account is not saved for the site you asked for, so the user picked it by hand for \
    that site (account.site may differ). Use it for this sign-in only.";

/// Added to the message of an approved login or code that names where it may be filled.
pub(crate) fn fill_note(sites: &[String]) -> String {
    format!(
        " Fill it only on a page whose host is {} or below; check the address bar first, and if the page is \
         elsewhere, stop and tell the user.",
        sites.join(" or ")
    )
}

/// `fill_only_on` of an approved code or login answer with an account (`None` when neither the
/// account nor the target names a website).
pub(crate) fn fill_only_on(a: &Answer, kind: Kind, target: &str) -> Option<Vec<String>> {
    if a.decision != Decision::Approved || !matches!(kind, Kind::Code | Kind::Login) {
        return None;
    }
    let sites = site::fill_only_on(target, a.account.as_ref()?, a.match_kind);
    (!sites.is_empty()).then_some(sites)
}

/// A `queued` or `rejected` answer to anything but a `suggest` request.
pub(crate) const MISFIT: &str =
    "The phone sent an answer that does not fit this request; nothing came of it.";

/// The phone refused without asking because the agent is paused: by the user (or all agents), or by
/// the agent limit (the answer then carries `quota`).
pub(crate) fn paused(a: &Answer) -> String {
    match &a.quota {
        Some(q) => format!(
            "Nodkey paused this agent: it received {} new logins and codes in the last 24 hours, more than the \
             phone allows ({}). The phone refused without asking. Do not retry; tell the user why. They can \
             resume this agent under Agents in Nodkey; after that, ask for fewer items and reuse the logins you \
             already have.",
            q.new_today,
            quota::PAUSE_ABOVE
        ),
        None => "The user has paused this agent in Nodkey, so the phone refused without asking. \
            Do not retry; tell them, and they can resume it under Agents."
            .to_owned(),
    }
}

/// Whether the agent is paused (`error: paused`).
pub(crate) fn is_paused(a: &Answer) -> bool {
    a.error.as_deref() == Some(quota::errors::PAUSED)
}

/// Added to the message when the phone asked with the agent limit warning (`quota_warning`); empty
/// otherwise.
pub(crate) fn limit_note(a: &Answer) -> String {
    if a.error.as_deref() != Some(quota::errors::QUOTA_WARNING) {
        return String::new();
    }
    let count = a.quota.as_ref().map_or_else(String::new, |q| {
        format!(
            " ({} in the last 24 hours; the user's limit for this agent is {})",
            q.new_today, q.limit
        )
    });
    let why = if a.quota.as_ref().is_some_and(|q| q.burst) {
        "many new logins and codes in a short time"
    } else {
        "many new logins and codes today"
    };
    format!(
        " Nodkey showed the user a notice: this agent has received {why}{count}. Tell the user why they were \
         asked. While the notice is on, leases and task sessions do not answer for you: each request waits for \
         the user. Ask for fewer items, reuse the logins you already have, and do not retry in a loop."
    )
}

impl<'a> Outcome<'a> {
    /// The result of `a`, the answer to a `kind` request for `target`.
    pub fn from_answer(
        a: &'a Answer,
        kind: Kind,
        phone: &'a str,
        target: &str,
        attachment_warning: Option<String>,
    ) -> Self {
        if kind == Kind::Cleanup {
            return Self::from_cleanup(a, phone);
        }
        let mut message = match a.decision {
            Decision::Approved if a.password.is_some() || a.via.is_some() => {
                "The user approved. Use these credentials for this sign-in only; do not store, log or repeat them."
            }
            Decision::Approved if a.code.is_some() => {
                "The user approved. Use the code right away (it is valid for seconds_left more seconds); do not store it."
            }
            Decision::Approved if kind == Kind::Insights => INSIGHTS,
            Decision::Approved => "The user approved.",
            Decision::Denied if is_paused(a) => return Self::paused(a, phone),
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
            Decision::Expired if kind == Kind::SmsCode => crate::signin::SMS_EXPIRED,
            Decision::Expired => "The request expired on the phone without an answer.",
            Decision::Queued | Decision::Rejected => MISFIT,
        }
        .to_owned();
        if a.decision == Decision::Approved && a.match_kind == Some(MatchKind::Chosen) {
            message.push_str(CHOSEN);
        }
        let fill_only_on = fill_only_on(a, kind, target);
        if let Some(sites) = &fill_only_on {
            message.push_str(&fill_note(sites));
        }
        let approved = a.decision == Decision::Approved;
        let method = a.method.as_ref().filter(|_| approved);
        let via = a.via.as_ref().filter(|_| approved);
        let second_step = a.second_step.as_ref().filter(|_| approved);
        message.push_str(&crate::signin::notes(method, via, second_step));
        let secrets = a
            .secrets
            .as_deref()
            .filter(|s| kind == Kind::List && !s.is_empty());
        if secrets.is_some() {
            message.push_str(KEYS);
        }
        message.push_str(&limit_note(a));
        Outcome {
            decision: a.decision,
            request_id: &a.request_id,
            phone,
            account: a.account.as_ref(),
            match_kind: a.match_kind,
            fill_only_on,
            code: a.code.as_ref().map(|c| c.expose()),
            seconds_left: a.seconds_left,
            username: a.username.as_deref(),
            password: a.password.as_ref().map(|p| p.expose()),
            method,
            via: crate::signin::via_out(method, via),
            second_step,
            accounts: a.accounts.as_deref().map(Accounts::Names),
            cards: a.cards.as_deref().filter(|_| kind == Kind::List),
            secrets,
            moved: None,
            lease: a.lease.as_ref(),
            attachment_warning,
            insights: a.insights.as_ref().filter(|_| kind == Kind::Insights),
            error: a.error.as_deref(),
            quota: a.quota.as_ref(),
            message,
        }
    }

    /// A refusal because the agent is paused: only the decision, the error and why.
    fn paused(a: &'a Answer, phone: &'a str) -> Self {
        Outcome {
            error: a.error.as_deref(),
            quota: a.quota.as_ref(),
            ..Self::empty(a.decision, &a.request_id, phone, None, paused(a))
        }
    }

    /// A result with only a decision and a message.
    fn empty(
        decision: Decision,
        request_id: &'a str,
        phone: &'a str,
        attachment_warning: Option<String>,
        message: String,
    ) -> Self {
        Outcome {
            decision,
            request_id,
            phone,
            account: None,
            match_kind: None,
            fill_only_on: None,
            code: None,
            seconds_left: None,
            username: None,
            password: None,
            method: None,
            via: None,
            second_step: None,
            accounts: None,
            cards: None,
            secrets: None,
            moved: None,
            lease: None,
            attachment_warning,
            insights: None,
            error: None,
            quota: None,
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
            Decision::Denied if is_paused(a) => return Self::paused(a, phone),
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
            Decision::Queued | Decision::Rejected => MISFIT.to_owned(),
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
            fill_only_on: None,
            code: None,
            seconds_left: None,
            username: None,
            password: None,
            method: None,
            via: None,
            second_step: None,
            accounts,
            cards: None,
            secrets: None,
            moved: (a.decision == Decision::Approved).then_some(moved),
            lease: None,
            attachment_warning: None,
            insights: None,
            error: a.error.as_deref(),
            quota: None,
            message,
        }
    }

    pub fn expired(
        request_id: &'a str,
        phone: &'a str,
        after: Duration,
        attachment_warning: Option<String>,
    ) -> Self {
        Self::empty(
            Decision::Expired,
            request_id,
            phone,
            attachment_warning,
            format!(
                "No answer from the phone within {} s. The user may be away from their iPhone; ask them before trying again.",
                after.as_secs()
            ),
        )
    }
}

impl Outcome<'_> {
    /// The same result with another message.
    pub fn with_message(mut self, message: String) -> Self {
        self.message = message;
        self
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
        let t = text(&Outcome::from_answer(
            &a,
            Kind::Code,
            "Test iPhone",
            "",
            None,
        ));
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
        let result = |a: &Answer, target: &str| -> serde_json::Value {
            serde_json::from_str(&text(&Outcome::from_answer(
                a,
                Kind::Login,
                "P",
                target,
                None,
            )))
            .unwrap()
        };
        let v = result(&a, "sora.com/alex@example.com");
        assert_eq!(v["match"], "chosen");
        assert_eq!(v["account"]["sites"], json!(["chatgpt.com"]));
        let message = v["message"].as_str().unwrap();
        assert!(message.contains("picked it by hand"));
        // Picked by hand for sora.com: filled only there.
        assert_eq!(v["fill_only_on"], json!(["sora.com"]));
        assert!(message.contains("host is sora.com or below"));
        a.match_kind = Some(MatchKind::Alias);
        let v = result(&a, "https://chatgpt.com/auth/login");
        assert_eq!(v["match"], "alias");
        assert!(!v["message"].as_str().unwrap().contains("by hand"));
        assert_eq!(v["fill_only_on"], json!(["openai.com", "chatgpt.com"]));
        // Denied: nothing to fill.
        let v = result(&Answer::decision("rid", Decision::Denied), "chatgpt.com");
        assert!(v.get("fill_only_on").is_none());
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
        let v: serde_json::Value = serde_json::from_str(&text(&Outcome::from_answer(
            &a,
            Kind::Cleanup,
            "P",
            "",
            None,
        )))
        .unwrap();
        assert_eq!(v["moved"], 2);
        assert_eq!(
            v["accounts"],
            json!([{"title": "192.168.1.1", "name": "admin", "site": "192.168.1.1"}, {"title": "Printer", "name": "demo"}])
        );
        assert!(v["message"].as_str().unwrap().contains("Recently deleted"));

        a.moved = Some(0);
        a.accounts = Some(vec![]);
        let v: serde_json::Value = serde_json::from_str(&text(&Outcome::from_answer(
            &a,
            Kind::Cleanup,
            "P",
            "",
            None,
        )))
        .unwrap();
        assert_eq!(v["moved"], 0);
        assert!(v["message"].as_str().unwrap().contains("nothing was moved"));

        let mut refused = Answer::decision("rid", Decision::Denied);
        refused.error = Some("empty_filter".into());
        let v: serde_json::Value = serde_json::from_str(&text(&Outcome::from_answer(
            &refused,
            Kind::Cleanup,
            "P",
            "",
            None,
        )))
        .unwrap();
        assert_eq!(v["decision"], "denied");
        assert!(v.get("moved").is_none() && v.get("accounts").is_none());
        assert!(v["message"].as_str().unwrap().contains("no criterion"));
    }

    #[test]
    fn limit_warning_and_pause() {
        let mut a = Answer::decision("rid", Decision::Approved);
        a.code = Some(nodkey_proto::Secret::new("123456"));
        a.error = Some("quota_warning".into());
        a.quota = Some(Quota {
            new_today: 12,
            limit: 10,
            burst: false,
        });
        let v: serde_json::Value =
            serde_json::from_str(&text(&Outcome::from_answer(&a, Kind::Code, "P", "", None)))
                .unwrap();
        assert_eq!(v["code"], "123456");
        assert_eq!(v["quota"], json!({"new_today": 12, "limit": 10}));
        let m = v["message"].as_str().unwrap();
        assert!(m.starts_with("The user approved."), "{m}");
        assert!(m.contains("12 in the last 24 hours; the user's limit for this agent is 10"));

        let mut p = Answer::decision("rid", Decision::Denied);
        p.error = Some("paused".into());
        let v: serde_json::Value =
            serde_json::from_str(&text(&Outcome::from_answer(&p, Kind::Login, "P", "", None)))
                .unwrap();
        assert!(v.get("quota").is_none());
        assert!(
            v["message"]
                .as_str()
                .unwrap()
                .starts_with("The user has paused")
        );
        p.quota = Some(Quota {
            new_today: 25,
            limit: 10,
            burst: false,
        });
        for kind in [Kind::Login, Kind::Cleanup] {
            let v: serde_json::Value =
                serde_json::from_str(&text(&Outcome::from_answer(&p, kind, "P", "", None)))
                    .unwrap();
            assert_eq!(v["error"], "paused");
            assert_eq!(v["quota"]["new_today"], 25);
            assert!(
                v["message"]
                    .as_str()
                    .unwrap()
                    .contains("received 25 new logins")
            );
        }
    }
}
