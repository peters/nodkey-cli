//! Bundles (`kind: bundle`): several codes and logins in one request, so a sign-in that needs a
//! login on one site and a code on another asks the user once. The phone answers each item on its
//! own; the bundle is `approved` when the user approved at least one item.

use serde::{Deserialize, Serialize};

use crate::{Account, Decision, Kind, Lease, MatchKind, Secret, client::MAX_TARGET};

/// At most this many items in one bundle.
pub const MAX_ITEMS: usize = 6;
/// The follow-up window (seconds) an agent may ask for; the default is the usual 120 s.
pub const FOLLOW_UP_MIN: u32 = 120;
pub const FOLLOW_UP_MAX: u32 = 600;
/// Longest item id, in characters.
pub const MAX_ITEM_ID: usize = 16;

/// What a `bundle` request asks for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleRequest {
    pub items: Vec<BundleItem>,
    /// For how many seconds after the approval a fresh code for an approved item is answered
    /// without asking (120 to 600; absent means 120).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub follow_up: Option<u32>,
}

/// One code or login in a bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleItem {
    /// The agent's name for the item, unique in the bundle ("1", "chatgpt"); the answer uses it.
    pub id: String,
    /// `code` or `login`.
    pub kind: Kind,
    /// As in a single request: a site or issuer, optionally `/account`.
    pub target: String,
}

impl BundleRequest {
    /// The rules both sides check before anything is sent or shown.
    pub fn check(&self) -> Result<(), String> {
        if self.items.is_empty() || self.items.len() > MAX_ITEMS {
            return Err(format!("a bundle holds 1 to {MAX_ITEMS} items"));
        }
        let mut ids = std::collections::HashSet::new();
        for item in &self.items {
            let id = item.id.trim();
            if id.is_empty() || id.chars().count() > MAX_ITEM_ID {
                return Err(format!(
                    "every item needs an id of 1 to {MAX_ITEM_ID} characters"
                ));
            }
            if !ids.insert(id) {
                return Err(format!("the item id {id:?} is used twice"));
            }
            if !matches!(item.kind, Kind::Code | Kind::Login) {
                return Err(format!(
                    "item {id:?}: a bundle holds only code and login items"
                ));
            }
            let target = item.target.trim();
            if target.is_empty() {
                return Err(format!(
                    "item {id:?}: target is required (a site or issuer, optionally /account)"
                ));
            }
            if target.chars().count() > MAX_TARGET {
                return Err(format!("item {id:?}: target is too long"));
            }
        }
        match self.follow_up {
            Some(s) if !(FOLLOW_UP_MIN..=FOLLOW_UP_MAX).contains(&s) => Err(format!(
                "follow_up must be {FOLLOW_UP_MIN} to {FOLLOW_UP_MAX} seconds"
            )),
            _ => Ok(()),
        }
    }
}

/// The phone's answer for one item of a bundle. Only the fields that apply are present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleItemAnswer {
    pub id: String,
    /// `approved` or `denied` (the user left the item out, or nothing could answer it).
    pub decision: Decision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<Account>,
    #[serde(default, rename = "match", skip_serializing_if = "Option::is_none")]
    pub match_kind: Option<MatchKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<Secret>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seconds_left: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<Secret>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease: Option<Lease>,
    /// Why the phone left the item out without asking (`not_allowed`: the agent's scope).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl BundleItemAnswer {
    /// An item answer with only a decision.
    pub fn decision(id: &str, decision: Decision) -> Self {
        BundleItemAnswer {
            id: id.to_owned(),
            decision,
            account: None,
            match_kind: None,
            code: None,
            seconds_left: None,
            username: None,
            password: None,
            lease: None,
            error: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(id: &str, kind: Kind, target: &str) -> BundleItem {
        BundleItem {
            id: id.into(),
            kind,
            target: target.into(),
        }
    }

    #[test]
    fn rules() {
        let ok = BundleRequest {
            items: vec![
                item("1", Kind::Login, "chatgpt.com"),
                item("2", Kind::Code, "github.com/alex"),
            ],
            follow_up: Some(300),
        };
        assert!(ok.check().is_ok());
        let with = |f: &dyn Fn(&mut BundleRequest)| {
            let mut b = ok.clone();
            f(&mut b);
            b.check()
        };
        assert!(with(&|b| b.items.clear()).unwrap_err().contains("1 to 6"));
        assert!(
            with(&|b| b.items = (0..7)
                .map(|i| item(&i.to_string(), Kind::Code, "x"))
                .collect())
            .is_err()
        );
        assert!(
            with(&|b| b.items[1].id = "1".into())
                .unwrap_err()
                .contains("twice")
        );
        assert!(with(&|b| b.items[0].id = " ".into()).is_err());
        assert!(with(&|b| b.items[0].id = "x".repeat(17)).is_err());
        assert!(
            with(&|b| b.items[0].kind = Kind::List)
                .unwrap_err()
                .contains("only code and login")
        );
        assert!(
            with(&|b| b.items[0].target = " ".into())
                .unwrap_err()
                .contains("target")
        );
        assert!(
            with(&|b| b.follow_up = Some(60))
                .unwrap_err()
                .contains("120 to 600")
        );
        assert!(with(&|b| b.follow_up = Some(601)).is_err());
        assert!(with(&|b| b.follow_up = None).is_ok());
    }

    #[test]
    fn json_names() {
        let mut a = BundleItemAnswer::decision("1", Decision::Approved);
        a.match_kind = Some(MatchKind::Alias);
        let text = serde_json::to_string(&a).unwrap();
        assert_eq!(text, r#"{"id":"1","decision":"approved","match":"alias"}"#);
        let b = BundleRequest {
            items: vec![item("1", Kind::Code, "github.com")],
            follow_up: None,
        };
        assert_eq!(
            serde_json::to_string(&b).unwrap(),
            r#"{"items":[{"id":"1","kind":"code","target":"github.com"}]}"#
        );
    }
}
