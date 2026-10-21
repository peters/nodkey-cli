//! Making a password (docs/agent-protocol.md, "Making a password"): `kind: generate` asks the
//! phone to make a new password for a sign-up or a password change, save it, and give it to the
//! agent or the browser to fill in (peters/nodkey#131).
//!
//! The request names the page ([`GenerateRequest`]) and its rules ([`Rules`], read by
//! [`rules`]). The phone always asks with Face ID or the passcode, saves the password before it
//! answers, and answers with `password`, `username` (as the user confirmed it), `account` and
//! `saved` (`added` or `updated`). Never a lease, a task session or a bundle.

use serde::{Deserialize, Serialize};

use crate::{Answer, Decision, LeaseKind, Saved, site};

mod make;
pub mod rules;

pub use rules::{CharSet, Reading};

/// The length of a password when the rules allow it.
pub const DEFAULT_LENGTH: u32 = 20;
/// The longest password Nodkey makes.
pub const MAX_LENGTH: u32 = 128;
/// The symbols Nodkey prefers, in ASCII order.
pub const SYMBOLS: &str = "!#$%*+-.=?@_";
/// How many passwords the phone tries against `pattern` before it answers `bad_rules`.
pub const PATTERN_TRIES: u32 = 100;
/// How long the phone keeps the replaced password of an updated login, in days.
pub const KEEP_OLD_DAYS: u32 = 30;
/// Longest `url`, `username`, `title`, `passwordrules` and `pattern`, in characters.
pub const MAX_URL: usize = 500;
pub const MAX_USERNAME: usize = 200;
pub const MAX_TITLE: usize = 100;
pub const MAX_RULES: usize = 300;
pub const MAX_PATTERN: usize = 300;

/// Why the phone refused a `generate` request (`decision: denied`, `Answer.error`).
pub mod errors {
    /// The phone has no passcode, so it cannot verify who approves; at once (#126).
    pub const NO_PASSCODE: &str = "no_passcode";
    /// The agent's scope is `codes`; at once.
    pub const NOT_ALLOWED: &str = "not_allowed";
    /// The request breaks a rule of [`super::GenerateRequest::check`]; at once.
    pub const BAD_GENERATE: &str = "bad_generate";
    /// No password Nodkey makes can meet the rules ([`super::Rules::check`], or none of
    /// [`super::PATTERN_TRIES`] passwords matched `pattern`); at once.
    pub const BAD_RULES: &str = "bad_rules";
    /// The user approved, but the phone could not save the password, so it gave none.
    pub const SAVE_FAILED: &str = "save_failed";
    /// The refusals the phone makes at once, after `paused`, in the order it checks.
    pub const IN_ORDER: [&str; 4] = [NO_PASSCODE, NOT_ALLOWED, BAD_GENERATE, BAD_RULES];
}

/// The page a `generate` request makes a password for. `target` is the page's host.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerateRequest {
    /// The page's address without query and fragment (`https://accounts.example.com/signup`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// The user name the agent or the page knows; the user can correct it on the phone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// A title for a new login (the service's name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// The page changes the password of an existing account.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub change: bool,
    /// What the page says about the password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<Rules>,
}

/// The rules of the new password field: its `passwordrules`, `minlength`, `maxlength` and
/// `pattern` attributes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rules {
    /// Apple's syntax (`minlength: 12; required: lower; required: digit;`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passwordrules: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_length: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_length: Option<u32>,
    /// A JavaScript regular expression the whole password must match; only the phone checks it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
}

impl Rules {
    /// True when no rule is set.
    pub fn is_empty(&self) -> bool {
        *self == Rules::default()
    }
}

/// The host a `generate` request names for `site` (a URL or a host), and the address to send
/// as `url`: the URL without query and fragment, `None` for a bare host. `None` when `site` is
/// not a website.
pub fn page(site: &str) -> Option<(String, Option<String>)> {
    let s = site.trim();
    let host = site::host(s)?;
    let lower = s.to_ascii_lowercase();
    if !(lower.starts_with("https://") || lower.starts_with("http://")) {
        return (!s.contains("://")).then_some((host, None));
    }
    let end = s.find(['?', '#']).unwrap_or(s.len());
    Some((host, Some(s[..end].to_owned())))
}

impl GenerateRequest {
    /// The rules both sides check (the phone answers `bad_generate` when one fails). `target` is
    /// the request's.
    pub fn check(&self, target: &str) -> Result<(), String> {
        if site::host(target).as_deref() != Some(target) {
            return Err(
                "target is the host of the page, in lower case, e.g. accounts.example.com".into(),
            );
        }
        text("url", self.url.as_deref(), MAX_URL)?;
        text("username", self.username.as_deref(), MAX_USERNAME)?;
        text("title", self.title.as_deref(), MAX_TITLE)?;
        if let Some(url) = &self.url {
            let lower = url.to_ascii_lowercase();
            if !(lower.starts_with("https://") || lower.starts_with("http://")) {
                return Err("url is an https:// or http:// address".into());
            }
            if url.contains(['?', '#']) {
                return Err("url has no query or fragment; they can hold tokens".into());
            }
            if site::host(url).as_deref() != Some(target) {
                return Err("the host of url is target".into());
            }
        }
        if let Some(r) = &self.rules {
            text("passwordrules", r.passwordrules.as_deref(), MAX_RULES)?;
            text("pattern", r.pattern.as_deref(), MAX_PATTERN)?;
        }
        Ok(())
    }
}

fn text(name: &str, value: Option<&str>, max: usize) -> Result<(), String> {
    match value {
        Some(v) if v.chars().count() > max => {
            Err(format!("{name} is longer than {max} characters"))
        }
        Some(v) if v.chars().any(char::is_control) => {
            Err(format!("{name} must not hold control characters"))
        }
        _ => Ok(()),
    }
}

/// The agent's check of an approved answer: it carries a password, says it was saved (`added`
/// or `updated`), and no lease other than `once` answered it. The text says what is wrong.
pub fn check_answer(a: &Answer) -> Result<(), &'static str> {
    if a.decision != Decision::Approved {
        return Ok(());
    }
    if a.password.as_ref().is_none_or(|p| p.expose().is_empty()) {
        return Err("the phone approved but sent no password");
    }
    if !matches!(a.saved, Some(Saved::Added | Saved::Updated)) {
        return Err("the phone sent a password but did not say that it saved it");
    }
    if a.lease.as_ref().is_some_and(|l| l.kind != LeaseKind::Once) {
        return Err("the phone answered under a lease, which a new password never has");
    }
    Ok(())
}

/// Where the password of an approved answer may be filled: the website of `target`.
pub fn fill_only_on(target: &str) -> Vec<String> {
    site::site_key(target).into_iter().collect()
}

#[cfg(test)]
mod tests;
