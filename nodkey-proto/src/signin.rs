//! Sign-in methods (docs/agent-protocol.md, "Sign-in methods"): how a website is signed in to
//! ("Sign in with Google", a passkey, an e-mail code, ...), the provider login that does the work
//! for a "Sign in with" method (`via`), which second step to choose (`second_step`), and the two
//! requests that go with them: `suggest` (a method the agent saw work, for the user's suggestion
//! list) and `sms_code` (a code that only comes by SMS).
//!
//! Names match the app (`SiteMethod.swift`, `SecondStep.swift` in peters/nodkey); the app's
//! `emailCode` is `email_code` on the wire. Reading is tolerant like the app: an unknown provider is
//! `other` with its name, an unknown certainty is `likely`, an unknown second step is left out, and
//! an answer whose `method` this version cannot read has no `method`.

use serde::{Deserialize, Deserializer, Serialize, de::DeserializeOwned};

use crate::{Account, Secret, client::MAX_TARGET};

/// Why the phone did not queue a suggestion (`Answer.error` with `decision: rejected`).
pub mod errors {
    /// The agent sent more suggestions than [`super::SUGGEST_PER_HOUR`] or
    /// [`super::SUGGEST_PER_DAY`].
    pub const RATE_LIMITED: &str = "rate_limited";
    /// The suggestion breaks a rule of [`super::Suggestion::check`].
    pub const BAD_SUGGESTION: &str = "bad_suggestion";
}

/// Suggestions the phone takes from one agent per hour and per 24 hours; more are `rejected`.
pub const SUGGEST_PER_HOUR: u32 = 5;
pub const SUGGEST_PER_DAY: u32 = 20;

/// Longest `provider_name`, in characters.
pub const MAX_PROVIDER_NAME: usize = 40;
/// Longest `mailbox`, in characters.
pub const MAX_MAILBOX: usize = 254;

/// `wait_seconds` of an `sms_code` request: absent means the default.
pub const SMS_WAIT_DEFAULT: u32 = 120;
pub const SMS_WAIT_MIN: u32 = 30;
pub const SMS_WAIT_MAX: u32 = 300;
/// After the wait, the user has this many seconds to approve a code that arrived. The relay keeps
/// an `sms_code` request for `wait_seconds` plus this (the envelope's `ttl`).
pub const SMS_APPROVE_MARGIN: u32 = 60;

/// How a website is signed in to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignInKind {
    /// A user name and a password saved in Nodkey.
    Password,
    /// "Sign in with Google" (or Apple, GitHub, ...): the provider's own login does the work.
    Federated,
    /// A passkey.
    Passkey,
    /// A code the site sends by e-mail (the app's `emailCode`).
    EmailCode,
    /// The company's single sign-on.
    Sso,
    /// A code the site sends by SMS.
    Sms,
}

/// Whose account a "Sign in with" method uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    Google,
    Apple,
    Github,
    Microsoft,
    Facebook,
    /// Another provider; [`SignInMethod::provider_name`] names it.
    Other,
}

impl Provider {
    /// A provider from a protocol value or a name ("google", "GitHub"); unknown names are `Other`.
    pub fn parse(name: &str) -> Self {
        match name.trim().to_ascii_lowercase().as_str() {
            "google" => Provider::Google,
            "apple" => Provider::Apple,
            "github" => Provider::Github,
            "microsoft" => Provider::Microsoft,
            "facebook" => Provider::Facebook,
            _ => Provider::Other,
        }
    }

    /// The name people know ("Google"); empty for `Other`.
    pub const fn display(self) -> &'static str {
        match self {
            Provider::Google => "Google",
            Provider::Apple => "Apple",
            Provider::Github => "GitHub",
            Provider::Microsoft => "Microsoft",
            Provider::Facebook => "Facebook",
            Provider::Other => "",
        }
    }

    /// The exact hosts of the provider's own sign-in pages: where its login may be filled
    /// ([`via_sites`]). Not the whole domain: `google.com` also has pages anyone can make
    /// (`sites.google.com`). Empty for `Other`.
    pub const fn sign_in_hosts(self) -> &'static [&'static str] {
        match self {
            Provider::Google => &["accounts.google.com"],
            Provider::Apple => &["appleid.apple.com", "idmsa.apple.com", "account.apple.com"],
            Provider::Github => &["github.com"],
            Provider::Microsoft => &[
                "login.microsoftonline.com",
                "login.live.com",
                "login.microsoft.com",
            ],
            Provider::Facebook => &["www.facebook.com", "m.facebook.com"],
            Provider::Other => &[],
        }
    }

    /// The registrable domains where the provider's own login is saved, as the app has them
    /// (a login saved for `accounts.google.com` is below `google.com`). Empty for `Other`.
    pub const fn sites(self) -> &'static [&'static str] {
        match self {
            Provider::Google => &["google.com"],
            Provider::Apple => &["apple.com", "icloud.com"],
            Provider::Github => &["github.com"],
            Provider::Microsoft => &[
                "microsoft.com",
                "live.com",
                "microsoftonline.com",
                "outlook.com",
                "office.com",
            ],
            Provider::Facebook => &["facebook.com", "meta.com"],
            Provider::Other => &[],
        }
    }
}

/// How sure Nodkey is that a method works.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Certainty {
    /// The user said so, or accepted a suggestion.
    Confirmed,
    /// An agent or the browser extension signed in that way and it worked.
    Seen,
    /// Found in a list, such as Google's connected apps.
    Likely,
}

/// Who added a method or proposed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MethodSource {
    Manual,
    Agent,
    Extension,
    Import,
}

/// One way to sign in to a site. No secret is part of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "RawMethod")]
pub struct SignInMethod {
    pub kind: SignInKind,
    /// `federated` only: whose account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<Provider>,
    /// `provider: other` only: the provider's name ("Okta").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_name: Option<String>,
    /// The phone always sends it; absent in a `suggest` for a method that failed. A reader takes
    /// absent as `likely`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certainty: Option<Certainty>,
    /// `email_code` only: the address the code goes to, so the agent knows which mailbox to read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mailbox: Option<String>,
    /// Who added the method (answers) or proposes it (`agent` or `extension` in a `suggest`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<MethodSource>,
}

/// The wire form, read tolerantly (see the module documentation).
#[derive(Deserialize)]
struct RawMethod {
    kind: SignInKind,
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    provider_name: Option<String>,
    #[serde(default)]
    certainty: Option<String>,
    #[serde(default)]
    mailbox: Option<String>,
    #[serde(default)]
    source: Option<String>,
}

impl From<RawMethod> for SignInMethod {
    fn from(raw: RawMethod) -> Self {
        let provider = raw.provider.as_deref().map(Provider::parse);
        let provider_name = match (provider, raw.provider_name, raw.provider) {
            (Some(Provider::Other), None, Some(name)) if name.trim() != "other" => {
                Some(name.trim().to_owned())
            }
            (_, name, _) => name,
        };
        SignInMethod {
            kind: raw.kind,
            provider,
            provider_name,
            certainty: raw
                .certainty
                .map(|c| match c.trim().to_ascii_lowercase().as_str() {
                    "confirmed" => Certainty::Confirmed,
                    "seen" => Certainty::Seen,
                    _ => Certainty::Likely,
                }),
            mailbox: raw.mailbox,
            source: raw
                .source
                .and_then(|s| match s.trim().to_ascii_lowercase().as_str() {
                    "manual" => Some(MethodSource::Manual),
                    "agent" => Some(MethodSource::Agent),
                    "extension" => Some(MethodSource::Extension),
                    "import" => Some(MethodSource::Import),
                    _ => None,
                }),
        }
    }
}

impl SignInMethod {
    /// A method of `kind` without any other field.
    pub fn new(kind: SignInKind) -> Self {
        SignInMethod {
            kind,
            provider: None,
            provider_name: None,
            certainty: None,
            mailbox: None,
            source: None,
        }
    }

    /// "Sign in with" a provider; `Provider::Other` takes `name`.
    pub fn federated(provider: Provider, name: Option<&str>) -> Self {
        SignInMethod {
            provider: Some(provider),
            provider_name: name.map(|n| n.trim().to_owned()),
            ..Self::new(SignInKind::Federated)
        }
    }

    /// "Google", or the name of another provider.
    pub fn provider_label(&self) -> Option<String> {
        match self.provider? {
            Provider::Other => self.provider_name.clone(),
            p => Some(p.display().to_owned()),
        }
    }

    /// The shape rules every method follows: a provider exactly for `federated`, a name exactly
    /// for `other`, a mailbox only for `email_code`.
    pub fn check(&self) -> Result<(), String> {
        match (self.kind, self.provider) {
            (SignInKind::Federated, None) => {
                return Err("a federated method needs its provider (google, apple, github, microsoft, facebook or other)".into());
            }
            (SignInKind::Federated, Some(_)) => {}
            (_, Some(_)) => return Err("only a federated method has a provider".into()),
            (_, None) => {}
        }
        let name = self.provider_name.as_deref().map(str::trim);
        match (self.provider, name) {
            (Some(Provider::Other), None | Some("")) => {
                return Err("provider other needs provider_name (for example Okta)".into());
            }
            (Some(Provider::Other), Some(n)) if n.chars().count() > MAX_PROVIDER_NAME => {
                return Err("provider_name is too long".into());
            }
            (Some(Provider::Other), Some(_)) | (_, None) => {}
            (_, Some(_)) => return Err("only provider other has a provider_name".into()),
        }
        match (self.kind, self.mailbox.as_deref()) {
            (SignInKind::EmailCode, Some(m))
                if !m.contains('@') || m.chars().count() > MAX_MAILBOX =>
            {
                Err("mailbox must be an e-mail address".into())
            }
            (SignInKind::EmailCode, _) | (_, None) => Ok(()),
            (_, Some(_)) => Err("only an email_code method has a mailbox".into()),
        }
    }
}

/// The provider login for a "Sign in with" method, approved with the same Face ID as the answer.
/// The agent fills it only on the provider's own sign-in pages ([`may_fill_via`]), never on the
/// target site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Via {
    /// The provider account (`site` is its own sign-in site, for example `accounts.google.com`).
    pub account: Account,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<Secret>,
    /// The provider account's one-time code, when Nodkey keeps its TOTP key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<Secret>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seconds_left: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_code: Option<Secret>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_seconds_left: Option<u32>,
}

/// The hosts where the `via` login of `method` may be filled (`fill_only_on` of `via`): the
/// provider's own sign-in hosts ([`Provider::sign_in_hosts`]), or for another provider the exact
/// site of the via account.
pub fn via_sites(method: &SignInMethod, via: &Via) -> Vec<String> {
    match method.provider {
        Some(Provider::Other) | None => via
            .account
            .site
            .as_deref()
            .and_then(site)
            .into_iter()
            .collect(),
        Some(p) => p.sign_in_hosts().iter().map(|s| (*s).to_owned()).collect(),
    }
}

/// Whether the agent may fill the `via` login on a page at `host`: the host is one of
/// [`via_sites`] or below one ([`crate::site::may_fill`]), and it is not on the target's website.
pub fn may_fill_via(host: &str, target: &str, method: &SignInMethod, via: &Via) -> bool {
    !crate::site::same_site(host, target) && crate::site::may_fill(host, &via_sites(method, via))
}

/// A second step a site may ask for after the password or the "Sign in with" page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecondStep {
    /// A passkey Nodkey holds.
    Passkey,
    /// A one-time code from Nodkey (authenticator code).
    Totp,
    /// "Tap Yes on your phone" in another app.
    AppPrompt,
    Sms,
    Email,
}

impl SecondStep {
    /// Every step, in the order used for the steps in neither list.
    pub const ALL: [SecondStep; 5] = [
        SecondStep::Passkey,
        SecondStep::Totp,
        SecondStep::AppPrompt,
        SecondStep::Sms,
        SecondStep::Email,
    ];
}

/// Which second steps to choose, in order, and which to avoid. A step in neither list is allowed,
/// after the preferred ones.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecondStepOrder {
    #[serde(default, deserialize_with = "known_steps")]
    pub prefer: Vec<SecondStep>,
    #[serde(default, deserialize_with = "known_steps")]
    pub avoid: Vec<SecondStep>,
}

impl Default for SecondStepOrder {
    /// What an agent uses when the answer has no `second_step`: a passkey, then a Nodkey code;
    /// avoid app prompts and SMS.
    fn default() -> Self {
        SecondStepOrder {
            prefer: vec![SecondStep::Passkey, SecondStep::Totp],
            avoid: vec![SecondStep::AppPrompt, SecondStep::Sms],
        }
    }
}

impl SecondStepOrder {
    /// The step to choose among those the site `offered`: the first preferred one, else the first
    /// in neither list. `None` when the site offers only avoided steps: then ask the user (or use
    /// one with their consent).
    pub fn pick(&self, offered: &[SecondStep]) -> Option<SecondStep> {
        let preferred = self.prefer.iter().find(|s| offered.contains(s));
        let neutral = || {
            SecondStep::ALL.iter().find(|s| {
                offered.contains(s) && !self.prefer.contains(s) && !self.avoid.contains(s)
            })
        };
        preferred.or_else(neutral).copied()
    }
}

fn known_steps<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<SecondStep>, D::Error> {
    let names = Vec::<serde_json::Value>::deserialize(d)?;
    Ok(names
        .into_iter()
        .filter_map(|v| serde_json::from_value(v).ok())
        .collect())
}

/// Reads an optional field that a newer app may send in a form this version cannot read: such a
/// value is left out instead of failing the whole answer. Only for fields without secrets.
pub(crate) fn lenient<'de, D: Deserializer<'de>, T: DeserializeOwned>(
    d: D,
) -> Result<Option<T>, D::Error> {
    let value = Option::<serde_json::Value>::deserialize(d)?;
    Ok(value.and_then(|v| serde_json::from_value(v).ok()))
}

/// What happened when the agent tried a method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuggestOutcome {
    /// The agent signed in with it.
    SignedIn,
    /// The agent tried it and it did not work.
    Failed,
}

/// What a `suggest` request proposes: a method for `target` and what happened when the agent
/// tried it. It holds no secret; the phone puts it in the user's suggestion list without Face ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Suggestion {
    pub method: SignInMethod,
    pub outcome: SuggestOutcome,
}

impl Suggestion {
    /// The rules both sides check: a valid method, no `confirmed` (only the user confirms), and
    /// `source`, when present, `agent` or `extension`.
    pub fn check(&self) -> Result<(), String> {
        self.method.check()?;
        if self.method.certainty == Some(Certainty::Confirmed) {
            return Err("only the user confirms a method; suggest it as seen or likely".into());
        }
        match self.method.source {
            None | Some(MethodSource::Agent | MethodSource::Extension) => Ok(()),
            Some(_) => Err("a suggestion comes from an agent or the extension".into()),
        }
    }
}

/// The site of a value as a suggestion names it: the host, lower case, without scheme, user,
/// port, path or `www.` (`https://www.Example.com/login` → `example.com`). `None` when it is not
/// a website (no dot, other characters), except `localhost`.
pub fn site(value: &str) -> Option<String> {
    let v = value.trim();
    let v = v.split_once("://").map_or(v, |(_, rest)| rest);
    let v = v.split(['/', '?', '#']).next().unwrap_or_default();
    let v = v.rsplit_once('@').map_or(v, |(_, host)| host);
    let v = v.split(':').next().unwrap_or_default();
    let host = v.trim_end_matches('.').to_ascii_lowercase();
    let host = host.strip_prefix("www.").unwrap_or(&host).to_owned();
    let ok_chars = host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.');
    let labels_ok = host.split('.').all(|l| !l.is_empty());
    let shaped = host == "localhost" || (host.contains('.') && labels_ok);
    (ok_chars && shaped && host.chars().count() <= MAX_TARGET).then_some(host)
}

/// The `wait_seconds` of an `sms_code` request, absent → the default; `None` when out of range.
pub fn sms_wait(wait_seconds: Option<u32>) -> Option<u32> {
    let wait = wait_seconds.unwrap_or(SMS_WAIT_DEFAULT);
    (SMS_WAIT_MIN..=SMS_WAIT_MAX)
        .contains(&wait)
        .then_some(wait)
}

#[cfg(test)]
mod tests;
