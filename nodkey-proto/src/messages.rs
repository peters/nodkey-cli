//! Every JSON message of protocol v1: relay bodies (outside HPKE) and plaintexts (inside HPKE).
//!
//! Binary values are b64u strings; times are Unix seconds.

use crate::Secret;
pub use crate::client_info::ClientInfo;
use serde::{Deserialize, Serialize};

use crate::Error;

// ---------------------------------------------------------------------------------------------
// Relay bodies
// ---------------------------------------------------------------------------------------------

/// `PUT /v1/phones/{phone_id}` body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhoneRegistration {
    pub sign: String,
    pub kem: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apns_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apns_sandbox: Option<bool>,
}

/// `POST /v1/pairings` body, and the response of `POST /v1/pairings/{code}/claim`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentInfo {
    pub agent_id: String,
    pub name: String,
    pub sign: String,
    pub kem: String,
}

/// `POST /v1/pairings` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingCode {
    /// Canonical code, 6 Crockford base32 characters.
    pub code: String,
    /// Unix time the code stops working (300 s after it was made).
    pub expires: u64,
}

/// `{enc, ct}`: the claim body, the answer body and the answer the agent fetches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedBox {
    pub enc: String,
    pub ct: String,
}

/// `GET /v1/pairings/{code}` response once a phone claimed the code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingClaimed {
    pub phone_id: String,
    pub sign: String,
    pub kem: String,
    pub enc: String,
    pub ct: String,
}

impl PairingClaimed {
    /// The sealed grant part.
    pub fn sealed(&self) -> SealedBox {
        SealedBox {
            enc: self.enc.clone(),
            ct: self.ct.clone(),
        }
    }
}

/// `POST /v1/phones/{phone_id}/requests` body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestEnvelope {
    pub request_id: String,
    pub enc: String,
    pub ct: String,
    /// `true` when an attachment follows (the relay holds the push for it up to 5 s).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attachment: Option<bool>,
    /// How long the relay keeps the request and its answer, in seconds (120 to 360; absent means
    /// 120). Only `sms_code` requests send it ([`crate::signin::SMS_APPROVE_MARGIN`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
}

/// One entry of `GET /v1/phones/{phone_id}/requests`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingRequest {
    pub request_id: String,
    pub agent_id: String,
    pub enc: String,
    pub ct: String,
    pub created: u64,
}

/// Error body of every non-2xx relay response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: String,
    #[serde(default)]
    pub message: String,
}

// ---------------------------------------------------------------------------------------------
// Plaintexts
// ---------------------------------------------------------------------------------------------

/// What the phone lets the agent ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    /// The user picks accounts per request.
    Selected,
    Codes,
    Logins,
    All,
}

/// Kind of a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// One TOTP code.
    Code,
    /// User name, password and, when the login has a TOTP key, a code.
    Login,
    /// Names of the accounts this agent may ask for (no secrets).
    List,
    /// Move the saved logins that match a [`CleanupFilter`] to "Recently deleted" on the phone.
    /// Never covered by a lease: The user sees the list and confirms with Face ID every time.
    Cleanup,
    /// Counts and anonymous groups for clean-up suggestions, never a site or user name.
    Insights,
    /// Save a login the user just used (for example in a browser) in Nodkey: a new one, or a new
    /// password for one the phone has. Never covered by a lease.
    Save,
    /// Sign in with a passkey, or make a new one: the phone signs with a key that never leaves it.
    /// `target` is the `rp_id`; the request carries a [`crate::PasskeyRequest`].
    Passkey,
    /// Several codes and logins in one request ([`crate::BundleRequest`]); `target` is empty.
    Bundle,
    /// A payment card for one purchase ([`crate::CardRequest`]); `target` is the merchant. Never
    /// covered by a lease and never part of a bundle.
    Card,
    /// Ends a task session ([`Request::session_id`]); answered at once, without asking.
    #[serde(rename = "session_end")]
    SessionEnd,
    /// A sign-in method for the user's suggestion list ([`crate::Suggestion`]); no secret, no Face
    /// ID, answered at once with `queued` or `rejected`. Never covered by a lease or a bundle.
    Suggest,
    /// A code the site sends only by SMS, passed to Nodkey by the user's Shortcuts automation
    /// within [`Request::wait_seconds`]. Never covered by a lease, a bundle or a session.
    #[serde(rename = "sms_code")]
    SmsCode,
    /// An API key or other secret ([`crate::apikey`]); `target` names its service and/or variable
    /// name. Face ID every time: never covered by a lease; a task session may cover it.
    Secret,
    /// Keep a key an agent made ([`crate::SaveSecret`]); never covered by a lease.
    #[serde(rename = "save_secret")]
    SaveSecret,
    /// The agent's nonce for the check number of a new pairing ([`crate::pairing`]); the phone
    /// answers at once with its own, without asking. Once per pairing.
    #[serde(rename = "pairing_check")]
    PairingCheck,
}

/// The login a `save` request asks the phone to keep.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaveLogin {
    /// The page the login was used on, e.g. `https://www.vg.no/login`.
    pub url: String,
    pub username: String,
    /// The password, sealed to the phone on its own (`nodkey/v1/password`, `aad` = `agent_id`).
    pub password: SealedBox,
    /// A title for a new login, e.g. the page's title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
}

/// What the phone did with a `save` request it approved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Saved {
    /// A new login.
    Added,
    /// The password of an existing login (same site and user name) changed.
    Updated,
    /// The phone already had exactly this login.
    Unchanged,
}

/// Which saved logins a `cleanup` request is about. Every criterion that is set must hold; at
/// least one must be set (an empty filter is refused by the agent tools and by the phone).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanupFilter {
    /// Shell-style wildcard (`*`, `?`) over site, address, title and user name; without a
    /// wildcard a plain case-insensitive "contains".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    /// The user name, exactly (case-insensitive), or a wildcard pattern (`alex.old@*`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// A domain; its subdomains match too (`old-company.no` takes `mail.old-company.no`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// The site is an IPv4 or IPv6 address (with or without port), `localhost` or a `*.local` name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_only: Option<bool>,
    /// Last used before this Unix time; a login never used counts as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_before: Option<u64>,
    /// Added before this Unix time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub added_before: Option<u64>,
    /// The password was last changed (or, without a change date, added) before this Unix time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_changed_before: Option<u64>,
    /// Never used from Nodkey (never copied, never handed to an agent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub never_used: Option<bool>,
    /// An anonymous group from `insights` (`d_…` a site, `u_…` a user name); only the phone knows
    /// what it stands for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
}

impl CleanupFilter {
    /// True when no criterion is set: blank strings and `false` flags do not count.
    pub fn is_empty(&self) -> bool {
        let blank = |s: &Option<String>| s.as_deref().is_none_or(|v| v.trim().is_empty());
        blank(&self.query)
            && blank(&self.username)
            && blank(&self.domain)
            && self.ip_only != Some(true)
            && self.last_used_before.is_none()
            && self.added_before.is_none()
            && self.password_changed_before.is_none()
            && self.never_used != Some(true)
            && blank(&self.group)
    }
}

/// Media type of an attachment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImageType {
    #[serde(rename = "image/png")]
    Png,
    #[serde(rename = "image/jpeg")]
    Jpeg,
    #[serde(rename = "image/gif")]
    Gif,
}

impl ImageType {
    /// Detects the type from the file's first bytes (never from its name).
    pub fn sniff(bytes: &[u8]) -> Option<Self> {
        if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
            Some(ImageType::Png)
        } else if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
            Some(ImageType::Jpeg)
        } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
            Some(ImageType::Gif)
        } else {
            None
        }
    }

    /// The media type string.
    pub const fn mime(self) -> &'static str {
        match self {
            ImageType::Png => "image/png",
            ImageType::Jpeg => "image/jpeg",
            ImageType::Gif => "image/gif",
        }
    }
}

/// Description of an attachment inside the request plaintext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentInfo {
    #[serde(rename = "type")]
    pub kind: ImageType,
    /// Size of the image in bytes (before sealing).
    pub bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caption: Option<String>,
    /// b64u of SHA-256 of the image bytes; the phone shows only an image that matches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

/// Request, agent → phone (`nodkey/v1/request`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub v: u8,
    pub request_id: String,
    pub kind: Kind,
    /// Site or issuer, optionally `/account`.
    pub target: String,
    pub reason: String,
    /// The agent's display name.
    pub agent: String,
    pub ts: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attachment: Option<AttachmentInfo>,
    /// Which logins a `cleanup` request is about; absent for the other kinds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<CleanupFilter>,
    /// The login a `save` request is about; absent for the other kinds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub save: Option<SaveLogin>,
    /// What a `passkey` request asks for; absent for the other kinds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passkey: Option<crate::PasskeyRequest>,
    /// The items of a `bundle` request; absent for the other kinds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle: Option<crate::BundleRequest>,
    /// What a `card` request asks for; absent for the other kinds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub card: Option<crate::CardRequest>,
    /// The card a `save` request is about (instead of `save`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub save_card: Option<crate::SaveCard>,
    /// Who is asking, as the agent reports it (shown in the phone's history; self-reported).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<ClientInfo>,
    /// The task session this request belongs to (see "Task sessions").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// What a `suggest` request proposes; absent for the other kinds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggest: Option<crate::Suggestion>,
    /// `sms_code`: how long the phone waits for the SMS (30 to 300 s; absent means 120).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait_seconds: Option<u32>,
    /// The key a `save_secret` request asks the phone to keep; absent for the other kinds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub save_secret: Option<crate::SaveSecret>,
    /// The project a `secret` request (or the `secret` items of a bundle) asks in: that project's
    /// key, else the global one ([`crate::apikey::project`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    /// `pairing_check`: the agent's nonce (b64u, 32 bytes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

/// the user's decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Approved,
    Denied,
    Expired,
    /// `suggest`: the suggestion is in the user's list (nothing was approved).
    Queued,
    /// `suggest`: the phone did not queue it, without asking the user (`error` says why).
    Rejected,
}

/// How long the phone answers by itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LeaseKind {
    Once,
    Day,
    Week,
    Always,
    /// Answered under a task session ([`crate::SessionInfo`]).
    Session,
}

/// Lease information in an answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease {
    pub kind: LeaseKind,
    /// Absent for `once` and `always`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
}

/// The account an answer is about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    pub issuer: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
    /// More websites the account is used on ("Also used on" in the app); absent when none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sites: Option<Vec<String>>,
}

/// How the phone found the account of a `code` or `login` answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchKind {
    /// Its name or its own site matches the target.
    Direct,
    /// One of its extra websites matches the target.
    Alias,
    /// Nothing matched; the user picked this account by hand.
    Chosen,
}

/// One account in a `list` answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountEntry {
    pub issuer: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
    #[serde(default)]
    pub has_code: bool,
    #[serde(default)]
    pub has_password: bool,
    /// More websites the account is used on; absent when none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sites: Option<Vec<String>>,
}

/// Answer, phone → agent (`nodkey/v1/answer`). Only the fields that apply are present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Answer {
    pub v: u8,
    pub request_id: String,
    pub decision: Decision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease: Option<Lease>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<Account>,
    /// `code`/`login`: how the account was found (absent in answers from older apps).
    #[serde(default, rename = "match", skip_serializing_if = "Option::is_none")]
    pub match_kind: Option<MatchKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<Secret>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seconds_left: Option<u32>,
    /// The next code, when `seconds_left` is below [`crate::session::NEXT_CODE_BELOW`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_code: Option<Secret>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_seconds_left: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<Secret>,
    /// `list`: the account names. `cleanup`: the logins that were moved (names only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accounts: Option<Vec<AccountEntry>>,
    /// `cleanup`: how many logins were moved to "Recently deleted".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub moved: Option<u32>,
    /// What an approved `save` did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saved: Option<Saved>,
    /// What an approved `passkey` request made or signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passkey: Option<crate::PasskeyAnswer>,
    /// `bundle`: one answer per item, in the request's order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub items: Option<Vec<crate::BundleItemAnswer>>,
    /// An approved `card` request: the card for this one purchase.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub card: Option<crate::CardAnswer>,
    /// `list`: the cards this agent may use (no numbers), only when cards are on for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cards: Option<Vec<crate::CardEntry>>,
    /// Why the phone refused without asking the user: `empty_filter`, `paused`, `unknown_group`,
    /// `unsupported_version`, `unsupported_kind`, for passkeys `bad_client_data`, `no_passkey`,
    /// `unsupported_algorithm` or `excluded` (see [`crate::passkey::errors`]), and for cards
    /// [`crate::card::errors`]. Also `quota_warning`, with any decision: the phone asked with the
    /// agent limit warning ([`crate::quota::errors`]). For keys [`crate::apikey::errors`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// `insights`: counts, age buckets and anonymous groups (docs/agent-protocol.md), passed on as is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub insights: Option<serde_json::Value>,
    /// An approved `bundle` with `session`: the task session it started.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<crate::SessionInfo>,
    /// The request named a session that is unknown or has ended.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_ended: Option<bool>,
    /// `login`: how the user signs in to the target site, when the phone knows.
    #[serde(
        default,
        deserialize_with = "crate::signin::lenient",
        skip_serializing_if = "Option::is_none"
    )]
    pub method: Option<crate::SignInMethod>,
    /// `login` with a `federated` method: the provider login, for the provider's own pages only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<crate::Via>,
    /// `login` and `code`: which second step to choose and which to avoid.
    #[serde(
        default,
        deserialize_with = "crate::signin::lenient",
        skip_serializing_if = "Option::is_none"
    )]
    pub second_step: Option<crate::SecondStepOrder>,
    /// With `quota_warning`, or `paused` by the agent limit: the count behind it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota: Option<crate::Quota>,
    /// An approved `secret` request: the key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<crate::SecretAnswer>,
    /// `list`: the keys this agent may ask for (names only), when its scope allows keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets: Option<Vec<crate::SecretEntry>>,
    /// `pairing_check`: the phone's nonce (b64u, 32 bytes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

impl Answer {
    /// An answer with only a decision.
    pub fn decision(request_id: &str, decision: Decision) -> Self {
        Answer {
            v: crate::VERSION,
            request_id: request_id.to_owned(),
            decision,
            lease: None,
            account: None,
            match_kind: None,
            code: None,
            seconds_left: None,
            next_code: None,
            next_seconds_left: None,
            username: None,
            password: None,
            accounts: None,
            moved: None,
            saved: None,
            passkey: None,
            items: None,
            card: None,
            cards: None,
            error: None,
            insights: None,
            session: None,
            session_ended: None,
            method: None,
            via: None,
            second_step: None,
            quota: None,
            secret: None,
            secrets: None,
            nonce: None,
        }
    }
}

/// Parses a decrypted plaintext and checks its version.
pub fn parse_plaintext<T: serde::de::DeserializeOwned + Versioned>(
    bytes: &[u8],
) -> Result<T, Error> {
    let msg: T = serde_json::from_slice(bytes)?;
    if msg.version() != crate::VERSION {
        return Err(Error::Json(format!(
            "unsupported version {}",
            msg.version()
        )));
    }
    Ok(msg)
}

/// Plaintext messages carry `"v"`.
pub trait Versioned {
    /// The message's `v`.
    fn version(&self) -> u8;
}

impl Versioned for Request {
    fn version(&self) -> u8 {
        self.v
    }
}
impl Versioned for Answer {
    fn version(&self) -> u8 {
        self.v
    }
}

#[cfg(test)]
mod tests;
