//! Every JSON message of protocol v1: relay bodies (outside HPKE) and plaintexts (inside HPKE).
//!
//! Binary values are b64u strings; times are Unix seconds.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

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

/// Pairing grant, phone → agent (`nodkey/v1/pairing`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingGrant {
    pub v: u8,
    pub phone_name: String,
    pub scope: Scope,
    /// Six digits without a space.
    pub check: String,
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
    /// Who is asking, as the agent reports it (shown in the phone's history; self-reported).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<ClientInfo>,
}

/// What the agent says about itself, for the history on the phone. Self-reported: the phone shows
/// it as such and never decides anything on it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientInfo {
    /// The MCP client, e.g. "Claude Code".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_version: Option<String>,
    /// The model the agent runs on, as it says, e.g. "claude-opus-5-5".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Reasoning effort, as the agent says, e.g. "high".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effort: Option<String>,
    /// Operating system and version, e.g. "linux 7.0.0 x86_64".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    /// The computer's name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// The last component of the working directory (the project), never the full path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workdir: Option<String>,
    /// nodkey-mcp's version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_version: Option<String>,
}

impl ClientInfo {
    /// Trims every field to at most 80 characters and drops empty ones.
    pub fn tidy(mut self) -> Self {
        for field in [
            &mut self.app,
            &mut self.app_version,
            &mut self.model,
            &mut self.effort,
            &mut self.os,
            &mut self.host,
            &mut self.workdir,
            &mut self.mcp_version,
        ] {
            *field = field
                .take()
                .map(|v| v.trim().chars().take(80).collect::<String>())
                .filter(|v| !v.is_empty());
        }
        self
    }
}

/// the user's decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Approved,
    Denied,
    Expired,
}

/// How long the phone answers by itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LeaseKind {
    Once,
    Day,
    Week,
    Always,
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
}

/// A secret string from the phone (a code or a password). Its `Debug` output is redacted and its
/// memory is wiped on drop; serialising it writes the value (that is how it reaches the model).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    /// Wraps a value.
    pub fn new(s: impl Into<String>) -> Self {
        Secret(s.into())
    }

    /// The value.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<Secret>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seconds_left: Option<u32>,
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
    /// Why the phone refused without asking the user: `empty_filter`, `paused`, `unknown_group`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// `insights`: counts, age buckets and anonymous groups (docs/agent-protocol.md), passed on as is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub insights: Option<serde_json::Value>,
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
            code: None,
            seconds_left: None,
            username: None,
            password: None,
            accounts: None,
            moved: None,
            error: None,
            insights: None,
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

impl Versioned for PairingGrant {
    fn version(&self) -> u8 {
        self.v
    }
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
mod tests {
    use super::*;

    #[test]
    fn protocol_examples_parse() {
        let g: PairingGrant = parse_plaintext(
            br#"{"v":1, "phone_name":"Test iPhone", "scope":"selected", "check":"418902"}"#,
        )
        .unwrap();
        assert_eq!(g.scope, Scope::Selected);

        let r: Request = parse_plaintext(
            br#"{"v":1, "request_id":"AAECAwQFBgcICQoLDA0ODw", "kind":"code", "target":"github.com/alex",
                "reason":"Merge PR #42", "agent":"Agent \u00b7 Horizon", "ts":1791620000,
                "attachment":{"type":"image/png","bytes":12345,"caption":"vg.no login page"}}"#,
        )
        .unwrap();
        assert_eq!(r.kind, Kind::Code);
        assert_eq!(r.attachment.unwrap().kind, ImageType::Png);

        let a: Answer = parse_plaintext(
            br#"{"v":1, "request_id":"x", "decision":"approved",
                "lease":{"kind":"day", "until":1791706400},
                "account":{"issuer":"GitHub", "name":"alex", "site":"github.com"},
                "code":"190274", "seconds_left":12, "username":"alex", "password":"pw",
                "accounts":[{"issuer":"GitHub","name":"alex","site":"github.com","has_code":true,"has_password":true}]}"#,
        )
        .unwrap();
        assert_eq!(a.decision, Decision::Approved);
        assert_eq!(a.code.as_ref().unwrap().expose(), "190274");
        assert_eq!(a.lease.as_ref().unwrap().kind, LeaseKind::Day);
        assert!(a.accounts.as_ref().unwrap()[0].has_password);
    }

    #[test]
    fn cleanup_request_and_answer() {
        let r: Request = parse_plaintext(
            br#"{"v":1, "request_id":"x", "kind":"cleanup", "target":"", "reason":"Old router logins",
                "agent":"A", "ts":1791620000, "filter":{"ip_only":true, "username":"admin"}}"#,
        )
        .unwrap();
        assert_eq!(r.kind, Kind::Cleanup);
        let f = r.filter.unwrap();
        assert_eq!(f.ip_only, Some(true));
        assert_eq!(f.username.as_deref(), Some("admin"));
        assert!(!f.is_empty());

        let a: Answer = parse_plaintext(
            br#"{"v":1, "request_id":"x", "decision":"approved", "moved":1,
                "accounts":[{"issuer":"Router","name":"admin","site":"192.168.1.1"}]}"#,
        )
        .unwrap();
        assert_eq!(a.moved, Some(1));
        assert_eq!(a.accounts.unwrap()[0].site.as_deref(), Some("192.168.1.1"));
        let refused: Answer = parse_plaintext(
            br#"{"v":1, "request_id":"x", "decision":"denied", "error":"empty_filter"}"#,
        )
        .unwrap();
        assert_eq!(refused.error.as_deref(), Some("empty_filter"));
    }

    #[test]
    fn empty_cleanup_filters() {
        assert!(CleanupFilter::default().is_empty());
        let blank = CleanupFilter {
            query: Some("  ".into()),
            username: Some(String::new()),
            ip_only: Some(false),
            never_used: Some(false),
            ..Default::default()
        };
        assert!(blank.is_empty());
        assert_eq!(
            serde_json::to_string(&CleanupFilter::default()).unwrap(),
            "{}"
        );
        for f in [
            CleanupFilter {
                query: Some("*.old.no".into()),
                ..Default::default()
            },
            CleanupFilter {
                username: Some("alex@example.com".into()),
                ..Default::default()
            },
            CleanupFilter {
                domain: Some("old.no".into()),
                ..Default::default()
            },
            CleanupFilter {
                ip_only: Some(true),
                ..Default::default()
            },
            CleanupFilter {
                last_used_before: Some(1),
                ..Default::default()
            },
            CleanupFilter {
                added_before: Some(1),
                ..Default::default()
            },
            CleanupFilter {
                password_changed_before: Some(1),
                ..Default::default()
            },
            CleanupFilter {
                never_used: Some(true),
                ..Default::default()
            },
        ] {
            assert!(!f.is_empty(), "{f:?}");
        }
    }

    #[test]
    fn optional_fields_are_omitted() {
        let a = Answer::decision("rid", Decision::Denied);
        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            r#"{"v":1,"request_id":"rid","decision":"denied"}"#
        );
    }

    #[test]
    fn wrong_version_is_rejected() {
        let e = parse_plaintext::<Answer>(br#"{"v":2,"request_id":"x","decision":"denied"}"#);
        assert!(e.is_err());
    }

    #[test]
    fn secrets_are_redacted_in_debug() {
        let mut a = Answer::decision("rid", Decision::Approved);
        a.code = Some(Secret::new("190274"));
        a.password = Some(Secret::new("hunter2"));
        let s = format!("{a:?}");
        assert!(!s.contains("190274") && !s.contains("hunter2"));
        assert!(serde_json::to_string(&a).unwrap().contains("hunter2"));
    }

    #[test]
    fn image_sniffing() {
        assert_eq!(
            ImageType::sniff(b"\x89PNG\r\n\x1a\n...."),
            Some(ImageType::Png)
        );
        assert_eq!(
            ImageType::sniff(&[0xff, 0xd8, 0xff, 0xe0]),
            Some(ImageType::Jpeg)
        );
        assert_eq!(ImageType::sniff(b"GIF89a.."), Some(ImageType::Gif));
        assert_eq!(ImageType::sniff(b"GIF87a.."), Some(ImageType::Gif));
        assert_eq!(ImageType::sniff(b"<svg"), None);
        assert_eq!(
            serde_json::to_string(&AttachmentInfo {
                kind: ImageType::Jpeg,
                bytes: 3,
                caption: None
            })
            .unwrap(),
            r#"{"type":"image/jpeg","bytes":3}"#
        );
    }
}
