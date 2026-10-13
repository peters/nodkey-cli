//! Passkey requests (`kind: passkey`): the WebAuthn data an agent sends the phone, what the phone
//! answers, and the check of `client_data_json` that the agent and the phone both run before
//! anything is signed.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::b64u;

/// COSE algorithm ES256 (ECDSA P-256 with SHA-256), the only one the phone makes.
pub const ES256: i64 = -7;

/// Most entries in `allow_credentials` or `exclude_credentials`.
pub const MAX_CREDENTIALS: usize = 64;

/// Longest `client_data_json` in bytes (before b64u).
pub const MAX_CLIENT_DATA: usize = 4096;

/// The phone's `error` when it refuses a passkey request without asking.
pub mod errors {
    /// `client_data_json` failed the check in [`super::check_client_data`].
    pub const BAD_CLIENT_DATA: &str = "bad_client_data";
    /// No passkey for the `rp_id` (or none of those in `allow_credentials`).
    pub const NO_PASSKEY: &str = "no_passkey";
    /// A create request without ES256 (-7) in `algorithms`.
    pub const UNSUPPORTED_ALGORITHM: &str = "unsupported_algorithm";
    /// A create request where the phone already holds a passkey in `exclude_credentials`
    /// (answered after the user approved, as WebAuthn asks).
    pub const EXCLUDED: &str = "excluded";
}

/// WebAuthn's `required`, `preferred` or `discouraged` (user verification, resident key).
/// Absent means `preferred`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Requirement {
    Required,
    #[default]
    Preferred,
    Discouraged,
}

/// Sign in or make a new passkey.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PasskeyOp {
    Get,
    Create,
}

impl PasskeyOp {
    /// The `type` in `client_data_json` for this operation.
    pub const fn client_data_type(self) -> &'static str {
        match self {
            PasskeyOp::Get => "webauthn.get",
            PasskeyOp::Create => "webauthn.create",
        }
    }
}

/// The user a new passkey is for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyUser {
    /// The user handle, b64u (1 to 64 bytes).
    pub id: String,
    pub name: String,
    pub display_name: String,
}

/// `op: get`: sign in with a passkey.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyGet {
    pub rp_id: String,
    /// The whole `clientDataJSON` the browser side made, b64u.
    pub client_data_json: String,
    /// Credential ids (b64u) the site accepts; empty means any passkey for `rp_id`.
    #[serde(default)]
    pub allow_credentials: Vec<String>,
    #[serde(default)]
    pub user_verification: Requirement,
}

/// `op: create`: make a new passkey.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyCreate {
    pub rp_id: String,
    pub rp_name: String,
    /// The whole `clientDataJSON` the browser side made, b64u.
    pub client_data_json: String,
    pub user: PasskeyUser,
    /// COSE algorithm ids the site accepts, in its order of preference.
    pub algorithms: Vec<i64>,
    /// Credential ids (b64u) the site already has for this user.
    #[serde(default)]
    pub exclude_credentials: Vec<String>,
    #[serde(default)]
    pub resident_key: Requirement,
    #[serde(default)]
    pub user_verification: Requirement,
}

/// The `passkey` of a request (`kind: passkey`). `target` of the request is the `rp_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum PasskeyRequest {
    Get(PasskeyGet),
    Create(PasskeyCreate),
}

impl PasskeyRequest {
    pub fn op(&self) -> PasskeyOp {
        match self {
            PasskeyRequest::Get(_) => PasskeyOp::Get,
            PasskeyRequest::Create(_) => PasskeyOp::Create,
        }
    }

    pub fn rp_id(&self) -> &str {
        match self {
            PasskeyRequest::Get(g) => &g.rp_id,
            PasskeyRequest::Create(c) => &c.rp_id,
        }
    }

    /// `client_data_json` as sent (b64u).
    pub fn client_data_json(&self) -> &str {
        match self {
            PasskeyRequest::Get(g) => &g.client_data_json,
            PasskeyRequest::Create(c) => &c.client_data_json,
        }
    }

    /// Decodes `client_data_json` and checks it against the operation and `rp_id`.
    pub fn check_client_data(&self) -> Result<ClientData, &'static str> {
        let bytes = b64u::decode(self.client_data_json())
            .map_err(|_| "client_data_json is not base64url")?;
        check_client_data(self.op(), self.rp_id(), &bytes)
    }

    /// Everything the agent checks before it sends the request: `client_data_json`, the
    /// credential ids and the user, and the size limits. `target` must be the `rp_id`.
    pub fn check(&self, target: &str) -> Result<ClientData, String> {
        if target != self.rp_id() {
            return Err("target must be the rp_id of the passkey request".into());
        }
        let ids = match self {
            PasskeyRequest::Get(g) => &g.allow_credentials,
            PasskeyRequest::Create(c) => &c.exclude_credentials,
        };
        if ids.len() > MAX_CREDENTIALS {
            return Err(format!("at most {MAX_CREDENTIALS} credential ids"));
        }
        for id in ids {
            let raw = b64u::decode(id).map_err(|_| "a credential id is not base64url")?;
            if raw.is_empty() || raw.len() > 1023 {
                return Err("a credential id must be 1 to 1023 bytes".into());
            }
        }
        if let PasskeyRequest::Create(c) = self {
            let handle = b64u::decode(&c.user.id).map_err(|_| "user.id is not base64url")?;
            if handle.is_empty() || handle.len() > 64 {
                return Err("user.id must be 1 to 64 bytes".into());
            }
            if c.user.name.trim().is_empty() {
                return Err("user.name is required".into());
            }
            if c.algorithms.is_empty() {
                return Err("algorithms is empty".into());
            }
            let long = |s: &str| s.chars().count() > 200;
            if long(&c.rp_name) || long(&c.user.name) || long(&c.user.display_name) {
                return Err("rp_name or a user name is too long".into());
            }
        }
        if self.client_data_json().len() > b64u::encoded_len(MAX_CLIENT_DATA) {
            return Err("client_data_json is too long".into());
        }
        self.check_client_data().map_err(str::to_owned)
    }
}

/// What the phone answers to an approved passkey request. A get answer carries `signature`,
/// `user_handle` and `user_name`; a create answer `attestation_object`, `public_key` and
/// `public_key_algorithm`. Binary values are b64u.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyAnswer {
    pub credential_id: String,
    /// CBOR `{"fmt": "none", "attStmt": {}, "authData": …}` (create).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_object: Option<String>,
    pub authenticator_data: String,
    /// DER ECDSA signature over `authenticator_data ‖ SHA-256(client_data_json)` (get).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// The user handle stored with the passkey (get).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_handle: Option<String>,
    /// The user name stored with the passkey (get).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_name: Option<String>,
    /// SubjectPublicKeyInfo DER of the new key (create).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    /// COSE algorithm of the new key, `-7` (create).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key_algorithm: Option<i64>,
}

/// What a checked `client_data_json` says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientData {
    /// The origin the phone shows the user, e.g. `https://webauthn.io`.
    pub origin: String,
    /// The site's challenge, b64u.
    pub challenge: String,
}

#[derive(Deserialize)]
struct RawClientData {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin", default)]
    cross_origin: Option<bool>,
}

/// Checks `client_data_json` the way the phone does before it asks the user:
///
/// - `type` is `webauthn.get` (get) or `webauthn.create` (create);
/// - `challenge` is a non-empty b64u string;
/// - `crossOrigin` is absent or `false`;
/// - `origin` is `https://<host>[:port]` where `host` is `rp_id` or ends with `"." + rp_id`, or
///   `http://localhost[:port]` with `rp_id` `localhost`;
/// - `rp_id` is a domain name with a dot, or `localhost`.
///
/// Any failure is answered with `error: "bad_client_data"`.
pub fn check_client_data(
    op: PasskeyOp,
    rp_id: &str,
    client_data_json: &[u8],
) -> Result<ClientData, &'static str> {
    let raw: RawClientData = serde_json::from_slice(client_data_json)
        .map_err(|_| "client_data_json is not a client data object")?;
    if raw.kind != op.client_data_type() {
        return Err("client_data_json has the wrong type for this operation");
    }
    if raw.challenge.is_empty() || b64u::decode(&raw.challenge).is_err() {
        return Err("client_data_json has no valid challenge");
    }
    if raw.cross_origin == Some(true) {
        return Err("cross-origin requests are not allowed");
    }
    if !valid_rp_id(rp_id) {
        return Err("rp_id is not a domain name");
    }
    let (https, host) = split_origin(&raw.origin).ok_or("origin is not a web origin")?;
    let localhost = host.eq_ignore_ascii_case("localhost");
    if !https && !localhost {
        return Err("origin must use https (http only for localhost)");
    }
    if !host_matches(host, rp_id) {
        return Err("origin does not belong to rp_id");
    }
    Ok(ClientData {
        origin: raw.origin,
        challenge: raw.challenge,
    })
}

/// SHA-256 of the `client_data_json` bytes, the hash the phone signs over.
pub fn client_data_hash(client_data_json: &[u8]) -> [u8; 32] {
    Sha256::digest(client_data_json).into()
}

/// The `clientDataJSON` a browser makes, byte for byte:
/// `{"type":…,"challenge":…,"origin":…,"crossOrigin":false}`. The host that makes it takes the
/// origin from the page's frame, never from the page or the model.
pub fn build_client_data_json(op: PasskeyOp, challenge: &str, origin: &str) -> String {
    let q = |s: &str| serde_json::to_string(s).expect("a string serializes");
    format!(
        "{{\"type\":{},\"challenge\":{},\"origin\":{},\"crossOrigin\":false}}",
        q(op.client_data_type()),
        q(challenge),
        q(origin)
    )
}

/// `(is https, host)` of `scheme://host[:port]` without path, query, fragment or user info.
fn split_origin(origin: &str) -> Option<(bool, &str)> {
    let (https, rest) = match (
        origin.strip_prefix("https://"),
        origin.strip_prefix("http://"),
    ) {
        (Some(r), _) => (true, r),
        (None, Some(r)) => (false, r),
        _ => return None,
    };
    let host = match rest.rsplit_once(':') {
        Some((host, port)) => {
            let ok = !port.is_empty()
                && port.len() <= 5
                && port.bytes().all(|b| b.is_ascii_digit())
                && port.parse::<u16>().is_ok_and(|p| p > 0);
            if !ok {
                return None;
            }
            host
        }
        None => rest,
    };
    valid_host(host).then_some((https, host))
}

/// Letters, digits and hyphens in non-empty dot-separated labels.
fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// A domain with a dot (not an IPv4 address), or `localhost`.
fn valid_rp_id(rp_id: &str) -> bool {
    if rp_id.eq_ignore_ascii_case("localhost") {
        return true;
    }
    let last = rp_id.rsplit('.').next().unwrap_or("");
    valid_host(rp_id) && rp_id.contains('.') && !last.bytes().all(|b| b.is_ascii_digit())
}

fn host_matches(host: &str, rp_id: &str) -> bool {
    let (host, rp_id) = (host.to_ascii_lowercase(), rp_id.to_ascii_lowercase());
    host == rp_id || host.ends_with(&format!(".{rp_id}"))
}

#[cfg(test)]
mod tests;
