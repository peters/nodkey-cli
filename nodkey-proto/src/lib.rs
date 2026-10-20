//! Nodkey agent protocol, version 1.
//!
//! The binding contract is `docs/agent-protocol.md`; this crate implements it for the agent side
//! (and for tests that play the phone): the JSON messages, HPKE sealing with the protocol's `info`
//! and `aad` rules, Ed25519 signatures on relay calls and on sealed messages, pairing with a
//! commitment and its check number, and pairing codes.

pub mod apikey;
pub mod attachment;
pub mod auth;
pub mod b64u;
pub mod bundle;
pub mod card;
pub mod check;
pub mod client;
mod client_info;
pub mod code;
pub mod dh;
pub mod import;
pub mod keys;
pub mod messages;
pub mod pairing;
pub mod passkey;
pub mod prf;
pub mod quota;
pub mod seal;
pub mod secret;
pub mod session;
pub mod signed;
pub mod signin;
pub mod site;
#[doc(hidden)]
pub mod testing;
#[doc(hidden)]
pub mod vectors;
pub mod webauthn;

pub use apikey::{SaveSecret, SecretAnswer, SecretEntry, SecretTarget};
pub use bundle::{BundleItem, BundleItemAnswer, BundleRequest};
pub use card::{
    CardAnswer, CardEntry, CardMode, CardPurpose, CardRequest, Money, SaveCard, TotalSource,
};
pub use import::{ImportCounts, ImportFormat, ImportRequest};
pub use keys::{KeyPair, PublicKeys};
pub use messages::*;
pub use pairing::PairingGrant;
pub use passkey::{
    PasskeyAnswer, PasskeyCreate, PasskeyGet, PasskeyOp, PasskeyRequest, PasskeyUser, Requirement,
};
pub use prf::{PrfInput, PrfOutput, PrfResults, PrfValues};
pub use quota::Quota;
pub use seal::{Purpose, Sealed};
pub use secret::Secret;
pub use session::SessionInfo;
pub use signin::{
    Certainty, MethodSource, Provider, SecondStep, SecondStepOrder, SignInKind, SignInMethod,
    SuggestOutcome, Suggestion, Via,
};

/// Protocol version carried in every plaintext message (`"v": 1`).
pub const VERSION: u8 = 1;

/// Length of every id (`phone_id`, `agent_id`, `request_id`) in raw bytes.
pub const ID_LEN: usize = 16;

/// Errors from encoding, crypto and validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A value is not valid base64url, has the wrong length or is otherwise malformed.
    Encoding(&'static str),
    /// HPKE sealing or opening failed (opening fails on any tampering or wrong key).
    Crypto(&'static str),
    /// A relay signature header is malformed, stale or does not verify.
    BadSignature(&'static str),
    /// A pairing code is not six Crockford base32 characters.
    Code(&'static str),
    /// A plaintext message is not valid JSON for its type.
    Json(String),
    /// The pairing grant has no commitment: the phone's app was made before it. Such a pairing
    /// does not hold against a relay that swaps keys, so it is refused (never a fallback).
    OldApp,
    /// The phone's answer to the pairing check does not fit its commitment.
    BadCommitment(&'static str),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Encoding(m) => write!(f, "encoding: {m}"),
            Error::Crypto(m) => write!(f, "crypto: {m}"),
            Error::BadSignature(m) => write!(f, "signature: {m}"),
            Error::Code(m) => write!(f, "pairing code: {m}"),
            Error::Json(m) => write!(f, "message: {m}"),
            Error::OldApp => write!(
                f,
                "Nodkey on the iPhone is too old for this pairing; update Nodkey from the App Store, then pair again"
            ),
            Error::BadCommitment(m) => write!(f, "pairing check: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        // serde_json errors never include the input, so no plaintext leaks into the message.
        Error::Json(e.to_string())
    }
}

/// Fills `buf` from the operating system's random source.
pub fn random_bytes(buf: &mut [u8]) {
    getrandom::fill(buf).expect("operating system random source failed");
}

/// A new random id: 16 random bytes in base64url (22 characters).
pub fn random_id() -> String {
    let mut raw = [0u8; ID_LEN];
    random_bytes(&mut raw);
    b64u::encode(&raw)
}

/// Checks that `id` is 16 bytes in strict base64url.
pub fn validate_id(id: &str) -> Result<(), Error> {
    b64u::decode_array::<ID_LEN>(id).map(|_| ())
}

/// The `aad` of every sealed message: the ASCII of two b64u strings (or the pairing code and a
/// b64u id) concatenated without a separator.
pub fn aad(first: &str, second: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(first.len() + second.len());
    v.extend_from_slice(first.as_bytes());
    v.extend_from_slice(second.as_bytes());
    v
}

/// Current Unix time in seconds.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_22_chars_and_unique() {
        let a = random_id();
        let b = random_id();
        assert_eq!(a.len(), 22);
        assert_ne!(a, b);
        validate_id(&a).unwrap();
        assert!(validate_id("short").is_err());
        assert!(validate_id(&b64u::encode(&[0u8; 32])).is_err());
    }

    #[test]
    fn aad_is_plain_concatenation() {
        assert_eq!(aad("abc", "XYZ"), b"abcXYZ");
    }
}
