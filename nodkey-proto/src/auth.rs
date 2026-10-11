//! Ed25519 signatures on relay calls: the `Nodkey-Auth: <id>.<ts>.<sig>` header.
//!
//! ```text
//! M = "nodkey/v1\n" + METHOD + "\n" + PATH_WITH_QUERY + "\n" + ts + "\n" + hex(SHA-256(body))
//! ```

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::{Error, b64u};

/// Name of the header.
pub const HEADER: &str = "Nodkey-Auth";

/// Largest accepted difference between `ts` and the verifier's clock, in seconds.
pub const MAX_SKEW: u64 = 120;

/// The signed message `M` for one call. `method` is upper case (`GET`, `POST`, …), `path` is the
/// path with its query string exactly as sent (`/v1/requests/abc?wait=60`), `body` the raw body
/// bytes (empty for `GET`/`DELETE`).
pub fn message(method: &str, path: &str, ts: u64, body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    let mut m = String::with_capacity(10 + method.len() + path.len() + 24 + 64);
    m.push_str("nodkey/v1\n");
    m.push_str(method);
    m.push('\n');
    m.push_str(path);
    m.push('\n');
    m.push_str(&ts.to_string());
    m.push('\n');
    m.push_str(&b64u::hex(&digest));
    m
}

/// The header value `<id>.<ts>.<sig>` for one call.
pub fn sign(key: &SigningKey, id: &str, method: &str, path: &str, ts: u64, body: &[u8]) -> String {
    let sig = key.sign(message(method, path, ts, body).as_bytes());
    let mut h = String::with_capacity(id.len() + 24 + 86);
    h.push_str(id);
    h.push('.');
    h.push_str(&ts.to_string());
    h.push('.');
    b64u::encode_into(&sig.to_bytes(), &mut h);
    h
}

/// A parsed header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed<'a> {
    /// Caller id (`phone_id` or `agent_id`).
    pub id: &'a str,
    /// Unix time the caller signed at.
    pub ts: u64,
    /// The 64-byte signature.
    pub sig: [u8; 64],
}

/// Splits a header value into its parts (does not verify).
pub fn parse(header: &str) -> Result<Parsed<'_>, Error> {
    let mut parts = header.trim().splitn(3, '.');
    let (Some(id), Some(ts), Some(sig)) = (parts.next(), parts.next(), parts.next()) else {
        return Err(Error::BadSignature("header must be <id>.<ts>.<sig>"));
    };
    crate::validate_id(id).map_err(|_| Error::BadSignature("bad id"))?;
    if ts.is_empty()
        || !ts.bytes().all(|b| b.is_ascii_digit())
        || (ts.len() > 1 && ts.starts_with('0'))
    {
        return Err(Error::BadSignature("bad timestamp"));
    }
    let ts = ts
        .parse()
        .map_err(|_| Error::BadSignature("bad timestamp"))?;
    let sig =
        b64u::decode_array::<64>(sig).map_err(|_| Error::BadSignature("bad signature encoding"))?;
    Ok(Parsed { id, ts, sig })
}

/// Verifies a header against the caller's registered key and the verifier's clock `now`.
/// Returns the caller id on success.
pub fn verify<'a>(
    header: &'a str,
    sign_pk: &[u8; 32],
    method: &str,
    path: &str,
    body: &[u8],
    now: u64,
) -> Result<&'a str, Error> {
    let p = parse(header)?;
    if p.ts.abs_diff(now) > MAX_SKEW {
        return Err(Error::BadSignature("timestamp outside ±120 s"));
    }
    let key = VerifyingKey::from_bytes(sign_pk).map_err(|_| Error::BadSignature("bad key"))?;
    key.verify_strict(
        message(method, path, p.ts, body).as_bytes(),
        &Signature::from_bytes(&p.sig),
    )
    .map_err(|_| Error::BadSignature("signature does not verify"))?;
    Ok(p.id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyPair;

    const ID: &str = "AAECAwQFBgcICQoLDA0ODw";

    #[test]
    fn message_format() {
        let m = message("GET", "/v1/requests/x?wait=60", 1791620000, b"");
        assert_eq!(
            m,
            "nodkey/v1\nGET\n/v1/requests/x?wait=60\n1791620000\n\
             e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sign_and_verify() {
        let kp = KeyPair::from_bytes([1; 32], [2; 32]);
        let pk = kp.public().sign;
        let body = br#"{"request_id":"x"}"#;
        let h = sign(
            &kp.signing_key(),
            ID,
            "POST",
            "/v1/phones/p/requests",
            1000,
            body,
        );
        assert_eq!(h.split('.').nth(2).unwrap().len(), 86);
        assert_eq!(
            verify(&h, &pk, "POST", "/v1/phones/p/requests", body, 1000).unwrap(),
            ID
        );
        assert_eq!(
            verify(&h, &pk, "POST", "/v1/phones/p/requests", body, 1120).unwrap(),
            ID
        );
        assert_eq!(
            verify(&h, &pk, "POST", "/v1/phones/p/requests", body, 880).unwrap(),
            ID
        );
    }

    #[test]
    fn rejects_tampering_and_staleness() {
        let kp = KeyPair::from_bytes([1; 32], [2; 32]);
        let pk = kp.public().sign;
        let h = sign(&kp.signing_key(), ID, "POST", "/v1/a", 1000, b"body");
        assert!(verify(&h, &pk, "POST", "/v1/a", b"bodx", 1000).is_err());
        assert!(verify(&h, &pk, "PUT", "/v1/a", b"body", 1000).is_err());
        assert!(verify(&h, &pk, "POST", "/v1/b", b"body", 1000).is_err());
        assert!(verify(&h, &pk, "POST", "/v1/a", b"body", 1121).is_err());
        assert!(verify(&h, &pk, "POST", "/v1/a", b"body", 879).is_err());
        let other = KeyPair::from_bytes([1; 32], [3; 32]).public().sign;
        assert!(verify(&h, &other, "POST", "/v1/a", b"body", 1000).is_err());
        // changed timestamp in the header
        let forged = h.replacen(".1000.", ".1001.", 1);
        assert!(verify(&forged, &pk, "POST", "/v1/a", b"body", 1000).is_err());
    }

    #[test]
    fn parse_rejects_malformed() {
        assert!(parse("abc").is_err());
        assert!(parse(&format!("{ID}.12a.sig")).is_err());
        assert!(parse(&format!("{ID}.0012.{}", "A".repeat(86))).is_err());
        assert!(parse(&format!("short.12.{}", "A".repeat(86))).is_err());
        assert!(parse(&format!("{ID}.12.{}", "A".repeat(86))).is_ok());
    }
}
