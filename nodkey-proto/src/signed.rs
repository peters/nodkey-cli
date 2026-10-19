//! End-to-end signatures on requests and answers: the sender signs the plaintext with its Ed25519
//! key, inside the HPKE box, so a relay can neither read nor make up a message.
//!
//! ```text
//! B   = the message's JSON as the sender wrote it, without "sig"
//! M   = "nodkey/v1/signed\n" + purpose + "\n" + agent_id + "\n" + phone_id + "\n" + B
//! sig = Ed25519(sender's sign key, M)
//! plaintext = B without its last "}" + ",\"sig\":\"" + b64u(sig) + "\"}"
//! ```
//!
//! `sig` is always the last member, so a receiver finds it in the last [`SUFFIX_LEN`] bytes and
//! gets `B` back byte for byte, without a canonical JSON form. Receivers made before signatures
//! ignore the unknown `sig` member.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::{Error, b64u};

/// Which way a signed message goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// A request, agent → phone, signed with the agent's key.
    Request,
    /// An answer, phone → agent, signed with the phone's key.
    Answer,
}

impl Direction {
    /// The word in `M`.
    pub const fn name(self) -> &'static str {
        match self {
            Direction::Request => "request",
            Direction::Answer => "answer",
        }
    }
}

const PREFIX: &[u8] = b",\"sig\":\"";
/// Length of b64u of a 64-byte signature.
const SIG_B64U_LEN: usize = 86;
/// Length of the signature member at the end of a signed plaintext: `,"sig":"<86>"}`.
pub const SUFFIX_LEN: usize = PREFIX.len() + SIG_B64U_LEN + 2;

/// The bytes the sender signs.
pub fn message(direction: Direction, agent_id: &str, phone_id: &str, body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(32 + agent_id.len() + phone_id.len() + body.len());
    m.extend_from_slice(b"nodkey/v1/signed\n");
    m.extend_from_slice(direction.name().as_bytes());
    m.push(b'\n');
    m.extend_from_slice(agent_id.as_bytes());
    m.push(b'\n');
    m.extend_from_slice(phone_id.as_bytes());
    m.push(b'\n');
    m.extend_from_slice(body);
    m
}

/// `body` with `sig` added as its last member. `body` must be a JSON object with at least one
/// member and no `sig` (every protocol message has `v`).
pub fn attach(body: &[u8], sig: &[u8; 64]) -> Result<Vec<u8>, Error> {
    let inner = body
        .strip_suffix(b"}")
        .filter(|b| b.starts_with(b"{") && b.len() > 1)
        .ok_or(Error::Encoding("a signed message is a JSON object"))?;
    let mut out = Vec::with_capacity(body.len() + SUFFIX_LEN);
    out.extend_from_slice(inner);
    out.extend_from_slice(PREFIX);
    out.extend_from_slice(b64u::encode(sig).as_bytes());
    out.extend_from_slice(b"\"}");
    Ok(out)
}

/// Signs `body` with a key in memory and attaches the signature.
pub fn sign(
    direction: Direction,
    agent_id: &str,
    phone_id: &str,
    body: &[u8],
    key: &SigningKey,
) -> Result<Vec<u8>, Error> {
    let sig = key.sign(&message(direction, agent_id, phone_id, body));
    attach(body, &sig.to_bytes())
}

/// A plaintext split into the signed body and its signature.
pub struct Split {
    /// `B`: the plaintext without the signature member.
    pub body: zeroize::Zeroizing<Vec<u8>>,
    pub sig: [u8; 64],
}

/// Finds the signature member at the end of `plain`. `None` when there is none (a sender made
/// before signatures).
pub fn split(plain: &[u8]) -> Option<Split> {
    let start = plain.len().checked_sub(SUFFIX_LEN)?;
    let tail = &plain[start..];
    if start < 2 || !tail.starts_with(PREFIX) || !tail.ends_with(b"\"}") {
        return None;
    }
    let sig = b64u::decode_array::<64>(
        std::str::from_utf8(&tail[PREFIX.len()..PREFIX.len() + SIG_B64U_LEN]).ok()?,
    )
    .ok()?;
    let mut body = zeroize::Zeroizing::new(Vec::with_capacity(start + 1));
    body.extend_from_slice(&plain[..start]);
    body.push(b'}');
    Some(Split { body, sig })
}

/// The result of [`open`].
pub struct Opened {
    /// The message's JSON without `sig`.
    pub body: zeroize::Zeroizing<Vec<u8>>,
    /// Whether it carried a valid signature.
    pub signed: bool,
}

/// Checks the signature on a plaintext the receiver opened. With a signature it must verify
/// against `sender_sign`; without one the message is refused when `required`.
pub fn open(
    direction: Direction,
    agent_id: &str,
    phone_id: &str,
    plain: &[u8],
    sender_sign: &[u8; 32],
    required: bool,
) -> Result<Opened, Error> {
    let Some(split) = split(plain) else {
        if required {
            return Err(Error::BadSignature("the message is not signed"));
        }
        return Ok(Opened {
            body: zeroize::Zeroizing::new(plain.to_vec()),
            signed: false,
        });
    };
    let key =
        VerifyingKey::from_bytes(sender_sign).map_err(|_| Error::BadSignature("bad sender key"))?;
    key.verify(
        &message(direction, agent_id, phone_id, &split.body),
        &Signature::from_bytes(&split.sig),
    )
    .map_err(|_| Error::BadSignature("the message's signature does not verify"))?;
    Ok(Opened {
        body: split.body,
        signed: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyPair;

    #[test]
    fn round_trip_and_tampering() {
        let k = KeyPair::generate();
        let body = br#"{"v":1,"request_id":"r","decision":"approved"}"#;
        let plain = sign(Direction::Answer, "a", "p", body, &k.signing_key()).unwrap();
        assert_eq!(plain.len(), body.len() - 1 + SUFFIX_LEN);
        assert!(plain.ends_with(b"\"}"));
        // Still JSON, so a receiver made before signatures reads it as before.
        let v: serde_json::Value = serde_json::from_slice(&plain).unwrap();
        assert_eq!(v["decision"], "approved");
        assert_eq!(v["sig"].as_str().unwrap().len(), SIG_B64U_LEN);

        let pk = k.public().sign;
        let o = open(Direction::Answer, "a", "p", &plain, &pk, true).unwrap();
        assert!(o.signed);
        assert_eq!(&o.body[..], &body[..]);

        // Another direction, another id, another key or a changed byte: refused.
        assert!(open(Direction::Request, "a", "p", &plain, &pk, true).is_err());
        assert!(open(Direction::Answer, "b", "p", &plain, &pk, true).is_err());
        assert!(open(Direction::Answer, "a", "q", &plain, &pk, false).is_err());
        let other = KeyPair::generate().public().sign;
        assert!(open(Direction::Answer, "a", "p", &plain, &other, false).is_err());
        let mut changed = plain.clone();
        changed[10] ^= 1;
        assert!(open(Direction::Answer, "a", "p", &changed, &pk, false).is_err());
    }

    #[test]
    fn unsigned_messages() {
        let pk = KeyPair::generate().public().sign;
        let body = br#"{"v":1,"request_id":"r","decision":"denied"}"#;
        let o = open(Direction::Answer, "a", "p", body, &pk, false).unwrap();
        assert!(!o.signed);
        assert_eq!(&o.body[..], &body[..]);
        assert!(matches!(
            open(Direction::Answer, "a", "p", body, &pk, true),
            Err(Error::BadSignature(_))
        ));
        assert!(split(b"").is_none());
        assert!(split(b"{}").is_none());
    }

    #[test]
    fn attach_needs_an_object_with_members() {
        assert!(attach(b"{}", &[0; 64]).is_err());
        assert!(attach(b"[1]", &[0; 64]).is_err());
        assert!(attach(b"{\"v\":1}", &[0; 64]).is_ok());
    }

    #[test]
    fn known_message() {
        assert_eq!(
            message(Direction::Request, "AG", "PH", b"{\"v\":1}"),
            b"nodkey/v1/signed\nrequest\nAG\nPH\n{\"v\":1}".to_vec()
        );
    }
}
