//! Long-term keys of one side (phone or agent): an X25519 HPKE key and an Ed25519 signing key.

use ed25519_dalek::{SigningKey, VerifyingKey};
use hpke::{Deserializable, Kem as _, Serializable, kem::X25519HkdfSha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, b64u};

/// Public keys of one side, raw 32 bytes each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKeys {
    /// Ed25519 verifying key.
    pub sign: [u8; 32],
    /// X25519 HPKE public key.
    pub kem: [u8; 32],
}

impl PublicKeys {
    /// Parses the b64u strings used on the wire (`sign`, `kem`).
    pub fn from_b64u(sign: &str, kem: &str) -> Result<Self, Error> {
        let keys = PublicKeys {
            sign: b64u::decode_array(sign)?,
            kem: b64u::decode_array(kem)?,
        };
        VerifyingKey::from_bytes(&keys.sign).map_err(|_| Error::Encoding("not an Ed25519 key"))?;
        Ok(keys)
    }

    /// `sign` as b64u.
    pub fn sign_b64u(&self) -> String {
        b64u::encode(&self.sign)
    }

    /// `kem` as b64u.
    pub fn kem_b64u(&self) -> String {
        b64u::encode(&self.kem)
    }
}

/// Private keys of one side. Both are the raw 32-byte forms (the X25519 scalar before clamping,
/// as CryptoKit's `rawRepresentation`; the Ed25519 seed). Wiped from memory on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KeyPair {
    kem_sk: [u8; 32],
    sign_sk: [u8; 32],
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair").finish_non_exhaustive()
    }
}

impl KeyPair {
    /// New random keys from the operating system's random source.
    pub fn generate() -> Self {
        let mut kp = KeyPair {
            kem_sk: [0; 32],
            sign_sk: [0; 32],
        };
        crate::random_bytes(&mut kp.kem_sk);
        crate::random_bytes(&mut kp.sign_sk);
        kp
    }

    /// Keys from their raw private bytes.
    pub fn from_bytes(kem_sk: [u8; 32], sign_sk: [u8; 32]) -> Self {
        KeyPair { kem_sk, sign_sk }
    }

    /// Raw X25519 private key.
    pub fn kem_secret(&self) -> &[u8; 32] {
        &self.kem_sk
    }

    /// Raw Ed25519 seed.
    pub fn sign_secret(&self) -> &[u8; 32] {
        &self.sign_sk
    }

    /// The Ed25519 signing key.
    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.sign_sk)
    }

    /// Both public keys.
    pub fn public(&self) -> PublicKeys {
        PublicKeys {
            sign: self.signing_key().verifying_key().to_bytes(),
            kem: x25519_public(&self.kem_sk),
        }
    }
}

/// X25519 public key for a raw private key.
pub fn x25519_public(sk: &[u8; 32]) -> [u8; 32] {
    let sk = <X25519HkdfSha256 as hpke::Kem>::PrivateKey::from_bytes(sk)
        .expect("any 32 bytes are an X25519 private key");
    let mut out = [0u8; 32];
    out.copy_from_slice(&X25519HkdfSha256::sk_to_pk(&sk).to_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7748_public_key() {
        // RFC 7748 §6.1, Alice.
        let sk: [u8; 32] =
            hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let pk = hex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        assert_eq!(x25519_public(&sk), pk);
    }

    #[test]
    fn rfc8032_public_key() {
        // RFC 8032 §7.1, test 1.
        let sk = hex32("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let pk = hex32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        assert_eq!(KeyPair::from_bytes([1; 32], sk).public().sign, pk);
    }

    #[test]
    fn public_keys_round_trip_b64u() {
        let p = KeyPair::generate().public();
        assert_eq!(
            PublicKeys::from_b64u(&p.sign_b64u(), &p.kem_b64u()).unwrap(),
            p
        );
    }

    #[test]
    fn debug_hides_secrets() {
        let kp = KeyPair::from_bytes([0xaa; 32], [0xbb; 32]);
        let s = format!("{kp:?}");
        assert!(!s.contains("170") && !s.contains("aa"));
    }

    pub(crate) fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }
}
