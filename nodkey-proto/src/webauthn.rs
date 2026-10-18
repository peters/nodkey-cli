//! A software WebAuthn authenticator made the way Nodkey on the iPhone makes passkeys: ES256,
//! flags UP, UV, BE and BS on every answer, sign count 0, "none" attestation and Nodkey's AAGUID.
//! The fake phone and the vectors sign with it; an agent uses [`check_answer`] on what the phone
//! sent and tests use [`verify`].

use p256::ecdsa::{
    Signature,
    signature::{Signer, Verifier},
};
use sha2::{Digest, Sha256};

pub use p256::ecdsa::{SigningKey, VerifyingKey};

use crate::{
    Error, b64u,
    passkey::{ES256, PasskeyAnswer, PasskeyOp, PasskeyRequest, client_data_hash},
};

/// Nodkey's authenticator id: 97531e9d-ff39-4e63-aaec-b1d68400c3c9.
pub const AAGUID: [u8; 16] = [
    0x97, 0x53, 0x1e, 0x9d, 0xff, 0x39, 0x4e, 0x63, 0xaa, 0xec, 0xb1, 0xd6, 0x84, 0x00, 0xc3, 0xc9,
];

pub const FLAG_UP: u8 = 0x01;
pub const FLAG_UV: u8 = 0x04;
pub const FLAG_BE: u8 = 0x08;
pub const FLAG_BS: u8 = 0x10;
pub const FLAG_AT: u8 = 0x40;

/// The flags of every answer: user present, user verified, backup eligible, backed up.
pub const FLAGS: u8 = FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS;

/// DER prefix of a P-256 SubjectPublicKeyInfo; the 65-byte uncompressed point follows.
const SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// `rpIdHash ‖ flags ‖ signCount (0)` and, for a new passkey, the attested credential data
/// (`AAGUID ‖ u16be(len) ‖ credential id ‖ COSE key`).
pub fn authenticator_data(rp_id: &str, attested: Option<(&[u8], &VerifyingKey)>) -> Vec<u8> {
    let mut data = Sha256::digest(rp_id.as_bytes()).to_vec();
    data.push(if attested.is_some() {
        FLAGS | FLAG_AT
    } else {
        FLAGS
    });
    data.extend_from_slice(&[0, 0, 0, 0]);
    if let Some((credential_id, key)) = attested {
        data.extend_from_slice(&AAGUID);
        data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        data.extend_from_slice(credential_id);
        data.extend_from_slice(&cose_key(key));
    }
    data
}

/// The COSE_Key of an ES256 public key: `{1: 2, 3: -7, -1: 1, -2: x, -3: y}`, in this order.
pub fn cose_key(key: &VerifyingKey) -> Vec<u8> {
    let point = key.to_sec1_point(false);
    let xy = &point.as_bytes()[1..];
    let mut out = cbor::head(5, 5);
    for (k, v) in [(1, 2), (3, ES256), (-1, 1)] {
        out.extend(cbor::int(k));
        out.extend(cbor::int(v));
    }
    out.extend(cbor::int(-2));
    out.extend(cbor::bytes(&xy[..32]));
    out.extend(cbor::int(-3));
    out.extend(cbor::bytes(&xy[32..]));
    out
}

/// `{"fmt": "none", "attStmt": {}, "authData": …}`, in this order (as the app writes it).
pub fn attestation_object(authenticator_data: &[u8]) -> Vec<u8> {
    let mut out = cbor::head(5, 3);
    out.extend(cbor::text("fmt"));
    out.extend(cbor::text("none"));
    out.extend(cbor::text("attStmt"));
    out.extend(cbor::head(5, 0));
    out.extend(cbor::text("authData"));
    out.extend(cbor::bytes(authenticator_data));
    out
}

/// SubjectPublicKeyInfo DER of a P-256 key (91 bytes), WebAuthn's `getPublicKey()`.
pub fn spki_der(key: &VerifyingKey) -> Vec<u8> {
    let mut out = SPKI_PREFIX.to_vec();
    out.extend_from_slice(key.to_sec1_point(false).as_bytes());
    out
}

/// The key in a P-256 SubjectPublicKeyInfo DER.
pub fn key_from_spki(der: &[u8]) -> Result<VerifyingKey, Error> {
    let point = der
        .strip_prefix(&SPKI_PREFIX[..])
        .filter(|p| p.len() == 65)
        .ok_or(Error::Encoding("not a P-256 public key"))?;
    VerifyingKey::from_sec1_bytes(point).map_err(|_| Error::Encoding("not a P-256 public key"))
}

/// A signing key from its 32-byte scalar.
pub fn signing_key(secret: &[u8; 32]) -> Result<SigningKey, Error> {
    SigningKey::from_slice(secret).map_err(|_| Error::Encoding("not a P-256 private key"))
}

/// A new random signing key.
pub fn random_signing_key() -> SigningKey {
    loop {
        let mut secret = zeroize::Zeroizing::new([0u8; 32]);
        crate::random_bytes(&mut *secret);
        if let Ok(key) = signing_key(&secret) {
            return key;
        }
    }
}

/// The DER signature over `authenticator_data ‖ SHA-256(client_data_json)` (RFC 6979, so the same
/// input always gives the same signature).
pub fn sign(key: &SigningKey, authenticator_data: &[u8], client_data_json: &[u8]) -> Vec<u8> {
    let signature: Signature = key.sign(&signed_data(authenticator_data, client_data_json));
    der::encode(&signature.to_bytes())
}

/// Checks a DER signature over `authenticator_data ‖ SHA-256(client_data_json)`.
pub fn verify(
    key: &VerifyingKey,
    authenticator_data: &[u8],
    client_data_json: &[u8],
    signature_der: &[u8],
) -> Result<(), Error> {
    let raw = der::decode(signature_der).ok_or(Error::Encoding("not a DER ECDSA signature"))?;
    let signature =
        Signature::from_slice(&raw).map_err(|_| Error::Encoding("not an ECDSA signature"))?;
    key.verify(
        &signed_data(authenticator_data, client_data_json),
        &signature,
    )
    .map_err(|_| Error::BadSignature("the passkey signature does not verify"))
}

/// The bytes a passkey signs: `authenticator_data ‖ SHA-256(client_data_json)`.
pub fn signed_data(authenticator_data: &[u8], client_data_json: &[u8]) -> Vec<u8> {
    let mut data = authenticator_data.to_vec();
    data.extend_from_slice(&client_data_hash(client_data_json));
    data
}

/// The agent's check of an approved answer before it hands it on: every value is b64u, the
/// authenticator data is for `rp_id` with the user present, and the answer has the fields of
/// its operation (a signature for get; an attestation object and an ES256 key for create), and
/// PRF results only for inputs the request had ([`crate::prf::check_output`]).
pub fn check_answer(request: &PasskeyRequest, answer: &PasskeyAnswer) -> Result<(), String> {
    let decode = |name: &str, v: &str| {
        b64u::decode(v)
            .ok()
            .filter(|b| !b.is_empty())
            .ok_or(format!("the phone sent a bad {name}"))
    };
    decode("credential_id", &answer.credential_id)?;
    let auth = decode("authenticator_data", &answer.authenticator_data)?;
    let rp_hash = Sha256::digest(request.rp_id().as_bytes());
    if auth.len() < 37 || auth[..32] != rp_hash[..] || auth[32] & FLAG_UP == 0 {
        return Err("the phone's authenticator data is not for this site".into());
    }
    match request {
        PasskeyRequest::Get(_) => {
            let sig = answer
                .signature
                .as_deref()
                .ok_or("the phone sent no signature")?;
            der::decode(&decode("signature", sig)?).ok_or("the phone sent a bad signature")?;
            if let Some(handle) = &answer.user_handle {
                decode("user_handle", handle)?;
            }
        }
        PasskeyRequest::Create(_) => {
            let att = answer.attestation_object.as_deref();
            decode(
                "attestation_object",
                att.ok_or("the phone sent no attestation")?,
            )?;
            let key = answer
                .public_key
                .as_deref()
                .ok_or("the phone sent no public key")?;
            key_from_spki(&decode("public_key", key)?).map_err(|e| e.to_string())?;
            if answer.public_key_algorithm != Some(ES256) || auth[32] & FLAG_AT == 0 {
                return Err("the phone's new passkey is not an ES256 key".into());
            }
        }
    }
    if let Some(out) = &answer.prf {
        let asked = request
            .prf()
            .and_then(|p| p.values_for(&answer.credential_id));
        crate::prf::check_output(asked, out)?;
        if request.op() == PasskeyOp::Get && out.enabled.is_some() {
            return Err("the phone sent prf.enabled for a sign in".into());
        }
    }
    Ok(())
}

/// The few CBOR shapes WebAuthn needs (RFC 8949): integers, byte and text strings, map heads.
mod cbor {
    pub fn head(major: u8, value: u64) -> Vec<u8> {
        let m = major << 5;
        match value {
            0..24 => vec![m | value as u8],
            24..0x100 => vec![m | 24, value as u8],
            0x100..0x1_0000 => [&[m | 25][..], &(value as u16).to_be_bytes()].concat(),
            0x1_0000..0x1_0000_0000 => [&[m | 26][..], &(value as u32).to_be_bytes()].concat(),
            _ => [&[m | 27][..], &value.to_be_bytes()].concat(),
        }
    }

    pub fn int(v: i64) -> Vec<u8> {
        if v >= 0 {
            head(0, v as u64)
        } else {
            head(1, (-1 - v) as u64)
        }
    }

    pub fn bytes(b: &[u8]) -> Vec<u8> {
        [head(2, b.len() as u64), b.to_vec()].concat()
    }

    pub fn text(s: &str) -> Vec<u8> {
        [head(3, s.len() as u64), s.as_bytes().to_vec()].concat()
    }
}

/// DER `SEQUENCE { INTEGER r, INTEGER s }` of a P-256 signature, strict both ways.
mod der {
    fn integer(v: &[u8]) -> Vec<u8> {
        let start = v.iter().position(|&b| b != 0).unwrap_or(v.len() - 1);
        let v = &v[start..];
        let pad = v[0] & 0x80 != 0;
        let mut out = vec![0x02, (v.len() + usize::from(pad)) as u8];
        if pad {
            out.push(0);
        }
        out.extend_from_slice(v);
        out
    }

    /// `r ‖ s` (64 bytes) to DER.
    pub fn encode(rs: &[u8]) -> Vec<u8> {
        let body = [integer(&rs[..32]), integer(&rs[32..])].concat();
        [vec![0x30, body.len() as u8], body].concat()
    }

    /// One minimal positive INTEGER of at most 32 bytes (after a sign byte), left-padded.
    fn read_integer(input: &[u8]) -> Option<([u8; 32], &[u8])> {
        let (&[0x02, len], rest) = input.split_first_chunk::<2>()? else {
            return None;
        };
        let (v, rest) = rest.split_at_checked(usize::from(len))?;
        let minimal = match v {
            [] => false,
            [0, next, ..] => next & 0x80 != 0,
            [first, ..] => first & 0x80 == 0,
        };
        let v = if v.len() > 1 && v[0] == 0 { &v[1..] } else { v };
        if !minimal || v.len() > 32 {
            return None;
        }
        let mut out = [0u8; 32];
        out[32 - v.len()..].copy_from_slice(v);
        Some((out, rest))
    }

    /// DER to `r ‖ s` (64 bytes).
    pub fn decode(der: &[u8]) -> Option<[u8; 64]> {
        let (&[0x30, len], body) = der.split_first_chunk::<2>()? else {
            return None;
        };
        if usize::from(len) != body.len() {
            return None;
        }
        let (r, rest) = read_integer(body)?;
        let (s, rest) = read_integer(rest)?;
        if !rest.is_empty() {
            return None;
        }
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&r);
        out[32..].copy_from_slice(&s);
        Some(out)
    }
}

#[cfg(test)]
mod tests;
