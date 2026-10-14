//! HPKE (RFC 9180) base mode, DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305,
//! single-shot, with the protocol's `info` strings.

use hpke::{
    Deserializable, OpModeR, OpModeS, Serializable,
    aead::{AeadTag, ChaCha20Poly1305},
    inout::InOutBuf,
    kdf::HkdfSha256,
    kem::X25519HkdfSha256,
    rand_core::{CryptoRng, TryCryptoRng, TryRng},
};
use zeroize::Zeroizing;

use crate::{Error, b64u, messages::SealedBox};

type Kem = X25519HkdfSha256;
type PrivateKey = <Kem as hpke::Kem>::PrivateKey;
type PublicKey = <Kem as hpke::Kem>::PublicKey;
type EncappedKey = <Kem as hpke::Kem>::EncappedKey;

/// Length of `enc` (the sender's ephemeral X25519 public key).
pub const ENC_LEN: usize = 32;
/// Length of the ChaCha20-Poly1305 tag at the end of every ciphertext.
pub const TAG_LEN: usize = 16;

/// What a sealed message is; selects the HPKE `info`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// Request, agent → phone. `aad` = `request_id` ‖ `agent_id`.
    Request,
    /// Answer, phone → agent. `aad` = `request_id` ‖ `phone_id`.
    Answer,
    /// Pairing grant, phone → agent. `aad` = pairing `code` ‖ `phone_id`.
    Pairing,
    /// Image attachment, agent → phone. `aad` = `request_id` ‖ `agent_id`.
    Attachment,
    /// The password of a `save` request, agent → phone, sealed on its own so the agent never has
    /// to keep it in clear to send the request again. `aad` = `agent_id`.
    Password,
    /// The number or CVC of a card in a `save` request, agent → phone, sealed on its own like a
    /// password. `aad` = `agent_id`.
    Card,
}

impl Purpose {
    /// The HPKE `info` string.
    pub const fn info(self) -> &'static str {
        match self {
            Purpose::Request => "nodkey/v1/request",
            Purpose::Answer => "nodkey/v1/answer",
            Purpose::Pairing => "nodkey/v1/pairing",
            Purpose::Attachment => "nodkey/v1/attachment",
            Purpose::Password => "nodkey/v1/password",
            Purpose::Card => "nodkey/v1/card",
        }
    }

    /// Seals `plaintext` to `recipient_kem` with a fresh ephemeral key from the OS.
    pub fn seal(
        self,
        recipient_kem: &[u8; 32],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Sealed, Error> {
        seal_with_rng(
            self.info().as_bytes(),
            recipient_kem,
            aad,
            plaintext,
            &mut OsRng,
        )
    }

    /// Opens a sealed message with the recipient's private key. Fails on any change to `enc`,
    /// `ct` or `aad`, and on a wrong key or purpose.
    pub fn open(
        self,
        recipient_kem_sk: &[u8; 32],
        enc: &[u8],
        aad: &[u8],
        ct: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        open(self.info().as_bytes(), recipient_kem_sk, enc, aad, ct)
    }

    /// Opens a [`SealedBox`] as sent on the wire.
    pub fn open_box(
        self,
        recipient_kem_sk: &[u8; 32],
        sealed: &SealedBox,
        aad: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let enc = b64u::decode(&sealed.enc)?;
        let ct = b64u::decode(&sealed.ct)?;
        self.open(recipient_kem_sk, &enc, aad, &ct)
    }
}

/// `enc` and `ct` of one sealed message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    /// Encapsulated key (ephemeral X25519 public key).
    pub enc: [u8; ENC_LEN],
    /// Ciphertext followed by the 16-byte tag.
    pub ct: Vec<u8>,
}

impl Sealed {
    /// The `{enc, ct}` object used in relay bodies.
    pub fn to_box(&self) -> SealedBox {
        SealedBox {
            enc: b64u::encode(&self.enc),
            ct: b64u::encode(&self.ct),
        }
    }
}

/// Single-shot seal with an explicit `info` and random source (the source only makes the
/// ephemeral key; a seeded one gives reproducible test vectors).
pub fn seal_with_rng(
    info: &[u8],
    recipient_kem: &[u8; 32],
    aad: &[u8],
    plaintext: &[u8],
    rng: &mut impl CryptoRng,
) -> Result<Sealed, Error> {
    let pk =
        PublicKey::from_bytes(recipient_kem).map_err(|_| Error::Crypto("bad recipient key"))?;
    let (enc, ct) = hpke::single_shot_seal_with_rng::<ChaCha20Poly1305, HkdfSha256, Kem>(
        &OpModeS::Base,
        &pk,
        info,
        plaintext,
        aad,
        rng,
    )
    .map_err(|_| Error::Crypto("seal failed"))?;
    let mut out = [0u8; ENC_LEN];
    out.copy_from_slice(&enc.to_bytes());
    Ok(Sealed { enc: out, ct })
}

/// Single-shot open with an explicit `info`.
pub fn open(
    info: &[u8],
    recipient_kem_sk: &[u8; 32],
    enc: &[u8],
    aad: &[u8],
    ct: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if enc.len() != ENC_LEN {
        return Err(Error::Crypto("enc must be 32 bytes"));
    }
    if ct.len() < TAG_LEN {
        return Err(Error::Crypto("ciphertext too short"));
    }
    let sk =
        PrivateKey::from_bytes(recipient_kem_sk).map_err(|_| Error::Crypto("bad private key"))?;
    let enc = EncappedKey::from_bytes(enc).map_err(|_| Error::Crypto("bad enc"))?;
    let (body, tag) = ct.split_at(ct.len() - TAG_LEN);
    let tag = AeadTag::<ChaCha20Poly1305>::from_bytes(tag).map_err(|_| Error::Crypto("bad tag"))?;
    let mut buf = Zeroizing::new(body.to_vec());
    hpke::single_shot_open_inout_detached::<ChaCha20Poly1305, HkdfSha256, Kem>(
        &OpModeR::Base,
        &sk,
        &enc,
        info,
        InOutBuf::from(buf.as_mut_slice()),
        aad,
        &tag,
    )
    .map_err(|_| Error::Crypto("open failed"))?;
    Ok(buf)
}

/// Seals an image for `PUT /v1/requests/{request_id}/attachment` and returns the raw body
/// `enc ‖ ct`, built in one buffer without copying the image twice.
pub fn seal_attachment_body(
    recipient_kem: &[u8; 32],
    aad: &[u8],
    image: &[u8],
    rng: &mut impl CryptoRng,
) -> Result<Vec<u8>, Error> {
    let pk =
        PublicKey::from_bytes(recipient_kem).map_err(|_| Error::Crypto("bad recipient key"))?;
    let mut body = Vec::with_capacity(ENC_LEN + image.len() + TAG_LEN);
    body.resize(ENC_LEN, 0);
    body.extend_from_slice(image);
    let (enc, tag) =
        hpke::single_shot_seal_inout_detached_with_rng::<ChaCha20Poly1305, HkdfSha256, Kem>(
            &OpModeS::Base,
            &pk,
            Purpose::Attachment.info().as_bytes(),
            InOutBuf::from(&mut body[ENC_LEN..]),
            aad,
            rng,
        )
        .map_err(|_| Error::Crypto("seal failed"))?;
    body[..ENC_LEN].copy_from_slice(&enc.to_bytes());
    body.extend_from_slice(&tag.to_bytes());
    Ok(body)
}

/// Opens an attachment body `enc ‖ ct` (the phone's side; used by tests and the fake relay).
pub fn open_attachment_body(
    recipient_kem_sk: &[u8; 32],
    aad: &[u8],
    body: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if body.len() < ENC_LEN + TAG_LEN {
        return Err(Error::Crypto("attachment too short"));
    }
    let (enc, ct) = body.split_at(ENC_LEN);
    Purpose::Attachment.open(recipient_kem_sk, enc, aad, ct)
}

/// The operating system's random source as a `rand_core` generator.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsRng;

impl TryRng for OsRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        crate::random_bytes(&mut b);
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        crate::random_bytes(&mut b);
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        crate::random_bytes(dst);
        Ok(())
    }
}

impl TryCryptoRng for OsRng {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{keys::x25519_public, testing::FixedRng};

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 9180 Appendix A.2.1 (our exact suite, base mode), first encryption.
    #[test]
    fn rfc9180_known_answer() {
        let info = unhex("4f6465206f6e2061204772656369616e2055726e");
        let ikm_e = unhex("909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b");
        let sk_r: [u8; 32] =
            unhex("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb")
                .try_into()
                .unwrap();
        let pk_r: [u8; 32] =
            unhex("4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a")
                .try_into()
                .unwrap();
        let aad = unhex("436f756e742d30");
        let pt = unhex("4265617574792069732074727574682c20747275746820626561757479");
        let ct = unhex(
            "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28",
        );
        assert_eq!(x25519_public(&sk_r), pk_r);
        let sealed = seal_with_rng(&info, &pk_r, &aad, &pt, &mut FixedRng::new(&ikm_e)).unwrap();
        assert_eq!(
            sealed.enc.to_vec(),
            unhex("1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a")
        );
        assert_eq!(sealed.ct, ct);
        assert_eq!(
            &*open(&info, &sk_r, &sealed.enc, &aad, &ct).unwrap(),
            &pt[..]
        );
    }

    #[test]
    fn round_trip_each_purpose() {
        let sk = [9u8; 32];
        let pk = x25519_public(&sk);
        for p in [
            Purpose::Request,
            Purpose::Answer,
            Purpose::Pairing,
            Purpose::Attachment,
        ] {
            let s = p.seal(&pk, b"aad", b"hello").unwrap();
            assert_eq!(s.ct.len(), 5 + TAG_LEN);
            assert_eq!(&*p.open(&sk, &s.enc, b"aad", &s.ct).unwrap(), b"hello");
            let b = s.to_box();
            assert_eq!(&*p.open_box(&sk, &b, b"aad").unwrap(), b"hello");
        }
    }

    #[test]
    fn tampering_is_detected() {
        let sk = [3u8; 32];
        let pk = x25519_public(&sk);
        let s = Purpose::Request
            .seal(&pk, b"rid-aid", b"{\"v\":1}")
            .unwrap();
        // wrong purpose
        assert!(
            Purpose::Answer
                .open(&sk, &s.enc, b"rid-aid", &s.ct)
                .is_err()
        );
        // wrong aad
        assert!(
            Purpose::Request
                .open(&sk, &s.enc, b"rid-aiX", &s.ct)
                .is_err()
        );
        // flipped ciphertext bit, flipped tag bit, flipped enc bit
        for i in [0, s.ct.len() - 1] {
            let mut ct = s.ct.clone();
            ct[i] ^= 1;
            assert!(Purpose::Request.open(&sk, &s.enc, b"rid-aid", &ct).is_err());
        }
        let mut enc = s.enc;
        enc[5] ^= 1;
        assert!(Purpose::Request.open(&sk, &enc, b"rid-aid", &s.ct).is_err());
        // wrong key
        assert!(
            Purpose::Request
                .open(&[4u8; 32], &s.enc, b"rid-aid", &s.ct)
                .is_err()
        );
        // truncated
        assert!(
            Purpose::Request
                .open(&sk, &s.enc, b"rid-aid", &s.ct[..10])
                .is_err()
        );
    }

    #[test]
    fn attachment_body_round_trip() {
        let sk = [5u8; 32];
        let pk = x25519_public(&sk);
        let image = b"\x89PNG\r\n\x1a\nfake image bytes";
        let body = seal_attachment_body(&pk, b"ridaid", image, &mut OsRng).unwrap();
        assert_eq!(body.len(), ENC_LEN + image.len() + TAG_LEN);
        assert_eq!(
            &*open_attachment_body(&sk, b"ridaid", &body).unwrap(),
            image
        );
        let mut bad = body.clone();
        bad[ENC_LEN + 3] ^= 0x80;
        assert!(open_attachment_body(&sk, b"ridaid", &bad).is_err());
        assert!(open_attachment_body(&sk, b"ridaiX", &body).is_err());
        assert!(open_attachment_body(&sk, b"ridaid", &body[..40]).is_err());
    }
}
