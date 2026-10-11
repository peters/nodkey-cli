//! Opening a sealed message when the X25519 step is done elsewhere.
//!
//! A browser keeps the agent's X25519 private key as a non-extractable WebCrypto key, so it cannot
//! hand the key to [`crate::seal::open`]. It computes `dh = X25519(sk, enc)` itself and passes the
//! result here; the rest of HPKE base mode (RFC 9180: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
//! ChaCha20-Poly1305) runs in this crate, so both sides stay byte-identical with `seal::open`.

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{AeadInOut, Nonce, Tag},
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{
    Error,
    seal::{ENC_LEN, TAG_LEN},
};

const KEM_SUITE: &[u8] = b"KEM\x00\x20";
const HPKE_SUITE: &[u8] = b"HPKE\x00\x20\x00\x01\x00\x03";
const MODE_BASE: u8 = 0;

fn labeled_extract(suite: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut input = Zeroizing::new(Vec::with_capacity(
        7 + suite.len() + label.len() + ikm.len(),
    ));
    input.extend_from_slice(b"HPKE-v1");
    input.extend_from_slice(suite);
    input.extend_from_slice(label);
    input.extend_from_slice(ikm);
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), &input);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&prk);
    out
}

fn labeled_expand(suite: &[u8], prk: &[u8; 32], label: &[u8], info: &[u8], out: &mut [u8]) {
    let mut full = Vec::with_capacity(9 + suite.len() + label.len() + info.len());
    full.extend_from_slice(&(out.len() as u16).to_be_bytes());
    full.extend_from_slice(b"HPKE-v1");
    full.extend_from_slice(suite);
    full.extend_from_slice(label);
    full.extend_from_slice(info);
    Hkdf::<Sha256>::from_prk(prk)
        .expect("32-byte PRK")
        .expand(&full, out)
        .expect("short output");
}

/// Opens `ct` sealed to the recipient whose X25519 public key is `recipient_kem`, given
/// `dh = X25519(recipient secret, enc)`. Fails exactly when [`crate::seal::open`] would.
pub fn open_with_dh(
    info: &[u8],
    dh: &[u8; 32],
    recipient_kem: &[u8; 32],
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
    if dh.iter().all(|&b| b == 0) {
        // X25519 with a low-order point; the hpke crate refuses it too.
        return Err(Error::Crypto("open failed"));
    }

    // DHKEM(X25519, HKDF-SHA256) Decap: shared_secret = ExtractAndExpand(dh, enc ‖ pkR).
    let mut kem_context = [0u8; 64];
    kem_context[..32].copy_from_slice(enc);
    kem_context[32..].copy_from_slice(recipient_kem);
    let eae_prk = labeled_extract(KEM_SUITE, b"", b"eae_prk", dh);
    let mut shared = Zeroizing::new([0u8; 32]);
    labeled_expand(
        KEM_SUITE,
        &eae_prk,
        b"shared_secret",
        &kem_context,
        &mut shared[..],
    );

    // KeySchedule, base mode (no PSK).
    let psk_id_hash = labeled_extract(HPKE_SUITE, b"", b"psk_id_hash", b"");
    let info_hash = labeled_extract(HPKE_SUITE, b"", b"info_hash", info);
    let mut context = [0u8; 65];
    context[0] = MODE_BASE;
    context[1..33].copy_from_slice(&psk_id_hash[..]);
    context[33..].copy_from_slice(&info_hash[..]);
    let secret = labeled_extract(HPKE_SUITE, &shared[..], b"secret", b"");
    let mut key = Zeroizing::new([0u8; 32]);
    labeled_expand(HPKE_SUITE, &secret, b"key", &context, &mut key[..]);
    let mut nonce = [0u8; 12];
    labeled_expand(HPKE_SUITE, &secret, b"base_nonce", &context, &mut nonce);

    // Single shot: sequence number 0, so the nonce is the base nonce.
    let cipher = ChaCha20Poly1305::new_from_slice(&key[..]).expect("32-byte key");
    let (body, tag) = ct.split_at(ct.len() - TAG_LEN);
    let mut buf = Zeroizing::new(body.to_vec());
    let nonce = Nonce::<ChaCha20Poly1305>::try_from(&nonce[..]).expect("12-byte nonce");
    let tag = Tag::<ChaCha20Poly1305>::try_from(tag).expect("16-byte tag");
    cipher
        .decrypt_inout_detached(&nonce, aad, buf.as_mut_slice().into(), &tag)
        .map_err(|_| Error::Crypto("open failed"))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        keys::x25519_public,
        seal::{Purpose, seal_with_rng},
        testing::DetRng,
    };

    #[test]
    fn matches_the_hpke_crate() {
        let sk = [7u8; 32];
        let pk = x25519_public(&sk);
        let info = Purpose::Answer.info().as_bytes();
        for (i, msg) in [&b""[..], b"x", &[0x5a; 1000]].iter().enumerate() {
            let sealed =
                seal_with_rng(info, &pk, b"aad", msg, &mut DetRng::new(&[i as u8])).unwrap();
            let dh = x25519_dalek::x25519(sk, sealed.enc);
            let opened = open_with_dh(info, &dh, &pk, &sealed.enc, b"aad", &sealed.ct).unwrap();
            assert_eq!(&opened[..], *msg);
            // The same failures as seal::open: other aad, other info, changed ciphertext.
            assert!(open_with_dh(info, &dh, &pk, &sealed.enc, b"other", &sealed.ct).is_err());
            assert!(
                open_with_dh(
                    b"nodkey/v1/request",
                    &dh,
                    &pk,
                    &sealed.enc,
                    b"aad",
                    &sealed.ct
                )
                .is_err()
            );
            let mut ct = sealed.ct.clone();
            ct[0] ^= 1;
            assert!(open_with_dh(info, &dh, &pk, &sealed.enc, b"aad", &ct).is_err());
        }
        assert!(open_with_dh(info, &[0; 32], &pk, &[1; 32], b"", &[0; 16]).is_err());
        assert!(open_with_dh(info, &[1; 32], &pk, &[1; 31], b"", &[0; 16]).is_err());
    }
}
