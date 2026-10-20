//! The sealing context of the vectors: a seeded RNG, so every HPKE vector is reproducible, and the
//! list the vectors go into.

use serde_json::{Value, json};

use super::Side;
use crate::{
    Purpose, b64u,
    seal::{ENC_LEN, seal_with_rng},
    testing::DetRng,
};

pub(super) struct Ctx {
    pub(super) rng: DetRng,
    pub(super) hpke: Vec<Value>,
}

impl Ctx {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn seal(
        &mut self,
        name: &str,
        purpose: Purpose,
        sender: &str,
        recipient: &Side,
        aad_str: String,
        plaintext: &[u8],
        text: bool,
    ) -> crate::SealedBox {
        let ikm_e: [u8; 32] = self.rng.clone().take();
        let pk = recipient.keys.public().kem;
        let s = seal_with_rng(
            purpose.info().as_bytes(),
            &pk,
            aad_str.as_bytes(),
            plaintext,
            &mut self.rng,
        )
        .expect("seal");
        let mut v = json!({
            "name": name,
            "purpose": format!("{purpose:?}").to_lowercase(),
            "sender": sender,
            "info": purpose.info(),
            "aad": aad_str,
            "recipient_kem_sk": b64u::encode(recipient.keys.kem_secret()),
            "recipient_kem_pk": b64u::encode(&pk),
            "ikm_e": b64u::encode(&ikm_e),
            "enc": b64u::encode(&s.enc),
            "ct": b64u::encode(&s.ct),
            "plaintext_b64u": b64u::encode(plaintext),
        });
        if text {
            v["plaintext"] = Value::String(String::from_utf8(plaintext.to_vec()).expect("utf-8"));
        }
        if matches!(purpose, Purpose::Attachment | Purpose::Import) {
            let mut body = Vec::with_capacity(ENC_LEN + s.ct.len());
            body.extend_from_slice(&s.enc);
            body.extend_from_slice(&s.ct);
            v["body_b64u"] = Value::String(b64u::encode(&body));
        }
        self.hpke.push(v);
        s.to_box()
    }
}
