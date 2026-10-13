//! The fake phone's passkeys. It starts with the vectors' test passkey for `webauthn.io` (user
//! `alex`) and makes new ones on create. It checks and signs the way Nodkey on the iPhone does,
//! with `nodkey_proto::webauthn`: refusals that need no user first, `excluded` only after approval.

use nodkey_proto::{
    Answer, Decision, PasskeyAnswer, PasskeyRequest, b64u,
    passkey::{ES256, errors},
    webauthn::{self, SigningKey},
};
use serde::Serialize;

use crate::Fake;

/// The relying party of the test passkey.
pub const RP_ID: &str = "webauthn.io";
/// The user name of the test passkey.
pub const USER_NAME: &str = "alex";

/// One passkey on the fake phone.
pub struct FakePasskey {
    pub rp_id: String,
    pub credential_id: Vec<u8>,
    pub user_handle: Vec<u8>,
    pub user_name: String,
    key: SigningKey,
}

/// What `GET /_fake/passkeys` shows of a passkey (b64u; never the private key).
#[derive(Debug, Clone, Serialize)]
pub struct PasskeyInfo {
    pub rp_id: String,
    pub credential_id: String,
    pub user_handle: String,
    pub user_name: String,
    /// SubjectPublicKeyInfo DER, to check signatures with.
    pub public_key: String,
}

impl FakePasskey {
    /// The vectors' passkey for `webauthn.io`.
    pub fn test() -> Self {
        let (key, credential_id, user_handle) = nodkey_proto::vectors::passkey::test_passkey();
        FakePasskey {
            rp_id: RP_ID.into(),
            credential_id,
            user_handle,
            user_name: USER_NAME.into(),
            key,
        }
    }

    pub fn info(&self) -> PasskeyInfo {
        PasskeyInfo {
            rp_id: self.rp_id.clone(),
            credential_id: b64u::encode(&self.credential_id),
            user_handle: b64u::encode(&self.user_handle),
            user_name: self.user_name.clone(),
            public_key: b64u::encode(&webauthn::spki_der(self.key.verifying_key())),
        }
    }
}

fn denied(rid: &str, error: &str) -> Answer {
    let mut a = Answer::decision(rid, Decision::Denied);
    a.error = Some(error.into());
    a
}

fn ids(list: &[String]) -> Vec<Vec<u8>> {
    list.iter().filter_map(|id| b64u::decode(id).ok()).collect()
}

/// The answer the phone gives at once, without asking the user: bad client data, no passkey for
/// a get, or a create without ES256. `None` when the user is asked.
pub(crate) fn refuse(fake: &Fake, rid: &str, request: &PasskeyRequest) -> Option<Answer> {
    if request.check_client_data().is_err() {
        return Some(denied(rid, errors::BAD_CLIENT_DATA));
    }
    match request {
        PasskeyRequest::Get(g) => {
            let allowed = ids(&g.allow_credentials);
            let passkeys = fake.passkeys.lock().unwrap();
            let found = passkeys.iter().any(|p| {
                p.rp_id.eq_ignore_ascii_case(&g.rp_id)
                    && (allowed.is_empty() || allowed.contains(&p.credential_id))
            });
            (!found).then(|| denied(rid, errors::NO_PASSKEY))
        }
        PasskeyRequest::Create(c) => {
            (!c.algorithms.contains(&ES256)).then(|| denied(rid, errors::UNSUPPORTED_ALGORITHM))
        }
    }
}

/// Fills in an approved answer: signs (get) or makes a new passkey (create), or answers
/// `excluded` when the phone already holds one the site listed.
pub(crate) fn approve(fake: &Fake, answer: &mut Answer, request: &PasskeyRequest) {
    let client_data = b64u::decode(request.client_data_json()).expect("checked before asking");
    let mut passkeys = fake.passkeys.lock().unwrap();
    match request {
        PasskeyRequest::Get(g) => {
            let allowed = ids(&g.allow_credentials);
            // The newest matching passkey (the app lets the user pick when there are several).
            let p = passkeys
                .iter()
                .rev()
                .find(|p| {
                    p.rp_id.eq_ignore_ascii_case(&g.rp_id)
                        && (allowed.is_empty() || allowed.contains(&p.credential_id))
                })
                .expect("checked before asking");
            let auth = webauthn::authenticator_data(&g.rp_id, None);
            let signature = webauthn::sign(&p.key, &auth, &client_data);
            answer.passkey = Some(PasskeyAnswer {
                credential_id: b64u::encode(&p.credential_id),
                attestation_object: None,
                authenticator_data: b64u::encode(&auth),
                signature: Some(b64u::encode(&signature)),
                user_handle: Some(b64u::encode(&p.user_handle)),
                user_name: Some(p.user_name.clone()),
                public_key: None,
                public_key_algorithm: None,
            });
        }
        PasskeyRequest::Create(c) => {
            // Never a lease: Face ID for every new passkey.
            answer.lease = None;
            let excluded = ids(&c.exclude_credentials);
            if passkeys.iter().any(|p| {
                p.rp_id.eq_ignore_ascii_case(&c.rp_id) && excluded.contains(&p.credential_id)
            }) {
                *answer = denied(&answer.request_id, errors::EXCLUDED);
                return;
            }
            let key = webauthn::random_signing_key();
            let mut credential_id = vec![0u8; 16];
            nodkey_proto::random_bytes(&mut credential_id);
            let user_handle = b64u::decode(&c.user.id).expect("checked by the agent");
            let auth =
                webauthn::authenticator_data(&c.rp_id, Some((&credential_id, key.verifying_key())));
            answer.passkey = Some(PasskeyAnswer {
                credential_id: b64u::encode(&credential_id),
                attestation_object: Some(b64u::encode(&webauthn::attestation_object(&auth))),
                authenticator_data: b64u::encode(&auth),
                signature: None,
                user_handle: None,
                user_name: None,
                public_key: Some(b64u::encode(&webauthn::spki_der(key.verifying_key()))),
                public_key_algorithm: Some(ES256),
            });
            // A new passkey replaces one for the same site and user handle, as in the app.
            passkeys.retain(|p| !(p.rp_id == c.rp_id && p.user_handle == user_handle));
            passkeys.push(FakePasskey {
                rp_id: c.rp_id.clone(),
                credential_id,
                user_handle,
                user_name: c.user.name.clone(),
                key,
            });
        }
    }
}
