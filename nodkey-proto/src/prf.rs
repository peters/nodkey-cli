//! The WebAuthn PRF extension (CTAP2 `hmac-secret`) for passkeys: the inputs an agent sends with
//! a passkey request, the outputs the phone answers with, and the derivation both sides use.
//!
//! Each passkey that supports PRF holds `credRandom`, 32 random bytes made with the passkey. For
//! each input the phone answers `HMAC-SHA256(credRandom, SHA-256("WebAuthn PRF" ‖ 0x00 ‖ input))`
//! (WebAuthn Level 3, "Pseudo-random function extension"). The same passkey and input always give
//! the same 32 bytes; another input or another passkey gives other bytes.

use std::collections::BTreeMap;

use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Secret, b64u, passkey::MAX_CREDENTIALS};

/// The context string WebAuthn puts in front of every PRF input.
pub const LABEL: &[u8] = b"WebAuthn PRF";

/// Length of `credRandom` and of every PRF output.
pub const LEN: usize = 32;

/// Longest PRF input in bytes (before b64u).
pub const MAX_INPUT: usize = 256;

/// One or two PRF inputs (b64u). WebAuthn's `AuthenticationExtensionsPRFValues`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrfValues {
    pub first: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub second: Option<String>,
}

/// `prf` in a passkey request. On create, `{}` asks the phone to make the passkey with PRF;
/// `eval` there also asks for the outputs at once. On get, `eval` holds the inputs for any
/// passkey and `eval_by_credential` the inputs for given credential ids (b64u), which must be in
/// `allow_credentials`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrfInput {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eval: Option<PrfValues>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub eval_by_credential: BTreeMap<String, PrfValues>,
}

/// The outputs (b64u, 32 bytes each). Secret: they are key material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrfResults {
    pub first: Secret,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub second: Option<Secret>,
}

/// `prf` in a passkey answer. `enabled` (create only) says whether the new passkey supports PRF;
/// `results` holds the outputs when the request had inputs for the passkey that answered.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrfOutput {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub results: Option<PrfResults>,
}

/// `SHA-256("WebAuthn PRF" ‖ 0x00 ‖ input)`: the salt WebAuthn gives the authenticator.
pub fn salt(input: &[u8]) -> [u8; LEN] {
    let mut h = Sha256::new();
    h.update(LABEL);
    h.update([0]);
    h.update(input);
    h.finalize().into()
}

/// `HMAC-SHA256(cred_random, salt(input))`: one PRF output.
pub fn evaluate(cred_random: &[u8; LEN], input: &[u8]) -> zeroize::Zeroizing<[u8; LEN]> {
    let mut mac = Hmac::<Sha256>::new_from_slice(cred_random).expect("HMAC takes any key length");
    mac.update(&salt(input));
    zeroize::Zeroizing::new(mac.finalize().into_bytes().into())
}

/// The outputs for `values` (b64u inputs), as the phone answers them.
pub fn results(cred_random: &[u8; LEN], values: &PrfValues) -> Result<PrfResults, &'static str> {
    let one = |v: &str| {
        let input = decode_input(v)?;
        Ok(Secret::new(b64u::encode(&*evaluate(cred_random, &input))))
    };
    Ok(PrfResults {
        first: one(&values.first)?,
        second: values.second.as_deref().map(one).transpose()?,
    })
}

/// A new random `credRandom`.
pub fn random_cred_random() -> zeroize::Zeroizing<[u8; LEN]> {
    let mut out = zeroize::Zeroizing::new([0u8; LEN]);
    crate::random_bytes(&mut *out);
    out
}

fn decode_input(v: &str) -> Result<Vec<u8>, &'static str> {
    let raw = b64u::decode(v).map_err(|_| "a prf input is not base64url")?;
    if raw.len() > MAX_INPUT {
        return Err("a prf input is longer than 256 bytes");
    }
    Ok(raw)
}

impl PrfValues {
    fn check(&self) -> Result<(), &'static str> {
        decode_input(&self.first)?;
        self.second.as_deref().map(decode_input).transpose()?;
        Ok(())
    }
}

impl PrfInput {
    /// True when the request has an input for some passkey.
    pub fn has_inputs(&self) -> bool {
        self.eval.is_some() || !self.eval_by_credential.is_empty()
    }

    /// The inputs for the passkey with `credential_id` (b64u): its entry in
    /// `eval_by_credential`, else `eval`.
    pub fn values_for(&self, credential_id: &str) -> Option<&PrfValues> {
        let raw = b64u::decode(credential_id).ok();
        self.eval_by_credential
            .iter()
            .find(|(id, _)| raw.is_some() && b64u::decode(id).ok() == raw)
            .map(|(_, v)| v)
            .or(self.eval.as_ref())
    }

    /// The agent's check, WebAuthn's rules: inputs are b64u of at most 256 bytes; create has no
    /// `eval_by_credential`; get has inputs, and every key of `eval_by_credential` is one of
    /// `allow_credentials` (so it is not empty).
    pub fn check(&self, create: bool, allow_credentials: &[String]) -> Result<(), String> {
        if let Some(v) = &self.eval {
            v.check()?;
        }
        if create {
            if !self.eval_by_credential.is_empty() {
                return Err("prf.eval_by_credential is only for sign in (get)".into());
            }
            return Ok(());
        }
        if !self.has_inputs() {
            return Err("prf on get needs eval or eval_by_credential".into());
        }
        if self.eval_by_credential.len() > MAX_CREDENTIALS {
            return Err(format!(
                "at most {MAX_CREDENTIALS} entries in prf.eval_by_credential"
            ));
        }
        let allowed: Vec<Vec<u8>> = allow_credentials
            .iter()
            .filter_map(|id| b64u::decode(id).ok())
            .collect();
        for (id, v) in &self.eval_by_credential {
            let raw =
                b64u::decode(id).map_err(|_| "a prf.eval_by_credential key is not base64url")?;
            if raw.is_empty() || !allowed.contains(&raw) {
                return Err("every prf.eval_by_credential key must be in allow_credentials".into());
            }
            v.check()?;
        }
        Ok(())
    }
}

/// The agent's check of the `prf` in an answer: results only for asked inputs, 32 bytes each,
/// `second` exactly when it was asked. `asked` is [`PrfInput::values_for`] of the answering
/// passkey (`None` when the request had no inputs for it).
pub fn check_output(asked: Option<&PrfValues>, output: &PrfOutput) -> Result<(), String> {
    let Some(results) = &output.results else {
        return Ok(());
    };
    let asked = asked.ok_or("the phone sent PRF results that were not asked for")?;
    let ok = |s: &Secret| b64u::decode(s.expose()).is_ok_and(|b| b.len() == LEN);
    if !ok(&results.first) || results.second.as_ref().is_some_and(|s| !ok(s)) {
        return Err("the phone sent a bad PRF result".into());
    }
    if results.second.is_some() != asked.second.is_some() {
        return Err("the phone's PRF results do not match the inputs".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
