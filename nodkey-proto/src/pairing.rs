//! Pairing with a commitment (docs/agent-protocol.md, "Pairing and the check number").
//!
//! The phone puts `commit` = SHA-256("nodkey/v1/pairing-commit" ‖ phone_sign ‖ phone_kem ‖
//! phone_nonce) in the grant. The agent then sends its own nonce in a `pairing_check` request, and
//! only then does the phone answer with its nonce. Both sides show
//!
//! ```text
//! check = u32be(SHA-256("nodkey/v1/pairing-check" ‖ agent_sign ‖ agent_kem ‖ phone_sign ‖
//!               phone_kem ‖ agent_nonce ‖ phone_nonce)[0..4]) mod 1_000_000
//! ```
//!
//! A relay that swaps keys must fix the phone's nonce before it sees the agent's, and the agent's
//! before it sees the phone's, so it cannot choose values that give the same number on both
//! screens.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Answer, Decision, Error, Kind, PublicKeys, Request, Scope, VERSION, b64u};

/// Length of each side's nonce in bytes.
pub const NONCE_LEN: usize = 32;

/// Pairing grant, phone → agent (`nodkey/v1/pairing`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingGrant {
    pub v: u8,
    pub phone_name: String,
    pub scope: Scope,
    /// Six digits of the check number without a commitment: only apps made before the
    /// commitment send it. The agent refuses such a grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check: Option<String>,
    /// b64u of the phone's commitment ([`commit`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
}

impl crate::Versioned for PairingGrant {
    fn version(&self) -> u8 {
        self.v
    }
}

/// A grant the agent can finish a pairing with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub phone_name: String,
    pub scope: Scope,
    pub commit: [u8; 32],
}

/// A new random nonce for one pairing.
pub fn nonce() -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    crate::random_bytes(&mut n);
    n
}

/// The phone's commitment to its keys and its nonce.
pub fn commit(phone: &PublicKeys, phone_nonce: &[u8; NONCE_LEN]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"nodkey/v1/pairing-commit");
    h.update(phone.sign);
    h.update(phone.kem);
    h.update(phone_nonce);
    h.finalize().into()
}

/// The check number (0 ..= 999 999) both sides show; format it with [`crate::check::display`].
pub fn check_number(
    agent: &PublicKeys,
    phone: &PublicKeys,
    agent_nonce: &[u8; NONCE_LEN],
    phone_nonce: &[u8; NONCE_LEN],
) -> u32 {
    let mut h = Sha256::new();
    h.update(b"nodkey/v1/pairing-check");
    h.update(agent.sign);
    h.update(agent.kem);
    h.update(phone.sign);
    h.update(phone.kem);
    h.update(agent_nonce);
    h.update(phone_nonce);
    let d = h.finalize();
    u32::from_be_bytes([d[0], d[1], d[2], d[3]]) % 1_000_000
}

/// Reads an opened pairing grant. A grant without `commit` comes from an app made before the
/// commitment: [`Error::OldApp`]. Never fall back to its `check`: a relay could pretend to be such
/// an app.
pub fn read_grant(plain: &[u8]) -> Result<Grant, Error> {
    let grant: PairingGrant = crate::parse_plaintext(plain)?;
    let commit = grant.commit.as_deref().ok_or(Error::OldApp)?;
    Ok(Grant {
        commit: b64u::decode_array(commit)?,
        phone_name: grant.phone_name,
        scope: grant.scope,
    })
}

/// The agent's `pairing_check` request: its nonce, sent once the grant is in.
pub fn check_request(agent_name: &str, agent_nonce: &[u8; NONCE_LEN], ts: u64) -> Request {
    Request {
        v: VERSION,
        request_id: crate::random_id(),
        kind: Kind::PairingCheck,
        target: String::new(),
        reason: String::new(),
        agent: agent_name.to_owned(),
        ts,
        attachment: None,
        filter: None,
        save: None,
        passkey: None,
        bundle: None,
        card: None,
        save_card: None,
        client: None,
        session_id: None,
        suggest: None,
        wait_seconds: None,
        save_secret: None,
        project: None,
        nonce: Some(b64u::encode(agent_nonce)),
        import: None,
    }
}

/// The phone's answer to a `pairing_check` request: its nonce.
pub fn check_answer(request_id: &str, phone_nonce: &[u8; NONCE_LEN]) -> Answer {
    let mut a = Answer::decision(request_id, Decision::Approved);
    a.nonce = Some(b64u::encode(phone_nonce));
    a
}

/// Checks the phone's answer to `pairing_check` against the grant's commitment and gives the
/// check number.
pub fn finish(
    answer: &Answer,
    grant: &Grant,
    agent: &PublicKeys,
    phone: &PublicKeys,
    agent_nonce: &[u8; NONCE_LEN],
) -> Result<u32, Error> {
    if answer.decision != Decision::Approved {
        return Err(Error::BadCommitment(
            "the phone did not answer the pairing check",
        ));
    }
    let phone_nonce: [u8; NONCE_LEN] = answer
        .nonce
        .as_deref()
        .ok_or(Error::BadCommitment("the phone's answer has no nonce"))
        .and_then(|n| {
            b64u::decode_array(n)
                .map_err(|_| Error::BadCommitment("the phone's nonce is not valid"))
        })?;
    if commit(phone, &phone_nonce) != grant.commit {
        return Err(Error::BadCommitment(
            "the phone's nonce does not match its commitment",
        ));
    }
    Ok(check_number(agent, phone, agent_nonce, &phone_nonce))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyPair;

    fn grant_json(commit: Option<String>, check: Option<String>) -> Vec<u8> {
        serde_json::to_vec(&PairingGrant {
            v: VERSION,
            phone_name: "Test iPhone".into(),
            scope: Scope::Selected,
            check,
            commit,
        })
        .unwrap()
    }

    #[test]
    fn a_whole_pairing_check() {
        let (agent, phone) = (KeyPair::generate().public(), KeyPair::generate().public());
        let (an, pn) = (nonce(), nonce());
        let grant =
            read_grant(&grant_json(Some(b64u::encode(&commit(&phone, &pn))), None)).unwrap();
        assert_eq!(grant.phone_name, "Test iPhone");
        let r = check_request("Test agent", &an, 1);
        assert_eq!(r.kind, Kind::PairingCheck);
        assert!(crate::client::check_request(&r).is_ok());
        let n = finish(
            &check_answer(&r.request_id, &pn),
            &grant,
            &agent,
            &phone,
            &an,
        )
        .unwrap();
        assert_eq!(n, check_number(&agent, &phone, &an, &pn));
        assert!(n < 1_000_000);

        // Another nonce than the one committed to, no nonce, or a denial: refused.
        let other = nonce();
        assert!(matches!(
            finish(
                &check_answer(&r.request_id, &other),
                &grant,
                &agent,
                &phone,
                &an
            ),
            Err(Error::BadCommitment(_))
        ));
        let mut none = check_answer(&r.request_id, &pn);
        none.nonce = None;
        assert!(finish(&none, &grant, &agent, &phone, &an).is_err());
        let denied = Answer::decision(&r.request_id, Decision::Denied);
        assert!(finish(&denied, &grant, &agent, &phone, &an).is_err());
        // The commitment covers the phone's keys too.
        let swapped = KeyPair::generate().public();
        assert!(
            finish(
                &check_answer(&r.request_id, &pn),
                &grant,
                &agent,
                &swapped,
                &an
            )
            .is_err()
        );
    }

    #[test]
    fn an_app_without_the_commitment_is_refused() {
        assert_eq!(
            read_grant(&grant_json(None, Some("418902".into()))),
            Err(Error::OldApp)
        );
        assert!(read_grant(&grant_json(Some("short".into()), None)).is_err());
    }

    #[test]
    fn the_number_depends_on_every_input() {
        let (a, p) = (
            PublicKeys {
                sign: [1; 32],
                kem: [2; 32],
            },
            PublicKeys {
                sign: [3; 32],
                kem: [4; 32],
            },
        );
        let base = check_number(&a, &p, &[5; 32], &[6; 32]);
        assert_ne!(base, check_number(&a, &p, &[6; 32], &[5; 32]));
        assert_ne!(base, check_number(&p, &a, &[5; 32], &[6; 32]));
        let mut n = [5; 32];
        n[31] ^= 1;
        assert_ne!(base, check_number(&a, &p, &n, &[6; 32]));
        // Independent computation.
        let mut input = b"nodkey/v1/pairing-check".to_vec();
        for b in 1..=6u8 {
            input.extend_from_slice(&[b; 32]);
        }
        let d = Sha256::digest(&input);
        assert_eq!(
            base,
            u32::from_be_bytes(d[..4].try_into().unwrap()) % 1_000_000
        );
        let mut input = b"nodkey/v1/pairing-commit".to_vec();
        for b in [3u8, 4, 6] {
            input.extend_from_slice(&[b; 32]);
        }
        assert_eq!(
            commit(&p, &[6; 32]),
            <[u8; 32]>::from(Sha256::digest(&input))
        );
    }
}
