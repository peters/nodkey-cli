//! The check number's formatting, and the number of pairings made before the commitment.
//!
//! New pairings use [`crate::pairing::check_number`], which also covers both sides' nonces. The
//! number here covers the four keys only: a relay that swaps keys can choose its keys so that
//! both screens show the same number, so no agent pairs with it any more. Apps made before the
//! commitment still show it; the vectors keep it in `check`.
//!
//! `check = u32be(SHA-256("nodkey/v1/check" ‖ agent_sign ‖ agent_kem ‖ phone_sign ‖ phone_kem)[0..4]) mod 1_000_000`

use sha2::{Digest, Sha256};

use crate::PublicKeys;

/// The check number without a commitment (0 ..= 999 999).
pub fn check_number(agent: &PublicKeys, phone: &PublicKeys) -> u32 {
    let mut h = Sha256::new();
    h.update(b"nodkey/v1/check");
    h.update(agent.sign);
    h.update(agent.kem);
    h.update(phone.sign);
    h.update(phone.kem);
    let d = h.finalize();
    u32::from_be_bytes([d[0], d[1], d[2], d[3]]) % 1_000_000
}

/// Six digits without a space, as carried in the pairing grant (`"418902"`).
pub fn digits(check: u32) -> String {
    format!("{:06}", check % 1_000_000)
}

/// Six digits grouped for display (`"418 902"`).
pub fn display(check: u32) -> String {
    let d = digits(check);
    format!("{} {}", &d[..3], &d[3..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formatting() {
        assert_eq!(digits(418902), "418902");
        assert_eq!(digits(7), "000007");
        assert_eq!(display(418902), "418 902");
        assert_eq!(display(42), "000 042");
    }

    #[test]
    fn depends_on_every_key_and_order() {
        let a = PublicKeys {
            sign: [1; 32],
            kem: [2; 32],
        };
        let p = PublicKeys {
            sign: [3; 32],
            kem: [4; 32],
        };
        let base = check_number(&a, &p);
        assert!(base < 1_000_000);
        assert_ne!(base, check_number(&p, &a));
        for i in 0..4 {
            let (mut a2, mut p2) = (a, p);
            match i {
                0 => a2.sign[0] ^= 1,
                1 => a2.kem[31] ^= 1,
                2 => p2.sign[7] ^= 1,
                _ => p2.kem[13] ^= 1,
            }
            assert_ne!(base, check_number(&a2, &p2), "key {i}");
        }
    }

    #[test]
    fn known_value() {
        // Independent computation: SHA-256("nodkey/v1/check" ‖ 01×32 ‖ 02×32 ‖ 03×32 ‖ 04×32).
        let mut input = b"nodkey/v1/check".to_vec();
        for b in 1..=4u8 {
            input.extend_from_slice(&[b; 32]);
        }
        let d = Sha256::digest(&input);
        let expected = u32::from_be_bytes(d[..4].try_into().unwrap()) % 1_000_000;
        let a = PublicKeys {
            sign: [1; 32],
            kem: [2; 32],
        };
        let p = PublicKeys {
            sign: [3; 32],
            kem: [4; 32],
        };
        assert_eq!(check_number(&a, &p), expected);
    }
}
