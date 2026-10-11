//! Pairing codes: 6 Crockford base32 characters, shown as `K7P-2QX`.
//!
//! The canonical form (what the relay returns, what goes into URLs and into the pairing grant's
//! `aad`) is six upper-case characters from `0123456789ABCDEFGHJKMNPQRSTVWXYZ` without a dash.

use crate::Error;

/// Crockford base32 alphabet (no I, L, O, U).
pub const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Number of characters in a code.
pub const LEN: usize = 6;

/// True when `code` is already canonical.
pub fn is_canonical(code: &str) -> bool {
    code.len() == LEN && code.bytes().all(|b| ALPHABET.contains(&b))
}

/// Turns what a person typed into the canonical form: ignores case, dashes and spaces, and reads
/// `O` as `0` and `I`/`L` as `1` as Crockford base32 allows.
pub fn normalize(input: &str) -> Result<String, Error> {
    let mut out = String::with_capacity(LEN);
    for c in input.chars() {
        let c = match c.to_ascii_uppercase() {
            '-' | ' ' => continue,
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        };
        if !c.is_ascii() || !ALPHABET.contains(&(c as u8)) {
            return Err(Error::Code("only Crockford base32 characters are allowed"));
        }
        if out.len() == LEN {
            return Err(Error::Code("must be 6 characters"));
        }
        out.push(c);
    }
    if out.len() != LEN {
        return Err(Error::Code("must be 6 characters"));
    }
    Ok(out)
}

/// Display form `K7P-2QX` of a canonical code.
pub fn display(code: &str) -> String {
    if code.len() == LEN {
        format!("{}-{}", &code[..3], &code[3..])
    } else {
        code.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_codes() {
        assert!(is_canonical("K7P2QX"));
        assert!(is_canonical("000000"));
        assert!(!is_canonical("K7P-2QX"));
        assert!(!is_canonical("K7P2Q"));
        assert!(!is_canonical("K7P2QU")); // U is not in the alphabet
        assert!(!is_canonical("k7p2qx"));
    }

    #[test]
    fn normalizes_typing() {
        assert_eq!(normalize("K7P-2QX").unwrap(), "K7P2QX");
        assert_eq!(normalize(" k7p 2qx ").unwrap(), "K7P2QX");
        assert_eq!(normalize("OIL-abc").unwrap(), "011ABC");
        assert!(normalize("K7P-2QU").is_err());
        assert!(normalize("K7P-2Q").is_err());
        assert!(normalize("K7P-2QXX").is_err());
        assert!(normalize("K7P-2Q✓").is_err());
    }

    #[test]
    fn display_form() {
        assert_eq!(display("K7P2QX"), "K7P-2QX");
    }
}
