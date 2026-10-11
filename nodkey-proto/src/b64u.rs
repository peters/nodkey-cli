//! Base64url without padding (RFC 4648 §5), the protocol's encoding for binary values.
//!
//! Decoding is strict: no padding, no whitespace, and the unused low bits of the last
//! character must be zero, so every byte string has exactly one accepted encoding.

use crate::Error;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

const fn decode_table() -> [u8; 256] {
    let mut table = [0xff_u8; 256];
    let mut i = 0;
    while i < 64 {
        table[ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    table
}

const DECODE: [u8; 256] = decode_table();

/// Length of the encoding of `n` bytes.
pub const fn encoded_len(n: usize) -> usize {
    (n * 4).div_ceil(3)
}

/// Appends the encoding of `bytes` to `out`.
pub fn encode_into(bytes: &[u8], out: &mut String) {
    out.reserve(encoded_len(bytes.len()));
    let mut chunks = bytes.chunks_exact(3);
    for c in &mut chunks {
        let n = (u32::from(c[0]) << 16) | (u32::from(c[1]) << 8) | u32::from(c[2]);
        for shift in [18, 12, 6, 0] {
            out.push(ALPHABET[((n >> shift) & 63) as usize] as char);
        }
    }
    match *chunks.remainder() {
        [a] => {
            let n = u32::from(a) << 16;
            out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
            out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
        }
        [a, b] => {
            let n = (u32::from(a) << 16) | (u32::from(b) << 8);
            out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
            out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
            out.push(ALPHABET[((n >> 6) & 63) as usize] as char);
        }
        _ => {}
    }
}

/// Encodes `bytes`.
pub fn encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(encoded_len(bytes.len()));
    encode_into(bytes, &mut s);
    s
}

/// Decodes a strict base64url string without padding.
pub fn decode(s: &str) -> Result<Vec<u8>, Error> {
    let input = s.as_bytes();
    if input.len() % 4 == 1 {
        return Err(Error::Encoding("base64url length"));
    }
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut chunks = input.chunks_exact(4);
    for c in &mut chunks {
        let n =
            (sextet(c[0])? << 18) | (sextet(c[1])? << 12) | (sextet(c[2])? << 6) | sextet(c[3])?;
        out.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8, n as u8]);
    }
    match *chunks.remainder() {
        [a, b] => {
            let n = (sextet(a)? << 18) | (sextet(b)? << 12);
            if n & 0xffff != 0 {
                return Err(Error::Encoding("base64url trailing bits"));
            }
            out.push((n >> 16) as u8);
        }
        [a, b, c] => {
            let n = (sextet(a)? << 18) | (sextet(b)? << 12) | (sextet(c)? << 6);
            if n & 0xff != 0 {
                return Err(Error::Encoding("base64url trailing bits"));
            }
            out.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8]);
        }
        _ => {}
    }
    Ok(out)
}

/// Decodes into a fixed-size array, failing on any other length.
pub fn decode_array<const N: usize>(s: &str) -> Result<[u8; N], Error> {
    if s.len() != encoded_len(N) {
        return Err(Error::Encoding("base64url value has the wrong length"));
    }
    decode(s)?
        .try_into()
        .map_err(|_| Error::Encoding("base64url value has the wrong length"))
}

#[inline]
fn sextet(c: u8) -> Result<u32, Error> {
    match DECODE[c as usize] {
        0xff => Err(Error::Encoding("base64url character")),
        v => Ok(u32::from(v)),
    }
}

/// Lower-case hex, used for the body hash in signed relay calls.
pub fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 15) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors() {
        let cases: [(&[u8], &str); 7] = [
            (b"", ""),
            (b"f", "Zg"),
            (b"fo", "Zm8"),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg"),
            (b"fooba", "Zm9vYmE"),
            (b"foobar", "Zm9vYmFy"),
        ];
        for (raw, enc) in cases {
            assert_eq!(encode(raw), enc);
            assert_eq!(decode(enc).unwrap(), raw);
        }
    }

    #[test]
    fn url_alphabet() {
        assert_eq!(encode(&[0xfb, 0xff, 0xfe]), "-__-");
        assert_eq!(decode("-__-").unwrap(), [0xfb, 0xff, 0xfe]);
    }

    #[test]
    fn rejects_non_canonical() {
        assert!(decode("Zg==").is_err());
        assert!(decode("Zh").is_err()); // trailing bits set
        assert!(decode("Z").is_err());
        assert!(decode("Zm9v+g").is_err());
        assert!(decode("Zm 9").is_err());
    }

    #[test]
    fn round_trip_all_lengths() {
        let data: Vec<u8> = (0..=255u8).collect();
        for n in 0..data.len() {
            let e = encode(&data[..n]);
            assert_eq!(e.len(), encoded_len(n));
            assert_eq!(decode(&e).unwrap(), &data[..n]);
        }
    }

    #[test]
    fn fixed_arrays() {
        let id = [7u8; 16];
        let s = encode(&id);
        assert_eq!(s.len(), 22);
        assert_eq!(decode_array::<16>(&s).unwrap(), id);
        assert!(decode_array::<32>(&s).is_err());
    }

    #[test]
    fn hex_lower() {
        assert_eq!(hex(&[0x00, 0xab, 0xff]), "00abff");
    }
}
