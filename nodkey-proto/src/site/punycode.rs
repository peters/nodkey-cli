//! Punycode (RFC 3492): the `xn--` form of a host label with letters outside ASCII, as browsers
//! put it in URLs. Only encoding is needed: hosts and the public suffix list are compared in their
//! ASCII form.

const BASE: u32 = 36;
const T_MIN: u32 = 1;
const T_MAX: u32 = 26;
const SKEW: u32 = 38;
const DAMP: u32 = 700;
const INITIAL_BIAS: u32 = 72;
const INITIAL_N: u32 = 128;

fn adapt(delta: u32, points: u32, first: bool) -> u32 {
    let mut delta = if first { delta / DAMP } else { delta / 2 };
    delta += delta / points;
    let mut k = 0;
    while delta > ((BASE - T_MIN) * T_MAX) / 2 {
        delta /= BASE - T_MIN;
        k += BASE;
    }
    k + (BASE - T_MIN + 1) * delta / (delta + SKEW)
}

fn digit(d: u32) -> char {
    let b = if d < 26 {
        b'a' + d as u8
    } else {
        b'0' + (d - 26) as u8
    };
    char::from(b)
}

/// The Punycode of `label` without the `xn--` prefix (`bücher` → `bcher-kva`). `None` on overflow,
/// which only a label far longer than a host allows can cause.
pub fn encode(label: &str) -> Option<String> {
    let input: Vec<u32> = label.chars().map(u32::from).collect();
    let mut out: String = label.chars().filter(char::is_ascii).collect();
    let basic = out.len() as u32;
    let mut handled = basic;
    if basic > 0 {
        out.push('-');
    }
    let (mut n, mut delta, mut bias) = (INITIAL_N, 0u32, INITIAL_BIAS);
    while (handled as usize) < input.len() {
        let m = input.iter().copied().filter(|&c| c >= n).min()?;
        delta = delta.checked_add((m - n).checked_mul(handled + 1)?)?;
        n = m;
        for &c in &input {
            if c < n {
                delta = delta.checked_add(1)?;
            }
            if c == n {
                let mut q = delta;
                let mut k = BASE;
                loop {
                    let t = if k <= bias {
                        T_MIN
                    } else if k >= bias + T_MAX {
                        T_MAX
                    } else {
                        k - bias
                    };
                    if q < t {
                        break;
                    }
                    out.push(digit(t + (q - t) % (BASE - t)));
                    q = (q - t) / (BASE - t);
                    k += BASE;
                }
                out.push(digit(q));
                bias = adapt(delta, handled + 1, handled == basic);
                delta = 0;
                handled += 1;
            }
        }
        delta = delta.checked_add(1)?;
        n = n.checked_add(1)?;
    }
    Some(out)
}

/// A label in its ASCII form: lower case, and `xn--` plus Punycode when it has letters outside
/// ASCII (`Bücher` → `xn--bcher-kva`). This is the lower-casing step of UTS #46 only; a label that
/// needs more mapping comes out unlike a browser's, so it never equals a saved site by accident.
pub fn to_ascii(label: &str) -> Option<String> {
    if label.is_ascii() {
        return Some(label.to_ascii_lowercase());
    }
    Some(format!("xn--{}", encode(&label.to_lowercase())?))
}
