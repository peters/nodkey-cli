//! Websites (docs/agent-protocol.md, "Websites"): the host of an address read the way a browser
//! reads it, its registrable domain from the Public Suffix List, and the rules built on them.
//!
//! - An account belongs to a website when the registrable domain of the website equals the
//!   registrable domain of the account's site or of one of its extra websites ([`same_site`]).
//!   `login.github.com` is GitHub; `github.xyz`, `git-hub.com` and `alice.github.io` are not:
//!   `github.io` is an ending (a public suffix) like `com`, so each name below it is a website of
//!   its own.
//! - A passkey's `rp_id` is never a public suffix ([`is_public_suffix`]).
//! - An agent fills a login only on the sites in its `fill_only_on` ([`fill_only_on`],
//!   [`may_fill`]).
//!
//! The iPhone app has the same rules (`LoginSite.swift`); the `sites` vectors keep both in step.

mod psl;
mod punycode;

use crate::{Account, MatchKind};

pub use psl::{TEXT as PUBLIC_SUFFIX_LIST, rule_count, version};

/// Longest host, in characters.
const MAX_HOST: usize = 253;
/// Longest label, in characters.
const MAX_LABEL: usize = 63;

/// The host of an address or target the way a browser reads it: lower case, without scheme, user
/// name, port, path, query or fragment (a backslash ends the host, as in a browser), one trailing
/// dot removed, and labels with letters outside ASCII in their `xn--` form. An IPv6 address keeps
/// its brackets.
///
/// `None` when it is not a host: no dot (except `localhost`), an empty label, a character a host
/// cannot have (`%`, a space), or numbers that are not a plain IPv4 address (`0x7f.1`, `010.0.0.1`).
pub fn host(value: &str) -> Option<String> {
    parse_host(value, false)
}

/// [`host`], and with `single` also a name without a dot (`com`, `intranet`).
fn parse_host(value: &str, single: bool) -> Option<String> {
    let v = value.trim();
    let rest = match v.split_once("://") {
        Some((scheme, rest)) if is_scheme(scheme) => rest,
        _ => v.strip_prefix("//").unwrap_or(v),
    };
    let authority = rest.split(['/', '\\', '?', '#']).next().unwrap_or_default();
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    if let Some(inside) = authority.strip_prefix('[') {
        let (address, port) = inside.split_once(']')?;
        let address_ok = address.contains(':')
            && address
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.');
        return (address_ok && (port.is_empty() || port_ok(port.strip_prefix(':')?)))
            .then(|| format!("[{}]", address.to_ascii_lowercase()));
    }
    let (name, port) = authority.split_once(':').unwrap_or((authority, ""));
    if !port.is_empty() && !port_ok(port) {
        return None;
    }
    let name = name.strip_suffix('.').unwrap_or(name);
    let labels: Option<Vec<String>> = name
        .split('.')
        .map(|label| {
            let ascii = punycode::to_ascii(label)?;
            let ok = !ascii.is_empty()
                && ascii.len() <= MAX_LABEL
                && ascii
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
            ok.then_some(ascii)
        })
        .collect();
    let labels = labels?;
    let host = labels.join(".");
    if host.len() > MAX_HOST {
        return None;
    }
    // A browser reads a name that ends in a number as an IPv4 address; only the plain form is one.
    let last = labels.last()?;
    if last.bytes().all(|b| b.is_ascii_digit()) || last.starts_with("0x") {
        return is_ipv4(&host).then_some(host);
    }
    (single || labels.len() > 1 || host == "localhost").then_some(host)
}

fn is_scheme(s: &str) -> bool {
    s.starts_with(|c: char| c.is_ascii_alphabetic())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
}

fn port_ok(port: &str) -> bool {
    !port.is_empty() && port.len() <= 5 && port.bytes().all(|b| b.is_ascii_digit())
}

/// Four decimal numbers from 0 to 255 without leading zeros.
fn is_ipv4(host: &str) -> bool {
    let parts: Vec<&str> = host.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 3
                && p.bytes().all(|b| b.is_ascii_digit())
                && (p.len() == 1 || !p.starts_with('0'))
                && p.parse::<u16>().is_ok_and(|n| n <= 255)
        })
}

/// Whether `host` (from [`host`]) is an IP address.
fn is_address(host: &str) -> bool {
    host.starts_with('[') || is_ipv4(host)
}

/// The public suffix of an address (`co.uk` for `www.bbc.co.uk`, `github.io` for
/// `alice.github.io`, the last label when no rule matches). `None` for an IP address or a value
/// that is not a host.
pub fn public_suffix(value: &str) -> Option<String> {
    let host = host(value)?;
    (!is_address(&host)).then(|| suffix_of(&host).0)
}

/// The public suffix of a host name and how many labels it has in front of it.
fn suffix_of(host: &str) -> (String, usize) {
    let labels: Vec<&str> = host.split('.').collect();
    let n = psl::suffix_len(&labels);
    (labels[labels.len() - n..].join("."), labels.len() - n)
}

/// The registrable domain of an address: its public suffix and one label more
/// (`login.bbc.co.uk` → `bbc.co.uk`, `alice.github.io` → `alice.github.io`). `None` for an IP
/// address, for a host that is a public suffix itself (`co.uk`, `github.io`, `localhost`) and for
/// a value that is not a host.
pub fn registrable_domain(value: &str) -> Option<String> {
    let host = host(value)?;
    if is_address(&host) {
        return None;
    }
    let (suffix, before) = suffix_of(&host);
    let label = host.split('.').nth(before.checked_sub(1)?)?;
    Some(format!("{label}.{suffix}"))
}

/// Whether an address is a public suffix itself: an ending such as `com` or `co.uk`, or a shared
/// hosting domain such as `github.io`. `localhost` counts as one (the list has no rule for it);
/// an IP address does not.
pub fn is_public_suffix(value: &str) -> bool {
    parse_host(value, true).is_some_and(|h| !is_address(&h) && suffix_of(&h).1 == 0)
}

/// What two addresses must share to be the same website: the registrable domain, or the host
/// itself when it has none (an IP address, `localhost`). `None` when the value is not a host.
pub fn site_key(value: &str) -> Option<String> {
    let host = host(value)?;
    Some(registrable_domain(&host).unwrap_or(host))
}

/// Whether two addresses are the same website (equal [`site_key`]).
pub fn same_site(a: &str, b: &str) -> bool {
    matches!((site_key(a), site_key(b)), (Some(a), Some(b)) if a == b)
}

/// The sites where an agent may fill the login or code of an answer: the site and extra websites
/// of the account, as [`site_key`]s, in order and without duplicates. For an account the user
/// picked by hand (`match: chosen`), the site of the request's `target` instead: the user approved
/// it for that website. Empty when neither has a website.
pub fn fill_only_on(target: &str, account: &Account, match_kind: Option<MatchKind>) -> Vec<String> {
    let own: Vec<&str> = account
        .site
        .iter()
        .chain(account.sites.iter().flatten())
        .map(String::as_str)
        .collect();
    let wanted = match (match_kind, site_key(target_host(target))) {
        (Some(MatchKind::Chosen), Some(target)) => vec![target],
        _ => own.into_iter().filter_map(site_key).collect(),
    };
    let mut out: Vec<String> = Vec::new();
    for site in wanted {
        if !out.contains(&site) {
            out.push(site);
        }
    }
    out
}

/// The site part of a request target: `github.com` for `github.com/alex` (an account name after
/// the site), the URL itself after a scheme.
fn target_host(target: &str) -> &str {
    let t = target.trim();
    if t.contains("://") {
        return t;
    }
    t.split('/').next().unwrap_or_default()
}

/// Whether an agent may fill on a page at `page` (a URL or host): its host is one of `sites` or
/// below one (`login.example.com` for `example.com`). Below a public suffix never counts, so a
/// list entry such as `github.io` allows only that host itself.
pub fn may_fill(page: &str, sites: &[String]) -> bool {
    let Some(page) = host(page) else {
        return false;
    };
    sites.iter().filter_map(|s| host(s)).any(|site| {
        page == site || (!is_public_suffix(&site) && page.ends_with(&format!(".{site}")))
    })
}

#[cfg(test)]
mod tests;
