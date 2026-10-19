//! The Public Suffix List (https://publicsuffix.org), both sections: the ICANN endings (`com`,
//! `co.uk`) and the private ones, where anyone can have a name of their own (`github.io`,
//! `herokuapp.com`, `pages.dev`). The snapshot in `data/public_suffix_list.dat` is pinned: its
//! `VERSION` and `COMMIT` lines say which, and the vectors carry its SHA-256 so the iPhone app
//! bundles the same file. `docs/agent-protocol.md`, "Websites", says how to update it.

use std::collections::HashSet;
use std::sync::OnceLock;

use super::punycode;

/// The list as published, unchanged (MPL 2.0, see its first lines).
pub const TEXT: &str = include_str!("../../data/public_suffix_list.dat");

/// The rules, every label in its ASCII form.
struct Rules {
    /// `com`, `co.uk`, `github.io`.
    plain: HashSet<String>,
    /// `*.ck` is kept as `ck`: every name directly below it is an ending.
    wildcard: HashSet<String>,
    /// `!www.ck` is kept as `www.ck`: not an ending, although a wildcard covers it.
    exception: HashSet<String>,
}

fn rules() -> &'static Rules {
    static RULES: OnceLock<Rules> = OnceLock::new();
    RULES.get_or_init(|| parse(TEXT))
}

fn parse(text: &str) -> Rules {
    let mut rules = Rules {
        plain: HashSet::new(),
        wildcard: HashSet::new(),
        exception: HashSet::new(),
    };
    for line in text.lines() {
        let Some(rule) = line.split_whitespace().next() else {
            continue;
        };
        if rule.starts_with("//") {
            continue;
        }
        let (set, rule) = if let Some(r) = rule.strip_prefix('!') {
            (&mut rules.exception, r)
        } else if let Some(r) = rule.strip_prefix("*.") {
            (&mut rules.wildcard, r)
        } else {
            (&mut rules.plain, rule)
        };
        let ascii: Option<Vec<String>> = rule.split('.').map(punycode::to_ascii).collect();
        if let Some(labels) = ascii {
            set.insert(labels.join("."));
        }
    }
    rules
}

/// How many labels at the end of `labels` are the public suffix, by the list's algorithm: the
/// longest matching rule, an exception before every other rule, and `*` (the last label) when no
/// rule matches.
pub fn suffix_len(labels: &[&str]) -> usize {
    let r = rules();
    let n = labels.len();
    let tail = |i: usize| labels[n - i..].join(".");
    if let Some(i) = (1..=n).find(|&i| r.exception.contains(&tail(i))) {
        return i - 1;
    }
    let mut best = 1;
    for i in 1..=n {
        if r.plain.contains(&tail(i)) || (i >= 2 && r.wildcard.contains(&tail(i - 1))) {
            best = i;
        }
    }
    best
}

/// The `VERSION` and `COMMIT` lines of the snapshot.
pub fn version() -> (&'static str, &'static str) {
    let field = |name: &str| {
        TEXT.lines()
            .find_map(|l| l.strip_prefix(name))
            .map_or("", str::trim)
    };
    (field("// VERSION:"), field("// COMMIT:"))
}

/// How many rules the snapshot has.
pub fn rule_count() -> usize {
    let r = rules();
    r.plain.len() + r.wildcard.len() + r.exception.len()
}
