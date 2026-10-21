//! What a page says about a new password (docs/agent-protocol.md, "The rules"): Apple's
//! `passwordrules` syntax read leniently, joined with the field's `minlength` and `maxlength`,
//! whether any password can meet the result, and whether one does.

use super::{DEFAULT_LENGTH, MAX_LENGTH, Rules};

/// A set of ASCII characters (bit `n` is the character with code `n`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct CharSet(u128);

/// The lowest and highest character a class may hold: space and `~`.
const FIRST: u8 = b' ';
const LAST: u8 = b'~';

impl CharSet {
    /// No character.
    pub const EMPTY: CharSet = CharSet(0);

    /// The characters `from` to `to`, both included.
    pub const fn range(from: u8, to: u8) -> CharSet {
        let mut bits = 0u128;
        let mut c = from;
        while c <= to {
            bits |= 1 << c;
            c += 1;
        }
        CharSet(bits)
    }

    /// The characters of `s` (characters outside space to `~` are left out).
    pub fn of(s: &str) -> CharSet {
        s.chars().fold(CharSet::EMPTY, |set, c| set.with(c))
    }

    /// Every ASCII character from space to `~`.
    pub const PRINTABLE: CharSet = CharSet::range(FIRST, LAST);
    pub const UPPER: CharSet = CharSet::range(b'A', b'Z');
    pub const LOWER: CharSet = CharSet::range(b'a', b'z');
    pub const DIGIT: CharSet = CharSet::range(b'0', b'9');
    /// Every printable character that is not a letter or a digit, space included.
    pub const SPECIAL: CharSet =
        CharSet(CharSet::PRINTABLE.0 & !CharSet::UPPER.0 & !CharSet::LOWER.0 & !CharSet::DIGIT.0);

    /// This set and `c`, when `c` is from space to `~`.
    pub fn with(self, c: char) -> CharSet {
        match u8::try_from(c) {
            Ok(b) if (FIRST..=LAST).contains(&b) => CharSet(self.0 | 1 << b),
            _ => self,
        }
    }

    /// This set without `c`.
    pub fn without(self, c: char) -> CharSet {
        match u8::try_from(c) {
            Ok(b) if b < 128 => CharSet(self.0 & !(1 << b)),
            _ => self,
        }
    }

    pub fn contains(self, c: char) -> bool {
        u8::try_from(c).is_ok_and(|b| b < 128 && self.0 & (1 << b) != 0)
    }

    pub fn union(self, other: CharSet) -> CharSet {
        CharSet(self.0 | other.0)
    }

    pub fn intersect(self, other: CharSet) -> CharSet {
        CharSet(self.0 & other.0)
    }

    /// The characters Nodkey may put in a password: all but the space.
    pub fn usable(self) -> CharSet {
        self.without(' ')
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub fn len(self) -> usize {
        self.0.count_ones() as usize
    }

    /// The characters in ASCII order.
    pub fn chars(self) -> impl Iterator<Item = char> {
        (FIRST..=LAST)
            .filter(move |b| self.0 & (1 << b) != 0)
            .map(char::from)
    }

    /// The characters in ASCII order, as a string (`"0123456789"`).
    pub fn text(self) -> String {
        self.chars().collect()
    }
}

/// How the phone reads the rules of a request: one set per `required` property, the allowed
/// characters and the limits, with the field's `minlength` and `maxlength` joined in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reading {
    /// Each `required` property, in the order of the text: the password has one of these.
    pub required: Vec<CharSet>,
    /// The characters the password may use.
    pub allowed: CharSet,
    pub max_consecutive: Option<u32>,
    pub min_length: Option<u32>,
    pub max_length: Option<u32>,
}

impl Rules {
    /// The reading of these rules (no rules: [`Reading::default`]).
    pub fn read(&self) -> Reading {
        let mut r = self
            .passwordrules
            .as_deref()
            .map(read_passwordrules)
            .unwrap_or_default();
        if let Some(n) = self.min_length {
            r.min_length = Some(r.min_length.map_or(n, |m| m.max(n)));
        }
        if let Some(n) = self.max_length {
            r.max_length = Some(r.max_length.map_or(n, |m| m.min(n)));
        }
        r
    }

    /// The reading, or why no password can meet it (`bad_rules`). `pattern` is the phone's to
    /// check: this crate has no regular expressions.
    pub fn check(&self) -> Result<Reading, String> {
        let r = self.read();
        r.problem().map_or(Ok(r), Err)
    }

    /// Whether `password` meets these rules (all but `pattern`).
    pub fn fits(&self, password: &str) -> bool {
        self.read().fits(password)
    }
}

impl Default for Reading {
    /// No rules: any printable ASCII character, any length.
    fn default() -> Self {
        Reading {
            required: Vec::new(),
            allowed: CharSet::PRINTABLE,
            max_consecutive: None,
            min_length: None,
            max_length: None,
        }
    }
}

impl Reading {
    /// The longest password the rules let Nodkey make.
    fn cap(&self) -> u32 {
        self.max_length.unwrap_or(MAX_LENGTH).min(MAX_LENGTH)
    }

    /// The length of the password Nodkey makes: [`DEFAULT_LENGTH`], raised to the minimum and
    /// lowered to the maximum, and at least one per `required` property.
    pub fn length(&self) -> u32 {
        let min = self.min_length.unwrap_or(0);
        DEFAULT_LENGTH
            .max(min)
            .min(self.cap())
            .max(self.required.len() as u32)
    }

    /// Why no password Nodkey makes can meet this reading, or `None`.
    pub fn problem(&self) -> Option<String> {
        let min = self.min_length.unwrap_or(0);
        if let Some(max) = self.max_length {
            if max == 0 {
                return Some("the maximum length is 0".into());
            }
            if min > max {
                return Some(format!(
                    "the minimum length {min} is above the maximum {max}"
                ));
            }
        }
        if min > MAX_LENGTH {
            return Some(format!(
                "the minimum length {min} is above {MAX_LENGTH}, the longest password Nodkey makes"
            ));
        }
        if self.max_consecutive == Some(0) {
            return Some("max-consecutive is 0".into());
        }
        if self.required.iter().any(|r| r.usable().is_empty()) {
            return Some("a required class has no character but a space".into());
        }
        let usable = self.allowed.usable();
        if usable.is_empty() {
            return Some("no character but a space is allowed".into());
        }
        if (self.cap() as usize) < self.required.len() {
            return Some(format!(
                "{} required classes do not fit in {} characters",
                self.required.len(),
                self.cap()
            ));
        }
        if usable.len() == 1 && self.max_consecutive.is_some_and(|m| self.length() > m) {
            return Some(
                "only one character is allowed, and max-consecutive is below the length".into(),
            );
        }
        None
    }

    /// Whether `password` meets this reading.
    pub fn fits(&self, password: &str) -> bool {
        let n = password.chars().count() as u64;
        let long_enough = self.min_length.is_none_or(|m| n >= u64::from(m));
        let short_enough = self.max_length.is_none_or(|m| n <= u64::from(m));
        let allowed = password.chars().all(|c| self.allowed.contains(c));
        let required = self
            .required
            .iter()
            .all(|r| password.chars().any(|c| r.contains(c)));
        long_enough && short_enough && allowed && required && self.runs_fit(password)
    }

    fn runs_fit(&self, password: &str) -> bool {
        let Some(max) = self.max_consecutive else {
            return true;
        };
        let (mut run, mut last) = (0u32, None);
        for c in password.chars() {
            run = if Some(c) == last { run + 1 } else { 1 };
            last = Some(c);
            if run > max {
                return false;
            }
        }
        true
    }
}

/// Reads `passwordrules` text: properties separated by `;` (outside a custom class), each
/// `name: value`. Parts without `:`, unknown properties, unknown classes and numbers that are not
/// whole are left out.
pub fn read_passwordrules(text: &str) -> Reading {
    let chars: Vec<char> = text.chars().collect();
    let mut required = Vec::new();
    let mut allowed: Option<CharSet> = None;
    let (mut max_consecutive, mut min_length, mut max_length) = (None::<u32>, None::<u32>, None);
    for part in split(&chars, ';') {
        let Some(colon) = part.iter().position(|&c| c == ':') else {
            continue;
        };
        let name: String = part[..colon]
            .iter()
            .collect::<String>()
            .trim()
            .to_lowercase();
        let value = &part[colon + 1..];
        match name.as_str() {
            "required" => required.extend(classes(value)),
            "allowed" => {
                if let Some(set) = classes(value) {
                    allowed = Some(allowed.unwrap_or_default().union(set));
                }
            }
            "max-consecutive" => keep(&mut max_consecutive, number(value), u32::min),
            "minlength" => keep(&mut min_length, number(value), u32::max),
            "maxlength" => keep(&mut max_length, number(value), u32::min),
            _ => {}
        }
    }
    let allowed = match (allowed, required.is_empty()) {
        (None, true) => CharSet::PRINTABLE,
        (a, _) => required
            .iter()
            .fold(a.unwrap_or_default(), |set, r| set.union(*r)),
    };
    Reading {
        required,
        allowed,
        max_consecutive,
        min_length,
        max_length,
    }
}

fn keep(slot: &mut Option<u32>, value: Option<u32>, pick: fn(u32, u32) -> u32) {
    if let Some(v) = value {
        *slot = Some(slot.map_or(v, |s| pick(s, v)));
    }
}

fn number(value: &[char]) -> Option<u32> {
    let text: String = value.iter().collect();
    let t = text.trim();
    (!t.is_empty() && t.bytes().all(|b| b.is_ascii_digit()))
        .then(|| t.parse().ok())
        .flatten()
}

/// The union of a list of classes separated by `,`; `None` when no item is a class.
fn classes(value: &[char]) -> Option<CharSet> {
    split(value, ',')
        .into_iter()
        .filter_map(class)
        .reduce(CharSet::union)
}

/// One item of a class list: a named class, or exactly one custom class.
fn class(item: &[char]) -> Option<CharSet> {
    let text: String = item.iter().collect();
    let t = text.trim();
    if t.starts_with('[') {
        let chars: Vec<char> = t.chars().collect();
        return match custom_class(&chars, 0) {
            (set, end, true) if end == chars.len() => Some(set),
            _ => None,
        };
    }
    match t.to_lowercase().as_str() {
        "upper" => Some(CharSet::UPPER),
        "lower" => Some(CharSet::LOWER),
        "digit" => Some(CharSet::DIGIT),
        "special" => Some(CharSet::SPECIAL),
        "ascii-printable" | "unicode" => Some(CharSet::PRINTABLE),
        _ => None,
    }
}

/// The custom class that opens at `open` (a `[`): its characters, the index after it and whether
/// it was closed. `-` counts only as the first character; `]]` is a `]` that ends the class.
/// Characters outside space to `~` are left out. An unclosed class runs to the end.
fn custom_class(chars: &[char], open: usize) -> (CharSet, usize, bool) {
    let first = open + 1;
    let mut set = CharSet::EMPTY;
    let mut i = first;
    while i < chars.len() {
        let c = chars[i];
        i += 1;
        if c == ']' {
            if chars.get(i) == Some(&']') {
                return (set.with(']'), i + 1, true);
            }
            return (set, i, true);
        }
        if c == '-' && i - 1 > first {
            continue;
        }
        set = set.with(c);
    }
    (set, chars.len(), false)
}

/// `chars` split at `sep`, except inside a custom class.
fn split(chars: &[char], sep: char) -> Vec<&[char]> {
    let mut parts = Vec::new();
    let (mut start, mut i) = (0, 0);
    while i < chars.len() {
        match chars[i] {
            '[' => i = custom_class(chars, i).1,
            c if c == sep => {
                parts.push(&chars[start..i]);
                i += 1;
                start = i;
            }
            _ => i += 1,
        }
    }
    parts.push(&chars[start..]);
    parts
}
