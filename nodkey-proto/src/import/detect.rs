//! What an export file holds, without its values: the format (the hint for the phone) and counts
//! per type (for `nodkey import --dry-run` and the fake phone). It reads the content only, never
//! the file name, and keeps no value: CSV fields are looked at in place, JSON values only for
//! whether they are blank, and nothing is copied out except the CSV column names.
//!
//! The column rules follow the app's `PasswordImport` (`source`, the password and code columns),
//! so the hint names the same app the phone will see. The phone's own counts are the ones that
//! count; these are an estimate made before anything is sent.

use serde::{
    Deserialize, Deserializer,
    de::{IgnoredAny, MapAccess, SeqAccess, Visitor},
};
use zeroize::Zeroize;

use super::ImportFormat;

/// What [`detect`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Summary {
    pub format: ImportFormat,
    /// Entries: rows or items with a password or a code key (a login with a code is one).
    pub found: u32,
    /// Of `found`: with a password.
    pub logins: u32,
    /// Of `found`: with a code key (an `otpauth://` link, a TOTP column or field).
    pub codes: u32,
    /// Rows or items with neither (notes, cards, blank rows): the phone leaves them out.
    pub skipped: u32,
    /// The export is encrypted: the phone cannot read it. Export it again without a password.
    pub encrypted: bool,
    /// A zip archive (Dashlane, 1Password `.1pux`): unpack it and send the CSV inside.
    pub archive: bool,
}

impl Summary {
    fn entry(&mut self, password: bool, code: bool) {
        if password || code {
            self.found += 1;
            self.logins += u32::from(password);
            self.codes += u32::from(code);
        } else {
            self.skipped += 1;
        }
    }
}

/// Reads `file` for its format and counts.
pub fn detect(file: &[u8]) -> Summary {
    let file = file.strip_prefix(b"\xef\xbb\xbf").unwrap_or(file);
    if file.starts_with(b"PK\x03\x04") {
        return Summary {
            archive: true,
            ..Summary::default()
        };
    }
    let start = file.iter().position(|b| !b.is_ascii_whitespace());
    match start.map(|i| file[i]) {
        None => Summary::default(),
        Some(b'{') => json(file).unwrap_or_default(),
        Some(_) if first_line_is_link(file) => otpauth_list(file),
        Some(_) => match csv(file) {
            Some(s) => s,
            None if file.split(|&b| b == b'\n').any(is_link) => otpauth_list(file),
            None => Summary::default(),
        },
    }
}

fn is_link(line: &[u8]) -> bool {
    let line = line.trim_ascii();
    line.len() > 10 && line[..10].eq_ignore_ascii_case(b"otpauth://")
}

fn first_line_is_link(file: &[u8]) -> bool {
    file.split(|&b| b == b'\n')
        .find(|l| !l.trim_ascii().is_empty())
        .is_some_and(is_link)
}

fn otpauth_list(file: &[u8]) -> Summary {
    let mut s = Summary {
        format: ImportFormat::OtpauthList,
        ..Summary::default()
    };
    for line in file.split(|&b| b == b'\n') {
        if !line.trim_ascii().is_empty() {
            s.entry(false, is_link(line));
        }
    }
    s
}

// ---------------------------------------------------------------------------------------------
// CSV
// ---------------------------------------------------------------------------------------------

/// One CSV field in place: the bytes between the quotes (with `""` pairs left as they are) or the
/// whole unquoted field.
#[derive(Clone, Copy)]
struct Field<'a> {
    raw: &'a [u8],
    quoted: bool,
}

impl Field<'_> {
    /// Not empty, as the app reads a password (not trimmed).
    fn present(self) -> bool {
        !self.raw.is_empty()
    }

    /// Something other than white space.
    fn filled(self) -> bool {
        self.raw.iter().any(|b| !b.is_ascii_whitespace())
    }

    /// The text of a column name: unquoted, trimmed and in lower case.
    fn name(self) -> String {
        let text = String::from_utf8_lossy(self.raw);
        let text = if self.quoted {
            text.replace("\"\"", "\"")
        } else {
            text.into_owned()
        };
        text.trim().to_lowercase()
    }
}

/// The rows of an RFC 4180 file: commas, double quotes with `""` inside, CRLF or LF.
struct Rows<'a> {
    text: &'a [u8],
    at: usize,
}

impl<'a> Iterator for Rows<'a> {
    type Item = Vec<Field<'a>>;

    fn next(&mut self) -> Option<Vec<Field<'a>>> {
        let t = self.text;
        if self.at >= t.len() {
            return None;
        }
        let mut row = Vec::new();
        loop {
            let field = if t.get(self.at) == Some(&b'"') {
                let start = self.at + 1;
                let mut i = start;
                while i < t.len() {
                    if t[i] == b'"' {
                        if t.get(i + 1) == Some(&b'"') {
                            i += 2;
                            continue;
                        }
                        break;
                    }
                    i += 1;
                }
                let raw = &t[start..i.min(t.len())];
                // Anything between the closing quote and the next separator is dropped.
                self.at = i + 1;
                while self.at < t.len() && !matches!(t[self.at], b',' | b'\n' | b'\r') {
                    self.at += 1;
                }
                Field { raw, quoted: true }
            } else {
                let start = self.at;
                while self.at < t.len() && !matches!(t[self.at], b',' | b'\n' | b'\r') {
                    self.at += 1;
                }
                Field {
                    raw: &t[start..self.at],
                    quoted: false,
                }
            };
            row.push(field);
            match t.get(self.at) {
                Some(b',') => self.at += 1,
                Some(b'\r') => {
                    self.at += if t.get(self.at + 1) == Some(&b'\n') {
                        2
                    } else {
                        1
                    };
                    return Some(row);
                }
                Some(_) => {
                    self.at += 1;
                    return Some(row);
                }
                None => return Some(row),
            }
        }
    }
}

const PASSWORD: [&str; 3] = ["password", "login_password", "pass"];
const CODE: [&str; 7] = [
    "otpauth",
    "login_totp",
    "otp",
    "totp",
    "one-time password",
    "otpsecret",
    "otpurl",
];

/// A CSV with at least two columns; `None` when the first row is not such a header.
fn csv(file: &[u8]) -> Option<Summary> {
    let mut rows = Rows { text: file, at: 0 };
    let names: Vec<String> = rows.next()?.into_iter().map(Field::name).collect();
    if names.len() < 2 {
        return None;
    }
    let column = |candidates: &[&str]| {
        candidates
            .iter()
            .find_map(|c| names.iter().position(|n| n == c))
    };
    let password = column(&PASSWORD);
    let code = column(&CODE);
    let format = csv_format(&names, password.is_some());
    let mut s = Summary {
        format,
        ..Summary::default()
    };
    if format == ImportFormat::Unknown {
        return Some(s);
    }
    for row in rows {
        if row.len() == 1 && row[0].raw.is_empty() {
            continue;
        }
        let cell = |i: Option<usize>| i.and_then(|i| row.get(i).copied());
        s.entry(
            cell(password).is_some_and(Field::present),
            cell(code).is_some_and(Field::filled),
        );
    }
    Some(s)
}

/// Which app wrote a CSV, from its column names (the app's `PasswordImport.source`).
fn csv_format(names: &[String], has_password: bool) -> ImportFormat {
    let has = |n: &str| names.iter().any(|x| x == n);
    let exactly =
        |list: &[&str]| names.len() == list.len() && names.iter().zip(list).all(|(a, b)| a == b);
    if has("otpauth") && has("archived") {
        ImportFormat::OnePasswordCsv
    } else if has("otpauth") {
        ImportFormat::ApplePasswordsCsv
    } else if has("httprealm") {
        ImportFormat::FirefoxCsv
    } else if has("login_uri") {
        ImportFormat::BitwardenCsv
    } else if has("grouping") && has("extra") {
        ImportFormat::LastPassCsv
    } else if has("otpsecret") || has("username2") {
        ImportFormat::DashlaneCsv
    } else if has("vault") && has("createtime") {
        ImportFormat::ProtonPassCsv
    } else if has("additional_urls") {
        ImportFormat::NordPassCsv
    } else if has("group") && has("last modified") {
        ImportFormat::KeePassXcCsv
    } else if exactly(&["name", "url", "username", "password", "note"])
        || exactly(&["name", "url", "username", "password"])
    {
        ImportFormat::ChromeCsv
    } else if has_password {
        ImportFormat::GenericCsv
    } else {
        ImportFormat::Unknown
    }
}

// ---------------------------------------------------------------------------------------------
// JSON: Bitwarden, 2FAS, Aegis
// ---------------------------------------------------------------------------------------------

/// Whether a JSON value is there and not blank. The value itself is not kept: a string is looked
/// at where it lies, and one the parser had to copy is wiped.
#[derive(Debug, Clone, Copy, Default)]
struct Filled(bool);

impl<'de> Deserialize<'de> for Filled {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(FilledVisitor)
    }
}

struct FilledVisitor;

impl<'de> Visitor<'de> for FilledVisitor {
    type Value = Filled;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("any value")
    }
    fn visit_str<E>(self, v: &str) -> Result<Filled, E> {
        Ok(Filled(!v.trim().is_empty()))
    }
    fn visit_string<E>(self, mut v: String) -> Result<Filled, E> {
        let filled = !v.trim().is_empty();
        v.zeroize();
        Ok(Filled(filled))
    }
    fn visit_bool<E>(self, _: bool) -> Result<Filled, E> {
        Ok(Filled(true))
    }
    fn visit_i64<E>(self, _: i64) -> Result<Filled, E> {
        Ok(Filled(true))
    }
    fn visit_u64<E>(self, _: u64) -> Result<Filled, E> {
        Ok(Filled(true))
    }
    fn visit_f64<E>(self, _: f64) -> Result<Filled, E> {
        Ok(Filled(true))
    }
    fn visit_unit<E>(self) -> Result<Filled, E> {
        Ok(Filled(false))
    }
    fn visit_none<E>(self) -> Result<Filled, E> {
        Ok(Filled(false))
    }
    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Filled, D::Error> {
        Filled::deserialize(d)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Filled, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(Filled(true))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Filled, A::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(Filled(true))
    }
}

/// The top level of the JSON exports nodkey knows; every other member is skipped.
#[derive(Deserialize)]
struct Top {
    /// Bitwarden: `true` for both encrypted exports.
    #[serde(default)]
    encrypted: Option<bool>,
    /// Bitwarden: the vault items.
    #[serde(default)]
    items: Option<Vec<BitwardenItem>>,
    /// 2FAS: the code accounts.
    #[serde(default)]
    services: Option<Vec<TwoFasService>>,
    /// 2FAS: the accounts of an encrypted backup.
    #[serde(default, rename = "servicesEncrypted")]
    services_encrypted: Filled,
    #[serde(default, rename = "schemaVersion")]
    schema_version: Option<IgnoredAny>,
    /// Aegis: the vault (an object, or a string when encrypted).
    #[serde(default)]
    db: Option<AegisDb>,
    #[serde(default)]
    header: Option<IgnoredAny>,
}

#[derive(Deserialize)]
struct BitwardenItem {
    /// 1 login, 2 secure note, 3 card, 4 identity.
    #[serde(default, rename = "type")]
    kind: u8,
    #[serde(default)]
    login: Option<BitwardenLogin>,
}

#[derive(Deserialize)]
struct BitwardenLogin {
    #[serde(default)]
    password: Filled,
    #[serde(default)]
    totp: Filled,
}

#[derive(Deserialize)]
struct TwoFasService {
    #[serde(default)]
    secret: Filled,
}

enum AegisDb {
    Encrypted,
    Entries(Vec<AegisEntry>),
}

#[derive(Deserialize)]
struct AegisEntry {
    #[serde(default)]
    info: Option<AegisInfo>,
}

#[derive(Deserialize)]
struct AegisInfo {
    #[serde(default)]
    secret: Filled,
}

impl<'de> Deserialize<'de> for AegisDb {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = AegisDb;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an Aegis vault")
            }
            fn visit_str<E>(self, _: &str) -> Result<AegisDb, E> {
                Ok(AegisDb::Encrypted)
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<AegisDb, A::Error> {
                let mut entries = Vec::new();
                while let Some(key) = map.next_key::<String>()? {
                    if key == "entries" {
                        entries = map.next_value()?;
                    } else {
                        map.next_value::<IgnoredAny>()?;
                    }
                }
                Ok(AegisDb::Entries(entries))
            }
        }
        d.deserialize_any(V)
    }
}

fn json(file: &[u8]) -> Option<Summary> {
    let top: Top = serde_json::from_slice(file).ok()?;
    let mut s = Summary::default();
    if let Some(items) = &top.items {
        s.format = ImportFormat::BitwardenJson;
        s.encrypted = top.encrypted == Some(true);
        if !s.encrypted {
            for item in items {
                match (&item.login, item.kind) {
                    (Some(l), 1) => s.entry(l.password.0, l.totp.0),
                    _ => s.entry(false, false),
                }
            }
        }
    } else if top.encrypted == Some(true) {
        s.format = ImportFormat::BitwardenJson;
        s.encrypted = true;
    } else if let (Some(services), Some(_)) = (&top.services, &top.schema_version) {
        s.format = ImportFormat::TwoFasJson;
        s.encrypted = services.is_empty() && top.services_encrypted.0;
        for service in services {
            s.entry(false, service.secret.0);
        }
    } else if let (Some(db), Some(_)) = (&top.db, &top.header) {
        s.format = ImportFormat::AegisJson;
        match db {
            AegisDb::Encrypted => s.encrypted = true,
            AegisDb::Entries(entries) => {
                for e in entries {
                    s.entry(false, e.info.as_ref().is_some_and(|i| i.secret.0));
                }
            }
        }
    } else {
        return None;
    }
    Some(s)
}
