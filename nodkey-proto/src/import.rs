//! Moving in: an export file for the phone's import window (docs/agent-protocol.md, "Moving in").
//!
//! The request describes the file ([`ImportRequest`]); the file follows on the attachment path,
//! sealed to the phone on its own (`nodkey/v1/import`). The phone stages what it reads for the
//! user's review and answers `staged` with counts ([`ImportCounts`]), never with a secret.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    Error, Purpose, aad, b64u,
    seal::{ENC_LEN, OsRng, TAG_LEN, open_upload_body, seal_upload_body},
};

pub mod detect;

/// The largest body the relay takes on the attachment path (`enc` ‖ ciphertext ‖ tag).
pub const ATTACHMENT_MAX: usize = 1 << 20;
/// The largest export file: 1 048 528 bytes, so the sealed body fits [`ATTACHMENT_MAX`].
pub const MAX_FILE: usize = ATTACHMENT_MAX - ENC_LEN - TAG_LEN;
/// The longest `file_name`, in characters.
pub const MAX_FILE_NAME: usize = 120;
/// The longest `source`, in characters.
pub const MAX_SOURCE: usize = 80;
/// How many files one import window takes.
pub const WINDOW_FILES: u32 = 20;
/// How long an import window stays open, in seconds.
pub const WINDOW_SECONDS: u64 = 1800;
/// How long the phone waits for the file to reach the relay, in seconds.
pub const FILE_WAIT: u64 = 60;

/// Why the phone refused an `import` request (`decision: denied`), in the order it checks.
pub mod errors {
    /// The phone has no passcode: it cannot open an import window, nor add what one staged.
    pub const NO_PASSCODE: &str = "no_passcode";
    /// No import window is open for this agent (none, closed, timed out, or another agent's).
    pub const IMPORT_CLOSED: &str = "import_closed";
    /// The window already holds [`super::WINDOW_FILES`] files.
    pub const WINDOW_FULL: &str = "window_full";
    /// The file is larger than [`super::MAX_FILE`].
    pub const TOO_LARGE: &str = "too_large";
    /// The request breaks a rule of [`super::ImportRequest::check`], or the file did not arrive,
    /// does not open, or its size or hash differs from the request.
    pub const BAD_IMPORT: &str = "bad_import";
    /// The phone's importers cannot read the file: an unknown format, an encrypted export, or not
    /// one login or code in it.
    pub const IMPORT_UNREADABLE: &str = "import_unreadable";
    /// Every refusal of this module, in the order the phone checks.
    pub const IN_ORDER: [&str; 6] = [
        NO_PASSCODE,
        IMPORT_CLOSED,
        WINDOW_FULL,
        TOO_LARGE,
        BAD_IMPORT,
        IMPORT_UNREADABLE,
    ];
}

/// What the agent thinks an export file is. A hint only: the phone reads the file with its own
/// importers. An unknown value reads as [`ImportFormat::Unknown`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ImportFormat {
    /// Chrome, Chromium, Edge, Brave, Vivaldi or Opera: `name,url,username,password,note`.
    #[serde(rename = "chrome_csv")]
    ChromeCsv,
    /// Firefox (`about:logins`, Export Logins).
    #[serde(rename = "firefox_csv")]
    FirefoxCsv,
    /// Apple Passwords or Safari on a Mac (with the `OTPAuth` column).
    #[serde(rename = "apple_passwords_csv")]
    ApplePasswordsCsv,
    #[serde(rename = "bitwarden_csv")]
    BitwardenCsv,
    /// Bitwarden's JSON export, not encrypted.
    #[serde(rename = "bitwarden_json")]
    BitwardenJson,
    #[serde(rename = "1password_csv")]
    OnePasswordCsv,
    #[serde(rename = "lastpass_csv")]
    LastPassCsv,
    /// Dashlane's `credentials.csv` (from the zip it exports).
    #[serde(rename = "dashlane_csv")]
    DashlaneCsv,
    #[serde(rename = "proton_pass_csv")]
    ProtonPassCsv,
    #[serde(rename = "nordpass_csv")]
    NordPassCsv,
    #[serde(rename = "keepassxc_csv")]
    KeePassXcCsv,
    /// Another CSV with a password column.
    #[serde(rename = "generic_csv")]
    GenericCsv,
    /// One `otpauth://` link per line (Aegis and Ente Auth plain text exports, other code apps).
    #[serde(rename = "otpauth_list")]
    OtpauthList,
    /// A 2FAS backup (`.2fas`).
    #[serde(rename = "2fas_json")]
    TwoFasJson,
    /// Aegis's JSON export, not encrypted.
    #[serde(rename = "aegis_json")]
    AegisJson,
    /// None of these.
    #[default]
    #[serde(rename = "unknown", other)]
    Unknown,
}

impl ImportFormat {
    /// Every format, in the order of the protocol's table.
    pub const ALL: [ImportFormat; 16] = [
        ImportFormat::ChromeCsv,
        ImportFormat::FirefoxCsv,
        ImportFormat::ApplePasswordsCsv,
        ImportFormat::BitwardenCsv,
        ImportFormat::BitwardenJson,
        ImportFormat::OnePasswordCsv,
        ImportFormat::LastPassCsv,
        ImportFormat::DashlaneCsv,
        ImportFormat::ProtonPassCsv,
        ImportFormat::NordPassCsv,
        ImportFormat::KeePassXcCsv,
        ImportFormat::GenericCsv,
        ImportFormat::OtpauthList,
        ImportFormat::TwoFasJson,
        ImportFormat::AegisJson,
        ImportFormat::Unknown,
    ];

    /// The wire name (`chrome_csv`).
    pub fn as_str(self) -> &'static str {
        match self {
            ImportFormat::ChromeCsv => "chrome_csv",
            ImportFormat::FirefoxCsv => "firefox_csv",
            ImportFormat::ApplePasswordsCsv => "apple_passwords_csv",
            ImportFormat::BitwardenCsv => "bitwarden_csv",
            ImportFormat::BitwardenJson => "bitwarden_json",
            ImportFormat::OnePasswordCsv => "1password_csv",
            ImportFormat::LastPassCsv => "lastpass_csv",
            ImportFormat::DashlaneCsv => "dashlane_csv",
            ImportFormat::ProtonPassCsv => "proton_pass_csv",
            ImportFormat::NordPassCsv => "nordpass_csv",
            ImportFormat::KeePassXcCsv => "keepassxc_csv",
            ImportFormat::GenericCsv => "generic_csv",
            ImportFormat::OtpauthList => "otpauth_list",
            ImportFormat::TwoFasJson => "2fas_json",
            ImportFormat::AegisJson => "aegis_json",
            ImportFormat::Unknown => "unknown",
        }
    }

    /// A name for people, and the default `source` of a file in this format.
    pub fn label(self) -> &'static str {
        match self {
            ImportFormat::ChromeCsv => "Chrome",
            ImportFormat::FirefoxCsv => "Firefox",
            ImportFormat::ApplePasswordsCsv => "Apple Passwords",
            ImportFormat::BitwardenCsv | ImportFormat::BitwardenJson => "Bitwarden",
            ImportFormat::OnePasswordCsv => "1Password",
            ImportFormat::LastPassCsv => "LastPass",
            ImportFormat::DashlaneCsv => "Dashlane",
            ImportFormat::ProtonPassCsv => "Proton Pass",
            ImportFormat::NordPassCsv => "NordPass",
            ImportFormat::KeePassXcCsv => "KeePassXC",
            ImportFormat::GenericCsv => "CSV file",
            ImportFormat::OtpauthList => "Code list",
            ImportFormat::TwoFasJson => "2FAS",
            ImportFormat::AegisJson => "Aegis",
            ImportFormat::Unknown => "File",
        }
    }
}

/// The export file of an `import` request. The file itself follows on the attachment path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportRequest {
    /// The file's name without folders (`Chrome Passwords.csv`).
    pub file_name: String,
    /// The file's size in bytes.
    pub size: u64,
    /// b64u of SHA-256 of the file's bytes; the phone stages only a file with this hash.
    pub sha256: String,
    /// What the agent thinks the file is; a hint only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format_hint: Option<ImportFormat>,
    /// A short label for the phone's list (`Chrome, profile Default`).
    pub source: String,
}

impl ImportRequest {
    /// Describes `file`: its size and hash, with the name, hint and source given.
    pub fn new(
        file_name: &str,
        file: &[u8],
        format_hint: Option<ImportFormat>,
        source: &str,
    ) -> Self {
        ImportRequest {
            file_name: file_name.trim().to_owned(),
            size: file.len() as u64,
            sha256: file_sha256(file),
            format_hint,
            source: source.trim().to_owned(),
        }
    }

    /// The rules both sides check. On a failure, the phone's error code
    /// ([`errors::TOO_LARGE`] or [`errors::BAD_IMPORT`]) and a message.
    pub fn check(&self) -> Result<(), (&'static str, String)> {
        let bad = |m: &str| Err((errors::BAD_IMPORT, m.to_owned()));
        let name = self.file_name.trim();
        if name.is_empty() || name.chars().count() > MAX_FILE_NAME {
            return bad("file_name must be 1 to 120 characters");
        }
        if name
            .chars()
            .any(|c| c == '/' || c == '\\' || c.is_control())
        {
            return bad("file_name is the name only, without folders or control characters");
        }
        if self.size == 0 {
            return bad("the file is empty");
        }
        if self.size > MAX_FILE as u64 {
            return Err((
                errors::TOO_LARGE,
                format!(
                    "the file is {} bytes; the limit is 1 MiB ({MAX_FILE} bytes)",
                    self.size
                ),
            ));
        }
        if b64u::decode_array::<32>(&self.sha256).is_err() {
            return bad("sha256 must be the b64u of 32 bytes");
        }
        let source = self.source.trim();
        if source.is_empty() || source.chars().count() > MAX_SOURCE {
            return bad("source must be 1 to 80 characters");
        }
        if source.chars().any(char::is_control) {
            return bad("source must not hold control characters");
        }
        Ok(())
    }

    /// True when `file` is the file this request describes: the same size and hash.
    pub fn matches(&self, file: &[u8]) -> bool {
        file.len() as u64 == self.size && file_sha256(file) == self.sha256
    }
}

/// What the phone staged from one file: counts only. None of them depends on the vault: they
/// compare the file with the files staged before in the same window, never with what Nodkey
/// already holds, so an answer cannot tell an agent whether a guessed password is saved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportCounts {
    /// Entries read from this file (a login with a code is one entry).
    pub found: u32,
    /// Entries this file added to the window's staging list.
    pub new: u32,
    /// Entries merged into one staged before in this window (the same login on another host of
    /// the website, or a code for a staged login).
    pub merged: u32,
    /// Entries the same as one staged before in this window; left out.
    pub duplicates: u32,
    /// Of `new`: the same website and user name as an entry staged before, with another password.
    pub conflicts: u32,
    /// Rows the phone could not use (no password and no code key, or not readable).
    pub skipped: u32,
    /// Of `found`: how many have a password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logins: Option<u32>,
    /// Of `found`: how many have a code key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub codes: Option<u32>,
    /// How many files the window holds now, this one included.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub files: Option<u32>,
    /// When the window closes (Unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
}

/// `import.sha256` of a file: b64u of SHA-256 of its bytes.
pub fn file_sha256(file: &[u8]) -> String {
    b64u::encode(&Sha256::digest(file))
}

/// Seals an export file for `PUT /v1/requests/{request_id}/attachment`: the raw body `enc ‖ ct`
/// with `info` `nodkey/v1/import` and `aad` = `request_id` ‖ `agent_id`.
pub fn seal_file(
    request_id: &str,
    agent_id: &str,
    phone_kem: &[u8; 32],
    file: &[u8],
) -> Result<Vec<u8>, Error> {
    seal_upload_body(
        Purpose::Import,
        phone_kem,
        &aad(request_id, agent_id),
        file,
        &mut OsRng,
    )
}

/// Opens an uploaded export file (the phone's side; used by tests and the fake relay).
pub fn open_file(
    phone_kem_sk: &[u8; 32],
    request_id: &str,
    agent_id: &str,
    body: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if body.len() > ATTACHMENT_MAX {
        return Err(Error::Encoding("the file is larger than 1 MiB"));
    }
    open_upload_body(
        Purpose::Import,
        phone_kem_sk,
        &aad(request_id, agent_id),
        body,
    )
}

#[cfg(test)]
mod tests;
