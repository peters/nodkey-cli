//! The agent directory `~/.config/nodkey-agent/` (0700; `NODKEY_AGENT_DIR` overrides it):
//! `config.json` (relay) and one folder per agent under `agents/<profile>/` with that agent's
//! identity and paired phones (files 0600). Nothing received from a phone is stored here except
//! its public keys, name, scope and check number.
//!
//! The private keys of an identity are in the keychain of the system when there is one
//! (`keystore.rs`, `store/identity.rs`).
//!
//! Before profiles, nodkey-mcp kept one identity in the top folder. [`Home::agent`] moves it into
//! the profile it belongs to (by the name it was paired with), so the pairing keeps working.

use std::{
    fs, io,
    io::Write,
    path::{Path, PathBuf},
};

use nodkey_proto::{PublicKeys, Scope};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub use identity::{Identity, IdentitySummary};

use crate::keystore::Policy;

mod identity;

const IDENTITY: &str = "identity.json";
const PHONES: &str = "phones.json";
const CONFIG: &str = "config.json";
const AGENTS: &str = "agents";

/// A paired phone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Phone {
    pub phone_id: String,
    pub name: String,
    pub sign: String,
    pub kem: String,
    /// Six digits without a space.
    pub check: String,
    pub scope: Scope,
    pub paired_at: u64,
    /// The phone signs its answers: an answer without its valid signature is refused. Set for a
    /// pairing with the commitment, and for an older pairing after its first signed answer.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub signs: bool,
}

impl Phone {
    /// The phone's public keys.
    pub fn keys(&self) -> Result<PublicKeys, nodkey_proto::Error> {
        PublicKeys::from_b64u(&self.sign, &self.kem)
    }
}

#[derive(Default, Serialize, Deserialize)]
struct PhonesFile {
    phones: Vec<Phone>,
}

/// One agent's folder.
#[derive(Debug, Clone)]
pub struct Store {
    dir: PathBuf,
    /// Where new keys, and keys still in the file, go.
    keystore: Policy,
}

impl Store {
    /// A store in `dir`, with the keystore policy from `NODKEY_KEYSTORE`.
    pub fn at(dir: impl Into<PathBuf>) -> Self {
        Store {
            dir: dir.into(),
            keystore: Policy::from_env().unwrap_or_default(),
        }
    }

    /// The same store with another keystore policy.
    pub fn with_keystore(self, keystore: Policy) -> Self {
        Store { keystore, ..self }
    }

    /// The directory.
    pub fn dir(&self) -> &std::path::Path {
        &self.dir
    }

    fn ensure_dir(&self) -> io::Result<()> {
        ensure_private_dir(&self.dir)
    }

    /// Writes `name` atomically with mode 0600. With `exclusive`, fails with `AlreadyExists`
    /// instead of replacing an existing file.
    pub(crate) fn write(&self, name: &str, bytes: &[u8], exclusive: bool) -> io::Result<()> {
        self.ensure_dir()?;
        let target = self.dir.join(name);
        let tmp = self.dir.join(format!(".{name}.{}.tmp", std::process::id()));
        let _ = fs::remove_file(&tmp);
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let result = (|| {
            let mut f = opts.open(&tmp)?;
            f.write_all(bytes)?;
            f.sync_all()?;
            if exclusive {
                // A hard link fails when the target exists, so two servers starting at once
                // cannot both create an identity.
                fs::hard_link(&tmp, &target)?;
                fs::remove_file(&tmp)
            } else {
                fs::rename(&tmp, &target)
            }
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result
    }

    pub(crate) fn read(&self, name: &str) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
        match fs::read(self.dir.join(name)) {
            Ok(b) => Ok(Some(Zeroizing::new(b))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Paired phones, oldest first.
    pub fn phones(&self) -> io::Result<Vec<Phone>> {
        match self.read(PHONES)? {
            Some(bytes) => Ok(serde_json::from_slice::<PhonesFile>(&bytes)
                .map_err(|e| invalid(PHONES, e))?
                .phones),
            None => Ok(Vec::new()),
        }
    }

    fn save_phones(&self, phones: Vec<Phone>) -> io::Result<()> {
        let mut text = serde_json::to_vec_pretty(&PhonesFile { phones }).expect("serializable");
        text.push(b'\n');
        self.write(PHONES, &text, false)
    }

    /// Adds a phone, replacing an earlier pairing with the same `phone_id`.
    pub fn add_phone(&self, phone: Phone) -> io::Result<()> {
        let mut phones = self.phones()?;
        phones.retain(|p| p.phone_id != phone.phone_id);
        phones.push(phone);
        self.save_phones(phones)
    }

    /// Remembers that the phone `phone_id` signs its answers.
    pub fn mark_signs(&self, phone_id: &str) -> io::Result<()> {
        let mut phones = self.phones()?;
        let Some(p) = phones.iter_mut().find(|p| p.phone_id == phone_id) else {
            return Ok(());
        };
        if p.signs {
            return Ok(());
        }
        p.signs = true;
        self.save_phones(phones)
    }

    /// Removes a phone; returns it when it was there.
    pub fn remove_phone(&self, phone_id: &str) -> io::Result<Option<Phone>> {
        let mut phones = self.phones()?;
        let Some(pos) = phones.iter().position(|p| p.phone_id == phone_id) else {
            return Ok(None);
        };
        let removed = phones.remove(pos);
        self.save_phones(phones)?;
        Ok(Some(removed))
    }
}

/// Creates `dir` (and parents) and makes sure only the owner can enter it.
fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    let mut b = fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        b.mode(0o700);
        b.create(dir)?;
        let meta = fs::metadata(dir)?;
        if meta.permissions().mode() & 0o077 != 0 {
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }
    #[cfg(not(unix))]
    b.create(dir)
}

#[derive(Default, Deserialize)]
struct ConfigFile {
    relay: Option<String>,
    keystore: Option<String>,
}

/// The agent directory with the relay setting and one [`Store`] per agent profile.
#[derive(Debug, Clone)]
pub struct Home {
    dir: PathBuf,
}

impl Home {
    /// `NODKEY_AGENT_DIR`, else `~/.config/nodkey-agent`.
    pub fn from_env() -> io::Result<Self> {
        if let Some(dir) = std::env::var_os("NODKEY_AGENT_DIR").filter(|d| !d.is_empty()) {
            return Ok(Home { dir: dir.into() });
        }
        let home =
            home_dir().ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is not set"))?;
        Ok(Home {
            dir: home.join(".config").join("nodkey-agent"),
        })
    }

    /// A home in `dir`.
    pub fn at(dir: impl Into<PathBuf>) -> Self {
        Home { dir: dir.into() }
    }

    /// The directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The store of one agent profile. A pre-profile identity in the top folder whose name
    /// belongs to this profile ("Claude Code @ host" for `claude-code`) moves into it first.
    pub fn agent(&self, profile: &str) -> io::Result<Store> {
        if !crate::profile::is_slug(profile) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("bad agent profile {profile:?}"),
            ));
        }
        let store = Store::at(self.dir.join(AGENTS).join(profile)).with_keystore(self.keystore());
        if !store.dir().join(IDENTITY).exists()
            && self.legacy_profile()?.as_deref() == Some(profile)
        {
            self.adopt_legacy(profile)?;
        }
        Ok(store)
    }

    /// The profile a pre-profile identity in the top folder belongs to, from its name.
    pub fn legacy_profile(&self) -> io::Result<Option<String>> {
        let Some(id) = Store::at(&self.dir).identity_summary()? else {
            return Ok(None);
        };
        let app = id.name.split(" @ ").next().unwrap_or_default();
        let p = crate::profile::Profile::from_client(app, None);
        Ok(Some(p.slug))
    }

    /// Moves the pre-profile identity and phones in the top folder into `profile`. Does nothing
    /// when there is none or the profile already has an identity.
    pub fn adopt_legacy(&self, profile: &str) -> io::Result<bool> {
        let target = self.dir.join(AGENTS).join(profile);
        if !self.dir.join(IDENTITY).exists() || target.join(IDENTITY).exists() {
            return Ok(false);
        }
        ensure_private_dir(&self.dir.join(AGENTS))?;
        ensure_private_dir(&target)?;
        if self.dir.join(PHONES).exists() {
            fs::rename(self.dir.join(PHONES), target.join(PHONES))?;
        }
        // The identity last: while it is in the top folder, a second process adopts it too.
        match fs::rename(self.dir.join(IDENTITY), target.join(IDENTITY)) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// The profiles that have an identity, sorted.
    pub fn agents(&self) -> io::Result<Vec<String>> {
        let mut out = Vec::new();
        let entries = match fs::read_dir(self.dir.join(AGENTS)) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e),
        };
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if crate::profile::is_slug(&name) && entry.path().join(IDENTITY).exists() {
                out.push(name);
            }
        }
        out.sort();
        Ok(out)
    }

    fn config(&self) -> io::Result<ConfigFile> {
        match fs::read(self.dir.join(CONFIG)) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| invalid(CONFIG, e)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(ConfigFile::default()),
            Err(e) => Err(e),
        }
    }

    /// `relay` from `config.json`, if set.
    pub fn configured_relay(&self) -> io::Result<Option<String>> {
        Ok(self.config()?.relay.filter(|r| !r.trim().is_empty()))
    }

    /// Where keys go: `NODKEY_KEYSTORE`, else `keystore` in `config.json`, else `auto`.
    pub fn keystore(&self) -> Policy {
        Policy::from_env()
            .or_else(|| {
                let configured = self.config().ok()?.keystore?;
                (!configured.trim().is_empty()).then(|| Policy::parse(&configured))
            })
            .unwrap_or_default()
    }
}

/// The user's home folder (`HOME`, or `USERPROFILE` on Windows).
pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .or_else(|| std::env::var_os("USERPROFILE").filter(|h| !h.is_empty()))
        .map(PathBuf::from)
}

fn invalid(file: &str, e: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("{file}: {e}"))
}

/// Finds a phone by id, by name (case-insensitive) or by a unique id prefix. With no selector,
/// the only paired phone, or the most recently paired one.
pub fn select_phone<'a>(phones: &'a [Phone], selector: Option<&str>) -> Result<&'a Phone, String> {
    let Some(sel) = selector.map(str::trim).filter(|s| !s.is_empty()) else {
        return phones
            .iter()
            .max_by_key(|p| p.paired_at)
            .ok_or_else(|| "No phone is paired yet. Use the pair tool first.".to_owned());
    };
    if let Some(p) = phones.iter().find(|p| p.phone_id == sel) {
        return Ok(p);
    }
    let by_name: Vec<_> = phones
        .iter()
        .filter(|p| p.name.eq_ignore_ascii_case(sel))
        .collect();
    if by_name.len() == 1 {
        return Ok(by_name[0]);
    }
    let by_prefix: Vec<_> = phones
        .iter()
        .filter(|p| p.phone_id.starts_with(sel))
        .collect();
    match (by_name.len(), by_prefix.len()) {
        (0, 1) => Ok(by_prefix[0]),
        (0, 0) => Err(format!("No paired phone matches {sel:?}. See list_phones.")),
        _ => Err(format!(
            "Several paired phones match {sel:?}; use the phone_id from list_phones."
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store(tag: &str) -> Store {
        let dir = crate::test_dir(&format!("store-{tag}"));
        Store::at(dir.join("nested"))
    }

    fn phone(id: &str, name: &str, at: u64) -> Phone {
        Phone {
            phone_id: id.into(),
            name: name.into(),
            sign: String::new(),
            kem: String::new(),
            check: "000000".into(),
            signs: false,
            scope: Scope::Selected,
            paired_at: at,
        }
    }

    #[test]
    fn identity_is_created_once_and_renamed() {
        let s = temp_store("id");
        assert!(s.identity().unwrap().is_none());
        let a = s.identity_or_create("Agent @ box", None).unwrap();
        let b = s.identity_or_create("Other", None).unwrap();
        assert_eq!(a.agent_id, b.agent_id);
        assert_eq!(b.name, "Agent @ box");
        assert_eq!(a.keys.public(), b.keys.public());
        let c = s.identity_or_create("Other", Some("Renamed")).unwrap();
        assert_eq!(c.agent_id, a.agent_id);
        assert_eq!(s.identity().unwrap().unwrap().name, "Renamed");
        let _ = fs::remove_dir_all(s.dir().parent().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn permissions_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let s = temp_store("perm");
        s.identity_or_create("x", None).unwrap();
        s.add_phone(phone("p1", "A", 1)).unwrap();
        let mode = |p: &std::path::Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(s.dir()), 0o700);
        assert_eq!(mode(&s.dir().join(IDENTITY)), 0o600);
        assert_eq!(mode(&s.dir().join(PHONES)), 0o600);
        // No temp files left behind.
        let names: Vec<_> = fs::read_dir(s.dir())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 2, "{names:?}");
        let _ = fs::remove_dir_all(s.dir().parent().unwrap());
    }

    #[test]
    fn phones_add_replace_remove() {
        let s = temp_store("phones");
        s.add_phone(phone("p1", "A", 1)).unwrap();
        s.add_phone(phone("p2", "B", 2)).unwrap();
        s.add_phone(phone("p1", "A2", 3)).unwrap();
        let list = s.phones().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[1].name, "A2");
        assert_eq!(s.remove_phone("p2").unwrap().unwrap().name, "B");
        assert!(s.remove_phone("p2").unwrap().is_none());
        assert_eq!(s.phones().unwrap().len(), 1);
        let _ = fs::remove_dir_all(s.dir().parent().unwrap());
    }

    #[test]
    fn selecting_phones() {
        let phones = vec![
            phone("abc111", "Test iPhone", 1),
            phone("abd222", "iPad", 5),
        ];
        assert_eq!(select_phone(&phones, None).unwrap().name, "iPad");
        assert_eq!(
            select_phone(&phones, Some("test iphone")).unwrap().phone_id,
            "abc111"
        );
        assert_eq!(select_phone(&phones, Some("abd")).unwrap().name, "iPad");
        assert!(select_phone(&phones, Some("ab")).is_err());
        assert!(select_phone(&phones, Some("zzz")).is_err());
        assert!(select_phone(&[], None).is_err());
    }

    #[test]
    fn config_relay() {
        let dir = crate::test_dir("cfg");
        let home = Home::at(&dir);
        assert_eq!(home.configured_relay().unwrap(), None);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(CONFIG), br#"{"relay":"https://relay.example"}"#).unwrap();
        assert_eq!(
            home.configured_relay().unwrap().as_deref(),
            Some("https://relay.example")
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn profiles_and_legacy_identity() {
        let dir = crate::test_dir("legacy");
        let home = Home::at(&dir);
        let top = Store::at(&dir);
        let old = top.identity_or_create("Claude Code @ box", None).unwrap();
        top.add_phone(phone("p1", "A", 1)).unwrap();
        assert_eq!(
            home.legacy_profile().unwrap().as_deref(),
            Some("claude-code")
        );

        // Another profile does not take it.
        let codex = home.agent("codex").unwrap();
        assert!(codex.identity().unwrap().is_none());
        assert!(dir.join(IDENTITY).exists());

        // Its own profile does, with the same keys and phones.
        let claude = home.agent("claude-code").unwrap();
        let id = claude.identity().unwrap().unwrap();
        assert_eq!(id.agent_id, old.agent_id);
        assert_eq!(id.keys.public(), old.keys.public());
        assert_eq!(claude.phones().unwrap().len(), 1);
        assert!(!dir.join(IDENTITY).exists() && !dir.join(PHONES).exists());
        assert_eq!(home.legacy_profile().unwrap(), None);

        codex.identity_or_create("Codex @ box", None).unwrap();
        assert_eq!(home.agents().unwrap(), ["claude-code", "codex"]);
        assert!(home.agent("../x").is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
