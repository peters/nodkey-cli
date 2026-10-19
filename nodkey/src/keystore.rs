//! Where an agent's private keys are kept: the keychain of the operating system when there is
//! one, else `identity.json` (0600) as before.
//!
//! - macOS: the login Keychain (generic password, service `nodkey-agent`, account = `agent_id`).
//! - Windows: DPAPI for the current user. The sealed keys stay in `identity.json`, but only this
//!   user on this computer can open them.
//! - Linux and other Unix systems: the Secret Service through `secret-tool` (libsecret), when it
//!   is on `PATH` and a session bus is there. The key goes over stdin and stdout, never in argv.
//!
//! `NODKEY_KEYSTORE=file` (or `"keystore": "file"` in `config.json`) keeps new keys in the file.
//! The default, `auto`, uses the keychain when it works and moves keys that are still in the file
//! into it on first use. A copy of `identity.json` alone is then not enough to act as the agent.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(all(unix, not(target_os = "macos")))]
pub(crate) mod secret_tool;
#[cfg(test)]
pub mod tests;
#[cfg(windows)]
mod windows;

/// The service name the keys have in a keychain.
pub const SERVICE: &str = "nodkey-agent";

/// The environment variable that picks the policy.
pub const ENV: &str = "NODKEY_KEYSTORE";

/// Where an identity's private keys are (`keys` in `identity.json`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Location {
    /// In `identity.json` itself (`kem_sk`, `sign_sk`).
    #[default]
    File,
    /// In the macOS login Keychain.
    MacosKeychain,
    /// In `identity.json`, sealed with Windows DPAPI for the current user (`sealed_keys`).
    Dpapi,
    /// In the Secret Service (GNOME Keyring, KWallet), through `secret-tool`.
    SecretService,
}

impl Location {
    /// Words for `nodkey agents` and messages.
    pub fn describe(self) -> &'static str {
        match self {
            Location::File => "the file identity.json",
            Location::MacosKeychain => "the macOS Keychain",
            Location::Dpapi => "identity.json, sealed for this Windows user (DPAPI)",
            Location::SecretService => "the Secret Service (secret-tool)",
        }
    }

    /// The JSON name (`file`, `macos-keychain`, `dpapi`, `secret-service`).
    pub fn name(self) -> &'static str {
        match self {
            Location::File => "file",
            Location::MacosKeychain => "macos-keychain",
            Location::Dpapi => "dpapi",
            Location::SecretService => "secret-service",
        }
    }
}

/// A place for the 64 private-key bytes (`kem_sk ‖ sign_sk`) of one identity.
pub(crate) trait Backend {
    /// Where this backend keeps keys.
    fn location(&self) -> Location;
    /// Stores `secret` for `agent_id`. Returns what `identity.json` keeps (`sealed_keys`), if
    /// anything.
    fn put(&self, agent_id: &str, label: &str, secret: &[u8]) -> Result<Option<String>, String>;
    /// Reads the keys of `agent_id` back. `sealed` is what [`Backend::put`] returned.
    fn get(&self, agent_id: &str, sealed: Option<&str>) -> Result<Zeroizing<Vec<u8>>, String>;
    /// Removes the keys of `agent_id`, if this backend holds any (best effort).
    fn delete(&self, agent_id: &str);
}

/// Where new keys, and keys still in the file, go.
#[derive(Clone)]
pub enum Policy {
    /// The keychain of the operating system when it works, else the file.
    Auto,
    /// The file only.
    File,
    /// A keychain in memory, for tests.
    #[cfg(test)]
    Fake(std::sync::Arc<tests::Fake>),
}

impl Default for Policy {
    /// `auto`; unit tests use the file, so they never touch a real keychain.
    fn default() -> Self {
        if cfg!(test) {
            Policy::File
        } else {
            Policy::Auto
        }
    }
}

impl std::fmt::Debug for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Policy::Auto => "auto",
            Policy::File => "file",
            #[cfg(test)]
            Policy::Fake(_) => "fake",
        })
    }
}

impl Policy {
    /// `file` is the file; `auto`, an empty value or anything else is `auto`.
    pub fn parse(value: &str) -> Policy {
        if value.trim().eq_ignore_ascii_case("file") {
            Policy::File
        } else {
            Policy::Auto
        }
    }

    /// `NODKEY_KEYSTORE`, if it is set.
    pub fn from_env() -> Option<Policy> {
        std::env::var(ENV)
            .ok()
            .filter(|v| !v.trim().is_empty())
            .map(|v| Policy::parse(&v))
    }

    /// The backend new keys go to; `None` keeps them in the file.
    pub(crate) fn target(&self) -> Option<Box<dyn Backend>> {
        match self {
            Policy::File => None,
            Policy::Auto => os_backend(),
            #[cfg(test)]
            Policy::Fake(f) => Some(Box::new(f.clone())),
        }
    }

    /// The backend that holds keys at `location` (never [`Location::File`]).
    pub(crate) fn holder(&self, location: Location) -> Result<Box<dyn Backend>, String> {
        #[cfg(test)]
        if let Policy::Fake(f) = self {
            if f.location() == location {
                return Ok(Box::new(f.clone()));
            }
        }
        os_holder(location)
    }
}

/// The usable keychain of this system, if there is one.
fn os_backend() -> Option<Box<dyn Backend>> {
    #[cfg(target_os = "macos")]
    return Some(Box::new(macos::Keychain));
    #[cfg(windows)]
    return Some(Box::new(windows::Dpapi));
    #[cfg(all(unix, not(target_os = "macos")))]
    return secret_tool::SecretTool::available().map(|s| Box::new(s) as Box<dyn Backend>);
    #[allow(unreachable_code)]
    None
}

/// The backend for keys at `location`, or why this computer cannot read them.
fn os_holder(location: Location) -> Result<Box<dyn Backend>, String> {
    match location {
        #[cfg(target_os = "macos")]
        Location::MacosKeychain => Ok(Box::new(macos::Keychain)),
        #[cfg(windows)]
        Location::Dpapi => Ok(Box::new(windows::Dpapi)),
        #[cfg(all(unix, not(target_os = "macos")))]
        Location::SecretService => Ok(Box::new(secret_tool::SecretTool::from_path())),
        other => Err(format!(
            "identity.json says the private keys of this agent are in {}, which nodkey cannot use \
             on this computer. The folder may come from another computer. Pair this computer as \
             its own agent: use another --agent name, or move this agent's folder away and pair again.",
            other.describe()
        )),
    }
}

/// The message when a keychain that holds the keys does not open now.
pub(crate) fn unavailable(location: Location, why: &str) -> String {
    let hint = match location {
        Location::MacosKeychain => {
            " Over SSH the login keychain is often locked: unlock it with `security unlock-keychain`, \
             or run nodkey in your logged-in session."
        }
        Location::SecretService => {
            " Make sure your desktop session is unlocked and that `secret-tool` (libsecret-tools) \
             is installed."
        }
        _ => "",
    };
    format!(
        "The private keys of this agent are in {}, and nodkey cannot read them now ({why}).{hint} \
         The pairing stays as it is; try again when the keychain is open.",
        location.describe()
    )
}
