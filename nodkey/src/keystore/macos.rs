//! The macOS login Keychain: one generic password per agent (service `nodkey-agent`, account =
//! `agent_id`), its value the keys in base64url.

use nodkey_proto::b64u;
use security_framework::passwords::{
    PasswordOptions, delete_generic_password, generic_password, set_generic_password_options,
};
use zeroize::Zeroizing;

use super::{Backend, Location, SERVICE};

pub(crate) struct Keychain;

fn message(e: security_framework::base::Error) -> String {
    e.message()
        .unwrap_or_else(|| format!("OSStatus {}", e.code()))
}

impl Backend for Keychain {
    fn location(&self) -> Location {
        Location::MacosKeychain
    }

    fn put(&self, agent_id: &str, label: &str, secret: &[u8]) -> Result<Option<String>, String> {
        let mut options = PasswordOptions::new_generic_password(SERVICE, agent_id);
        options.set_label(label);
        let text = Zeroizing::new(b64u::encode(secret));
        set_generic_password_options(text.as_bytes(), options).map_err(message)?;
        Ok(None)
    }

    fn get(&self, agent_id: &str, _sealed: Option<&str>) -> Result<Zeroizing<Vec<u8>>, String> {
        let text = Zeroizing::new(
            generic_password(PasswordOptions::new_generic_password(SERVICE, agent_id))
                .map_err(message)?,
        );
        let text = std::str::from_utf8(&text).map_err(|_| "the keychain item is not text")?;
        b64u::decode(text.trim())
            .map(Zeroizing::new)
            .map_err(|e| e.to_string())
    }

    fn delete(&self, agent_id: &str) {
        let _ = delete_generic_password(SERVICE, agent_id);
    }
}
