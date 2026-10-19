//! The agent's own identity: `identity.json` and its private keys, kept where
//! [`crate::keystore`] says. With the keys in a keychain, the file keeps the id, the name, the
//! public keys and where the private keys are (`keys`); with DPAPI also the sealed keys.

use std::{
    collections::HashSet,
    io,
    path::PathBuf,
    sync::{Mutex, OnceLock},
};

use nodkey_proto::{KeyPair, b64u};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{IDENTITY, Store, invalid};
use crate::keystore::{self, Backend, Location};

/// The agent's own identity.
pub struct Identity {
    pub agent_id: String,
    pub name: String,
    pub keys: KeyPair,
}

/// An identity without its private keys, for lists.
pub struct IdentitySummary {
    pub agent_id: String,
    pub name: String,
    /// Where the private keys are.
    pub keys: Location,
}

#[derive(Serialize, Deserialize)]
struct IdentityFile {
    agent_id: String,
    name: String,
    /// Where the private keys are; absent means here, in `kem_sk` and `sign_sk`.
    #[serde(default, skip_serializing_if = "is_file")]
    keys: Location,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    kem_sk: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    sign_sk: String,
    /// The private keys sealed by the system (DPAPI).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sealed_keys: Option<String>,
    /// The public keys, to check that the keys from a keychain belong to this agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sign: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kem: Option<String>,
    created: u64,
}

fn is_file(l: &Location) -> bool {
    *l == Location::File
}

impl Drop for IdentityFile {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.kem_sk.zeroize();
        self.sign_sk.zeroize();
    }
}

impl IdentityFile {
    /// The file for `id` with its keys at `location`.
    fn new(id: &Identity, location: Location, sealed: Option<String>, created: u64) -> Self {
        let public = id.keys.public();
        let here = location == Location::File;
        IdentityFile {
            agent_id: id.agent_id.clone(),
            name: id.name.clone(),
            keys: location,
            kem_sk: if here {
                b64u::encode(id.keys.kem_secret())
            } else {
                String::new()
            },
            sign_sk: if here {
                b64u::encode(id.keys.sign_secret())
            } else {
                String::new()
            },
            sealed_keys: sealed,
            sign: (!here).then(|| public.sign_b64u()),
            kem: (!here).then(|| public.kem_b64u()),
            created,
        }
    }
}

/// `kem_sk ‖ sign_sk`, what a keychain holds.
fn secret_bytes(keys: &KeyPair) -> Zeroizing<Vec<u8>> {
    let mut v = Zeroizing::new(Vec::with_capacity(64));
    v.extend_from_slice(keys.kem_secret());
    v.extend_from_slice(keys.sign_secret());
    v
}

fn from_secret(bytes: &[u8]) -> Result<KeyPair, &'static str> {
    if bytes.len() != 64 {
        return Err("the stored keys have the wrong length");
    }
    let kem = Zeroizing::new(<[u8; 32]>::try_from(&bytes[..32]).expect("32 bytes"));
    let sign = Zeroizing::new(<[u8; 32]>::try_from(&bytes[32..]).expect("32 bytes"));
    Ok(KeyPair::from_bytes(*kem, *sign))
}

fn label(name: &str) -> String {
    format!("Nodkey agent keys: {name}")
}

/// Folders whose keys did not move into the keychain in this process, so each process tries once.
fn move_failed() -> &'static Mutex<HashSet<PathBuf>> {
    static FAILED: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
    FAILED.get_or_init(Default::default)
}

/// Puts the keys of `id` into `backend` and reads them back. Returns `sealed_keys`.
fn store_keys(backend: &dyn Backend, id: &Identity) -> Result<Option<String>, String> {
    let secret = secret_bytes(&id.keys);
    let sealed = backend.put(&id.agent_id, &label(&id.name), &secret)?;
    let back = backend.get(&id.agent_id, sealed.as_deref())?;
    if back[..] != secret[..] {
        backend.delete(&id.agent_id);
        return Err("the keychain gave back other keys".into());
    }
    Ok(sealed)
}

impl Store {
    fn identity_file(&self) -> io::Result<Option<IdentityFile>> {
        let Some(bytes) = self.read(IDENTITY)? else {
            return Ok(None);
        };
        let f: IdentityFile = serde_json::from_slice(&bytes).map_err(|e| invalid(IDENTITY, e))?;
        nodkey_proto::validate_id(&f.agent_id).map_err(|e| invalid(IDENTITY, e))?;
        Ok(Some(f))
    }

    fn write_identity(&self, f: &IdentityFile, exclusive: bool) -> io::Result<()> {
        let mut text = Zeroizing::new(serde_json::to_vec_pretty(f).expect("serializable"));
        text.push(b'\n');
        self.write(IDENTITY, &text, exclusive)
    }

    /// The identity's id, name and where its keys are, without opening the keys.
    pub fn identity_summary(&self) -> io::Result<Option<IdentitySummary>> {
        Ok(self.identity_file()?.map(|f| IdentitySummary {
            agent_id: f.agent_id.clone(),
            name: f.name.clone(),
            keys: f.keys,
        }))
    }

    /// The identity, if one was made. Keys still in the file move into the keychain first when
    /// the policy has one that works.
    pub fn identity(&self) -> io::Result<Option<Identity>> {
        let Some(f) = self.identity_file()? else {
            return Ok(None);
        };
        let keys = match f.keys {
            Location::File => {
                let decode =
                    |s: &str| b64u::decode_array::<32>(s).map_err(|e| invalid(IDENTITY, e));
                let kem = Zeroizing::new(decode(&f.kem_sk)?);
                let sign = Zeroizing::new(decode(&f.sign_sk)?);
                KeyPair::from_bytes(*kem, *sign)
            }
            location => {
                let holder = self.keystore.holder(location).map_err(io::Error::other)?;
                let secret = holder
                    .get(&f.agent_id, f.sealed_keys.as_deref())
                    .map_err(|e| io::Error::other(keystore::unavailable(location, &e)))?;
                let keys = from_secret(&secret).map_err(|e| invalid(IDENTITY, e))?;
                let public = keys.public();
                if f.sign.as_deref() != Some(&public.sign_b64u())
                    || f.kem.as_deref() != Some(&public.kem_b64u())
                {
                    return Err(invalid(
                        IDENTITY,
                        format!(
                            "the keys in {} do not belong to this agent",
                            location.describe()
                        ),
                    ));
                }
                keys
            }
        };
        let id = Identity {
            agent_id: f.agent_id.clone(),
            name: f.name.clone(),
            keys,
        };
        if f.keys == Location::File {
            self.move_keys(&f, &id);
        }
        Ok(Some(id))
    }

    /// Moves keys that are in the file into the keychain. On any failure the file stays as it
    /// is; this process does not try again.
    fn move_keys(&self, f: &IdentityFile, id: &Identity) {
        let Some(backend) = self.keystore.target() else {
            return;
        };
        let mut failed = move_failed().lock().expect("lock");
        if failed.contains(&self.dir) {
            return;
        }
        let moved = store_keys(&*backend, id).and_then(|sealed| {
            let file = IdentityFile::new(id, backend.location(), sealed, f.created);
            self.write_identity(&file, false).map_err(|e| e.to_string())
        });
        if moved.is_err() {
            failed.insert(self.dir.clone());
        }
    }

    /// Makes a new identity, its keys in the keychain when the policy has one that works.
    fn create_identity(&self, name: &str) -> io::Result<Identity> {
        let id = Identity {
            agent_id: nodkey_proto::random_id(),
            name: name.to_owned(),
            keys: KeyPair::generate(),
        };
        let backend = self.keystore.target();
        let stored = backend
            .as_deref()
            .and_then(|b| store_keys(b, &id).ok().map(|sealed| (b.location(), sealed)));
        let file = match stored {
            Some((location, sealed)) => IdentityFile::new(&id, location, sealed, now()),
            None => IdentityFile::new(&id, Location::File, None, now()),
        };
        match self.write_identity(&file, true) {
            Ok(()) => Ok(id),
            Err(e) => {
                if let Some(b) = backend.as_deref().filter(|_| file.keys != Location::File) {
                    b.delete(&id.agent_id);
                }
                if e.kind() != io::ErrorKind::AlreadyExists {
                    return Err(e);
                }
                // Another process made the identity at the same time: use that one.
                self.identity()?
                    .ok_or_else(|| io::Error::other("identity vanished"))
            }
        }
    }

    /// The identity, made on first use with `name`. When `rename` is given and differs from the
    /// stored name, the stored name changes (keys and id stay). When the keys are in a keychain
    /// that does not open, this fails; it never makes a second identity.
    pub fn identity_or_create(
        &self,
        default_name: &str,
        rename: Option<&str>,
    ) -> io::Result<Identity> {
        let id = match self.identity()? {
            Some(id) => id,
            None => self.create_identity(rename.unwrap_or(default_name))?,
        };
        match rename {
            Some(name) if name != id.name => {
                let mut f = self
                    .identity_file()?
                    .ok_or_else(|| io::Error::other("identity vanished"))?;
                f.name = name.to_owned();
                self.write_identity(&f, false)?;
                Ok(Identity {
                    name: name.to_owned(),
                    ..id
                })
            }
            _ => Ok(id),
        }
    }
}

fn now() -> u64 {
    nodkey_proto::unix_now()
}
