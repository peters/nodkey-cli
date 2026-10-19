//! A keychain in memory, and tests of where the store keeps an identity's keys.

use std::{
    collections::HashMap,
    fs,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use nodkey_proto::b64u;
use serde_json::Value;
use zeroize::Zeroizing;

use super::{Backend, Location, Policy};
use crate::store::{Home, Store};

/// A keychain in memory. As [`Location::Dpapi`] it seals into the file instead, like DPAPI.
pub struct Fake {
    location: Location,
    items: Mutex<HashMap<String, Vec<u8>>>,
    usable: AtomicBool,
    readable: AtomicBool,
}

impl Fake {
    pub(crate) fn new(location: Location) -> Arc<Self> {
        Arc::new(Fake {
            location,
            items: Mutex::default(),
            usable: AtomicBool::new(true),
            readable: AtomicBool::new(true),
        })
    }

    fn usable(&self) -> bool {
        self.usable.load(Ordering::SeqCst)
    }

    fn items(&self) -> usize {
        self.items.lock().unwrap().len()
    }
}

/// The DPAPI stand-in: the bytes reversed and in base64url.
fn fake_seal(secret: &[u8]) -> String {
    b64u::encode(&secret.iter().rev().copied().collect::<Vec<_>>())
}

impl Backend for Arc<Fake> {
    fn location(&self) -> Location {
        self.location
    }

    fn put(&self, agent_id: &str, _label: &str, secret: &[u8]) -> Result<Option<String>, String> {
        if !self.usable() {
            return Err("no keychain here".into());
        }
        if self.location == Location::Dpapi {
            return Ok(Some(fake_seal(secret)));
        }
        let mut items = self.items.lock().unwrap();
        items.insert(agent_id.to_owned(), secret.to_vec());
        Ok(None)
    }

    fn get(&self, agent_id: &str, sealed: Option<&str>) -> Result<Zeroizing<Vec<u8>>, String> {
        if !self.readable.load(Ordering::SeqCst) {
            return Err("the keychain is locked".into());
        }
        if self.location == Location::Dpapi {
            let mut v = b64u::decode(sealed.ok_or("nothing sealed")?).map_err(|e| e.to_string())?;
            v.reverse();
            return Ok(Zeroizing::new(v));
        }
        let items = self.items.lock().unwrap();
        items
            .get(agent_id)
            .map(|v| Zeroizing::new(v.clone()))
            .ok_or_else(|| "no item".into())
    }

    fn delete(&self, agent_id: &str) {
        self.items.lock().unwrap().remove(agent_id);
    }
}

fn store(tag: &str, fake: &Arc<Fake>) -> Store {
    Store::at(crate::test_dir(&format!("keystore-{tag}"))).with_keystore(Policy::Fake(fake.clone()))
}

fn file_json(s: &Store) -> Value {
    serde_json::from_slice(&fs::read(s.dir().join("identity.json")).unwrap()).unwrap()
}

#[test]
fn new_keys_go_to_the_keychain() {
    let fake = Fake::new(Location::MacosKeychain);
    let s = store("new", &fake);
    let a = s.identity_or_create("Agent @ box", None).unwrap();
    assert_eq!(fake.items(), 1);
    let f = file_json(&s);
    assert_eq!(f["keys"], "macos-keychain");
    assert!(
        f.get("kem_sk").is_none() && f.get("sign_sk").is_none(),
        "{f}"
    );
    assert_eq!(f["sign"], a.keys.public().sign_b64u());
    let b = s.identity().unwrap().unwrap();
    assert_eq!((b.agent_id, b.keys.public()), (a.agent_id, a.keys.public()));
    let summary = s.identity_summary().unwrap().unwrap();
    assert_eq!(summary.keys, Location::MacosKeychain);

    // A new name keeps the keys where they are.
    let c = s.identity_or_create("x", Some("Renamed")).unwrap();
    assert_eq!(c.keys.public(), a.keys.public());
    assert_eq!(file_json(&s)["keys"], "macos-keychain");
    assert_eq!(s.identity().unwrap().unwrap().name, "Renamed");
    let _ = fs::remove_dir_all(s.dir());
}

#[test]
fn keys_in_the_file_move_on_first_use() {
    let fake = Fake::new(Location::SecretService);
    let s = store("move", &fake);
    let old = s
        .clone()
        .with_keystore(Policy::File)
        .identity_or_create("Agent @ box", None)
        .unwrap();
    assert!(file_json(&s)["kem_sk"].is_string());
    assert_eq!(fake.items(), 0);

    let id = s.identity().unwrap().unwrap();
    assert_eq!(id.keys.public(), old.keys.public());
    assert_eq!(fake.items(), 1);
    let f = file_json(&s);
    assert_eq!(f["keys"], "secret-service");
    assert!(f.get("kem_sk").is_none(), "{f}");
    assert_eq!(f["agent_id"], old.agent_id.as_str());
    let _ = fs::remove_dir_all(s.dir());
}

#[test]
fn no_keychain_keeps_the_file() {
    let fake = Fake::new(Location::MacosKeychain);
    fake.usable.store(false, Ordering::SeqCst);
    let s = store("nokeychain", &fake);
    let a = s.identity_or_create("Agent @ box", None).unwrap();
    assert!(file_json(&s)["kem_sk"].is_string());
    assert!(file_json(&s).get("keys").is_none());
    // One try per process: it stays in the file even when the keychain works later.
    s.identity().unwrap();
    fake.usable.store(true, Ordering::SeqCst);
    s.identity().unwrap();
    let fresh = Store::at(s.dir()).with_keystore(Policy::Fake(fake.clone()));
    fresh.identity().unwrap();
    assert!(file_json(&s).get("keys").is_none());
    assert_eq!(fake.items(), 0);

    // Another folder moves at once.
    let t = store("nokeychain2", &fake);
    t.clone()
        .with_keystore(Policy::File)
        .identity_or_create("Agent @ box", None)
        .unwrap();
    t.identity().unwrap();
    assert_eq!(file_json(&t)["keys"], "macos-keychain");
    assert_ne!(
        t.identity().unwrap().unwrap().keys.public(),
        a.keys.public()
    );
    let _ = fs::remove_dir_all(s.dir());
    let _ = fs::remove_dir_all(t.dir());
}

#[test]
fn a_locked_keychain_fails_and_makes_no_new_identity() {
    let fake = Fake::new(Location::MacosKeychain);
    let s = store("locked", &fake);
    let a = s.identity_or_create("Agent @ box", None).unwrap();
    fake.readable.store(false, Ordering::SeqCst);
    let e = s.identity().err().unwrap().to_string();
    assert!(
        e.contains("macOS Keychain") && e.contains("security unlock-keychain"),
        "{e}"
    );
    assert!(e.contains("pairing stays"), "{e}");
    assert!(s.identity_or_create("Agent @ box", None).is_err());
    assert!(s.identity_or_create("Agent @ box", Some("New")).is_err());
    assert_eq!(file_json(&s)["agent_id"], a.agent_id.as_str());
    assert_eq!(file_json(&s)["name"], "Agent @ box");
    fake.readable.store(true, Ordering::SeqCst);
    assert_eq!(s.identity().unwrap().unwrap().agent_id, a.agent_id);
    let _ = fs::remove_dir_all(s.dir());
}

#[test]
fn keys_of_another_agent_are_refused() {
    let fake = Fake::new(Location::MacosKeychain);
    let s = store("mismatch", &fake);
    let a = s.identity_or_create("Agent @ box", None).unwrap();
    let other = nodkey_proto::KeyPair::generate();
    let mut secret = other.kem_secret().to_vec();
    secret.extend_from_slice(other.sign_secret());
    fake.items
        .lock()
        .unwrap()
        .insert(a.agent_id.clone(), secret);
    let e = s.identity().err().unwrap().to_string();
    assert!(e.contains("do not belong"), "{e}");
    let _ = fs::remove_dir_all(s.dir());
}

#[test]
fn sealed_keys_stay_in_the_file() {
    let fake = Fake::new(Location::Dpapi);
    let s = store("sealed", &fake);
    let a = s.identity_or_create("Agent @ box", None).unwrap();
    let f = file_json(&s);
    assert_eq!(f["keys"], "dpapi");
    assert!(
        f["sealed_keys"].is_string() && f.get("kem_sk").is_none(),
        "{f}"
    );
    assert_eq!(
        s.identity().unwrap().unwrap().keys.public(),
        a.keys.public()
    );
    let _ = fs::remove_dir_all(s.dir());
}

#[test]
fn keys_from_another_system_are_explained() {
    let s = Store::at(crate::test_dir("keystore-foreign"));
    let id = s.identity_or_create("Agent @ box", None).unwrap();
    let mut f = file_json(&s);
    let foreign = if cfg!(target_os = "macos") {
        "dpapi"
    } else {
        "macos-keychain"
    };
    f["keys"] = foreign.into();
    f["sign"] = id.keys.public().sign_b64u().into();
    f["kem"] = id.keys.public().kem_b64u().into();
    f.as_object_mut().unwrap().remove("kem_sk");
    fs::write(s.dir().join("identity.json"), f.to_string()).unwrap();
    let e = s.identity().err().unwrap().to_string();
    assert!(e.contains("cannot use on this computer"), "{e}");
    assert!(s.identity_or_create("Agent @ box", None).is_err());
    let _ = fs::remove_dir_all(s.dir());
}

#[test]
fn policy_from_the_config() {
    assert!(matches!(Policy::parse("file"), Policy::File));
    assert!(matches!(Policy::parse(" FILE "), Policy::File));
    assert!(matches!(Policy::parse("auto"), Policy::Auto));
    assert!(
        matches!(Policy::default(), Policy::File),
        "tests use the file"
    );
    let dir = crate::test_dir("keystore-config");
    let home = Home::at(&dir);
    fs::create_dir_all(&dir).unwrap();
    if std::env::var_os(super::ENV).is_none() {
        fs::write(dir.join("config.json"), br#"{"keystore":"auto"}"#).unwrap();
        assert!(matches!(home.keystore(), Policy::Auto));
        fs::write(dir.join("config.json"), br#"{"keystore":"file"}"#).unwrap();
        assert!(matches!(home.keystore(), Policy::File));
    }
    let _ = fs::remove_dir_all(&dir);
}

/// `secret-tool` played by a script that keeps items as files.
#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn secret_tool_gets_the_keys_on_stdin() {
    use super::secret_tool::SecretTool;

    let dir = crate::test_dir("keystore-secret-tool");
    fs::create_dir_all(&dir).unwrap();
    let script = dir.join("secret-tool.sh");
    // store --label L service S agent_id ID | lookup service S agent_id ID | clear ...
    fs::write(
        &script,
        format!(
            "d='{}'\nprintf '%s\\n' \"$*\" >> \"$d/argv\"\ncase \"$1\" in\n  store) cat > \"$d/item-$7\" ;;\n  lookup) [ -f \"$d/item-$5\" ] || exit 1; cat \"$d/item-$5\" ;;\n  clear) rm -f \"$d/item-$5\" ;;\nesac\n",
            dir.display()
        ),
    )
    .unwrap();
    let tool = SecretTool::with_program("/bin/sh".into(), vec![script.into_os_string()]);
    let secret = [9u8; 64];
    assert_eq!(
        tool.put("agent1", "Nodkey agent keys: Test", &secret),
        Ok(None)
    );
    assert_eq!(&tool.get("agent1", None).unwrap()[..], &secret[..]);
    let argv = fs::read_to_string(dir.join("argv")).unwrap();
    assert!(
        argv.contains("store --label Nodkey agent keys: Test service nodkey-agent agent_id agent1")
    );
    assert!(!argv.contains(&b64u::encode(&secret)), "{argv}");
    tool.delete("agent1");
    let e = tool.get("agent1", None).unwrap_err();
    assert!(e.contains("not in the keyring"), "{e}");
    let _ = fs::remove_dir_all(&dir);
}
