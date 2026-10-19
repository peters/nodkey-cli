//! Windows DPAPI for the current user: the keys stay in `identity.json` (`sealed_keys`), sealed so
//! that only this user on this computer can open them. The entropy binds them to the agent id.

use std::ptr::{null, null_mut};

use nodkey_proto::b64u;
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    },
};
use zeroize::Zeroizing;

use super::{Backend, Location};

pub(crate) struct Dpapi;

fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr().cast_mut(),
    }
}

fn entropy(agent_id: &str) -> Vec<u8> {
    format!("nodkey-agent/{agent_id}").into_bytes()
}

/// Copies the output blob, wipes it and frees it.
fn take(out: CRYPT_INTEGER_BLOB) -> Zeroizing<Vec<u8>> {
    // SAFETY: on success DPAPI returns `cbData` bytes at `pbData`, allocated with LocalAlloc.
    unsafe {
        let len = out.cbData as usize;
        let bytes = Zeroizing::new(std::slice::from_raw_parts(out.pbData, len).to_vec());
        std::ptr::write_bytes(out.pbData, 0, len);
        LocalFree(out.pbData.cast());
        bytes
    }
}

/// Seals `secret` for the current user.
pub(crate) fn protect(secret: &[u8], agent_id: &str) -> Result<Vec<u8>, String> {
    let (input, ent) = (blob(secret), entropy(agent_id));
    let ent = blob(&ent);
    let mut out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    // SAFETY: every pointer is valid for the call; the description and prompt are optional.
    let ok = unsafe {
        CryptProtectData(
            &input,
            null(),
            &ent,
            null(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(take(out).to_vec())
}

/// Opens what [`protect`] sealed.
pub(crate) fn unprotect(sealed: &[u8], agent_id: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let (input, ent) = (blob(sealed), entropy(agent_id));
    let ent = blob(&ent);
    let mut out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    // SAFETY: as in `protect`.
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            null_mut(),
            &ent,
            null(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(take(out))
}

impl Backend for Dpapi {
    fn location(&self) -> Location {
        Location::Dpapi
    }

    fn put(&self, agent_id: &str, _label: &str, secret: &[u8]) -> Result<Option<String>, String> {
        protect(secret, agent_id).map(|s| Some(b64u::encode(&s)))
    }

    fn get(&self, agent_id: &str, sealed: Option<&str>) -> Result<Zeroizing<Vec<u8>>, String> {
        let sealed = sealed.ok_or("identity.json has no sealed_keys")?;
        let sealed = b64u::decode(sealed).map_err(|e| e.to_string())?;
        unprotect(&sealed, agent_id)
    }

    fn delete(&self, _agent_id: &str) {}
}

#[cfg(test)]
mod tests {
    #[test]
    fn round_trip_for_this_user() {
        let secret = [7u8; 64];
        let sealed = super::protect(&secret, "agent-a").unwrap();
        assert_ne!(&sealed[..], &secret[..]);
        assert_eq!(
            &super::unprotect(&sealed, "agent-a").unwrap()[..],
            &secret[..]
        );
        assert!(super::unprotect(&sealed, "agent-b").is_err());
    }
}
