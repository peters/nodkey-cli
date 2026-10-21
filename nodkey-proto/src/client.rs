//! The agent's side of pairing and requests, shared by every agent (the `nodkey` binary and the
//! browser extension). Network calls, key storage and the X25519 step of opening stay with the
//! caller: it opens a sealed box with [`crate::Purpose::open_box`] (private key in memory) or
//! [`crate::dh::open_with_dh`] (key in WebCrypto) and hands the plaintext to the `read_*`
//! functions here.

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    Answer, AttachmentInfo, Error, ImageType, Kind, Purpose, Request, RequestEnvelope, SealedBox,
    aad, b64u, parse_plaintext,
    seal::{OsRng, seal_attachment_body},
    signed::{self, Direction},
};

/// Longest `reason` and `target` the agent sends, in characters.
pub const MAX_REASON: usize = 500;
pub const MAX_TARGET: usize = 200;
/// Longest `ct` (b64u characters) of a sealed request the relay takes, so the push stays under
/// APNs' 4 KB (relay `REQUEST_CT_MAX`).
pub const REQUEST_CT_MAX: usize = 3400;

/// The length of `ct` once `r` is sealed: the signed JSON plus the 16-byte tag, in b64u
/// characters.
pub fn sealed_ct_len(r: &Request) -> usize {
    let json = serde_json::to_vec(r).map_or(usize::MAX / 8, |v| v.len());
    // The signature replaces the final "}" and the tag follows.
    let sealed = json - 1 + signed::SUFFIX_LEN + 16;
    (4 * sealed).div_ceil(3)
}

/// Checks a request before it is sealed: what each kind needs, and the length limits. The text
/// is meant for the person or model that made the request.
pub fn check_request(r: &Request) -> Result<(), String> {
    let needs_target = matches!(
        r.kind,
        Kind::Code
            | Kind::Login
            | Kind::Save
            | Kind::Passkey
            | Kind::Card
            | Kind::Suggest
            | Kind::SmsCode
            | Kind::Secret
            | Kind::SaveSecret
            | Kind::Generate
    );
    if needs_target && r.target.trim().is_empty() {
        return Err(
            "target is required (a site or issuer, optionally /account, e.g. github.com/alex)"
                .into(),
        );
    }
    if r.kind == Kind::PairingCheck {
        return check_pairing(r);
    }
    if r.nonce.is_some() {
        return Err("only a pairing_check request carries a nonce".into());
    }
    if r.reason.trim().is_empty() {
        return Err(
            "reason is required: say in a short sentence why you need it; the user reads it on their iPhone"
                .into(),
        );
    }
    if r.reason.chars().count() > MAX_REASON || r.target.chars().count() > MAX_TARGET {
        return Err("target or reason is too long".into());
    }
    let checked: Result<(), String> = match (r.kind, &r.filter, &r.save) {
        (Kind::Cleanup, None, _) => Err("filter needs at least one criterion".into()),
        (Kind::Cleanup, Some(f), _) if f.is_empty() => {
            Err("filter needs at least one criterion".into())
        }
        (Kind::Save, _, Some(_)) if r.save_card.is_some() => {
            Err("a save request carries a login or a card, not both".into())
        }
        (Kind::Save, _, None) => match &r.save_card {
            Some(c) => c.check(),
            None => Err("a save request needs the login or card to save".into()),
        },
        (Kind::Save, _, Some(s)) if s.username.trim().is_empty() || s.password.ct.is_empty() => {
            Err("a save request needs a user name and a password".into())
        }
        (Kind::Save, _, Some(s)) if s.url.chars().count() > 2000 => {
            Err("the page address is too long".into())
        }
        _ if r.save_card.is_some() => Err("only a save request carries a card to save".into()),
        _ => Ok(()),
    };
    checked?;
    match (r.kind, &r.passkey) {
        (Kind::Passkey, None) => Err("a passkey request needs the passkey data".into()),
        (Kind::Passkey, Some(p)) => p.check(&r.target).map(|_| ()),
        (_, Some(_)) => Err("only a passkey request carries passkey data".into()),
        _ => Ok(()),
    }?;
    match (r.kind, &r.bundle) {
        (Kind::Bundle, None) => Err("a bundle request needs its items".into()),
        (Kind::Bundle, Some(_)) if !r.target.is_empty() => {
            Err("a bundle has no target of its own; give each item its target".into())
        }
        (Kind::Bundle, Some(b)) => b.check(),
        (_, Some(_)) => Err("only a bundle request carries items".into()),
        _ => Ok(()),
    }?;
    match (r.kind, &r.card) {
        (Kind::Card, None) => {
            Err("a card request needs the merchant and the amount (no amount for setup)".into())
        }
        (Kind::Card, Some(c)) => c.check(&r.target).map_err(|(_, e)| e),
        (_, Some(_)) => Err("only a card request carries card data".into()),
        _ => Ok(()),
    }?;
    check_signin(r)?;
    check_import(r)?;
    check_generate(r)?;
    crate::apikey::check_request(r)?;
    check_session(r)?;
    if sealed_ct_len(r) > REQUEST_CT_MAX {
        return Err(
            "the request is too large to send to the phone; ask for fewer items or shorten the reason"
                .into(),
        );
    }
    Ok(())
}

/// A `pairing_check` carries the agent's nonce and nothing else.
fn check_pairing(r: &Request) -> Result<(), String> {
    let nonce_ok = r
        .nonce
        .as_deref()
        .is_some_and(|n| b64u::decode_array::<{ crate::pairing::NONCE_LEN }>(n).is_ok());
    if !nonce_ok {
        return Err("a pairing_check request needs a 32-byte nonce".into());
    }
    let extra = r.attachment.is_some()
        || r.filter.is_some()
        || r.save.is_some()
        || r.passkey.is_some()
        || r.bundle.is_some()
        || r.card.is_some()
        || r.save_card.is_some()
        || r.session_id.is_some()
        || r.suggest.is_some()
        || r.wait_seconds.is_some()
        || r.save_secret.is_some()
        || r.project.is_some()
        || r.import.is_some()
        || r.generate.is_some();
    if extra || !r.target.is_empty() || !r.reason.is_empty() {
        return Err("a pairing_check request carries only the nonce".into());
    }
    Ok(())
}

/// The `suggest` and `sms_code` rules: a suggestion names a clean site and a valid method, and
/// `wait_seconds` belongs to `sms_code` only, within its range.
fn check_signin(r: &Request) -> Result<(), String> {
    match (r.kind, &r.suggest) {
        (Kind::Suggest, None) => Err("a suggest request needs the method and the outcome".into()),
        (Kind::Suggest, Some(_))
            if crate::signin::site(&r.target).as_deref() != Some(r.target.as_str()) =>
        {
            Err("a suggestion's target is the site's host, for example example.com".into())
        }
        (Kind::Suggest, Some(s)) => s.check(),
        (_, Some(_)) => Err("only a suggest request carries a suggestion".into()),
        _ => Ok(()),
    }?;
    match (r.kind, r.wait_seconds) {
        (Kind::SmsCode, w) if crate::signin::sms_wait(w).is_none() => Err(format!(
            "wait_seconds must be {} to {}",
            crate::signin::SMS_WAIT_MIN,
            crate::signin::SMS_WAIT_MAX
        )),
        (Kind::SmsCode, _) | (_, None) => Ok(()),
        (_, Some(_)) => Err("only an sms_code request carries wait_seconds".into()),
    }
}

/// An `import` request describes its file and nothing else; no other kind carries one.
fn check_import(r: &Request) -> Result<(), String> {
    match (r.kind, &r.import) {
        (Kind::Import, None) => {
            Err("an import request needs the file's name, size, hash and source".into())
        }
        (Kind::Import, Some(_)) if !r.target.is_empty() => {
            Err("an import request has no target".into())
        }
        (Kind::Import, Some(_)) if r.attachment.is_some() => {
            Err("an import request sends the file, not a picture".into())
        }
        (Kind::Import, Some(i)) => i.check().map_err(|(_, e)| e),
        (_, Some(_)) => Err("only an import request carries a file".into()),
        _ => Ok(()),
    }
}

/// A `generate` request names its page; no other kind carries one.
fn check_generate(r: &Request) -> Result<(), String> {
    match (r.kind, &r.generate) {
        (Kind::Generate, None) => Err("a generate request needs the page it is for".into()),
        (Kind::Generate, Some(g)) => g.check(&r.target),
        (_, Some(_)) => Err("only a generate request carries a page for a new password".into()),
        _ => Ok(()),
    }
}

/// The task session rules: `session_end` names a session and nothing else; a session id has the
/// right shape and goes only on requests a session can cover.
fn check_session(r: &Request) -> Result<(), String> {
    match (&r.kind, &r.session_id) {
        (Kind::SessionEnd, None) => Err("session_end needs the session_id".into()),
        (Kind::SessionEnd, Some(_)) if !r.target.is_empty() => {
            Err("session_end has no target".into())
        }
        (_, Some(id)) if !crate::session::valid_id(id) => {
            Err("session_id must be 22 base64url characters".into())
        }
        (Kind::Code | Kind::Login | Kind::Passkey | Kind::Secret | Kind::SessionEnd, _)
        | (_, None) => Ok(()),
        (_, Some(_)) => {
            Err("only code, login, passkey and secret requests belong to a session".into())
        }
    }
}

/// Seals a checked request to the phone, signed with the agent's key: the envelope to
/// `POST /v1/phones/{phone_id}/requests`. `attachment` says whether a picture follows.
pub fn seal_request(
    request: &Request,
    agent_id: &str,
    phone_id: &str,
    phone_kem: &[u8; 32],
    key: &SigningKey,
    attachment: bool,
) -> Result<RequestEnvelope, Error> {
    let body = Zeroizing::new(serde_json::to_vec(request)?);
    let plain = Zeroizing::new(signed::sign(
        Direction::Request,
        agent_id,
        phone_id,
        &body,
        key,
    )?);
    seal_plain(request, &plain, agent_id, phone_kem, attachment)
}

/// A request's JSON and the message its signature covers.
pub struct ToSign {
    pub body: Zeroizing<Vec<u8>>,
    pub message: Zeroizing<Vec<u8>>,
}

/// For an agent whose signing key cannot leave its store (WebCrypto): the request's JSON and the
/// message to sign. Sign `message` with Ed25519 and give `body` and the signature to
/// [`seal_signed_request`].
pub fn request_to_sign(request: &Request, agent_id: &str, phone_id: &str) -> Result<ToSign, Error> {
    let body = Zeroizing::new(serde_json::to_vec(request)?);
    let message = Zeroizing::new(signed::message(
        Direction::Request,
        agent_id,
        phone_id,
        &body,
    ));
    Ok(ToSign { body, message })
}

/// Seals a request whose JSON `body` (from [`request_to_sign`]) was signed elsewhere.
pub fn seal_signed_request(
    request: &Request,
    body: &[u8],
    sig: &[u8; 64],
    agent_id: &str,
    phone_kem: &[u8; 32],
    attachment: bool,
) -> Result<RequestEnvelope, Error> {
    let plain = Zeroizing::new(signed::attach(body, sig)?);
    seal_plain(request, &plain, agent_id, phone_kem, attachment)
}

fn seal_plain(
    request: &Request,
    plain: &[u8],
    agent_id: &str,
    phone_kem: &[u8; 32],
    attachment: bool,
) -> Result<RequestEnvelope, Error> {
    let sealed = Purpose::Request.seal(phone_kem, &aad(&request.request_id, agent_id), plain)?;
    Ok(RequestEnvelope {
        request_id: request.request_id.clone(),
        enc: b64u::encode(&sealed.enc),
        ct: b64u::encode(&sealed.ct),
        attachment: attachment.then_some(true),
        ttl: relay_ttl(request),
    })
}

/// The envelope's `ttl`: an `sms_code` request stays at the relay for its wait plus the time to
/// approve; every other request keeps the relay's 120 s.
pub fn relay_ttl(request: &Request) -> Option<u32> {
    (request.kind == Kind::SmsCode).then(|| {
        crate::signin::sms_wait(request.wait_seconds).unwrap_or(crate::signin::SMS_WAIT_DEFAULT)
            + crate::signin::SMS_APPROVE_MARGIN
    })
}

/// Seals the password of a `save` request to the phone on its own. The result can be kept and
/// sent again in a new request; only the phone can open it.
pub fn seal_password(
    agent_id: &str,
    phone_kem: &[u8; 32],
    password: &str,
) -> Result<SealedBox, Error> {
    if password.is_empty() {
        return Err(Error::Encoding("empty password"));
    }
    Ok(Purpose::Password
        .seal(phone_kem, agent_id.as_bytes(), password.as_bytes())?
        .to_box())
}

/// Seals a card number or CVC for a `save` request to the phone on its own, like a password.
pub fn seal_card_secret(
    agent_id: &str,
    phone_kem: &[u8; 32],
    secret: &str,
) -> Result<SealedBox, Error> {
    if secret.trim().is_empty() {
        return Err(Error::Encoding("empty card value"));
    }
    Ok(Purpose::Card
        .seal(phone_kem, agent_id.as_bytes(), secret.as_bytes())?
        .to_box())
}

/// What a request says about its picture, with the hash the phone checks the picture against.
pub fn attachment_info(kind: ImageType, image: &[u8], caption: Option<String>) -> AttachmentInfo {
    AttachmentInfo {
        kind,
        bytes: image.len() as u64,
        caption,
        sha256: Some(image_sha256(image)),
    }
}

/// `attachment.sha256` of a picture: b64u of SHA-256 of its bytes.
pub fn image_sha256(image: &[u8]) -> String {
    b64u::encode(&Sha256::digest(image))
}

/// Seals a picture for `PUT /v1/requests/{request_id}/attachment`.
pub fn seal_attachment(
    request_id: &str,
    agent_id: &str,
    phone_kem: &[u8; 32],
    image: &[u8],
) -> Result<Vec<u8>, Error> {
    seal_attachment_body(phone_kem, &aad(request_id, agent_id), image, &mut OsRng)
}

/// The `aad` of the phone's answer to `request_id`.
pub fn answer_aad(request_id: &str, phone_id: &str) -> Vec<u8> {
    aad(request_id, phone_id)
}

/// The `aad` of the pairing grant for `code` (canonical, without the dash).
pub fn grant_aad(code: &str, phone_id: &str) -> Vec<u8> {
    aad(code, phone_id)
}

/// The phone an answer comes from, as this agent knows it from the pairing.
#[derive(Debug, Clone, Copy)]
pub struct AnswerFrom<'a> {
    pub agent_id: &'a str,
    pub phone_id: &'a str,
    /// The phone's Ed25519 key, pinned at pairing.
    pub sign: &'a [u8; 32],
    /// Whether this phone signs its answers (a pairing with the commitment, or a signed answer
    /// seen before): an answer without a valid signature is then refused.
    pub signs: bool,
}

/// Reads an opened answer: checks its signature (see [`AnswerFrom::signs`]) and that it belongs
/// to `request_id`. Also says whether it was signed, so the agent can remember that this phone
/// signs.
pub fn read_answer(
    plain: &[u8],
    request_id: &str,
    from: &AnswerFrom<'_>,
) -> Result<(Answer, bool), Error> {
    let opened = signed::open(
        Direction::Answer,
        from.agent_id,
        from.phone_id,
        plain,
        from.sign,
        from.signs,
    )?;
    let answer: Answer = parse_plaintext(&opened.body)?;
    if answer.request_id != request_id {
        return Err(Error::Json(
            "the answer belongs to a different request".into(),
        ));
    }
    Ok((answer, opened.signed))
}

#[cfg(test)]
mod tests;
