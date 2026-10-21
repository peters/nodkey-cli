//! Routes a test uses to steer the fake phone. Not part of the protocol.
//!
//! - `GET /_fake/phone`: `{phone_id, phone_name}`.
//! - `PUT /_fake/mode` with `"approve"`, `"deny"`, `"silent"` or `"gone"`: how the phone answers.
//! - `GET /_fake/seen`: every request the phone opened, oldest first (with any password in it:
//!   test data only).
//! - `GET /_fake/check/{agent_id}`: the check number the phone shows for a paired agent.
//! - `GET /_fake/passkeys`: the phone's passkeys, `[{rp_id, credential_id, user_handle, user_name,
//!   public_key}]` (b64u; `public_key` is SPKI DER, to check signatures with).
//! - `PUT /_fake/cards` with `{"enabled": bool, "reveal": bool, "setup"?: bool, "limit": {"value",
//!   "currency"} | null}`: what the user allowed for cards (default: on, full numbers on, cards for
//!   later payments on, 1000.00 NOK per purchase; `setup` is on when left out).
//! - `GET /_fake/sessions`: the running task sessions, `[{id, agent_id, until, items, used}]`.
//! - `PUT /_fake/seconds_left` with a number: the seconds left of every code from now on (17 by
//!   default); below 8 the answer also carries the next code.
//! - `PUT /_fake/methods` with `{"<site>": <method>}`: the sign-in method the phone knows for each
//!   site (replaces the defaults: Google for `renderfarm.example`, an e-mail code for
//!   `mail.example.com`, a password for `vg.no`).
//! - `GET /_fake/suggestions`: the queued suggestions, `[{agent_id, target, reason, suggest}]`.
//! - `PUT /_fake/sms` with `{"text": "Your code is 482913"}`: a message reaches Nodkey through the
//!   Shortcuts automation, for the waiting `sms_code` request; `{"expire": true}` ends the wait.
//! - `PUT /_fake/quota` with `{"state": "off" | "warning" | "paused" | "paused_by_user", "new_today",
//!   "limit", "burst"}`: the agent limit (see [`crate::quota`]).
//! - `GET /_fake/secrets`, `PUT /_fake/secrets` with `[{title, service, variable, value,
//!   projects}]`: the phone's API keys (test values only; two global test keys to begin with;
//!   `projects` absent or empty for a global key).
//! - `PUT /_fake/account` with `{"site", "sites", "match"}`: the account every code and login
//!   answer names from now on (default, or after `null`: the request's own site, `match: direct`).
//! - `PUT /_fake/pairing` with `{"old_app", "bad_nonce", "unsigned_answers"}` (each `false` when
//!   absent): pair like an app made before the commitment, answer the pairing check with a nonce
//!   that does not match the commitment, or send answers without a signature.
//! - `PUT /_fake/passcode` with `true` or `false`: whether the phone has a passcode (`true` to
//!   begin with). Without one it refuses cards, keys and passkey requests that need user
//!   verification or PRF with `no_passcode`, and signs other passkey answers without UV.
//! - `PUT /_fake/import` with `{"agent_id"?, "seconds"?}`: the user opens an import window for that
//!   agent (absent: the first agent that sends), for `seconds` (1800 when absent); `DELETE` closes
//!   it; `GET` gives the window, `{agent_id, until, files: [{agent_id, file_name, source, sha256,
//!   format, counts}]}`, or `null` (see [`crate::imports`]).
//! - `PUT /_fake/generate` with `{"username"?, "codes_only"?, "save_fails"?}`: what the user does
//!   with a new password: the user name they type on the phone instead of the request's, whether
//!   the agent is paired for codes only (`not_allowed`), whether saving fails (`save_failed`).
//!   `GET` gives those and `made`: every login saved for a `generate` request, `[{agent_id, site,
//!   username, title, password, saved, old_password}]` (test data only).
//!
//! The phone answers a `pairing_check` with its nonce (the first one of a pairing only), and drops
//! a request without the agent's valid signature: it never answers it.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use serde_json::json;

use crate::{Mode, PHONE_NAME, Shared};

pub(crate) fn routes() -> Router<Shared> {
    Router::new()
        .route("/_fake/phone", get(phone))
        .route("/_fake/mode", axum::routing::put(set_mode))
        .route("/_fake/seen", get(seen))
        .route("/_fake/check/{agent_id}", get(check))
        .route("/_fake/passkeys", get(passkeys))
        .route("/_fake/cards", axum::routing::put(set_cards))
        .route("/_fake/sessions", get(sessions))
        .route("/_fake/seconds_left", axum::routing::put(set_seconds_left))
        .route("/_fake/methods", axum::routing::put(set_methods))
        .route("/_fake/suggestions", get(suggestions))
        .route("/_fake/sms", axum::routing::put(deliver_sms))
        .route("/_fake/quota", axum::routing::put(set_quota))
        .route("/_fake/secrets", get(secrets).put(set_secrets))
        .route("/_fake/account", axum::routing::put(set_account))
        .route("/_fake/pairing", axum::routing::put(set_pairing))
        .route("/_fake/passcode", axum::routing::put(set_passcode))
        .route(
            "/_fake/import",
            get(import_window).put(open_import).delete(close_import),
        )
        .route("/_fake/generate", get(generated).put(set_generate))
}

async fn generated(State(fake): State<Shared>) -> Response {
    Json(fake.generate.lock().unwrap().clone()).into_response()
}

/// Keeps the logins saved so far.
async fn set_generate(
    State(fake): State<Shared>,
    Json(set): Json<crate::generate::FakeGenerate>,
) -> StatusCode {
    let mut state = fake.generate.lock().unwrap();
    *state = crate::generate::FakeGenerate {
        made: std::mem::take(&mut state.made),
        ..set
    };
    StatusCode::NO_CONTENT
}

async fn import_window(State(fake): State<Shared>) -> Response {
    Json(fake.import.lock().unwrap().clone()).into_response()
}

async fn open_import(
    State(fake): State<Shared>,
    Json(open): Json<crate::imports::OpenWindow>,
) -> StatusCode {
    *fake.import.lock().unwrap() = Some(crate::imports::Window::open(open));
    StatusCode::NO_CONTENT
}

async fn close_import(State(fake): State<Shared>) -> StatusCode {
    *fake.import.lock().unwrap() = None;
    StatusCode::NO_CONTENT
}

async fn set_passcode(State(fake): State<Shared>, Json(on): Json<bool>) -> StatusCode {
    *fake.passcode.lock().unwrap() = on;
    StatusCode::NO_CONTENT
}

async fn set_pairing(
    State(fake): State<Shared>,
    Json(mode): Json<crate::pairing::PairingMode>,
) -> StatusCode {
    fake.set_pairing(mode);
    StatusCode::NO_CONTENT
}

async fn set_account(
    State(fake): State<Shared>,
    Json(account): Json<Option<crate::phone::FakeAccount>>,
) -> StatusCode {
    *fake.account.lock().unwrap() = account;
    StatusCode::NO_CONTENT
}

async fn secrets(State(fake): State<Shared>) -> Response {
    Json(fake.secrets.lock().unwrap().clone()).into_response()
}

async fn set_secrets(
    State(fake): State<Shared>,
    Json(keys): Json<Vec<crate::secrets::FakeKey>>,
) -> StatusCode {
    *fake.secrets.lock().unwrap() = keys;
    StatusCode::NO_CONTENT
}

async fn set_quota(
    State(fake): State<Shared>,
    Json(quota): Json<crate::quota::FakeQuota>,
) -> StatusCode {
    *fake.quota.lock().unwrap() = quota;
    StatusCode::NO_CONTENT
}

async fn set_methods(
    State(fake): State<Shared>,
    Json(methods): Json<std::collections::HashMap<String, nodkey_proto::SignInMethod>>,
) -> StatusCode {
    fake.signin.lock().unwrap().methods = methods;
    StatusCode::NO_CONTENT
}

async fn suggestions(State(fake): State<Shared>) -> Response {
    Json(fake.signin.lock().unwrap().suggestions.clone()).into_response()
}

async fn deliver_sms(
    State(fake): State<Shared>,
    Json(sms): Json<crate::signin::Sms>,
) -> StatusCode {
    fake.signin.lock().unwrap().sms = Some(sms);
    StatusCode::NO_CONTENT
}

async fn sessions(State(fake): State<Shared>) -> Response {
    Json(fake.sessions.lock().unwrap().list.clone()).into_response()
}

async fn set_seconds_left(State(fake): State<Shared>, Json(seconds): Json<u32>) -> StatusCode {
    fake.sessions.lock().unwrap().seconds_left = seconds;
    StatusCode::NO_CONTENT
}

async fn set_cards(
    State(fake): State<Shared>,
    Json(cards): Json<crate::cards::FakeCards>,
) -> StatusCode {
    *fake.cards.lock().unwrap() = cards;
    StatusCode::NO_CONTENT
}

async fn phone(State(fake): State<Shared>) -> Response {
    Json(json!({ "phone_id": fake.phone_id, "phone_name": PHONE_NAME })).into_response()
}

async fn set_mode(State(fake): State<Shared>, Json(mode): Json<Mode>) -> StatusCode {
    fake.set_mode(mode);
    StatusCode::NO_CONTENT
}

async fn seen(State(fake): State<Shared>) -> Response {
    Json(fake.seen()).into_response()
}

async fn passkeys(State(fake): State<Shared>) -> Response {
    Json(fake.passkeys()).into_response()
}

async fn check(State(fake): State<Shared>, Path(agent_id): Path<String>) -> Response {
    let known = Arc::clone(&fake).knows(&agent_id);
    if !known {
        return StatusCode::NOT_FOUND.into_response();
    }
    Json(json!({ "check": fake.check_for(&agent_id) })).into_response()
}
