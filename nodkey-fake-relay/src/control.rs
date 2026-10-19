//! Routes a test uses to steer the fake phone. Not part of the protocol.
//!
//! - `GET /_fake/phone`: `{phone_id, phone_name}`.
//! - `PUT /_fake/mode` with `"approve"`, `"deny"`, `"silent"` or `"gone"`: how the phone answers.
//! - `GET /_fake/seen`: every request the phone opened, oldest first (with any password in it:
//!   test data only).
//! - `GET /_fake/check/{agent_id}`: the check number the phone shows for a paired agent.
//! - `GET /_fake/passkeys`: the phone's passkeys, `[{rp_id, credential_id, user_handle, user_name,
//!   public_key}]` (b64u; `public_key` is SPKI DER, to check signatures with).
//! - `PUT /_fake/cards` with `{"enabled": bool, "reveal": bool, "limit": {"value", "currency"} | null}`:
//!   what the user allowed for cards (default: on, full numbers on, 1000.00 NOK per purchase).
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
