//! Routes a test uses to steer the fake phone. Not part of the protocol.
//!
//! - `GET /_fake/phone`: `{phone_id, phone_name}`.
//! - `PUT /_fake/mode` with `"approve"`, `"deny"`, `"silent"` or `"gone"`: how the phone answers.
//! - `GET /_fake/seen`: every request the phone opened, oldest first (with any password in it:
//!   test data only).
//! - `GET /_fake/check/{agent_id}`: the check number the phone shows for a paired agent.
//! - `GET /_fake/passkeys`: the phone's passkeys, `[{rp_id, credential_id, user_handle, user_name,
//!   public_key}]` (b64u; `public_key` is SPKI DER, to check signatures with).

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
