//! The phone's side of a pairing lookup: `GET /v1/pairings/{code}/agent`, served by this relay and
//! called by the fake phone before it claims a code.

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use nodkey_proto::{AgentInfo, PublicKeys, auth};

use crate::{Fake, Shared, claimed_id, fail, verify};

/// `GET /v1/pairings/{code}/agent`, signed by the phone: the waiting agent's keys while the code
/// is unclaimed, 404 otherwise.
pub(crate) async fn pairing_agent(
    State(fake): State<Shared>,
    Path(code): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if claimed_id(&headers).as_deref() != Some(fake.phone_id.as_str()) {
        return fail(StatusCode::UNAUTHORIZED, "bad_signature");
    }
    if let Err(r) = verify(&headers, &fake.phone.public(), &method, &uri, b"") {
        return r;
    }
    let mut inner = fake.inner.lock().unwrap();
    inner.lookups += 1;
    match inner.pairings.get(&code) {
        Some(p) if p.claimed.is_none() => Json(p.agent.clone()).into_response(),
        _ => fail(StatusCode::NOT_FOUND, "not_found"),
    }
}

/// The phone's side of the lookup: a real signed HTTP call to this relay.
pub(crate) async fn phone_looks_up(fake: &Fake, code: &str) -> Result<PublicKeys, StatusCode> {
    let addr = *fake.addr.get().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let path = format!("/v1/pairings/{code}/agent");
    let header = auth::sign(
        &fake.phone.signing_key(),
        &fake.phone_id,
        "GET",
        &path,
        nodkey_proto::unix_now(),
        b"",
    );
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}{path}"))
        .header(auth::HEADER, header)
        .send()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    if resp.status() != reqwest::StatusCode::OK {
        return Err(StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY));
    }
    let bytes = resp.bytes().await.map_err(|_| StatusCode::BAD_GATEWAY)?;
    let agent: AgentInfo = serde_json::from_slice(&bytes).map_err(|_| StatusCode::BAD_GATEWAY)?;
    PublicKeys::from_b64u(&agent.sign, &agent.kem).map_err(|_| StatusCode::BAD_GATEWAY)
}
