//! The phone's side of pairing: the lookup (`GET /v1/pairings/{code}/agent`, served by this relay
//! and called by the fake phone before it claims a code), the grant with its commitment, and the
//! answer to the agent's `pairing_check`.

use std::collections::HashMap;

use axum::{
    Json,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use nodkey_proto::{
    AgentInfo, Answer, Decision, PairingClaimed, PairingCode, PairingGrant, PublicKeys, Purpose,
    Request, Scope, VERSION, aad, auth, b64u, check, pairing,
};
use serde::Deserialize;

use crate::{Fake, Pairing, Shared, claimed_id, fail, verify};

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

pub(crate) async fn start_pairing(
    State(fake): State<Shared>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Ok(info) = serde_json::from_slice::<AgentInfo>(&body) else {
        return fail(StatusCode::BAD_REQUEST, "bad_request");
    };
    let Ok(keys) = PublicKeys::from_b64u(&info.sign, &info.kem) else {
        return fail(StatusCode::BAD_REQUEST, "bad_request");
    };
    match verify(&headers, &keys, &method, &uri, &body) {
        Ok(id) if id == info.agent_id => {}
        Ok(_) => return fail(StatusCode::UNAUTHORIZED, "bad_signature"),
        Err(r) => return r,
    }
    let code = "K7P2QX".to_owned();
    let mut inner = fake.inner.lock().unwrap();
    inner.pairings.insert(
        code.clone(),
        Pairing {
            agent: info,
            polls: 0,
            claimed: None,
        },
    );
    (
        StatusCode::CREATED,
        Json(PairingCode {
            code,
            expires: nodkey_proto::unix_now() + 300,
        }),
    )
        .into_response()
}

pub(crate) async fn wait_pairing(
    State(fake): State<Shared>,
    Path(code): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let agent = {
        let inner = fake.inner.lock().unwrap();
        match inner.pairings.get(&code) {
            Some(p) => p.agent.clone(),
            None => return fail(StatusCode::NOT_FOUND, "not_found"),
        }
    };
    let keys = PublicKeys::from_b64u(&agent.sign, &agent.kem).unwrap();
    if let Err(r) = verify(&headers, &keys, &method, &uri, b"") {
        return r;
    }
    let claim_now = {
        let mut inner = fake.inner.lock().unwrap();
        let p = inner.pairings.get_mut(&code).unwrap();
        p.polls += 1;
        p.claimed.is_none() && p.polls >= fake.claim_on_poll
    };
    if claim_now {
        // The phone claims the way Nodkey does: it looks up the waiting agent's keys with a signed
        // GET /v1/pairings/{code}/agent and seals the grant (with its commitment) to those.
        let keys = match phone_looks_up(&fake, &code).await {
            Ok(k) => k,
            Err(status) => return fail(status, "phone lookup failed"),
        };
        let mut inner = fake.inner.lock().unwrap();
        let p = inner.pairings.get_mut(&code).unwrap();
        let phone_pub = fake.phone.public();
        let grant = grant(&fake, &p.agent.agent_id, &keys);
        let sealed = Purpose::Pairing
            .seal(
                &keys.kem,
                &aad(&code, &fake.phone_id),
                &serde_json::to_vec(&grant).unwrap(),
            )
            .unwrap();
        p.claimed = Some(PairingClaimed {
            phone_id: fake.phone_id.clone(),
            sign: phone_pub.sign_b64u(),
            kem: phone_pub.kem_b64u(),
            enc: b64u::encode(&sealed.enc),
            ct: b64u::encode(&sealed.ct),
        });
        let agent_id = p.agent.agent_id.clone();
        inner.agents.insert(agent_id, keys);
    }
    let inner = fake.inner.lock().unwrap();
    let p = &inner.pairings[&code];
    match &p.claimed {
        Some(c) => Json(c.clone()).into_response(),
        None => StatusCode::NO_CONTENT.into_response(),
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

/// How the phone pairs and signs, as a test set it (`PUT /_fake/pairing`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
pub struct PairingMode {
    /// Pair like an app made before the commitment: `check` in the grant, no `commit`.
    #[serde(default)]
    pub old_app: bool,
    /// Answer the pairing check with a nonce that does not match the commitment.
    #[serde(default)]
    pub bad_nonce: bool,
    /// Send answers without a signature, like an app made before signatures.
    #[serde(default)]
    pub unsigned_answers: bool,
}

/// The phone's pairings: the mode and each agent's nonces.
#[derive(Default)]
pub struct FakePairing {
    pub mode: PairingMode,
    /// By agent id: the phone's nonce and, once the check came, the agent's.
    checks: HashMap<String, ([u8; 32], Option<[u8; 32]>)>,
}

/// The grant the phone seals to `agent` when it claims: with a fresh commitment, or with the old
/// check number when the test plays an old app.
pub(crate) fn grant(fake: &Fake, agent_id: &str, agent: &PublicKeys) -> PairingGrant {
    let mut p = fake.pairing.lock().unwrap();
    let phone = fake.phone.public();
    let (check, commit) = if p.mode.old_app {
        (
            Some(check::digits(check::check_number(agent, &phone))),
            None,
        )
    } else {
        let nonce = pairing::nonce();
        p.checks.insert(agent_id.to_owned(), (nonce, None));
        (None, Some(b64u::encode(&pairing::commit(&phone, &nonce))))
    };
    PairingGrant {
        v: VERSION,
        phone_name: crate::PHONE_NAME.into(),
        scope: Scope::Selected,
        check,
        commit,
    }
}

/// The phone's answer to a `pairing_check`: its nonce, for the first check of a pairing only.
pub(crate) fn answer_check(fake: &Fake, agent_id: &str, rid: &str, request: &Request) -> Answer {
    let mut p = fake.pairing.lock().unwrap();
    let bad_nonce = p.mode.bad_nonce;
    let agent_nonce = request
        .nonce
        .as_deref()
        .and_then(|n| b64u::decode_array::<32>(n).ok());
    match (p.checks.get_mut(agent_id), agent_nonce) {
        (Some((phone_nonce, seen @ None)), Some(n)) => {
            *seen = Some(n);
            let nonce = if bad_nonce {
                pairing::nonce()
            } else {
                *phone_nonce
            };
            pairing::check_answer(rid, &nonce)
        }
        _ => {
            let mut a = Answer::decision(rid, Decision::Denied);
            a.error = Some("unexpected_pairing_check".into());
            a
        }
    }
}

/// The check number the phone shows for `agent_id` (empty before the agent's check came).
pub(crate) fn check_for(fake: &Fake, agent_id: &str, agent: &PublicKeys) -> String {
    let p = fake.pairing.lock().unwrap();
    let phone = fake.phone.public();
    if p.mode.old_app {
        return check::display(check::check_number(agent, &phone));
    }
    match p.checks.get(agent_id) {
        Some((pn, Some(an))) => check::display(pairing::check_number(agent, &phone, an, pn)),
        _ => String::new(),
    }
}
