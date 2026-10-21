//! A tiny relay for tests that also plays the phone: it verifies every signature, claims
//! pairings, opens requests and attachments with the phone's key and answers as told.
//!
//! Used in-process by the `nodkey` tests and, as the `nodkey-fake-relay` binary, by other agents'
//! tests (the browser extension). `/_fake/...` routes let such a test steer the phone; see
//! [`control`]. Never point a real agent at it: it answers with invented secrets.

// Handlers return early with ready-made responses; their size does not matter in a test.
#![allow(clippy::result_large_err)]

mod bundle;
pub mod cards;
pub mod control;
pub mod generate;
pub mod imports;
pub mod pairing;
pub mod passkeys;
mod phone;
pub mod quota;
pub mod secrets;
pub mod sessions;
pub mod signin;

pub use phone::{FakeAccount, SAVED_LOGINS, cleanup_matches};

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use nodkey_proto::{
    AgentInfo, Answer, CleanupFilter, Decision, KeyPair, Kind, PairingClaimed, PublicKeys, Purpose,
    Request, RequestEnvelope, aad, auth, b64u, parse_plaintext, seal,
    signed::{self, Direction},
};
use serde::Deserialize;
use serde_json::json;

pub const PHONE_NAME: &str = "Test iPhone";
pub const CODE: &str = "190274";
pub const USERNAME: &str = "alex@example.com";
pub const PASSWORD: &str = "correct horse battery staple";

/// How the phone answers requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Approve,
    Deny,
    /// Never answers (the relay keeps returning 204).
    Silent,
    /// The relay already dropped the request (410).
    Gone,
}

/// What the phone saw for one request.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Seen {
    pub request: Request,
    pub agent_id: String,
    /// `attachment` in the posted envelope.
    pub announced: Option<bool>,
    pub attachment: Option<Vec<u8>>,
    /// The password of a `save` request, opened as the phone would (test data only).
    pub saved_password: Option<String>,
    /// The card number of a card `save` request, opened likewise (test numbers only).
    pub saved_card: Option<String>,
    /// The key of a `save_secret` request, opened likewise (test values only).
    pub saved_secret: Option<String>,
    /// Whether the request carried the agent's valid signature. The phone drops one that did
    /// not: it never answers it.
    pub signed: bool,
}

struct Pairing {
    agent: AgentInfo,
    polls: u32,
    claimed: Option<PairingClaimed>,
}

#[derive(Default)]
struct Inner {
    agents: HashMap<String, PublicKeys>,
    pairings: HashMap<String, Pairing>,
    requests: HashMap<String, Seen>,
    order: Vec<String>,
    /// Agents that left with `DELETE /v1/agents/{agent_id}/phones/{phone_id}`.
    left: Vec<String>,
    /// `GET /v1/pairings/{code}/agent` calls by the phone.
    lookups: u32,
}

pub struct Fake {
    pub phone_id: String,
    pub phone: KeyPair,
    pub mode: Mutex<Mode>,
    /// Largest attachment body accepted (protocol: 1 MiB); bigger gets `413 too_large`.
    pub attachment_limit: Mutex<usize>,
    /// The phone claims a pairing on this many-th poll (1 = the first).
    pub claim_on_poll: u32,
    /// The phone's passkeys, oldest first (the test passkey for `webauthn.io` to begin with).
    pub passkeys: Mutex<Vec<passkeys::FakePasskey>>,
    /// What the user allowed for cards.
    pub cards: Mutex<cards::FakeCards>,
    /// Whether the phone has a passcode; without one it gives no cards or keys (`no_passcode`).
    pub passcode: Mutex<bool>,
    /// Running task sessions and the code clock.
    pub sessions: Mutex<sessions::FakeSessions>,
    /// Sign-in methods, queued suggestions and the SMS a test delivers.
    pub signin: Mutex<signin::FakeSignin>,
    /// The agent limit a test set: off, the warning or a pause.
    pub quota: Mutex<quota::FakeQuota>,
    /// The phone's API keys (two test keys to begin with).
    pub secrets: Mutex<Vec<secrets::FakeKey>>,
    /// The account every code and login answer names, when a test set one.
    pub account: Mutex<Option<phone::FakeAccount>>,
    /// How the phone pairs and signs, and each agent's pairing nonces.
    pub pairing: Mutex<pairing::FakePairing>,
    /// The import window a test opened, and what it staged.
    pub import: Mutex<Option<imports::Window>>,
    /// What the user does with a new password, and the logins saved for one.
    pub generate: Mutex<generate::FakeGenerate>,
    /// Where this relay listens; the phone calls it for the pairing lookup.
    addr: std::sync::OnceLock<SocketAddr>,
    inner: Mutex<Inner>,
}

impl Fake {
    pub fn set_mode(&self, m: Mode) {
        *self.mode.lock().unwrap() = m;
    }

    /// The phone's passkeys (public parts only).
    pub fn passkeys(&self) -> Vec<passkeys::PasskeyInfo> {
        self.passkeys
            .lock()
            .unwrap()
            .iter()
            .map(passkeys::FakePasskey::info)
            .collect()
    }

    /// How often the phone looked up a waiting agent before claiming.
    pub fn lookups(&self) -> u32 {
        self.inner.lock().unwrap().lookups
    }

    /// Agents that left.
    pub fn left(&self) -> Vec<String> {
        self.inner.lock().unwrap().left.clone()
    }

    /// Requests in arrival order (without pairing checks).
    pub fn seen(&self) -> Vec<Seen> {
        let inner = self.inner.lock().unwrap();
        inner
            .order
            .iter()
            .map(|id| inner.requests[id].clone())
            .collect()
    }

    /// Whether `agent_id` registered with this relay.
    pub fn knows(&self, agent_id: &str) -> bool {
        self.inner.lock().unwrap().agents.contains_key(agent_id)
    }

    /// The check number the phone shows for `agent_id`.
    pub fn check_for(&self, agent_id: &str) -> String {
        let agent = self.inner.lock().unwrap().agents[agent_id];
        pairing::check_for(self, agent_id, &agent)
    }

    /// How the phone pairs and signs from now on.
    pub fn set_pairing(&self, mode: pairing::PairingMode) {
        self.pairing.lock().unwrap().mode = mode;
    }
}

pub type Shared = Arc<Fake>;

fn fail(status: StatusCode, code: &str) -> Response {
    (status, Json(json!({"error": code, "message": code}))).into_response()
}

fn verify(
    headers: &HeaderMap,
    key: &PublicKeys,
    method: &Method,
    uri: &Uri,
    body: &[u8],
) -> Result<String, Response> {
    let header = headers
        .get(auth::HEADER)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| fail(StatusCode::UNAUTHORIZED, "bad_signature"))?;
    let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("");
    auth::verify(
        header,
        &key.sign,
        method.as_str(),
        path,
        body,
        nodkey_proto::unix_now(),
    )
    .map(str::to_owned)
    .map_err(|_| fail(StatusCode::UNAUTHORIZED, "bad_signature"))
}

/// The id in a header, before verification.
fn claimed_id(headers: &HeaderMap) -> Option<String> {
    let h = headers.get(auth::HEADER)?.to_str().ok()?;
    auth::parse(h).ok().map(|p| p.id.to_owned())
}

fn agent_key(fake: &Fake, headers: &HeaderMap) -> Result<(String, PublicKeys), Response> {
    let id = claimed_id(headers).ok_or_else(|| fail(StatusCode::UNAUTHORIZED, "bad_signature"))?;
    let inner = fake.inner.lock().unwrap();
    let key = *inner
        .agents
        .get(&id)
        .ok_or_else(|| fail(StatusCode::FORBIDDEN, "not_paired"))?;
    Ok((id, key))
}

#[derive(Deserialize)]
struct Wait {
    wait: Option<u64>,
}

async fn agent_leaves(
    State(fake): State<Shared>,
    Path((agent_id, phone_id)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let (caller, key) = match agent_key(&fake, &headers) {
        Ok(k) => k,
        Err(r) => return r,
    };
    if let Err(r) = verify(&headers, &key, &method, &uri, b"") {
        return r;
    }
    if caller != agent_id {
        return fail(StatusCode::FORBIDDEN, "not_paired");
    }
    if phone_id != fake.phone_id {
        return fail(StatusCode::NOT_FOUND, "not_found");
    }
    let mut inner = fake.inner.lock().unwrap();
    inner.agents.remove(&agent_id);
    inner.left.push(agent_id);
    StatusCode::NO_CONTENT.into_response()
}

async fn post_request(
    State(fake): State<Shared>,
    Path(phone_id): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if phone_id != fake.phone_id {
        return fail(StatusCode::NOT_FOUND, "not_found");
    }
    let (agent_id, key) = match agent_key(&fake, &headers) {
        Ok(k) => k,
        Err(r) => return r,
    };
    if let Err(r) = verify(&headers, &key, &method, &uri, &body) {
        return r;
    }
    let Ok(env) = serde_json::from_slice::<RequestEnvelope>(&body) else {
        return fail(StatusCode::BAD_REQUEST, "bad_request");
    };
    let plain = Purpose::Request
        .open(
            fake.phone.kem_secret(),
            &b64u::decode(&env.enc).unwrap(),
            &aad(&env.request_id, &agent_id),
            &b64u::decode(&env.ct).unwrap(),
        )
        .expect("request opens with the phone key");
    let opened = signed::open(
        Direction::Request,
        &agent_id,
        &fake.phone_id,
        &plain,
        &key.sign,
        true,
    );
    let signed = opened.is_ok();
    let request: Request = parse_plaintext(&plain).unwrap();
    assert_eq!(request.request_id, env.request_id);
    let saved_password = request.save.as_ref().map(|s| {
        let opened = Purpose::Password
            .open_box(fake.phone.kem_secret(), &s.password, agent_id.as_bytes())
            .expect("the save password opens with the phone key");
        String::from_utf8(opened.to_vec()).expect("utf-8 password")
    });
    let saved_card = cards::saved_number(&fake, &request, &agent_id);
    let saved_secret = secrets::saved_value(&fake, &request, &agent_id);
    let mut inner = fake.inner.lock().unwrap();
    // A pairing check belongs to the pairing; `seen` lists the requests after it.
    if request.kind != Kind::PairingCheck {
        inner.order.push(env.request_id.clone());
    }
    inner.requests.insert(
        env.request_id,
        Seen {
            request,
            agent_id,
            announced: env.attachment,
            attachment: None,
            saved_password,
            saved_card,
            saved_secret,
            signed,
        },
    );
    StatusCode::ACCEPTED.into_response()
}

async fn put_attachment(
    State(fake): State<Shared>,
    Path(rid): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let (agent_id, key) = match agent_key(&fake, &headers) {
        Ok(k) => k,
        Err(r) => return r,
    };
    if let Err(r) = verify(&headers, &key, &method, &uri, &body) {
        return r;
    }
    if body.len() > *fake.attachment_limit.lock().unwrap() {
        return fail(StatusCode::PAYLOAD_TOO_LARGE, "too_large");
    }
    let mut inner = fake.inner.lock().unwrap();
    let Some(seen) = inner.requests.get_mut(&rid) else {
        return fail(StatusCode::NOT_FOUND, "not_found");
    };
    if seen.agent_id != agent_id {
        return fail(StatusCode::FORBIDDEN, "not_paired");
    }
    if seen.request.kind == Kind::Import {
        // The phone refused at once, before the upload: the request is answered.
        if *fake.mode.lock().unwrap() == Mode::Approve
            && imports::refuse_at_once(&fake, &agent_id, &rid, &seen.request).is_some()
        {
            return fail(StatusCode::CONFLICT, "already_claimed");
        }
        // An export file: the phone checks its size and hash when it answers.
        let file = nodkey_proto::import::open_file(fake.phone.kem_secret(), &rid, &agent_id, &body)
            .expect("the import file opens with the phone key");
        seen.attachment = Some(file.to_vec());
        return StatusCode::NO_CONTENT.into_response();
    }
    let image = seal::open_attachment_body(fake.phone.kem_secret(), &aad(&rid, &agent_id), &body)
        .expect("attachment opens with the phone key");
    // The phone shows only the picture the signed request names by its hash.
    let hash = seen
        .request
        .attachment
        .as_ref()
        .and_then(|a| a.sha256.clone());
    if hash.is_none_or(|h| h == nodkey_proto::client::image_sha256(&image)) {
        seen.attachment = Some(image.to_vec());
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn wait_answer(
    State(fake): State<Shared>,
    Path(rid): Path<String>,
    Query(q): Query<Wait>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let (agent_id, key) = match agent_key(&fake, &headers) {
        Ok(k) => k,
        Err(r) => return r,
    };
    if let Err(r) = verify(&headers, &key, &method, &uri, b"") {
        return r;
    }
    let (mut request, signed) = {
        let inner = fake.inner.lock().unwrap();
        match inner.requests.get(&rid) {
            Some(s) if s.agent_id == agent_id => (s.request.clone(), s.signed),
            Some(_) => return fail(StatusCode::FORBIDDEN, "not_paired"),
            None => return fail(StatusCode::NOT_FOUND, "not_found"),
        }
    };
    let mode = *fake.mode.lock().unwrap();
    if !signed {
        // The phone dropped it.
        tokio::time::sleep(Duration::from_secs(q.wait.unwrap_or(1).min(60))).await;
        return StatusCode::NO_CONTENT.into_response();
    }
    if request.kind == Kind::PairingCheck {
        let answer = pairing::answer_check(&fake, &agent_id, &rid, &request);
        return seal_answer(&fake, &agent_id, &rid, &answer);
    }
    if let Some(refused) = quota::refuse(&fake, &rid, &request) {
        return seal_answer(&fake, &agent_id, &rid, &refused);
    }
    // The open import window answers at once; `deny` plays a refusal without a reason.
    if request.kind == Kind::Import && matches!(mode, Mode::Approve | Mode::Deny) {
        let answer = match mode {
            Mode::Deny => Answer::decision(&rid, Decision::Denied),
            _ => imports::answer(&fake, &agent_id, &rid, &request)
                .await
                .expect("an import request"),
        };
        return seal_answer(&fake, &agent_id, &rid, &answer);
    }
    let warned = quota::warn(&fake, &agent_id, &mut request);
    // The phone refuses an empty clean-up filter by itself, whatever the user would say.
    if request.kind == Kind::Cleanup && request.filter.as_ref().is_none_or(CleanupFilter::is_empty)
    {
        let mut refused = Answer::decision(&rid, Decision::Denied);
        refused.error = Some("empty_filter".into());
        return seal_answer(&fake, &agent_id, &rid, &refused);
    }
    // Passkey requests the phone refuses at once: bad client data, no passkey, no ES256.
    if let Some(refused) = request
        .passkey
        .as_ref()
        .and_then(|p| passkeys::refuse(&fake, &rid, p))
    {
        return seal_answer(&fake, &agent_id, &rid, &refused);
    }
    if let Some(refused) = generate::refuse(&fake, &rid, &request) {
        return seal_answer(&fake, &agent_id, &rid, &refused);
    }
    if let Some(refused) = secrets::refuse(&fake, &rid, &request) {
        return seal_answer(&fake, &agent_id, &rid, &refused);
    }
    if let Some(refused) = cards::refuse(&fake, &rid, &request) {
        return seal_answer(&fake, &agent_id, &rid, &refused);
    }
    if let Some(mut covered) = sessions::answer_now(&fake, &agent_id, &rid, &request) {
        sessions::after(&fake, &agent_id, &request, &mut covered);
        return seal_answer(&fake, &agent_id, &rid, &covered);
    }
    if let Some(answer) = signin::answer(&fake, &agent_id, &rid, &request, mode, q.wait).await {
        return answer.map_or(StatusCode::NO_CONTENT.into_response(), |a| {
            seal_answer(&fake, &agent_id, &rid, &a)
        });
    }
    let mut answer = match mode {
        Mode::Silent => {
            tokio::time::sleep(Duration::from_secs(q.wait.unwrap_or(1).min(60))).await;
            return StatusCode::NO_CONTENT.into_response();
        }
        Mode::Gone => return fail(StatusCode::GONE, "expired"),
        Mode::Deny => Answer::decision(&rid, Decision::Denied),
        Mode::Approve => Answer::decision(&rid, Decision::Approved),
    };
    if mode == Mode::Approve {
        phone::approve(&fake, &mut answer, &request);
        if request.kind == Kind::Generate {
            generate::approve(&fake, &agent_id, &mut answer, &request);
        }
    }
    sessions::after(&fake, &agent_id, &request, &mut answer);
    if warned {
        quota::mark(&fake, &mut answer);
    }
    seal_answer(&fake, &agent_id, &rid, &answer)
}

fn seal_answer(fake: &Shared, agent_id: &str, rid: &str, answer: &Answer) -> Response {
    let agent_kem = fake.inner.lock().unwrap().agents[agent_id].kem;
    let mut plain = serde_json::to_vec(answer).unwrap();
    if !fake.pairing.lock().unwrap().mode.unsigned_answers {
        let key = fake.phone.signing_key();
        plain = signed::sign(Direction::Answer, agent_id, &fake.phone_id, &plain, &key).unwrap();
    }
    let sealed = Purpose::Answer
        .seal(&agent_kem, &aad(rid, &fake.phone_id), &plain)
        .unwrap();
    Json(sealed.to_box()).into_response()
}

/// Starts the fake relay on a free loopback port in a background thread.
pub fn start(claim_on_poll: u32) -> (Shared, SocketAddr) {
    start_on("127.0.0.1:0", claim_on_poll)
}

/// Starts the fake relay on `bind` (e.g. `127.0.0.1:8787`) in a background thread.
pub fn start_on(bind: &str, claim_on_poll: u32) -> (Shared, SocketAddr) {
    let fake = Arc::new(Fake {
        phone_id: nodkey_proto::random_id(),
        phone: KeyPair::generate(),
        mode: Mutex::new(Mode::Approve),
        attachment_limit: Mutex::new(1024 * 1024),
        claim_on_poll,
        passkeys: Mutex::new(vec![passkeys::FakePasskey::test()]),
        cards: Mutex::new(cards::FakeCards::default()),
        passcode: Mutex::new(true),
        sessions: Mutex::new(sessions::FakeSessions::default()),
        signin: Mutex::new(signin::FakeSignin::default()),
        quota: Mutex::new(quota::FakeQuota::default()),
        secrets: Mutex::new(secrets::test_keys()),
        account: Mutex::new(None),
        pairing: Mutex::new(pairing::FakePairing::default()),
        import: Mutex::new(None),
        generate: Mutex::new(generate::FakeGenerate::default()),
        addr: std::sync::OnceLock::new(),
        inner: Mutex::new(Inner::default()),
    });
    let app = Router::new()
        .route("/v1/pairings", post(pairing::start_pairing))
        .route(
            "/v1/agents/{agent_id}/phones/{phone_id}",
            axum::routing::delete(agent_leaves),
        )
        .route("/v1/pairings/{code}", get(pairing::wait_pairing))
        .route("/v1/pairings/{code}/agent", get(pairing::pairing_agent))
        .route("/v1/phones/{phone_id}/requests", post(post_request))
        .route("/v1/requests/{rid}/attachment", put(put_attachment))
        .route("/v1/requests/{rid}", get(wait_answer))
        .merge(control::routes())
        .layer(axum::extract::DefaultBodyLimit::max(2 * 1024 * 1024))
        .with_state(Arc::clone(&fake));
    let (tx, rx) = std::sync::mpsc::channel();
    let bind = bind.to_owned();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let listener = tokio::net::TcpListener::bind(&bind).await.unwrap();
            tx.send(listener.local_addr().unwrap()).unwrap();
            axum::serve(listener, app).await.unwrap();
        });
    });
    let addr = rx.recv().unwrap();
    fake.addr.set(addr).unwrap();
    (fake, addr)
}
