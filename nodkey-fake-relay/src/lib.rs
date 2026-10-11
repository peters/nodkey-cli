//! A tiny relay for tests that also plays the phone: it verifies every signature, claims
//! pairings, opens requests and attachments with the phone's key and answers as told.
//!
//! Used in-process by the `nodkey` tests and, as the `nodkey-fake-relay` binary, by other agents'
//! tests (the browser extension). `/_fake/...` routes let such a test steer the phone; see
//! [`control`]. Never point a real agent at it: it answers with invented secrets.

// Handlers return early with ready-made responses; their size does not matter in a test.
#![allow(clippy::result_large_err)]

pub mod control;

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
    Account, AccountEntry, AgentInfo, Answer, CleanupFilter, Decision, KeyPair, Kind, Lease,
    LeaseKind, PairingClaimed, PairingCode, PairingGrant, PublicKeys, Purpose, Request,
    RequestEnvelope, Scope, Secret, aad, auth, b64u, check, parse_plaintext, seal,
};
use serde::Deserialize;
use serde_json::json;

pub const PHONE_NAME: &str = "Test iPhone";
pub const CODE: &str = "190274";
pub const USERNAME: &str = "alex@example.com";
pub const PASSWORD: &str = "correct horse battery staple";

/// The fake phone's saved logins for clean-up requests (title, user name, site). Invented.
pub const SAVED_LOGINS: [(&str, &str, &str); 5] = [
    ("Router", "admin", "192.168.1.1"),
    ("Printer", "demo", "10.0.0.138:8080"),
    ("NAS", "admin", "[fe80::1]"),
    (
        "Old company mail",
        "alex@old-company.example",
        "mail.old-company.example",
    ),
    ("VG", USERNAME, "vg.no"),
];

/// The fake phone's clean-up: a small stand-in for the app's filter (ip_only, exact user name,
/// domain with subdomains).
pub fn cleanup_matches(filter: &CleanupFilter) -> Vec<AccountEntry> {
    let is_ip = |site: &str| {
        let host = site
            .trim_start_matches('[')
            .split([']', ':'])
            .next()
            .unwrap_or("");
        host.parse::<std::net::Ipv4Addr>().is_ok() || site.starts_with('[')
    };
    SAVED_LOGINS
        .iter()
        .filter(|(_, _, site)| filter.ip_only != Some(true) || is_ip(site))
        .filter(|(_, user, _)| {
            filter
                .username
                .as_deref()
                .is_none_or(|u| u.eq_ignore_ascii_case(user))
        })
        .filter(|(_, _, site)| {
            filter
                .domain
                .as_deref()
                .is_none_or(|d| *site == d || site.ends_with(&format!(".{d}")))
        })
        .map(|(title, user, site)| AccountEntry {
            issuer: (*title).into(),
            name: (*user).into(),
            site: Some((*site).into()),
            has_code: false,
            has_password: true,
        })
        .collect()
}

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
    /// Where this relay listens; the phone calls it for the pairing lookup.
    addr: std::sync::OnceLock<SocketAddr>,
    inner: Mutex<Inner>,
}

impl Fake {
    pub fn set_mode(&self, m: Mode) {
        *self.mode.lock().unwrap() = m;
    }

    /// How often the phone looked up a waiting agent before claiming.
    pub fn lookups(&self) -> u32 {
        self.inner.lock().unwrap().lookups
    }

    /// Agents that left.
    pub fn left(&self) -> Vec<String> {
        self.inner.lock().unwrap().left.clone()
    }

    /// Requests in arrival order.
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
        let inner = self.inner.lock().unwrap();
        check::display(check::check_number(
            &inner.agents[agent_id],
            &self.phone.public(),
        ))
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

async fn start_pairing(
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

async fn wait_pairing(
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
        // GET /v1/pairings/{code}/agent and seals the grant (with the check number) to those.
        let keys = match phone_looks_up(&fake, &code).await {
            Ok(k) => k,
            Err(status) => return fail(status, "phone lookup failed"),
        };
        let mut inner = fake.inner.lock().unwrap();
        let p = inner.pairings.get_mut(&code).unwrap();
        let phone_pub = fake.phone.public();
        let grant = PairingGrant {
            v: 1,
            phone_name: PHONE_NAME.into(),
            scope: Scope::Selected,
            check: check::digits(check::check_number(&keys, &phone_pub)),
        };
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

/// `GET /v1/pairings/{code}/agent`, signed by the phone: the waiting agent's keys while the code
/// is unclaimed, 404 otherwise.
async fn pairing_agent(
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
async fn phone_looks_up(fake: &Fake, code: &str) -> Result<PublicKeys, StatusCode> {
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
    let request: Request = parse_plaintext(&plain).unwrap();
    assert_eq!(request.request_id, env.request_id);
    let mut inner = fake.inner.lock().unwrap();
    inner.order.push(env.request_id.clone());
    inner.requests.insert(
        env.request_id,
        Seen {
            request,
            agent_id,
            announced: env.attachment,
            attachment: None,
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
    let image = seal::open_attachment_body(fake.phone.kem_secret(), &aad(&rid, &agent_id), &body)
        .expect("attachment opens with the phone key");
    seen.attachment = Some(image.to_vec());
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
    let request = {
        let inner = fake.inner.lock().unwrap();
        match inner.requests.get(&rid) {
            Some(s) if s.agent_id == agent_id => s.request.clone(),
            Some(_) => return fail(StatusCode::FORBIDDEN, "not_paired"),
            None => return fail(StatusCode::NOT_FOUND, "not_found"),
        }
    };
    let mode = *fake.mode.lock().unwrap();
    // The phone refuses an empty clean-up filter by itself, whatever the user would say.
    if request.kind == Kind::Cleanup && request.filter.as_ref().is_none_or(CleanupFilter::is_empty)
    {
        let mut refused = Answer::decision(&rid, Decision::Denied);
        refused.error = Some("empty_filter".into());
        return seal_answer(&fake, &agent_id, &rid, &refused);
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
        answer.lease = Some(Lease {
            kind: LeaseKind::Once,
            until: None,
        });
        match request.kind {
            Kind::Code => {
                answer.account = Some(Account {
                    issuer: "GitHub".into(),
                    name: "alex".into(),
                    site: Some("github.com".into()),
                });
                answer.code = Some(Secret::new(CODE));
                answer.seconds_left = Some(17);
            }
            Kind::Login => {
                answer.account = Some(Account {
                    issuer: "VG".into(),
                    name: USERNAME.into(),
                    site: Some("vg.no".into()),
                });
                answer.username = Some(USERNAME.into());
                answer.password = Some(Secret::new(PASSWORD));
            }
            Kind::List => {
                answer.accounts = Some(vec![AccountEntry {
                    issuer: "GitHub".into(),
                    name: "alex".into(),
                    site: Some("github.com".into()),
                    has_code: true,
                    has_password: false,
                }]);
            }
            Kind::Insights => {
                answer.insights = Some(serde_json::json!({
                    "total": 712, "with_code": 40,
                    "ages": {"never": 300, "over_5y": 50, "over_2y": 80, "over_1y": 60, "recent": 222},
                    "ip_or_local": 23, "test_hosts": 7, "no_site": 4,
                    "sites": [{"group": "d_3fa9c21b07e4", "logins": 47, "spread": 3, "last_used_year": 2019,
                               "never_used": 40, "added_year": 2017}],
                    "usernames": [{"group": "u_19c2ab5f0d11", "logins": 31, "spread": 29, "never_used": 31,
                                   "added_year": 2016, "email": true}]
                }));
            }
            Kind::Save => {
                // Never a lease: the user confirms every save.
                answer.lease = None;
                answer.saved = Some(nodkey_proto::Saved::Added);
            }
            Kind::Cleanup => {
                // Never a lease: the user confirms every clean-up.
                answer.lease = None;
                let moved = cleanup_matches(request.filter.as_ref().expect("checked above"));
                answer.moved = Some(moved.len() as u32);
                answer.accounts = Some(moved);
            }
        }
    }
    seal_answer(&fake, &agent_id, &rid, &answer)
}

fn seal_answer(fake: &Shared, agent_id: &str, rid: &str, answer: &Answer) -> Response {
    let agent_kem = fake.inner.lock().unwrap().agents[agent_id].kem;
    let sealed = Purpose::Answer
        .seal(
            &agent_kem,
            &aad(rid, &fake.phone_id),
            &serde_json::to_vec(answer).unwrap(),
        )
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
        addr: std::sync::OnceLock::new(),
        inner: Mutex::new(Inner::default()),
    });
    let app = Router::new()
        .route("/v1/pairings", post(start_pairing))
        .route(
            "/v1/agents/{agent_id}/phones/{phone_id}",
            axum::routing::delete(agent_leaves),
        )
        .route("/v1/pairings/{code}", get(wait_pairing))
        .route("/v1/pairings/{code}/agent", get(pairing_agent))
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
