//! What the tools do: pairing, requests and the local list of phones.
//!
//! Every operation returns the text for the tool result (JSON). Secrets from the phone only pass
//! through memory on their way into that text; they are never written to disk or to stderr.

use std::time::{Duration, Instant};

use nodkey_proto::{
    AgentInfo, Answer, AttachmentInfo, CleanupFilter, ClientInfo, Kind, Purpose, Request, VERSION,
    check, client, code,
};
use serde::Serialize;
use serde_json::json;
use zeroize::Zeroizing;

use crate::{
    host::{hostname, local_client},
    image::load_image,
    outcome::Outcome,
    profile::Profile,
    relay::{Poll, Relay, Signer},
    store::{Home, Phone, Store, select_phone},
};

/// Timing knobs. The defaults follow the protocol; tests shorten them.
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    /// How long a request waits for the user (protocol: 120 s).
    pub request: Duration,
    /// How long `pair` waits for the phone to claim the code (protocol: 300 s).
    pub pairing: Duration,
    /// Longest single long-poll `wait` (protocol: 60 s).
    pub max_wait: u64,
}

impl Default for Timing {
    fn default() -> Self {
        Timing {
            request: Duration::from_secs(120),
            pairing: Duration::from_secs(300),
            max_wait: 60,
        }
    }
}

impl Timing {
    /// Defaults, overridden by `NODKEY_REQUEST_TIMEOUT` / `NODKEY_PAIR_TIMEOUT` (seconds).
    pub fn from_env() -> Self {
        let secs = |name: &str| {
            std::env::var(name)
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())
                .filter(|&s| s > 0)
                .map(Duration::from_secs)
        };
        let d = Timing::default();
        Timing {
            request: secs("NODKEY_REQUEST_TIMEOUT").unwrap_or(d.request),
            pairing: secs("NODKEY_PAIR_TIMEOUT").unwrap_or(d.pairing),
            max_wait: d.max_wait,
        }
    }
}

/// Reports progress while a tool waits: `(elapsed seconds, total seconds, message)`.
pub type Progress<'a> = &'a (dyn Fn(u64, u64, &str) + Send + Sync);

/// Text of a tool result.
pub type Text = Zeroizing<String>;

/// The agent: its directory, profile, relay and timing.
pub struct Agent {
    pub home: Result<Home, String>,
    /// Which agent this is; its identity and phones live in `agents/<slug>/`.
    pub profile: std::sync::Mutex<Profile>,
    pub relay: Result<Relay, String>,
    pub timing: Timing,
    /// What every request says about this agent (app from MCP `initialize`, the computer).
    pub client: std::sync::Mutex<ClientInfo>,
}

/// The model and effort a tool call reports for itself (optional tool arguments).
#[derive(Debug, Clone, Copy, Default)]
pub struct Reported<'a> {
    pub model: Option<&'a str>,
    pub effort: Option<&'a str>,
}

fn err(msg: impl std::fmt::Display) -> String {
    msg.to_string()
}

impl Agent {
    /// A new agent for `profile`, with the relay and timing from the environment.
    pub fn new(home: Result<Home, String>, profile: Profile, relay_url: &str) -> Self {
        Agent {
            home,
            profile: std::sync::Mutex::new(profile),
            relay: Relay::new(relay_url).map_err(|e| e.to_string()),
            timing: Timing::from_env(),
            client: std::sync::Mutex::new(local_client()),
        }
    }

    /// The current profile.
    pub fn profile(&self) -> Profile {
        self.profile.lock().expect("lock").clone()
    }

    /// The name the phone shows for this agent unless the user picks one.
    pub fn default_name(&self) -> String {
        self.profile().agent_name(&hostname())
    }

    /// This profile's store.
    pub fn store(&self) -> Result<Store, String> {
        let home = self
            .home
            .as_ref()
            .map_err(|e| format!("Agent directory unavailable: {e}"))?;
        home.agent(&self.profile().slug)
            .map_err(|e| format!("Agent directory unavailable: {e}"))
    }

    fn relay(&self) -> Result<&Relay, String> {
        self.relay
            .as_ref()
            .map_err(|e| format!("Relay unavailable: {e}"))
    }

    /// Starts a pairing and returns the code to type on the phone.
    pub async fn pair_start(&self, name: Option<&str>) -> Result<Text, String> {
        let store = self.store()?;
        let relay = self.relay()?;
        let name = name.map(str::trim).filter(|n| !n.is_empty());
        if name.is_some_and(|n| n.chars().count() > 64) {
            return Err("name is too long (at most 64 characters)".into());
        }
        let id = store
            .identity_or_create(&self.default_name(), name)
            .map_err(err)?;
        let public = id.keys.public();
        let info = AgentInfo {
            agent_id: id.agent_id.clone(),
            name: id.name.clone(),
            sign: public.sign_b64u(),
            kem: public.kem_b64u(),
        };
        let signer = Signer {
            id: &id.agent_id,
            keys: &id.keys,
        };
        let pc = relay.start_pairing(&signer, &info).await.map_err(err)?;
        if !code::is_canonical(&pc.code) {
            return Err(format!(
                "relay returned an invalid pairing code {:?}",
                pc.code
            ));
        }
        let shown = code::display(&pc.code);
        let expires_in = pc.expires.saturating_sub(nodkey_proto::unix_now());
        Ok(text(&json!({
            "code": shown,
            "agent_name": id.name,
            "expires": pc.expires,
            "expires_in_seconds": expires_in,
            "next": format!(
                "Show the user the code {shown} and ask them to type it in Nodkey on their iPhone under Agents. \
                 Then call pair again with code \"{shown}\" to wait for their phone and get the check number."
            ),
        })))
    }

    /// Waits for the phone to claim `code`, checks the grant and remembers the phone.
    pub async fn pair_finish(&self, typed: &str, progress: Progress<'_>) -> Result<Text, String> {
        let store = self.store()?;
        let relay = self.relay()?;
        let code = code::normalize(typed).map_err(err)?;
        let id = store
            .identity()
            .map_err(err)?
            .ok_or("No pairing was started on this computer. Call pair without a code first.")?;
        let signer = Signer {
            id: &id.agent_id,
            keys: &id.keys,
        };
        let total = self.timing.pairing;
        let claimed = poll_until(total, self.timing.max_wait, progress, "Waiting for the user to type the code on their iPhone", |wait| {
            relay.wait_pairing(&signer, &code, wait)
        })
        .await?
        .ok_or_else(|| {
            format!(
                "The code {} expired or was not claimed within {} s. Call pair without a code to get a new one.",
                code::display(&code),
                total.as_secs()
            )
        })?;

        nodkey_proto::validate_id(&claimed.phone_id)
            .map_err(|e| format!("relay sent a bad phone_id: {e}"))?;
        let phone_keys = nodkey_proto::PublicKeys::from_b64u(&claimed.sign, &claimed.kem)
            .map_err(|e| format!("relay sent bad phone keys: {e}"))?;
        let plain = Purpose::Pairing
            .open_box(
                id.keys.kem_secret(),
                &claimed.sealed(),
                &client::grant_aad(&code, &claimed.phone_id),
            )
            .map_err(|_| {
                "The pairing grant does not decrypt; the pairing was not saved.".to_owned()
            })?;
        let grant = client::read_grant(&plain, &id.keys.public(), &phone_keys).map_err(|e| match e {
            nodkey_proto::Error::CheckMismatch { .. } => format!(
                "{e}. Someone may have swapped keys; the pairing was not saved. Tell the user and do not \
                 retry blindly."
            ),
            e => e.to_string(),
        })?;
        let n = check::check_number(&id.keys.public(), &phone_keys);
        let phone = Phone {
            phone_id: claimed.phone_id.clone(),
            name: grant.phone_name.clone(),
            sign: claimed.sign.clone(),
            kem: claimed.kem.clone(),
            check: grant.check.clone(),
            scope: grant.scope,
            paired_at: nodkey_proto::unix_now(),
        };
        store.add_phone(phone).map_err(err)?;
        let shown = check::display(n);
        Ok(text(&json!({
            "paired": true,
            "phone": grant.phone_name,
            "phone_id": claimed.phone_id,
            "check": shown,
            "scope": grant.scope,
            "next": format!(
                "Ask the user to confirm that their iPhone shows the check number {shown}. If it shows a different \
                 number, call unpair for this phone and tell them."
            ),
        })))
    }

    /// The paired phones.
    pub fn list_phones(&self) -> Result<Text, String> {
        let phones = self.store()?.phones().map_err(err)?;
        let list: Vec<_> = phones
            .iter()
            .map(|p| {
                json!({
                    "phone_id": p.phone_id,
                    "name": p.name,
                    "check": check::display(p.check.parse().unwrap_or(0)),
                    "scope": p.scope,
                    "paired_at": p.paired_at,
                })
            })
            .collect();
        Ok(text(&json!({ "phones": list })))
    }

    /// Forgets a phone on this computer.
    /// Leaves a phone: tells the relay (`DELETE /v1/agents/{agent_id}/phones/{phone_id}`), then
    /// forgets the phone on this computer. The phone is forgotten even when the relay cannot be
    /// reached; the result then says so.
    pub async fn unpair(&self, selector: &str) -> Result<Text, String> {
        let store = self.store()?;
        let phones = store.phones().map_err(err)?;
        if selector.trim().is_empty() {
            return Err("phone is required (a phone_id or name from list_phones)".into());
        }
        let phone = select_phone(&phones, Some(selector))?;
        let relay_result = match (store.identity().map_err(err)?, self.relay()) {
            (Some(id), Ok(relay)) => {
                let signer = Signer {
                    id: &id.agent_id,
                    keys: &id.keys,
                };
                relay
                    .leave(&signer, &phone.phone_id)
                    .await
                    .map_err(|e| e.to_string())
            }
            (None, _) => Err("no identity on this computer".to_owned()),
            (_, Err(e)) => Err(e.to_owned()),
        };
        let removed = store
            .remove_phone(&phone.phone_id)
            .map_err(err)?
            .ok_or("phone vanished")?;
        let mut out = json!({
            "unpaired": true,
            "phone": removed.name,
            "phone_id": removed.phone_id,
        });
        match relay_result {
            Ok(_) => {
                out["note"] = json!(
                    "The relay forgot the pairing; the phone drops this agent the next time it checks for requests."
                );
            }
            Err(e) => {
                out["relay_warning"] = json!(format!(
                    "Forgotten on this computer, but the relay could not be told ({e}). Ask the user to remove \
                     this agent under Agents in Nodkey."
                ));
            }
        }
        Ok(text(&out))
    }

    /// Sends one request and waits for the user's answer.
    #[allow(clippy::too_many_arguments)]
    pub async fn request(
        &self,
        kind: Kind,
        target: &str,
        reason: &str,
        image_path: Option<&str>,
        phone_selector: Option<&str>,
        reported: Reported<'_>,
        progress: Progress<'_>,
    ) -> Result<Text, String> {
        self.send(
            kind,
            target,
            reason,
            image_path,
            None,
            phone_selector,
            reported,
            progress,
        )
        .await
    }

    /// Proposes moving the saved logins that match `filter` to "Recently deleted" on the phone and
    /// waits for the user's answer. An empty filter is refused here, before anything is sent.
    pub async fn cleanup(
        &self,
        filter: CleanupFilter,
        reason: &str,
        phone_selector: Option<&str>,
        reported: Reported<'_>,
        progress: Progress<'_>,
    ) -> Result<Text, String> {
        if filter.is_empty() {
            return Err(
                "filter needs at least one criterion (for example ip_only: true or a username); \
                 an empty filter would match every saved login and is refused"
                    .into(),
            );
        }
        self.send(
            Kind::Cleanup,
            "",
            reason,
            None,
            Some(filter),
            phone_selector,
            reported,
            progress,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn send(
        &self,
        kind: Kind,
        target: &str,
        reason: &str,
        image_path: Option<&str>,
        filter: Option<CleanupFilter>,
        phone_selector: Option<&str>,
        reported: Reported<'_>,
        progress: Progress<'_>,
    ) -> Result<Text, String> {
        let client = ClientInfo {
            model: reported.model.map(str::to_owned),
            effort: reported.effort.map(str::to_owned),
            ..self.client.lock().expect("lock").clone()
        };
        let mut request = new_request(kind, target, reason, client);
        request.filter = filter;
        let ex = self
            .exchange(request, image_path, phone_selector, progress)
            .await?;
        Ok(text(&match &ex.answer {
            Some(answer) => {
                Outcome::from_answer(answer, kind, &ex.phone, ex.attachment_warning.clone())
            }
            None => Outcome::expired(
                &ex.request_id,
                &ex.phone,
                self.timing.request,
                ex.attachment_warning.clone(),
            ),
        }))
    }

    /// Seals and posts a request, uploads its picture and waits for the answer (`None` when
    /// none came in time). The request is checked before the agent folder is read, so a bad call
    /// fails the same everywhere.
    pub async fn exchange(
        &self,
        mut request: Request,
        image_path: Option<&str>,
        phone_selector: Option<&str>,
        progress: Progress<'_>,
    ) -> Result<Exchanged, String> {
        client::check_request(&request)?;
        let store = self.store()?;
        let relay = self.relay()?;
        let id = store
            .identity()
            .map_err(err)?
            .ok_or("This agent is not paired with Nodkey yet. Pair first (the pair tool, or `nodkey pair`).")?;
        let phones = store.phones().map_err(err)?;
        let phone = select_phone(&phones, phone_selector)?;
        let phone_keys = phone.keys().map_err(err)?;

        let image = match image_path.map(str::trim).filter(|p| !p.is_empty()) {
            Some(path) => Some(load_image(path).await?),
            None => None,
        };

        let request_id = request.request_id.clone();
        request.agent = id.name.clone();
        request.attachment = image.as_ref().map(|(kind, bytes, caption)| AttachmentInfo {
            kind: *kind,
            bytes: bytes.len() as u64,
            caption: Some(caption.clone()),
        });
        let envelope =
            client::seal_request(&request, &id.agent_id, &phone_keys.kem, image.is_some())
                .map_err(err)?;
        // Seal the picture before posting, so the upload follows the request at once (the relay
        // holds the push for it at most 5 s).
        let attachment_body = match &image {
            Some((_, bytes, _)) => Some(
                client::seal_attachment(&request_id, &id.agent_id, &phone_keys.kem, bytes)
                    .map_err(err)?,
            ),
            None => None,
        };
        let signer = Signer {
            id: &id.agent_id,
            keys: &id.keys,
        };
        relay.post_request(&signer, &phone.phone_id, &envelope).await.map_err(|e| match &e {
            crate::relay::RelayError::Status { status: 403, .. } => format!(
                "{e}. The phone no longer accepts this agent; the user may have removed it. Pair again."
            ),
            crate::relay::RelayError::Status { status: 429, .. } => {
                format!("{e}. Too many requests (20 per hour); wait before asking again.")
            }
            _ => e.to_string(),
        })?;
        let started = Instant::now();

        let mut attachment_warning = None;
        if let Some(body) = attachment_body
            && let Err(e) = relay.put_attachment(&signer, &request_id, body).await
        {
            let why = match &e {
                crate::relay::RelayError::Status { status: 413, .. } => {
                    "the relay says it is too large (more than 1 MiB)".to_owned()
                }
                _ => e.to_string(),
            };
            attachment_warning = Some(format!(
                "The picture could not be uploaded ({why}); the request was sent without it."
            ));
        }

        let remaining = self.timing.request.saturating_sub(started.elapsed());
        let answer_box = poll_until(
            remaining,
            self.timing.max_wait,
            progress,
            "Waiting for the user to answer on their iPhone",
            |wait| relay.wait_answer(&signer, &request_id, wait),
        )
        .await?;

        let mut ex = Exchanged {
            answer: None,
            request_id,
            phone: phone.name.clone(),
            attachment_warning,
        };
        let Some(answer_box) = answer_box else {
            return Ok(ex);
        };
        let plain = Purpose::Answer
            .open_box(
                id.keys.kem_secret(),
                &answer_box,
                &client::answer_aad(&ex.request_id, &phone.phone_id),
            )
            .map_err(|_| "The answer does not decrypt; ignoring it.".to_owned())?;
        let answer = client::read_answer(&plain, &ex.request_id)
            .map_err(|e| format!("{e}; ignoring it."))?;
        drop(plain);
        ex.answer = Some(answer);
        Ok(ex)
    }
}

/// A request that went to the phone: its answer, if one came in time.
pub struct Exchanged {
    pub answer: Option<Answer>,
    pub request_id: String,
    /// The phone's name.
    pub phone: String,
    pub attachment_warning: Option<String>,
}

/// A new request of `kind` with a fresh id; `agent` is filled in when it is sent.
pub fn new_request(kind: Kind, target: &str, reason: &str, client: ClientInfo) -> Request {
    Request {
        v: VERSION,
        request_id: nodkey_proto::random_id(),
        kind,
        target: target.trim().to_owned(),
        reason: reason.trim().to_owned(),
        agent: String::new(),
        ts: nodkey_proto::unix_now(),
        attachment: None,
        filter: None,
        save: None,
        passkey: None,
        client: Some(client.tidy()),
    }
}

/// Long-polls with `poll(wait)` until a value arrives (`Some`), the resource is gone or `total`
/// runs out (`None`). Transient failures are retried within the same deadline.
async fn poll_until<T, F, Fut>(
    total: Duration,
    max_wait: u64,
    progress: Progress<'_>,
    message: &str,
    mut poll: F,
) -> Result<Option<T>, String>
where
    F: FnMut(u64) -> Fut,
    Fut: std::future::Future<Output = Result<Poll<T>, crate::relay::RelayError>>,
{
    let start = Instant::now();
    let deadline = start + total;
    let mut failures = 0u32;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(None);
        }
        progress(start.elapsed().as_secs(), total.as_secs(), message);
        let wait = remaining.as_secs().clamp(1, max_wait.max(1));
        let round = Instant::now();
        match poll(wait).await {
            Ok(Poll::Ready(v)) => return Ok(Some(v)),
            Ok(Poll::Gone) => return Ok(None),
            Ok(Poll::Pending) => failures = 0,
            Err(e) if e.is_transient() => {
                failures += 1;
                if failures > 20 {
                    return Err(e.to_string());
                }
            }
            Err(e) => return Err(e.to_string()),
        }
        // Never spin: a relay that answers at once is asked again after a short pause.
        let min_round = Duration::from_millis(500);
        let took = round.elapsed();
        if took < min_round {
            let pause = (min_round - took).min(deadline.saturating_duration_since(Instant::now()));
            tokio::time::sleep(pause).await;
        }
    }
}

pub(crate) fn text<T: Serialize>(v: &T) -> Text {
    Zeroizing::new(serde_json::to_string(v).expect("serializable"))
}
