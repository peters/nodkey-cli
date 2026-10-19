//! API keys and other secrets: the `request_secret` and `save_secret` tools, `nodkey secret save`
//! and the results. The preferred way to use a key is `nodkey run --secret NAME -- <command>`
//! (see `run.rs`): the value then goes into the command's environment and never reaches the model.
//! The phone asks for Face ID every time; there is never a lease for a key.

use nodkey_proto::{
    Answer, Decision, Kind, Lease, Quota, SaveSecret, SecretAnswer, SecretTarget,
    apikey::{self, KeyFrom},
};
use serde::Serialize;
use serde_json::{Map, Value};
use zeroize::Zeroizing;

use crate::{
    agent::{Agent, Progress, Reported, Text, new_request, text},
    outcome::{OLD_PROTOCOL, Outcome, is_paused, limit_note, paused},
    store::select_phone,
};

/// How to use a key without it entering the conversation.
pub const PREFER_RUN: &str = "Next time use `nodkey run --secret VARIABLE[=SERVICE] -- <command>`: the key \
    then goes straight into the command's environment and never into this conversation.";

/// The target for a key: `service/VARIABLE`, `service` or `VARIABLE`. The service may be given as
/// a URL; it is cut down to its host.
pub fn target(variable: Option<&str>, service: Option<&str>) -> Result<String, String> {
    let variable = variable.map(str::trim).filter(|v| !v.is_empty());
    let service = match service.map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => Some(
            apikey::service(s)
                .ok_or_else(|| format!("{s:?} is not a service; give its host, e.g. openai.com"))?,
        ),
        None => None,
    };
    if variable.is_none() && service.is_none() {
        return Err(
            "name the key: its variable name (e.g. OPENAI_API_KEY), its service (e.g. openai.com) or both"
                .into(),
        );
    }
    if let Some(v) = variable
        && !apikey::valid_variable(v)
    {
        return Err(format!(
            "{v:?} is not a variable name (letters, digits and _, e.g. OPENAI_API_KEY)"
        ));
    }
    Ok(SecretTarget {
        service,
        variable: variable.map(str::to_owned),
        ..SecretTarget::default()
    }
    .to_target())
}

/// A project as an agent or the command line names it: `None` when it is empty or `global`
/// (only global keys then answer a request, and a save makes a global key).
pub fn project(name: Option<&str>) -> Result<Option<String>, String> {
    match name.map(str::trim).filter(|p| !p.is_empty()) {
        None => Ok(None),
        Some(p) if p.eq_ignore_ascii_case(apikey::GLOBAL) => Ok(None),
        Some(p) if apikey::valid_project(p) => Ok(Some(p.to_owned())),
        Some(p) => Err(format!(
            "{p:?} is not a project name (1 to {} characters, no / or ,); use the name from the .nodkey file",
            apikey::MAX_PROJECT
        )),
    }
}

/// The projects of a key to save, from a list (`global` or none: a global key).
pub fn projects<'a>(names: impl IntoIterator<Item = &'a str>) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for name in names {
        if let Some(p) = project(Some(name))?
            && !out.iter().any(|q| apikey::same_project(q, &p))
        {
            out.push(p);
        }
    }
    if out.len() > apikey::MAX_PROJECTS {
        return Err(format!(
            "a key belongs to at most {} projects",
            apikey::MAX_PROJECTS
        ));
    }
    Ok(out)
}

/// A key to save: everything but the value.
#[derive(Debug, Clone, Default)]
pub struct NewKey {
    pub variable: String,
    pub service: Option<String>,
    pub title: Option<String>,
    pub notes: Option<String>,
    pub expires: Option<u64>,
    /// The projects the key is for; empty for a global key.
    pub projects: Vec<String>,
}

impl NewKey {
    /// The variable name and service checked, the service cut down to its host.
    fn tidy(mut self) -> Result<NewKey, String> {
        let t = target(Some(&self.variable), self.service.as_deref())?;
        let parsed = SecretTarget::parse(&t)?;
        self.variable = parsed.variable.unwrap_or_default();
        self.service = parsed.service;
        let clean = |s: Option<String>| s.map(|t| t.trim().to_owned()).filter(|t| !t.is_empty());
        self.title = clean(self.title);
        self.notes = clean(self.notes);
        self.projects = projects(self.projects.iter().map(String::as_str))?;
        Ok(self)
    }
}

/// `expires` as Unix seconds or `YYYY-MM-DD`.
pub fn expires(v: Option<&Value>) -> Result<Option<u64>, String> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n
            .as_u64()
            .map(Some)
            .ok_or_else(|| "expires must be Unix seconds or YYYY-MM-DD".to_owned()),
        Some(Value::String(s)) => crate::filter::parse_date(s)
            .or_else(|| s.trim().parse().ok())
            .map(Some)
            .ok_or_else(|| format!("expires {s:?} is not a date like 2027-01-31")),
        Some(_) => Err("expires must be Unix seconds or YYYY-MM-DD".into()),
    }
}

impl Agent {
    /// Asks the phone for one key, in `project` when given (that project's key, else the global
    /// one), and waits for the answer (`image_path`: a picture for the notification). The result
    /// carries the value; the message tells the model to prefer `nodkey run`.
    #[allow(clippy::too_many_arguments)]
    pub async fn request_secret(
        &self,
        target: &str,
        project: Option<&str>,
        reason: &str,
        image_path: Option<&str>,
        phone_selector: Option<&str>,
        reported: Reported<'_>,
        progress: Progress<'_>,
    ) -> Result<Text, String> {
        let mut request = new_request(Kind::Secret, target, reason, self.client_for(reported));
        request.project = project.map(str::to_owned);
        let ex = self
            .exchange(request, image_path, phone_selector, progress)
            .await?;
        let v = match &ex.answer {
            Some(a) => serde_json::to_value(outcome(a, target, &ex.phone)),
            None => serde_json::to_value(Outcome::expired(
                &ex.request_id,
                &ex.phone,
                self.timing.request,
                ex.attachment_warning.clone(),
            )),
        }
        .map_err(|e| e.to_string())?;
        Ok(text(&v))
    }

    /// Seals `value` to the phone and asks it to keep the key: a key with the same service,
    /// variable name and projects gets the new value, else a new key is added.
    #[allow(clippy::too_many_arguments)]
    pub async fn save_secret(
        &self,
        key: NewKey,
        value: Zeroizing<String>,
        reason: &str,
        phone_selector: Option<&str>,
        reported: Reported<'_>,
        progress: Progress<'_>,
    ) -> Result<Text, String> {
        let key = key.tidy()?;
        if value.trim().is_empty() {
            return Err("the value is empty".into());
        }
        if value.len() > apikey::MAX_SAVE_VALUE {
            return Err(format!(
                "the value is longer than {} bytes; add this key in the Nodkey app instead",
                apikey::MAX_SAVE_VALUE
            ));
        }
        let store = self.store()?;
        let id = store
            .identity()
            .map_err(|e| e.to_string())?
            .ok_or("This agent is not paired with Nodkey yet. Pair first (the pair tool, or `nodkey pair`).")?;
        let phones = store.phones().map_err(|e| e.to_string())?;
        let phone = select_phone(&phones, phone_selector)?;
        let kem = phone.keys().map_err(|e| e.to_string())?.kem;
        let sealed = apikey::seal_value(&id.agent_id, &kem, &value).map_err(|e| e.to_string())?;
        drop(value);
        let save = SaveSecret {
            variable: key.variable,
            service: key.service,
            title: key.title,
            notes: key.notes,
            expires: key.expires,
            projects: key.projects,
            value: sealed,
        };
        let target = save.target();
        let mut request = new_request(Kind::SaveSecret, &target, reason, self.client_for(reported));
        request.save_secret = Some(save);
        let phone_id = phone.phone_id.clone();
        let ex = self
            .exchange(request, None, Some(&phone_id), progress)
            .await?;
        let v = match &ex.answer {
            Some(a) => serde_json::to_value(save_outcome(a, &target, &ex.phone)),
            None => serde_json::to_value(Outcome::expired(
                &ex.request_id,
                &ex.phone,
                self.timing.request,
                None,
            )),
        }
        .map_err(|e| e.to_string())?;
        Ok(text(&v))
    }
}

/// What `request_secret` and `save_secret` return.
#[derive(Serialize)]
pub struct SecretOutcome<'a> {
    decision: Decision,
    request_id: &'a str,
    phone: &'a str,
    target: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    secret: Option<&'a SecretAnswer>,
    /// `save_secret`: `added`, `updated` or `unchanged`.
    #[serde(skip_serializing_if = "Option::is_none")]
    saved: Option<nodkey_proto::Saved>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lease: Option<&'a Lease>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    quota: Option<&'a Quota>,
    message: String,
}

/// The message for a refusal, by the phone's error code.
pub fn refusal(a: &Answer) -> String {
    match a.error.as_deref() {
        _ if is_paused(a) => paused(a),
        Some("unsupported_version" | "unsupported_kind") => OLD_PROTOCOL.to_owned(),
        Some(apikey::errors::NO_SECRET) => {
            "The user says Nodkey has no such key. Ask them to add it in Nodkey \
            (Passwords, Keys). If you make a new key for them, save it at once with save_secret."
                .to_owned()
        }
        Some(apikey::errors::NOT_ALLOWED) => {
            "This agent may not ask for keys (it is paired for codes only). The \
            user can change that under Agents in Nodkey."
                .to_owned()
        }
        Some(apikey::errors::NO_PASSCODE) => crate::outcome::NO_PASSCODE.to_owned(),
        Some(apikey::errors::BAD_SECRET_REQUEST) => {
            "The phone refused the request as malformed.".to_owned()
        }
        _ => "The user denied the request. Do not ask again for the same key unless they say so."
            .to_owned(),
    }
}

/// The tool result for a `secret` answer.
pub fn outcome<'a>(a: &'a Answer, target: &'a str, phone: &'a str) -> SecretOutcome<'a> {
    let approved = a.decision == Decision::Approved;
    let message = match a.decision {
        Decision::Approved if a.secret.as_ref().is_some_and(|s| s.value.is_some()) => format!(
            "The user approved. The key is in secret.value.{} Use it only for this task: put it in the \
             environment of the command that needs it, never in a file, a commit, a chat message or a log, and \
             never repeat it. {PREFER_RUN}",
            from_note(a.secret.as_ref())
        ),
        Decision::Approved => "The phone approved but sent no key.".to_owned(),
        Decision::Denied => refusal(a),
        Decision::Expired => "The request expired on the phone without an answer.".to_owned(),
        Decision::Queued | Decision::Rejected => crate::outcome::MISFIT.to_owned(),
    } + &limit_note(a);
    SecretOutcome {
        decision: a.decision,
        request_id: &a.request_id,
        phone,
        target,
        secret: a.secret.as_ref().filter(|_| approved),
        saved: None,
        lease: a.lease.as_ref(),
        error: a.error.as_deref(),
        quota: a.quota.as_ref(),
        message,
    }
}

/// Where the key came from, for a result's message.
pub fn from_note(key: Option<&SecretAnswer>) -> String {
    match key.map(|k| (k.from, k.project.as_deref())) {
        Some((Some(KeyFrom::Project), Some(p))) => format!(" It is the key of the project {p}."),
        Some((Some(KeyFrom::Global), _)) => " It is the global key (secret.from).".to_owned(),
        Some((Some(KeyFrom::Chosen), _)) => {
            " No key matched, so the user picked this one by hand.".to_owned()
        }
        _ => String::new(),
    }
}

/// The tool result for a `save_secret` answer.
pub fn save_outcome<'a>(a: &'a Answer, target: &'a str, phone: &'a str) -> SecretOutcome<'a> {
    let message = match (a.decision, a.saved) {
        (Decision::Approved, Some(saved)) => format!(
            "Nodkey keeps the key now ({}). Do not keep the value anywhere else: take it out of files and notes \
             you made. To use it, run `nodkey run --secret {} -- <command>`.",
            match saved {
                nodkey_proto::Saved::Added => "added as a new key",
                nodkey_proto::Saved::Updated =>
                    "the key with this service and variable name has the new value",
                nodkey_proto::Saved::Unchanged => "it already had exactly this key",
            },
            target.rsplit('/').next().unwrap_or(target)
        ),
        (Decision::Approved, None) => {
            "The phone approved but did not say what it saved.".to_owned()
        }
        (Decision::Denied, _) if a.error.is_none() => {
            "The user did not save the key. Do not ask again unless they say so.".to_owned()
        }
        (Decision::Denied, _) => refusal(a),
        (Decision::Expired, _) => {
            "The request expired on the phone without an answer. The key was not \
            saved; ask the user before you send it again."
                .to_owned()
        }
        (Decision::Queued | Decision::Rejected, _) => crate::outcome::MISFIT.to_owned(),
    };
    SecretOutcome {
        decision: a.decision,
        request_id: &a.request_id,
        phone,
        target,
        secret: None,
        saved: a.saved.filter(|_| a.decision == Decision::Approved),
        lease: None,
        error: a.error.as_deref(),
        quota: None,
        message,
    }
}

/// Runs `request_secret` and `save_secret` for the MCP server.
pub async fn call(
    agent: &Agent,
    name: &str,
    args: &Map<String, Value>,
    reported: Reported<'_>,
    progress: Progress<'_>,
) -> Result<Text, String> {
    use crate::mcp::{opt_str, req_str};
    let phone = opt_str(args, "phone")?;
    let reason = req_str(args, "reason")?;
    if name == "request_secret" {
        let t = target(opt_str(args, "variable")?, opt_str(args, "service")?)?;
        let project = project(opt_str(args, "project")?)?;
        return agent
            .request_secret(
                &t,
                project.as_deref(),
                reason,
                opt_str(args, "image_path")?,
                phone,
                reported,
                progress,
            )
            .await;
    }
    let key = NewKey {
        variable: req_str(args, "variable")?.to_owned(),
        service: opt_str(args, "service")?.map(str::to_owned),
        title: opt_str(args, "title")?.map(str::to_owned),
        notes: opt_str(args, "notes")?.map(str::to_owned),
        expires: expires(args.get("expires"))?,
        projects: string_list(args.get("projects"))?,
    };
    let value = Zeroizing::new(req_str(args, "value")?.to_owned());
    agent
        .save_secret(key, value, reason, phone, reported, progress)
        .await
}

/// An optional list of strings (`projects`).
fn string_list(v: Option<&Value>) -> Result<Vec<String>, String> {
    match v {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(list)) => list
            .iter()
            .map(|p| p.as_str().map(str::to_owned))
            .collect::<Option<Vec<String>>>()
            .ok_or_else(|| "projects must be a list of project names".to_owned()),
        Some(_) => Err("projects must be a list of project names, e.g. [\"Sparrow\"]".into()),
    }
}

mod noecho;
pub mod save;

#[cfg(test)]
mod tests;
