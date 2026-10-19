//! API keys and other secrets (`kind: secret` and `kind: save_secret`): a key the user keeps in
//! Nodkey (an API key, a token) with its service and environment variable name. An agent asks for
//! one by service and/or variable name; the phone answers only after Face ID, never under a lease.
//! The preferred way is `nodkey run --secret NAME -- <command>`: the value goes into the child
//! process's environment and never reaches the model. An agent that made a new key saves it with
//! `save_secret`; the value is sealed to the phone on its own (`nodkey/v1/secret`). Keys belong to
//! projects or are global ([`project`]).

use serde::{Deserialize, Serialize};

use crate::{Error, Purpose, SealedBox, Secret, client::MAX_TARGET};

pub mod project;
pub use project::{
    Found, GLOBAL, KeyFrom, KeyNames, MAX_PROJECT, MAX_PROJECTS, lookup, same_project,
    same_projects, saved_key, valid_project,
};

/// Why the phone refused a `secret` or `save_secret` request (`Answer.error`).
pub mod errors {
    /// The user saw the request and told the agent that Nodkey has no such key. Sent only after
    /// the user answered, so an agent cannot probe for keys without them.
    pub const NO_SECRET: &str = "no_secret";
    /// The target or the key to save breaks a rule of [`super::SecretTarget::parse`] or
    /// [`super::SaveSecret::check`]; at once.
    pub const BAD_SECRET_REQUEST: &str = "bad_secret_request";
    /// The agent's scope does not allow keys (`codes`); at once.
    pub const NOT_ALLOWED: &str = "not_allowed";
}

/// Longest environment variable name, in characters.
pub const MAX_VARIABLE: usize = 100;
/// Longest value the agent tools save through the relay, in bytes (the request must stay under
/// [`crate::client::REQUEST_CT_MAX`]). Longer keys are added in the app.
pub const MAX_SAVE_VALUE: usize = 1500;
/// Longest title and notes of a key to save, in characters.
pub const MAX_TITLE: usize = 100;
pub const MAX_NOTES: usize = 500;

/// Whether `name` is an environment variable name: a letter or `_`, then letters, digits and
/// `_` (`OPENAI_API_KEY`), at most [`MAX_VARIABLE`] characters.
pub fn valid_variable(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && name.len() <= MAX_VARIABLE
}

/// The service of a key as the wire carries it: the host, lower case, without scheme, port, path
/// or `www.` ([`crate::signin::site`]: `https://API.OpenAI.com/v1` → `api.openai.com`).
pub fn service(value: &str) -> Option<String> {
    crate::signin::site(value)
}

/// Whether a key saved for `saved` serves `wanted`: the same host, or one is a subdomain of the
/// other (`openai.com` and `api.openai.com`). Both are [`service`] forms.
pub fn service_matches(saved: &str, wanted: &str) -> bool {
    saved == wanted
        || wanted.ends_with(&format!(".{saved}"))
        || saved.ends_with(&format!(".{wanted}"))
}

/// What a `secret` target names: a service, a variable name, or both (`service/VARIABLE`); or a
/// variable name in a project (`project/VARIABLE`) or among the global keys (`global/VARIABLE`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SecretTarget {
    pub service: Option<String>,
    pub variable: Option<String>,
    /// `project/VARIABLE`: the project named in the target (it wins over the request's `project`).
    pub project: Option<String>,
    /// `global/VARIABLE`: only a global key, whatever project the request names.
    pub global: bool,
}

impl SecretTarget {
    /// Reads a target: `openai.com` (a service: it has a dot), `OPENAI_API_KEY` (a variable
    /// name), `openai.com/OPENAI_API_KEY` (both), `sparrow/OPENAI_API_KEY` (a variable name in a
    /// project: the part before `/` has no dot and is not `localhost`) or `global/OPENAI_API_KEY`
    /// (only the global key). A service must already be in [`service`] form; the agent tools tidy
    /// it before they send. A project whose name has a dot goes in the request's `project`.
    pub fn parse(target: &str) -> Result<SecretTarget, String> {
        let t = target.trim();
        if t.is_empty() || t.chars().count() > MAX_TARGET {
            return Err("a key target is a service, a variable name or service/VARIABLE".into());
        }
        let (mut service_part, variable_part) = match t.split_once('/') {
            Some((s, v)) => (Some(s), Some(v)),
            None if valid_variable(t) => (None, Some(t)),
            None => (Some(t), None),
        };
        let (mut project, mut global) = (None, false);
        if let (Some(first), Some(_)) = (service_part, variable_part)
            && !first.contains('.')
            && first != "localhost"
        {
            if first.eq_ignore_ascii_case(GLOBAL) {
                global = true;
            } else if valid_project(first) {
                project = Some(first.to_owned());
            } else {
                return Err(format!(
                    "{first:?} is neither a service host (e.g. openai.com) nor a project name"
                ));
            }
            service_part = None;
        }
        if let Some(v) = variable_part
            && !valid_variable(v)
        {
            return Err(format!(
                "{v:?} is not a variable name (letters, digits and _, e.g. OPENAI_API_KEY)"
            ));
        }
        if let Some(s) = service_part
            && service(s).as_deref() != Some(s)
        {
            return Err(format!(
                "{s:?} is not a service host in lower case (e.g. openai.com)"
            ));
        }
        Ok(SecretTarget {
            service: service_part.map(str::to_owned),
            variable: variable_part.map(str::to_owned),
            project,
            global,
        })
    }

    /// The target string: `service/VARIABLE`, `service`, `VARIABLE`, `project/VARIABLE` or
    /// `global/VARIABLE` (a project or `global` goes with a variable name only, never a service).
    pub fn to_target(&self) -> String {
        let scope = if self.global {
            Some(GLOBAL)
        } else {
            self.project.as_deref()
        };
        match (scope, &self.service, &self.variable) {
            (Some(p), _, Some(v)) => format!("{p}/{v}"),
            (_, Some(s), Some(v)) => format!("{s}/{v}"),
            (_, Some(s), None) => s.clone(),
            (_, None, Some(v)) => v.clone(),
            (_, None, None) => String::new(),
        }
    }

    /// Whether a key with this service and variable name matches: every part the target names
    /// must match (the variable name without regard to case, the service by [`service_matches`]).
    pub fn matches(&self, service: Option<&str>, variable: Option<&str>) -> bool {
        let service_ok = match (&self.service, service) {
            (None, _) => true,
            (Some(w), Some(s)) => service_matches(s, w),
            (Some(_), None) => false,
        };
        let variable_ok = match (&self.variable, variable) {
            (None, _) => true,
            (Some(w), Some(v)) => w.eq_ignore_ascii_case(v),
            (Some(_), None) => false,
        };
        service_ok && variable_ok
    }
}

/// The key in an approved `secret` answer (and in an approved `secret` item of a bundle).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretAnswer {
    /// The user's name for the key, e.g. "OpenAI".
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// The environment variable name the user gave the key, when it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variable: Option<String>,
    /// The secret. Absent only in a `secret` item of a task plan (a bundle with `session`): the
    /// plan only lets later `secret` requests in the session go through.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Secret>,
    /// When the key stops working, if the user noted it (Unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<u64>,
    /// Where the key comes from: a key of the asked project, a global key, or one the user picked
    /// by hand. Absent in answers from apps before projects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<KeyFrom>,
    /// With `from: project`: the project's name as the user wrote it ("Sparrow").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
}

/// A key in a `list` answer: names only, never the value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretEntry {
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variable: Option<String>,
    /// The projects the key belongs to; absent (empty) for a global key.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub projects: Vec<String>,
}

/// The key a `save_secret` request asks the phone to keep. The value is sealed to the phone on
/// its own (`nodkey/v1/secret`, `aad` = `agent_id`) the moment the agent reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaveSecret {
    /// The environment variable name, e.g. `OPENAI_API_KEY`. Required: with `service` it says
    /// which key to update.
    pub variable: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// A title for a new key; the phone makes one from the service when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// When the key stops working, if the agent knows (Unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<u64>,
    /// The projects the key is for (`["Sparrow"]`); absent (empty) saves a global key.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub projects: Vec<String>,
    pub value: SealedBox,
}

impl SaveSecret {
    /// The target a `save_secret` request carries: `service/VARIABLE`, or `VARIABLE`.
    pub fn target(&self) -> String {
        SecretTarget {
            service: self.service.clone(),
            variable: Some(self.variable.clone()),
            ..SecretTarget::default()
        }
        .to_target()
    }

    /// What a save needs, for a request whose `target` is `target`.
    pub fn check(&self, target: &str) -> Result<(), String> {
        if !valid_variable(&self.variable) {
            return Err(format!(
                "{:?} is not a variable name (letters, digits and _, e.g. OPENAI_API_KEY)",
                self.variable
            ));
        }
        if let Some(s) = &self.service
            && service(s).as_deref() != Some(s.as_str())
        {
            return Err(format!(
                "{s:?} is not a service host in lower case (e.g. openai.com)"
            ));
        }
        if target != self.target() {
            return Err("the target of a save_secret request is service/VARIABLE".into());
        }
        if self.value.ct.is_empty() || self.value.enc.is_empty() {
            return Err("a save_secret request needs the sealed value".into());
        }
        let long =
            |s: &Option<String>, max: usize| s.as_ref().is_some_and(|t| t.chars().count() > max);
        if long(&self.title, MAX_TITLE) || long(&self.notes, MAX_NOTES) {
            return Err(format!(
                "the title (at most {MAX_TITLE}) or the notes (at most {MAX_NOTES}) are too long"
            ));
        }
        project::check_projects(&self.projects)
    }
}

/// The `secret` and `save_secret` rules of [`crate::client::check_request`], and the request's
/// `project`.
pub(crate) fn check_request(r: &crate::Request) -> Result<(), String> {
    use crate::Kind;
    project::check_request(r)?;
    match (r.kind, &r.save_secret) {
        (Kind::Secret, None) => SecretTarget::parse(&r.target).map(|_| ()),
        (Kind::SaveSecret, None) => Err("a save_secret request needs the key to save".into()),
        (Kind::SaveSecret, Some(s)) => s.check(&r.target),
        (_, Some(_)) => Err("only a save_secret request carries a key to save".into()),
        (_, None) => Ok(()),
    }
}

/// Seals the value of a `save_secret` request to the phone on its own, like a saved password.
/// The result can be kept and sent again in a new request; only the phone can open it.
pub fn seal_value(agent_id: &str, phone_kem: &[u8; 32], value: &str) -> Result<SealedBox, Error> {
    if value.trim().is_empty() {
        return Err(Error::Encoding("empty value"));
    }
    if value.len() > MAX_SAVE_VALUE {
        return Err(Error::Encoding("the value is too long to send"));
    }
    Ok(Purpose::Secret
        .seal(phone_kem, agent_id.as_bytes(), value.as_bytes())?
        .to_box())
}

#[cfg(test)]
mod tests;
