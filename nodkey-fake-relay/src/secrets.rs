//! The fake phone's API keys (`kind: secret` and `save_secret`): two global test keys to begin
//! with, the refusals the phone gives at once, the lookup by project (the project's key, else the
//! global one) and saves that update or add a key by service, variable name and projects. Test
//! values only.

use nodkey_proto::{
    Answer, Decision, Kind, Purpose, Request, Saved, Secret, SecretAnswer, SecretEntry,
    SecretTarget,
    apikey::{self, KeyFrom, KeyNames, errors},
};
use serde::{Deserialize, Serialize};

use crate::Fake;

/// One key on the fake phone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FakeKey {
    pub title: String,
    pub service: Option<String>,
    pub variable: Option<String>,
    pub value: String,
    /// The projects the key belongs to; empty for a global key.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub projects: Vec<String>,
}

impl FakeKey {
    fn names(&self) -> KeyNames<'_> {
        KeyNames {
            service: self.service.as_deref(),
            variable: self.variable.as_deref(),
            projects: &self.projects,
        }
    }
}

/// The keys the fake phone starts with.
pub fn test_keys() -> Vec<FakeKey> {
    let key = |title: &str, service: &str, variable: &str, value: &str| FakeKey {
        title: title.into(),
        service: Some(service.into()),
        variable: Some(variable.into()),
        value: value.into(),
        projects: vec![],
    };
    vec![
        key("OpenAI", "openai.com", "OPENAI_API_KEY", "sk-test-0000"),
        key(
            "Example API",
            "api.example.com",
            "EXAMPLE_TOKEN",
            "tok-test-1111",
        ),
    ]
}

fn denied(rid: &str, error: &str) -> Answer {
    let mut a = Answer::decision(rid, Decision::Denied);
    a.error = Some(error.into());
    a
}

/// A key request the phone refuses without asking: a target, a project or a save that breaks the
/// rules.
pub(crate) fn refuse(rid: &str, request: &Request) -> Option<Answer> {
    let bad_project = request
        .project
        .as_deref()
        .is_some_and(|p| !apikey::valid_project(p));
    let bad = bad_project
        || match request.kind {
            Kind::Secret => SecretTarget::parse(&request.target).is_err(),
            Kind::SaveSecret => request
                .save_secret
                .as_ref()
                .is_none_or(|s| s.check(&request.target).is_err()),
            _ => false,
        };
    bad.then(|| denied(rid, errors::BAD_SECRET_REQUEST))
}

/// The key the phone gives for `target` in `project` (the request's), as the answer carries it
/// (with its value): the first key of the asked project that matches, else the first global one.
pub(crate) fn find(fake: &Fake, target: &str, project: Option<&str>) -> Option<SecretAnswer> {
    let wanted = SecretTarget::parse(target).ok()?;
    let keys = fake.secrets.lock().unwrap();
    let names: Vec<KeyNames> = keys.iter().map(FakeKey::names).collect();
    let found = apikey::lookup(&wanted, project, &names)?;
    let key = &keys[found.keys[0]];
    let asked = wanted.asked_project(project);
    Some(SecretAnswer {
        title: key.title.clone(),
        service: key.service.clone(),
        variable: key.variable.clone(),
        value: Some(Secret::new(key.value.clone())),
        expires: None,
        from: Some(found.from),
        project: (found.from == KeyFrom::Project)
            .then(|| {
                let asked = asked?;
                key.projects
                    .iter()
                    .find(|p| apikey::same_project(p, asked))
                    .cloned()
            })
            .flatten(),
    })
}

/// What a session item covers: the asked project (none for global) and the target without it,
/// in lower case.
pub(crate) fn cover(target: &str, project: Option<&str>) -> String {
    let Ok(t) = SecretTarget::parse(target) else {
        return target.trim().to_lowercase();
    };
    let asked = t.asked_project(project).unwrap_or_default().to_lowercase();
    let plain = SecretTarget {
        project: None,
        global: false,
        ..t
    };
    format!("{asked}|{}", plain.to_target().to_lowercase())
}

/// The key names a `list` answer carries.
pub(crate) fn entries(fake: &Fake) -> Vec<SecretEntry> {
    fake.secrets
        .lock()
        .unwrap()
        .iter()
        .map(|k| SecretEntry {
            title: k.title.clone(),
            service: k.service.clone(),
            variable: k.variable.clone(),
            projects: k.projects.clone(),
        })
        .collect()
}

/// Fills in an approved `secret` or `save_secret` answer. A key that is not there: the user
/// tells the agent so (`no_secret`).
pub(crate) fn approve(fake: &Fake, answer: &mut Answer, request: &Request) {
    if request.kind == Kind::SaveSecret {
        answer.lease = None;
        answer.saved = Some(save(fake, request, &answer.request_id));
        return;
    }
    match find(fake, &request.target, request.project.as_deref()) {
        Some(key) => answer.secret = Some(key),
        None => *answer = denied(&answer.request_id, errors::NO_SECRET),
    }
}

/// The value of a `save_secret` request, opened as the phone would (test data only).
pub(crate) fn saved_value(fake: &Fake, request: &Request, agent_id: &str) -> Option<String> {
    let save = request.save_secret.as_ref()?;
    let opened = Purpose::Secret
        .open_box(fake.phone.kem_secret(), &save.value, agent_id.as_bytes())
        .expect("the key opens with the phone key");
    Some(String::from_utf8(opened.to_vec()).expect("utf-8 key"))
}

/// Updates the key with the same service, variable name and projects, or adds one.
fn save(fake: &Fake, request: &Request, rid: &str) -> Saved {
    let s = request.save_secret.as_ref().expect("checked before asking");
    let value = fake.inner.lock().unwrap().requests[rid]
        .saved_secret
        .clone()
        .expect("a save carries its value");
    let mut keys = fake.secrets.lock().unwrap();
    let names: Vec<KeyNames> = keys.iter().map(FakeKey::names).collect();
    let same = apikey::saved_key(s.service.as_deref(), &s.variable, &s.projects, &names);
    match same {
        Some(i) if keys[i].value == value => Saved::Unchanged,
        Some(i) => {
            keys[i].value = value;
            Saved::Updated
        }
        None => {
            keys.push(FakeKey {
                title: s
                    .title
                    .clone()
                    .or_else(|| s.service.clone())
                    .unwrap_or_else(|| s.variable.clone()),
                service: s.service.clone(),
                variable: Some(s.variable.clone()),
                value,
                projects: s.projects.clone(),
            });
            Saved::Added
        }
    }
}
