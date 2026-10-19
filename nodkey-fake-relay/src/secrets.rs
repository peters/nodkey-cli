//! The fake phone's API keys (`kind: secret` and `save_secret`): two test keys to begin with, the
//! refusals the phone gives at once, and saves that update or add a key by service and variable
//! name. Test values only.

use nodkey_proto::{
    Answer, Decision, Kind, Purpose, Request, Saved, Secret, SecretAnswer, SecretEntry,
    SecretTarget, apikey::errors,
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
}

/// The keys the fake phone starts with.
pub fn test_keys() -> Vec<FakeKey> {
    let key = |title: &str, service: &str, variable: &str, value: &str| FakeKey {
        title: title.into(),
        service: Some(service.into()),
        variable: Some(variable.into()),
        value: value.into(),
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

/// A key request the phone refuses without asking: a target or a save that breaks the rules.
pub(crate) fn refuse(rid: &str, request: &Request) -> Option<Answer> {
    let bad = match request.kind {
        Kind::Secret => SecretTarget::parse(&request.target).is_err(),
        Kind::SaveSecret => request
            .save_secret
            .as_ref()
            .is_none_or(|s| s.check(&request.target).is_err()),
        _ => false,
    };
    bad.then(|| denied(rid, errors::BAD_SECRET_REQUEST))
}

/// The first key that matches `target`, as the answer carries it (with its value).
pub(crate) fn find(fake: &Fake, target: &str) -> Option<SecretAnswer> {
    let wanted = SecretTarget::parse(target).ok()?;
    let keys = fake.secrets.lock().unwrap();
    let key = keys
        .iter()
        .find(|k| wanted.matches(k.service.as_deref(), k.variable.as_deref()))?;
    Some(SecretAnswer {
        title: key.title.clone(),
        service: key.service.clone(),
        variable: key.variable.clone(),
        value: Some(Secret::new(key.value.clone())),
        expires: None,
    })
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
    match find(fake, &request.target) {
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

/// Updates the key with the same service and variable name, or adds one.
fn save(fake: &Fake, request: &Request, rid: &str) -> Saved {
    let s = request.save_secret.as_ref().expect("checked before asking");
    let value = fake.inner.lock().unwrap().requests[rid]
        .saved_secret
        .clone()
        .expect("a save carries its value");
    let mut keys = fake.secrets.lock().unwrap();
    let same = keys.iter_mut().find(|k| {
        k.service == s.service
            && k.variable
                .as_deref()
                .is_some_and(|v| v.eq_ignore_ascii_case(&s.variable))
    });
    match same {
        Some(k) if k.value == value => Saved::Unchanged,
        Some(k) => {
            k.value = value;
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
            });
            Saved::Added
        }
    }
}
