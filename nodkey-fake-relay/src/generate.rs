//! The fake phone's new passwords (`kind: generate`, peters/nodkey#131): the refusals it makes at
//! once, in the phone's order, and an approval that makes a password by the rules, saves it first
//! (a login with the same website and user name gets it, else a new login) and then answers.
//! The fake phone does not check `pattern`: this crate has no regular expressions. Test data only.

use nodkey_proto::{Account, Answer, Decision, Kind, Request, Saved, generate::errors, site};
use serde::{Deserialize, Serialize};

use crate::Fake;

/// One login the fake phone saved for a `generate` request.
#[derive(Debug, Clone, Serialize)]
pub struct Made {
    pub agent_id: String,
    pub site: String,
    pub username: String,
    pub title: String,
    pub password: String,
    pub saved: Saved,
    /// The password the new one replaced (an update), which the phone keeps for 30 days.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_password: Option<String>,
}

/// What a test set with `PUT /_fake/generate`, and the logins the phone saved.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FakeGenerate {
    /// The user name the user types on the phone instead of the request's.
    #[serde(default)]
    pub username: Option<String>,
    /// The agent is paired for codes only (`not_allowed`).
    #[serde(default)]
    pub codes_only: bool,
    /// The phone cannot save (`save_failed` after the approval).
    #[serde(default)]
    pub save_fails: bool,
    /// Every login saved for a `generate` request, oldest first.
    #[serde(default, skip_deserializing)]
    pub made: Vec<Made>,
}

fn denied(rid: &str, error: &str) -> Answer {
    let mut a = Answer::decision(rid, Decision::Denied);
    a.error = Some(error.into());
    a
}

/// A `generate` request the phone refuses without asking, in its order (after `paused`).
pub(crate) fn refuse(fake: &Fake, rid: &str, request: &Request) -> Option<Answer> {
    if request.kind != Kind::Generate {
        return None;
    }
    if !*fake.passcode.lock().unwrap() {
        return Some(denied(rid, errors::NO_PASSCODE));
    }
    if fake.generate.lock().unwrap().codes_only {
        return Some(denied(rid, errors::NOT_ALLOWED));
    }
    let Some(g) = request
        .generate
        .as_ref()
        .filter(|g| g.check(&request.target).is_ok())
    else {
        return Some(denied(rid, errors::BAD_GENERATE));
    };
    if g.rules.clone().unwrap_or_default().check().is_err() {
        return Some(denied(rid, errors::BAD_RULES));
    }
    None
}

/// The user approved: make the password, save it, then fill in the answer.
pub(crate) fn approve(fake: &Fake, agent_id: &str, answer: &mut Answer, request: &Request) {
    answer.lease = None;
    let g = request.generate.clone().expect("checked before asking");
    let mut state = fake.generate.lock().unwrap();
    if state.save_fails {
        *answer = denied(&answer.request_id, errors::SAVE_FAILED);
        return;
    }
    let reading = g.rules.unwrap_or_default().read();
    let Some(password) = reading.make() else {
        *answer = denied(&answer.request_id, errors::BAD_RULES);
        return;
    };
    let username = state.username.clone().or(g.username).unwrap_or_default();
    let same = |m: &Made| {
        site::same_site(&m.site, &request.target) && m.username.eq_ignore_ascii_case(&username)
    };
    let (site, title, saved, old_password) = match state.made.iter().rev().find(|m| same(m)) {
        Some(m) => (
            m.site.clone(),
            m.title.clone(),
            Saved::Updated,
            Some(m.password.clone()),
        ),
        None => (
            request.target.clone(),
            g.title.unwrap_or_else(|| request.target.clone()),
            Saved::Added,
            None,
        ),
    };
    state.made.push(Made {
        agent_id: agent_id.to_owned(),
        site: site.clone(),
        username: username.clone(),
        title: title.clone(),
        password: password.expose().to_owned(),
        saved,
        old_password,
    });
    answer.saved = Some(saved);
    answer.account = Some(Account {
        issuer: title,
        name: username.clone(),
        site: Some(site),
        sites: None,
    });
    answer.username = Some(username);
    answer.password = Some(password);
}
