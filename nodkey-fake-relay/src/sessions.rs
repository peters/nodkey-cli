//! Task sessions on the fake phone (docs/agent-protocol.md, "Task sessions"): an approved bundle
//! with `session` starts one; a later `code`, `login` or passkey sign-in with its `session_id` for an
//! approved item is answered at once, whatever the mode; `session_end` ends it. Codes follow the
//! seconds left that a test sets, with the next code below the threshold.

use std::time::{SystemTime, UNIX_EPOCH};

use nodkey_proto::{
    Answer, BundleItemAnswer, Decision, Kind, Lease, LeaseKind, PasskeyRequest, Request, Secret,
    SessionInfo, session::NEXT_CODE_BELOW,
};
use serde::Serialize;

use crate::Fake;

/// The next code the fake phone hands out with a code that is about to run out.
pub const NEXT_CODE: &str = "582911";

/// A running session.
#[derive(Debug, Clone, Serialize)]
pub struct FakeSession {
    pub id: String,
    pub agent_id: String,
    pub until: u64,
    /// The approved items: kind and site (`accounts.example.com`) or relying party.
    pub items: Vec<(Kind, String)>,
    /// How many requests the session answered.
    pub used: u32,
}

/// Sessions and the code clock the tests steer.
#[derive(Debug)]
pub struct FakeSessions {
    pub list: Vec<FakeSession>,
    /// `seconds_left` of every code the phone hands out (17 unless a test sets it).
    pub seconds_left: u32,
}

impl Default for FakeSessions {
    fn default() -> Self {
        FakeSessions {
            list: Vec::new(),
            seconds_left: 17,
        }
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The site part of a target (`github.com/alex` → `github.com`), lower case.
fn site(target: &str) -> String {
    target
        .split('/')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

/// Whether an approved item covers a request.
fn covers(item: &(Kind, String), request: &Request) -> bool {
    let wanted = site(&request.target);
    match (request.kind, item.0) {
        (Kind::Code, Kind::Code | Kind::Login) | (Kind::Login, Kind::Login) => item.1 == wanted,
        // A key is covered by a key item with the same target in the same project.
        (Kind::Secret, Kind::Secret) => {
            item.1 == crate::secrets::cover(&request.target, request.project.as_deref())
        }
        // A get with PRF inputs is never covered: Face ID every time.
        (Kind::Passkey, Kind::Passkey) => {
            request
                .passkey
                .as_ref()
                .is_some_and(|p| matches!(p, PasskeyRequest::Get(_)) && !p.needs_prf_output())
                && item.1 == wanted
        }
        _ => false,
    }
}

/// Answers `session_end` and covered requests at once; `None` lets the phone ask as usual.
pub fn answer_now(fake: &Fake, agent_id: &str, rid: &str, request: &Request) -> Option<Answer> {
    let mut sessions = fake.sessions.lock().unwrap();
    let t = now();
    sessions.list.retain(|s| s.until > t);
    if request.kind == Kind::SessionEnd {
        let id = request.session_id.as_deref().unwrap_or_default();
        sessions
            .list
            .retain(|s| !(s.id == id && s.agent_id == agent_id));
        return Some(Answer::decision(rid, Decision::Approved));
    }
    let id = request.session_id.as_deref()?;
    let session = sessions
        .list
        .iter_mut()
        .find(|s| s.id == id && s.agent_id == agent_id)?;
    if !session.items.iter().any(|i| covers(i, request)) {
        return None;
    }
    session.used += 1;
    let until = session.until;
    drop(sessions);
    let mut answer = Answer::decision(rid, Decision::Approved);
    crate::phone::approve(fake, &mut answer, request);
    answer.lease = Some(Lease {
        kind: LeaseKind::Session,
        until: Some(until),
    });
    Some(answer)
}

/// After the phone answered as usual: starts the session an approved bundle asked for, marks a
/// request whose session is unknown or over, and sets the code clock.
pub fn after(fake: &Fake, agent_id: &str, request: &Request, answer: &mut Answer) {
    let mut sessions = fake.sessions.lock().unwrap();
    let seconds_left = sessions.seconds_left;
    if let Some(id) = &request.session_id {
        let t = now();
        let live = sessions
            .list
            .iter()
            .any(|s| &s.id == id && s.agent_id == agent_id && s.until > t);
        if !live {
            answer.session_ended = Some(true);
        }
    }
    let length = request.bundle.as_ref().and_then(|b| b.session);
    if let (Some(length), Some(items), Decision::Approved) =
        (length, answer.items.as_mut(), answer.decision)
    {
        let until = now() + u64::from(length);
        let mut approved = Vec::new();
        for (asked, item) in request.bundle.iter().flat_map(|b| &b.items).zip(items) {
            if item.decision != Decision::Approved {
                continue;
            }
            if asked.kind == Kind::Secret {
                // A key in a plan: no value and no lease; later key requests go through.
                let project = request.project.as_deref();
                approved.push((asked.kind, crate::secrets::cover(&asked.target, project)));
                item.lease = None;
                if let Some(key) = item.secret.as_mut() {
                    key.value = None;
                }
                continue;
            }
            approved.push((asked.kind, site(&asked.target)));
            if asked.kind == Kind::Passkey {
                // A passkey item only allows later sign-ins: no secret, no lease.
                item.lease = None;
                item.username = None;
                item.password = None;
                item.code = None;
                item.seconds_left = None;
            } else {
                item.lease = Some(Lease {
                    kind: LeaseKind::Session,
                    until: Some(until),
                });
            }
        }
        let info = SessionInfo {
            id: nodkey_proto::random_id(),
            until,
        };
        sessions.list.push(FakeSession {
            id: info.id.clone(),
            agent_id: agent_id.to_owned(),
            until,
            items: approved,
            used: 0,
        });
        answer.session = Some(info);
    }
    set_clock(answer, seconds_left);
}

/// Gives every code in the answer `seconds_left`, and the next code when that is below the
/// threshold.
fn set_clock(answer: &mut Answer, seconds_left: u32) {
    let next = seconds_left < NEXT_CODE_BELOW;
    if answer.code.is_some() {
        answer.seconds_left = Some(seconds_left);
        if next {
            answer.next_code = Some(Secret::new(NEXT_CODE));
            answer.next_seconds_left = Some(seconds_left + 30);
        }
    }
    for item in answer.items.iter_mut().flatten() {
        set_item_clock(item, seconds_left, next);
    }
}

fn set_item_clock(item: &mut BundleItemAnswer, seconds_left: u32, next: bool) {
    if item.code.is_some() {
        item.seconds_left = Some(seconds_left);
        if next {
            item.next_code = Some(Secret::new(NEXT_CODE));
            item.next_seconds_left = Some(seconds_left + 30);
        }
    }
}

#[cfg(test)]
mod tests {
    use nodkey_proto::{PasskeyGet, PrfInput, PrfValues, Requirement};

    use super::*;

    #[test]
    fn a_session_never_covers_prf() {
        let mut get = PasskeyGet {
            rp_id: "webauthn.io".into(),
            client_data_json: String::new(),
            allow_credentials: vec![],
            user_verification: Requirement::Preferred,
            prf: None,
        };
        let request = |g: &PasskeyGet| {
            let mut r: Request = serde_json::from_value(serde_json::json!({
                "v": 1, "request_id": "r", "kind": "passkey", "target": "webauthn.io",
                "reason": "x", "agent": "a", "ts": 1
            }))
            .unwrap();
            r.passkey = Some(PasskeyRequest::Get(g.clone()));
            r
        };
        let item = (Kind::Passkey, "webauthn.io".to_owned());
        assert!(covers(&item, &request(&get)));
        get.prf = Some(PrfInput {
            eval: Some(PrfValues {
                first: "AQ".into(),
                second: None,
            }),
            ..Default::default()
        });
        assert!(!covers(&item, &request(&get)));
    }
}
