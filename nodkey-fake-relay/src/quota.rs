//! The agent limit on the fake phone (docs/agent-protocol.md, "Agent limit"). The fake phone does not
//! count; a test sets the state with `PUT /_fake/quota`:
//!
//! - `{"state": "warning", "new_today": 12, "limit": 10, "burst": false}`: the phone asks with the
//!   warning. Answers to `code`, `login` and `bundle` carry `quota_warning` and `quota`; task
//!   sessions end and a bundle starts none.
//! - `{"state": "paused", "new_today": 25, "limit": 10}`: the limit paused every agent; requests
//!   are refused at once with `paused` and `quota`.
//! - `{"state": "paused_by_user"}`: the user paused every agent; `paused` without `quota`.
//! - `{"state": "off"}`: as usual (the default).

use nodkey_proto::{Answer, Decision, Kind, Quota, Request, quota};
use serde::Deserialize;

use crate::Fake;

/// What the fake phone does about the agent limit.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaState {
    #[default]
    Off,
    Warning,
    Paused,
    PausedByUser,
}

/// The state a test set, with the count the answers carry.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct FakeQuota {
    #[serde(default)]
    pub state: QuotaState,
    #[serde(default)]
    pub new_today: u32,
    #[serde(default = "default_limit")]
    pub limit: u32,
    #[serde(default)]
    pub burst: bool,
}

fn default_limit() -> u32 {
    quota::DEFAULT_LIMIT
}

impl FakeQuota {
    fn quota(&self) -> Quota {
        Quota {
            new_today: self.new_today,
            limit: self.limit,
            burst: self.burst,
        }
    }
}

/// The kinds the limit counts and warns for.
fn counted(kind: Kind) -> bool {
    matches!(kind, Kind::Code | Kind::Login | Kind::Bundle)
}

/// The refusal of a paused agent: every kind but `session_end`.
pub fn refuse(fake: &Fake, rid: &str, request: &Request) -> Option<Answer> {
    let q = fake.quota.lock().unwrap().clone();
    if request.kind == Kind::SessionEnd
        || !matches!(q.state, QuotaState::Paused | QuotaState::PausedByUser)
    {
        return None;
    }
    let decision = if request.kind == Kind::Suggest {
        Decision::Rejected
    } else {
        Decision::Denied
    };
    let mut a = Answer::decision(rid, decision);
    a.error = Some(quota::errors::PAUSED.into());
    if q.state == QuotaState::Paused {
        a.quota = Some(q.quota());
    }
    Some(a)
}

/// Whether the warning applies to this request. If it does, the agent's task sessions end and the
/// request loses its session length, so that nothing answers by itself.
pub fn warn(fake: &Fake, agent_id: &str, request: &mut Request) -> bool {
    if fake.quota.lock().unwrap().state != QuotaState::Warning || !counted(request.kind) {
        return false;
    }
    fake.sessions
        .lock()
        .unwrap()
        .list
        .retain(|s| s.agent_id != agent_id);
    if let Some(b) = request.bundle.as_mut() {
        b.session = None;
    }
    true
}

/// Marks an answer the phone gave with the warning.
pub fn mark(fake: &Fake, answer: &mut Answer) {
    answer.error = Some(quota::errors::QUOTA_WARNING.into());
    answer.quota = Some(fake.quota.lock().unwrap().quota());
}
