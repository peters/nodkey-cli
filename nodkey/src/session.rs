//! The agent's side of task sessions (docs/agent-protocol.md, "Task sessions"). The running session
//! of a profile lives in `session.json` next to its identity, so the MCP server and the command line
//! share it: later `code`, `login` and passkey requests to the same phone carry its id, and the file
//! goes when the session ends.

use nodkey_proto::{Answer, ClientInfo, Decision, Kind, Request};
use serde::{Deserialize, Serialize};

use crate::{
    agent::{Agent, Progress, Reported, Text, new_request, text},
    store::Store,
};

const FILE: &str = "session.json";
/// A session this close to its end is not used any more (the phone would ask anyway).
const MARGIN: u64 = 5;

/// A running task session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Running {
    pub id: String,
    /// When it ends (Unix seconds).
    pub until: u64,
    pub phone_id: String,
    /// What the user approved: `login:site`, `code:site`, `passkey:site`.
    pub items: Vec<String>,
}

/// The running session of this profile, if there is one that has not ended.
pub fn running(store: &Store) -> Option<Running> {
    let bytes = store.read(FILE).ok()??;
    let s: Running = serde_json::from_slice(&bytes).ok()?;
    (s.until > nodkey_proto::unix_now() + MARGIN).then_some(s)
}

/// Forgets the running session.
pub fn clear(store: &Store) {
    let _ = std::fs::remove_file(store.dir().join(FILE));
}

/// Puts the running session's id on a `code`, `login` or `passkey` request to the same phone.
pub fn attach(store: &Store, phone_id: &str, request: &mut Request) {
    if request.session_id.is_some()
        || !matches!(request.kind, Kind::Code | Kind::Login | Kind::Passkey)
    {
        return;
    }
    if let Some(s) = running(store).filter(|s| s.phone_id == phone_id) {
        request.session_id = Some(s.id);
    }
}

/// Keeps the session an approved bundle started, and forgets it when the phone says it ended or
/// the agent ended it.
pub fn note(store: &Store, phone_id: &str, request: &Request, answer: &Answer) {
    if request.kind == Kind::SessionEnd || answer.session_ended == Some(true) {
        clear(store);
    }
    let (Some(info), Some(bundle)) = (&answer.session, &request.bundle) else {
        return;
    };
    let approved: Vec<String> = bundle
        .items
        .iter()
        .filter(|item| {
            answer
                .items
                .iter()
                .flatten()
                .any(|a| a.id == item.id && a.decision == Decision::Approved)
        })
        .map(|item| format!("{}:{}", kind_word(item.kind), item.target))
        .collect();
    let s = Running {
        id: info.id.clone(),
        until: info.until,
        phone_id: phone_id.to_owned(),
        items: approved,
    };
    if let Ok(json) = serde_json::to_vec(&s) {
        let _ = store.write(FILE, &json, false);
    }
}

/// When a code in the answer has fewer than [`nodkey_proto::session::NEXT_CODE_BELOW`] seconds
/// left and the phone sent the next one, waits until the next one is current (at most that many
/// seconds) and hands it on instead, so the agent never gets a code that runs out while it types.
pub async fn settle(answer: &mut Answer) {
    let mut wait = 0;
    if let (Some(left), Some(_)) = (answer.seconds_left, &answer.next_code) {
        wait = wait.max(left);
    }
    for item in answer.items.iter().flatten() {
        if let (Some(left), Some(_)) = (item.seconds_left, &item.next_code) {
            wait = wait.max(left);
        }
    }
    if let Some(via) = &answer.via
        && let (Some(left), Some(_)) = (via.seconds_left, &via.next_code)
    {
        wait = wait.max(left);
    }
    if wait == 0 && !has_next(answer) {
        return;
    }
    tokio::time::sleep(std::time::Duration::from_secs(u64::from(wait) + 1)).await;
    let passed = wait + 1;
    if let Some(next) = answer.next_code.take() {
        answer.code = Some(next);
        answer.seconds_left = answer
            .next_seconds_left
            .take()
            .map(|s| s.saturating_sub(passed));
    }
    if let Some(via) = answer.via.as_mut()
        && let Some(next) = via.next_code.take()
    {
        via.code = Some(next);
        via.seconds_left = via
            .next_seconds_left
            .take()
            .map(|s| s.saturating_sub(passed));
    }
    for item in answer.items.iter_mut().flatten() {
        if let Some(next) = item.next_code.take() {
            item.code = Some(next);
            item.seconds_left = item
                .next_seconds_left
                .take()
                .map(|s| s.saturating_sub(passed));
        }
    }
}

fn has_next(answer: &Answer) -> bool {
    answer.next_code.is_some()
        || answer.via.as_ref().is_some_and(|v| v.next_code.is_some())
        || answer.items.iter().flatten().any(|i| i.next_code.is_some())
}

impl Agent {
    /// Ends this agent's running task session on the phone (the `end_session` tool and
    /// `nodkey end-session`) and forgets it here, whatever the phone says.
    pub async fn end_session(
        &self,
        reason: Option<&str>,
        reported: Reported<'_>,
        progress: Progress<'_>,
    ) -> Result<Text, String> {
        let store = self.store()?;
        let Some(s) = running(&store) else {
            return Ok(text(&serde_json::json!({
                "ended": false,
                "message": "No task session is running for this agent; nothing to end."
            })));
        };
        let client = ClientInfo {
            model: reported.model.map(str::to_owned),
            effort: reported.effort.map(str::to_owned),
            ..self.client.lock().expect("lock").clone()
        };
        let reason = reason.map(str::trim).filter(|r| !r.is_empty());
        let mut request = new_request(
            Kind::SessionEnd,
            "",
            reason.unwrap_or("The task is done"),
            client,
        );
        request.session_id = Some(s.id.clone());
        let ex = self
            .exchange(request, None, Some(&s.phone_id), progress)
            .await;
        clear(&store);
        let confirmed = ex
            .ok()
            .and_then(|e| e.answer)
            .is_some_and(|a| a.decision == Decision::Approved);
        Ok(text(&serde_json::json!({
            "ended": true,
            "message": if confirmed {
                "The task session is over. Later requests ask the user again."
            } else {
                "This agent forgot the session; the phone did not confirm (its app may be older), \
                 and the session ends by itself at its time."
            }
        })))
    }
}

fn kind_word(kind: Kind) -> &'static str {
    match kind {
        Kind::Login => "login",
        Kind::Passkey => "passkey",
        _ => "code",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nodkey_proto::{BundleItem, BundleItemAnswer, BundleRequest, SessionInfo};

    fn store(name: &str) -> Store {
        Store::at(crate::test_dir(name).join("agent"))
    }

    fn request(kind: Kind) -> Request {
        let mut r =
            crate::agent::new_request(kind, "accounts.example.com", "r", Default::default());
        if kind == Kind::Bundle {
            r.target = String::new();
            r.bundle = Some(BundleRequest {
                items: vec![
                    BundleItem {
                        id: "1".into(),
                        kind: Kind::Login,
                        target: "accounts.example.com".into(),
                    },
                    BundleItem {
                        id: "2".into(),
                        kind: Kind::Code,
                        target: "github.com".into(),
                    },
                ],
                follow_up: None,
                session: Some(900),
            });
        }
        r
    }

    #[test]
    fn keeps_attaches_and_forgets() {
        let s = store("session-keeps");
        let plan = request(Kind::Bundle);
        let mut a = Answer::decision(&plan.request_id, Decision::Approved);
        a.items = Some(vec![
            BundleItemAnswer::decision("1", Decision::Approved),
            BundleItemAnswer::decision("2", Decision::Denied),
        ]);
        a.session = Some(SessionInfo {
            id: "Qm9vdHN0cmFwU2Vzc2lvbg".into(),
            until: nodkey_proto::unix_now() + 900,
        });
        note(&s, "phone-1", &plan, &a);
        let r = running(&s).unwrap();
        assert_eq!(r.items, vec!["login:accounts.example.com"]);

        let mut code = request(Kind::Code);
        attach(&s, "phone-2", &mut code);
        assert_eq!(code.session_id, None, "another phone");
        attach(&s, "phone-1", &mut code);
        assert_eq!(code.session_id.as_deref(), Some("Qm9vdHN0cmFwU2Vzc2lvbg"));
        let mut list = request(Kind::List);
        attach(&s, "phone-1", &mut list);
        assert_eq!(list.session_id, None, "a list is never in a session");

        let mut ended = Answer::decision(&code.request_id, Decision::Approved);
        ended.session_ended = Some(true);
        note(&s, "phone-1", &code, &ended);
        assert!(running(&s).is_none());
    }

    #[test]
    fn an_old_session_is_not_used() {
        let s = store("session-old");
        let gone = Running {
            id: "Qm9vdHN0cmFwU2Vzc2lvbg".into(),
            until: nodkey_proto::unix_now() + 2,
            phone_id: "p".into(),
            items: vec![],
        };
        s.write(FILE, &serde_json::to_vec(&gone).unwrap(), false)
            .unwrap();
        assert!(running(&s).is_none());
    }

    #[tokio::test]
    async fn settle_hands_on_the_next_code() {
        use nodkey_proto::Secret;
        let mut a = Answer::decision("rid", Decision::Approved);
        a.code = Some(Secret::new("944570"));
        a.seconds_left = Some(0);
        a.next_code = Some(Secret::new("582911"));
        a.next_seconds_left = Some(30);
        settle(&mut a).await;
        assert_eq!(a.code.as_ref().map(Secret::expose), Some("582911"));
        assert_eq!(a.seconds_left, Some(29));
        assert!(a.next_code.is_none() && a.next_seconds_left.is_none());

        let mut plain = Answer::decision("rid", Decision::Approved);
        plain.code = Some(Secret::new("190274"));
        plain.seconds_left = Some(17);
        settle(&mut plain).await;
        assert_eq!(plain.code.as_ref().map(Secret::expose), Some("190274"));
    }
}
