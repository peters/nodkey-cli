//! Sign-in methods on the fake phone (docs/agent-protocol.md, "Sign-in methods"): the methods it
//! knows for a few invented sites (with the Google login as `via` for "Sign in with Google"), the
//! second step order in every approved `login` and `code` answer, `suggest` requests (queued at
//! once, at most [`SUGGEST_PER_HOUR`] per agent per hour) and `sms_code` requests, which wait
//! until a test delivers a message with `PUT /_fake/sms`.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use nodkey_proto::{
    Account, Answer, Certainty, Decision, Kind, Provider, Request, SecondStepOrder, Secret,
    SignInKind, SignInMethod, Via,
    signin::{SUGGEST_PER_HOUR, errors},
};
use serde::{Deserialize, Serialize};

use crate::{CODE, Fake, Mode, PASSWORD};

/// The site the fake phone signs in to only with Google (no password of its own).
pub const GOOGLE_SITE: &str = "renderfarm.example";
/// The site that sends its codes by e-mail.
pub const EMAIL_SITE: &str = "mail.example.com";
/// The Google login the fake phone gives as `via`.
pub const GOOGLE_USER: &str = "alex.example@gmail.example";

/// A suggestion the fake phone queued.
#[derive(Debug, Clone, Serialize)]
pub struct Queued {
    pub agent_id: String,
    pub target: String,
    pub reason: String,
    pub suggest: nodkey_proto::Suggestion,
}

/// What a test delivers with `PUT /_fake/sms`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Sms {
    /// The text of the message, as the user's Shortcuts automation passes it.
    #[serde(default)]
    pub text: Option<String>,
    /// End the wait now: the phone answers `expired`.
    #[serde(default)]
    pub expire: bool,
}

/// The fake phone's sign-in state.
#[derive(Debug)]
pub struct FakeSignin {
    /// Site → its first method. A `federated` Google method comes with [`GOOGLE_USER`] as `via`.
    pub methods: HashMap<String, SignInMethod>,
    pub suggestions: Vec<Queued>,
    /// When each agent's suggestions arrived, for the limit.
    sent: HashMap<String, Vec<Instant>>,
    /// The message waiting for an `sms_code` request.
    pub sms: Option<Sms>,
}

impl Default for FakeSignin {
    fn default() -> Self {
        let confirmed = |m: SignInMethod| SignInMethod {
            certainty: Some(Certainty::Confirmed),
            ..m
        };
        let mut email = SignInMethod::new(SignInKind::EmailCode);
        email.mailbox = Some(crate::USERNAME.into());
        let methods = HashMap::from([
            (
                GOOGLE_SITE.to_owned(),
                confirmed(SignInMethod::federated(Provider::Google, None)),
            ),
            (EMAIL_SITE.to_owned(), confirmed(email)),
            (
                "vg.no".to_owned(),
                confirmed(SignInMethod::new(SignInKind::Password)),
            ),
        ]);
        FakeSignin {
            methods,
            suggestions: Vec::new(),
            sent: HashMap::new(),
            sms: None,
        }
    }
}

fn site(target: &str) -> String {
    target
        .split('/')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

/// The method, provider login and second step order the phone adds to an approved `login` or
/// `code` answer (or bundle item) for `target`.
pub fn extras(
    fake: &Fake,
    kind: Kind,
    target: &str,
) -> (Option<SignInMethod>, Option<Via>, Option<SecondStepOrder>) {
    if !matches!(kind, Kind::Login | Kind::Code) {
        return (None, None, None);
    }
    let order = Some(SecondStepOrder::default());
    if kind == Kind::Code {
        return (None, None, order);
    }
    let method = fake
        .signin
        .lock()
        .unwrap()
        .methods
        .get(&site(target))
        .cloned();
    let via = method
        .as_ref()
        .filter(|m| m.provider == Some(Provider::Google))
        .map(|_| Via {
            account: Account {
                issuer: "Google".into(),
                name: GOOGLE_USER.into(),
                site: Some("accounts.google.com".into()),
                sites: None,
            },
            username: Some(GOOGLE_USER.into()),
            password: Some(Secret::new(PASSWORD)),
            code: Some(Secret::new(CODE)),
            seconds_left: Some(17),
            next_code: None,
            next_seconds_left: None,
        });
    (method, via, order)
}

/// Fills an approved `login` or `code` answer: a site signed in to only with Google has no login
/// of its own, so the answer carries the method and `via` instead.
pub fn approve(fake: &Fake, answer: &mut Answer, request: &Request) {
    let (method, via, order) = extras(fake, request.kind, &request.target);
    if via.is_some() {
        answer.account = None;
        answer.username = None;
        answer.password = None;
        answer.match_kind = Some(nodkey_proto::MatchKind::Direct);
    }
    answer.method = method;
    answer.via = via;
    answer.second_step = order;
}

/// Answers `suggest` and `sms_code` requests: `None` for other kinds (and when the mode makes the
/// relay answer by itself), `Some(None)` while an `sms_code` waits (the relay returns 204).
pub async fn answer(
    fake: &Fake,
    agent_id: &str,
    rid: &str,
    request: &Request,
    mode: Mode,
    wait: Option<u64>,
) -> Option<Option<Answer>> {
    if matches!(mode, Mode::Silent | Mode::Gone) {
        return None;
    }
    match request.kind {
        Kind::Suggest => Some(Some(suggest(fake, agent_id, rid, request))),
        Kind::SmsCode if mode == Mode::Deny => Some(Some(Answer::decision(rid, Decision::Denied))),
        Kind::SmsCode => {
            let until = Instant::now() + Duration::from_secs(wait.unwrap_or(1).min(60));
            loop {
                if let Some(a) = sms(fake, rid) {
                    return Some(Some(a));
                }
                if Instant::now() >= until {
                    return Some(None);
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
        _ => None,
    }
}

fn suggest(fake: &Fake, agent_id: &str, rid: &str, request: &Request) -> Answer {
    let rejected = |error: &str| {
        let mut a = Answer::decision(rid, Decision::Rejected);
        a.error = Some(error.into());
        a
    };
    let Some(s) = request.suggest.as_ref().filter(|s| s.check().is_ok()) else {
        return rejected(errors::BAD_SUGGESTION);
    };
    let mut state = fake.signin.lock().unwrap();
    let sent = state.sent.entry(agent_id.to_owned()).or_default();
    sent.retain(|t| t.elapsed() < Duration::from_secs(3600));
    if sent.len() >= SUGGEST_PER_HOUR as usize {
        return rejected(errors::RATE_LIMITED);
    }
    sent.push(Instant::now());
    state.suggestions.push(Queued {
        agent_id: agent_id.to_owned(),
        target: request.target.clone(),
        reason: request.reason.clone(),
        suggest: s.clone(),
    });
    Answer::decision(rid, Decision::Queued)
}

/// The answer once a test delivered a message: the code in it (4 to 8 digits), or `expired`.
fn sms(fake: &Fake, rid: &str) -> Option<Answer> {
    let sms = fake.signin.lock().unwrap().sms.take()?;
    if sms.expire {
        return Some(Answer::decision(rid, Decision::Expired));
    }
    let code = code_in(sms.text.as_deref().unwrap_or_default())?;
    let mut a = Answer::decision(rid, Decision::Approved);
    a.code = Some(Secret::new(code));
    Some(a)
}

/// The first run of 4 to 8 digits in a message, as the app takes it.
pub fn code_in(text: &str) -> Option<String> {
    text.split(|c: char| !c.is_ascii_digit())
        .find(|run| (4..=8).contains(&run.len()))
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    #[test]
    fn codes_in_messages() {
        use super::code_in;
        assert_eq!(
            code_in("Your code is 482913. Do not share it.").as_deref(),
            Some("482913")
        );
        assert_eq!(code_in("G-1234 is your code").as_deref(), Some("1234"));
        assert_eq!(
            code_in("Call 123456789 or use 4821").as_deref(),
            Some("4821")
        );
        assert_eq!(code_in("No code here, 12"), None);
    }
}
