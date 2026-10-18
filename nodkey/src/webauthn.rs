//! `nodkey webauthn`: the authenticator a browser host (Horizon) calls. It reads one JSON request
//! on stdin, asks the phone to sign in with a passkey or make one, and writes one JSON result on
//! stdout, also when it fails (docs/agent-protocol.md, "The authenticator command").

use std::{io::Read, process::ExitCode};

use nodkey_proto::{
    Decision, Kind, PasskeyCreate, PasskeyGet, PasskeyOp, PasskeyRequest, PasskeyUser, Requirement,
    passkey::errors, webauthn::check_answer,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    agent::{Agent, Exchanged, new_request},
    cli::{Args, DENIED, EXPIRED},
};

const BAD_INPUT: u8 = 64;

/// Largest request read from stdin.
const MAX_INPUT: u64 = 64 * 1024;

/// The JSON a host sends on stdin.
#[derive(Debug, Deserialize)]
struct Input {
    version: u8,
    op: PasskeyOp,
    rp_id: String,
    origin: String,
    client_data_json: String,
    #[serde(default)]
    allow_credentials: Vec<String>,
    #[serde(default)]
    user_verification: Requirement,
    rp_name: Option<String>,
    user: Option<PasskeyUser>,
    algorithms: Option<Vec<i64>>,
    #[serde(default)]
    exclude_credentials: Vec<String>,
    #[serde(default)]
    resident_key: Requirement,
    reason: Option<String>,
    requester: Option<Requester>,
}

/// Who asks, as the host says (self-reported; shown in the phone's history).
#[derive(Debug, Default, Deserialize)]
struct Requester {
    app: Option<String>,
    agent: Option<String>,
}

/// A checked input: the passkey request, the reason and the app for the phone's history.
#[derive(Debug)]
struct Checked {
    passkey: PasskeyRequest,
    reason: String,
    app: Option<String>,
}

fn parse(bytes: &[u8]) -> Result<Checked, String> {
    let input: Input = serde_json::from_slice(bytes).map_err(|e| format!("bad request: {e}"))?;
    if input.version != 1 {
        return Err(format!("unsupported version {}", input.version));
    }
    let rp_id = input.rp_id.trim().to_owned();
    let passkey = match input.op {
        PasskeyOp::Get => PasskeyRequest::Get(PasskeyGet {
            rp_id: rp_id.clone(),
            client_data_json: input.client_data_json,
            allow_credentials: input.allow_credentials,
            user_verification: input.user_verification,
        }),
        PasskeyOp::Create => PasskeyRequest::Create(PasskeyCreate {
            rp_id: rp_id.clone(),
            rp_name: input.rp_name.ok_or("create needs rp_name")?,
            client_data_json: input.client_data_json,
            user: input.user.ok_or("create needs user")?,
            algorithms: input.algorithms.ok_or("create needs algorithms")?,
            exclude_credentials: input.exclude_credentials,
            resident_key: input.resident_key,
            user_verification: input.user_verification,
        }),
    };
    let client_data = passkey.check(&rp_id)?;
    if client_data.origin != input.origin {
        return Err(format!(
            "origin {:?} is not the origin in client_data_json ({:?})",
            input.origin, client_data.origin
        ));
    }
    let reason = match input.reason.as_deref().map(str::trim) {
        Some(r) if !r.is_empty() => r.to_owned(),
        _ if input.op == PasskeyOp::Get => format!("Sign in to {rp_id} with a passkey"),
        _ => format!("Create a passkey for {rp_id}"),
    };
    let r = input.requester.unwrap_or_default();
    let app = match (r.app, r.agent) {
        (Some(app), Some(agent)) => Some(format!("{app} ({agent})")),
        (app, agent) => app.or(agent),
    };
    Ok(Checked {
        passkey,
        reason,
        app,
    })
}

fn failure(status: &str, message: &str, error: Option<&str>) -> Value {
    let mut v = json!({"version": 1, "status": status, "message": message});
    if let Some(e) = error {
        v["error"] = json!(e);
    }
    v
}

/// The result and exit code for what came back from the phone.
fn result(passkey: &PasskeyRequest, ex: &Exchanged) -> (Value, u8) {
    let Some(answer) = &ex.answer else {
        let msg = format!("No answer from {} in time.", ex.phone);
        return (failure("expired", &msg, None), EXPIRED);
    };
    let error = answer.error.as_deref();
    match answer.decision {
        Decision::Approved => {
            let Some(p) = &answer.passkey else {
                let msg = "The phone approved but sent no passkey.";
                return (failure("error", msg, None), 1);
            };
            if let Err(e) = check_answer(passkey, p) {
                return (failure("error", &e, None), 1);
            }
            let mut v = json!({
                "version": 1,
                "status": "ok",
                "credential_id": p.credential_id,
                "authenticator_data": p.authenticator_data,
            });
            let fields = [
                ("signature", &p.signature),
                ("user_handle", &p.user_handle),
                ("attestation_object", &p.attestation_object),
                ("public_key", &p.public_key),
            ];
            for (name, value) in fields {
                if let Some(value) = value {
                    v[name] = json!(value);
                }
            }
            if let Some(alg) = p.public_key_algorithm {
                v["public_key_algorithm"] = json!(alg);
                v["transports"] = json!(["internal", "hybrid"]);
            }
            (v, 0)
        }
        Decision::Expired => (
            failure("expired", "The request expired on the phone.", error),
            EXPIRED,
        ),
        Decision::Queued | Decision::Rejected => {
            (failure("error", crate::outcome::MISFIT, None), 1)
        }
        Decision::Denied => {
            let (status, msg, code) = match error {
                Some(errors::NO_PASSKEY) => (
                    "not_found",
                    "The phone has no passkey for this site.",
                    DENIED,
                ),
                Some(errors::EXCLUDED) => (
                    "excluded",
                    "The phone already holds a passkey for this account.",
                    DENIED,
                ),
                Some("unsupported_kind" | "unsupported_version") => (
                    "error",
                    "Nodkey on the iPhone does not know passkey requests yet; update the app.",
                    1,
                ),
                Some("paused") => (
                    "denied",
                    "This agent is paused in Nodkey (by the user or by its limit); the user can resume it under Agents.",
                    DENIED,
                ),
                Some(errors::BAD_CLIENT_DATA) => {
                    ("denied", "The phone refused the client data.", DENIED)
                }
                Some(errors::UNSUPPORTED_ALGORITHM) => (
                    "denied",
                    "The site accepts no algorithm the phone has (ES256).",
                    DENIED,
                ),
                _ => ("denied", "The user denied the request.", DENIED),
            };
            (failure(status, msg, error), code)
        }
    }
}

async fn run(agent: &Agent, phone: Option<&str>, checked: Checked) -> (Value, u8) {
    let client = nodkey_proto::ClientInfo {
        app: checked.app,
        ..agent.client.lock().expect("lock").clone()
    };
    let target = checked.passkey.rp_id().to_owned();
    let mut request = new_request(Kind::Passkey, &target, &checked.reason, client);
    request.passkey = Some(checked.passkey.clone());
    let shown = std::sync::atomic::AtomicBool::new(false);
    let note = format!(
        "Waiting for your answer in Nodkey on your iPhone (up to {} s) ...",
        agent.timing.request.as_secs()
    );
    let progress = move |_: u64, _: u64, _: &str| {
        if !shown.swap(true, std::sync::atomic::Ordering::Relaxed) {
            eprintln!("{note}");
        }
    };
    match agent.exchange(request, None, phone, &progress).await {
        Ok(ex) => result(&checked.passkey, &ex),
        Err(e) => (failure("error", &e, None), 1),
    }
}

/// `nodkey webauthn [--agent PROFILE] [--phone PHONE]`.
pub fn main(args: &Args, agent: Result<Agent, String>) -> ExitCode {
    let (v, code) = match prepare(args, agent) {
        Err(e) => (failure("error", &e, None), BAD_INPUT),
        Ok((agent, checked)) => match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt.block_on(run(&agent, args.value("phone"), checked)),
            Err(e) => (failure("error", &e.to_string(), None), 1),
        },
    };
    println!("{v}");
    ExitCode::from(code)
}

/// Bad arguments: the JSON result and exit code 64.
pub fn bad_input(message: &str) -> ExitCode {
    println!("{}", failure("error", message, None));
    ExitCode::from(BAD_INPUT)
}

fn prepare(args: &Args, agent: Result<Agent, String>) -> Result<(Agent, Checked), String> {
    if !args.positional.is_empty() {
        return Err("nodkey webauthn takes no arguments; it reads the request on stdin".into());
    }
    args.only("webauthn", &["phone"])?;
    let agent = agent?;
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(MAX_INPUT + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read stdin: {e}"))?;
    if bytes.len() as u64 > MAX_INPUT {
        return Err("the request is larger than 64 KiB".into());
    }
    Ok((agent, parse(&bytes)?))
}

#[cfg(test)]
mod tests;
