//! `nodkey webauthn`: the authenticator a browser host (Horizon) calls. It reads one JSON request
//! on stdin, asks the phone to sign in with a passkey or make one, and writes one JSON result on
//! stdout, also when it fails (docs/agent-protocol.md, "The authenticator command").

use std::{io::Read, process::ExitCode};

use std::collections::BTreeMap;

use nodkey_proto::{
    Decision, Kind, LeaseKind, PasskeyCreate, PasskeyGet, PasskeyOp, PasskeyRequest, PasskeyUser,
    PrfInput, PrfValues, Requirement, passkey::errors, webauthn::check_answer,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    agent::{Agent, Exchanged, new_request},
    cli::{Args, DENIED, EXPIRED},
};

const BAD_INPUT: u8 = 64;

/// `nodkey webauthn --help`: the exact request and result, the RP ID rule and PRF.
pub const HELP: &str = r#"nodkey webauthn: sign in with a passkey in Nodkey on your iPhone, or make a passkey there

Usage: nodkey webauthn [--agent PROFILE] [--phone PHONE] < request.json

The command reads one JSON request on stdin. It writes one JSON result on stdout, also when it
fails. Notes about the wait go to stderr. Binary values are base64url (b64u) without padding.

Sign in (get):
  {"version":1, "op":"get", "rp_id":"example.com", "origin":"https://example.com",
   "client_data_json":"<b64u>", "allow_credentials":["<b64u>"], "user_verification":"preferred",
   "reason":"Sign in to example.com", "requester":{"app":"Horizon", "agent":"Claude Code"}}

Make a passkey (create): use "op":"create" and add "rp_name":"Example",
  "user":{"id":"<b64u, 1 to 64 bytes>", "name":"alex@example.com", "display_name":"Alex"},
  "algorithms":[-7], "exclude_credentials":["<b64u>"] and "resident_key":"required".

client_data_json is the b64u of exactly these bytes (type "webauthn.create" for create):
  {"type":"webauthn.get","challenge":"<b64u>","origin":"https://example.com","crossOrigin":false}
"origin" must be the origin in client_data_json. "reason" and "requester" are optional.

RP ID rule:
  - rp_id is a domain name with a dot (not an IP address), or "localhost".
  - The host of the origin is rp_id, or it ends with "." + rp_id. Case does not matter.
  - The origin uses https. Only localhost can use http. A port is allowed; a path is not.
  - rp_id is not a public suffix: not an ending such as "co.uk" and not a shared hosting
    domain such as "github.io" ("alice.github.io" is fine).

PRF (the WebAuthn "prf" extension, CTAP2 hmac-secret): add "extensions":{"prf":{...}} in the
WebAuthn JSON form.
  create: "prf":{} makes the passkey with PRF support. "prf":{"eval":{"first":"<b64u>"}} also
          gives the output for this input at once.
  get:    "prf":{"eval":{"first":"<b64u>", "second":"<b64u>"}} ("second" is optional), and/or
          "prf":{"evalByCredential":{"<credential id b64u>":{"first":"<b64u>"}}}. Each key of
          evalByCredential must be in allow_credentials. Its entry wins over "eval".
  Each input is 0 to 256 bytes. Each output is 32 bytes:
    HMAC-SHA256(credRandom, SHA-256("WebAuthn PRF" || 0x00 || input))
  credRandom is 32 random bytes that the phone makes with each new passkey. The same passkey and
  the same input always give the same output. Another input gives another output.
  The phone always asks for Face ID for PRF. A lease or a task session never answers it.
  A passkey made before PRF support has no credRandom: the result is "prf_unsupported". Make a
  new passkey for PRF.

An iPhone without a passcode cannot verify the user. It refuses a get or create with
"user_verification":"required" and a get with PRF inputs ("status":"denied",
"error":"no_passcode"), and answers any other request without UV.

Results:
  {"version":1, "status":"ok", "credential_id":"<b64u>", "authenticator_data":"<b64u>",
   "signature":"<b64u DER>", "user_handle":"<b64u>",
   "clientExtensionResults":{"prf":{"results":{"first":"<b64u>", "second":"<b64u>"}}}}
  {"version":1, "status":"ok", "credential_id":"<b64u>", "attestation_object":"<b64u>",
   "authenticator_data":"<b64u>", "public_key":"<b64u SPKI DER>", "public_key_algorithm":-7,
   "transports":["internal","hybrid"],
   "clientExtensionResults":{"prf":{"enabled":true, "results":{"first":"<b64u>"}}}}
  {"version":1, "status":"denied|expired|not_found|excluded|prf_unsupported|error",
   "message":"...", "error":"<the phone's error code, if any>"}
  "clientExtensionResults" is in the result only when the request has "extensions.prf". On create,
  "enabled":false means that this version of Nodkey has no PRF. The PRF outputs are secret keys:
  do not log them or store them in clear.

Exit codes: 0 ok, 1 error, 2 denied, not_found, excluded or prf_unsupported, 3 expired,
64 the request is not valid.
"#;

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
    #[serde(default)]
    extensions: Extensions,
}

/// `extensions` as in WebAuthn's options JSON. Only `prf` is used; others are ignored.
#[derive(Debug, Default, Deserialize)]
struct Extensions {
    prf: Option<WebPrf>,
}

/// `extensions.prf` in WebAuthn's JSON form (`evalByCredential`), copied as is from the page.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct WebPrf {
    eval: Option<PrfValues>,
    #[serde(default, rename = "evalByCredential")]
    eval_by_credential: BTreeMap<String, PrfValues>,
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
    let prf = input.extensions.prf.map(|p| PrfInput {
        eval: p.eval,
        eval_by_credential: p.eval_by_credential,
    });
    let unlock = prf.as_ref().is_some_and(PrfInput::has_inputs);
    let passkey = match input.op {
        PasskeyOp::Get => PasskeyRequest::Get(PasskeyGet {
            rp_id: rp_id.clone(),
            client_data_json: input.client_data_json,
            allow_credentials: input.allow_credentials,
            user_verification: input.user_verification,
            prf,
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
            prf,
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
        _ if input.op == PasskeyOp::Get && unlock => format!("Unlock a key for {rp_id}"),
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
            let leased = answer
                .lease
                .as_ref()
                .is_some_and(|l| l.kind != LeaseKind::Once);
            if passkey.needs_prf_output() && leased {
                let msg = "The phone answered a PRF request from a lease; PRF needs Face ID.";
                return (failure("error", msg, None), 1);
            }
            let prf = match prf_results(passkey, p) {
                Ok(prf) => prf,
                Err(msg) => {
                    let code = Some(errors::PRF_UNSUPPORTED);
                    return (failure("prf_unsupported", msg, code), DENIED);
                }
            };
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
            if let Some(prf) = prf {
                v["clientExtensionResults"] = json!({ "prf": prf });
            }
            (v, 0)
        }
        Decision::Expired => (
            failure("expired", "The request expired on the phone.", error),
            EXPIRED,
        ),
        Decision::Queued | Decision::Rejected | Decision::Staged => {
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
                Some(errors::NO_PASSCODE) => ("denied", crate::outcome::NO_PASSCODE, DENIED),
                Some(errors::PRF_UNSUPPORTED) => (
                    "prf_unsupported",
                    "The passkey for this site has no PRF support (it was made before Nodkey had PRF); make a new passkey with prf.",
                    DENIED,
                ),
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

/// `clientExtensionResults.prf` in WebAuthn's JSON form, or `None` when the request had no `prf`.
/// A create says `enabled` (false from an app without PRF); a get without results for inputs it
/// had fails: the passkey (or the app) has no PRF.
fn prf_results(
    request: &PasskeyRequest,
    answer: &nodkey_proto::PasskeyAnswer,
) -> Result<Option<Value>, &'static str> {
    let Some(input) = request.prf() else {
        return Ok(None);
    };
    let out = answer.prf.clone().unwrap_or_default();
    let mut v = json!({});
    if request.op() == PasskeyOp::Create {
        v["enabled"] = json!(out.enabled == Some(true));
    } else if input.values_for(&answer.credential_id).is_some() && out.results.is_none() {
        return Err(
            "The phone signed in but sent no PRF output: this passkey or this version of Nodkey has no PRF.",
        );
    }
    if let Some(results) = &out.results {
        v["results"] = json!(results);
    }
    Ok(Some(v))
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
    // Read the request before the profile check, so a refused host can always write it.
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(MAX_INPUT + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read stdin: {e}"))?;
    let agent = agent?;
    if bytes.len() as u64 > MAX_INPUT {
        return Err("the request is larger than 64 KiB".into());
    }
    Ok((agent, parse(&bytes)?))
}

#[cfg(test)]
mod tests;
