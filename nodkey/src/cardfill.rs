//! `nodkey card-fill`: the command a browser host (Horizon) calls to fill a checkout form with a
//! card from the phone. It reads one JSON request on stdin and writes one JSON result on stdout,
//! also when it fails (waiting notes go to stderr). The card goes to the host, which fills the
//! form and gives the model only `summary`. It runs only under the host's own profile (`--agent
//! horizon`, see `cli::host_agent`), so the user turns card fill on for the host and not for the
//! model. That keeps the number from the model only when the model cannot run `nodkey` or read the
//! agent folder (no shell, or a sandbox). See docs/agent-protocol.md, "The card fill command".

use std::{io::Read, process::ExitCode};

use nodkey_proto::{CardMode, CardRequest, Decision, Kind, Money, Secret, TotalSource};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    agent::{Agent, Exchanged, Text, new_request, text},
    card::{exit_for_error, refusal},
    cli::{Args, DENIED, EXPIRED},
};

const BAD_INPUT: u8 = 64;
/// Largest request read from stdin.
const MAX_INPUT: u64 = 16 * 1024;

/// The JSON a host sends on stdin.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    version: u8,
    merchant: String,
    /// The checkout page's origin, as the host saw the frame (never from the page or the model).
    origin: String,
    /// What will be paid: from the agent, or the page total when the user fills by hand.
    amount: Option<Money>,
    page_total: Option<Money>,
    total_source: Option<TotalSource>,
    reason: Option<String>,
    requester: Option<Requester>,
}

/// Who asks, as the host says (self-reported; shown in the phone's history).
#[derive(Debug, Default, Deserialize)]
struct Requester {
    app: Option<String>,
    agent: Option<String>,
}

#[derive(Debug)]
struct Checked {
    card: CardRequest,
    reason: String,
    app: Option<String>,
}

/// Reads and checks the input. `Err` carries a refusal code when one applies.
fn parse(bytes: &[u8]) -> Result<Checked, (Option<&'static str>, String)> {
    let plain = |e: String| (None, e);
    let input: Input =
        serde_json::from_slice(bytes).map_err(|e| plain(format!("bad request: {e}")))?;
    if input.version != 1 {
        return Err(plain(format!("unsupported version {}", input.version)));
    }
    let merchant = input.merchant.trim().to_owned();
    let normalize = |m: Option<Money>| m.map(|m| Money::parse(&m.value, &m.currency)).transpose();
    let card = CardRequest {
        mode: CardMode::Fill,
        merchant: merchant.clone(),
        amount: normalize(input.amount)
            .map_err(|e| (Some(nodkey_proto::card::errors::AMOUNT_MISSING), e))?,
        origin: Some(input.origin.trim().to_owned()),
        page_total: normalize(input.page_total).map_err(|e| plain(format!("page_total: {e}")))?,
        total_source: input.total_source,
    };
    card.check(&merchant)?;
    let amount = card.amount.as_ref().expect("checked");
    let reason = match input.reason.as_deref().map(str::trim) {
        Some(r) if !r.is_empty() => r.to_owned(),
        _ => format!("Pay {amount} at {merchant}"),
    };
    let r = input.requester.unwrap_or_default();
    let app = match (r.app, r.agent) {
        (Some(app), Some(agent)) => Some(format!("{app} ({agent})")),
        (app, agent) => app.or(agent),
    };
    Ok(Checked { card, reason, app })
}

fn failure(status: &str, message: &str, error: Option<&str>) -> Text {
    let mut v = json!({"version": 1, "status": status, "message": message});
    if let Some(e) = error {
        v["error"] = json!(e);
    }
    text(&v)
}

/// An approved result; serialized straight into a wiped buffer.
#[derive(Serialize)]
struct Filled<'a> {
    version: u8,
    status: &'static str,
    card: FilledCard<'a>,
    approved_amount: &'a Money,
    summary: String,
}

#[derive(Serialize)]
struct FilledCard<'a> {
    number: &'a Secret,
    exp_month: u8,
    exp_year: u16,
    cvc: Option<&'a Secret>,
    holder: Option<&'a str>,
    brand: &'a str,
    last4: &'a str,
    title: &'a str,
}

/// The status a refusal code gets in the result.
fn status_for(error: &str) -> &'static str {
    match error {
        "over_limit" => "over_limit",
        "cards_off" | "no_card" => "cards_off",
        "total_mismatch" => "total_mismatch",
        "amount_missing" | "bad_card_request" => "error",
        _ => "denied",
    }
}

/// The result and exit code for what came back from the phone.
fn result(checked: &Checked, ex: &Exchanged) -> (Text, u8) {
    let Some(answer) = &ex.answer else {
        let msg = format!("No answer from {} in time.", ex.phone);
        return (failure("expired", &msg, None), EXPIRED);
    };
    let error = answer.error.as_deref();
    match (answer.decision, &answer.card) {
        (Decision::Approved, Some(card)) => {
            let amount = checked.card.amount.as_ref().expect("checked");
            if card.approved_amount.exceeds(amount) || amount.exceeds(&card.approved_amount) {
                let msg = "The phone approved a different amount than was asked; nothing to fill.";
                return (failure("error", msg, None), 1);
            }
            let brand = brand_name(&card.brand);
            let filled = Filled {
                version: 1,
                status: "ok",
                card: FilledCard {
                    number: &card.number,
                    exp_month: card.exp_month,
                    exp_year: card.exp_year,
                    cvc: card.cvc.as_ref(),
                    holder: card.holder.as_deref(),
                    brand: &card.brand,
                    last4: &card.last4,
                    title: &card.title,
                },
                approved_amount: &card.approved_amount,
                summary: format!(
                    "filled: {brand} \u{b7}\u{b7}\u{b7}\u{b7}{} on {}, at most {}. One purchase; ask again for the next one.",
                    card.last4, checked.card.merchant, card.approved_amount
                ),
            };
            (text(&filled), 0)
        }
        (Decision::Approved, None) => (
            failure("error", "The phone approved but sent no card.", None),
            1,
        ),
        (Decision::Queued | Decision::Rejected, _) => {
            (failure("error", crate::outcome::MISFIT, None), 1)
        }
        (Decision::Expired, _) => (
            failure("expired", "The request expired on the phone.", error),
            EXPIRED,
        ),
        (Decision::Denied, _) => match error {
            Some("unsupported_kind" | "unsupported_version") => (
                failure(
                    "error",
                    "Nodkey on the iPhone does not know card requests yet; update the app.",
                    error,
                ),
                1,
            ),
            Some("paused") => (
                failure(
                    "denied",
                    "This agent is paused in Nodkey (by the user or by its limit); the user can resume it under Agents.",
                    error,
                ),
                DENIED,
            ),
            Some(e) => (
                failure(
                    status_for(e),
                    refusal(e).unwrap_or("The phone refused the request."),
                    error,
                ),
                exit_for_error(error).unwrap_or(DENIED),
            ),
            None => (
                failure("denied", "The user denied the payment.", None),
                DENIED,
            ),
        },
    }
}

fn brand_name(brand: &str) -> String {
    match brand {
        "visa" => "Visa".into(),
        "mastercard" => "Mastercard".into(),
        "amex" => "American Express".into(),
        other => {
            let mut c = other.chars();
            c.next()
                .map(|f| f.to_uppercase().chain(c).collect())
                .unwrap_or_else(|| "Card".into())
        }
    }
}

async fn run(agent: &Agent, phone: Option<&str>, checked: Checked) -> (Text, u8) {
    let client = nodkey_proto::ClientInfo {
        app: checked.app.clone(),
        ..agent.client.lock().expect("lock").clone()
    };
    let mut request = new_request(Kind::Card, &checked.card.merchant, &checked.reason, client);
    request.card = Some(checked.card.clone());
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
        Ok(ex) => result(&checked, &ex),
        Err(e) => (failure("error", &e, None), 1),
    }
}

/// `nodkey card-fill [--agent PROFILE] [--phone PHONE]`.
pub fn main(args: &Args, agent: Result<Agent, String>) -> ExitCode {
    let (v, code) = match prepare(args, agent) {
        Err((Some(e), msg)) => (
            failure(status_for(e), &msg, Some(e)),
            exit_for_error(Some(e)).unwrap_or(BAD_INPUT),
        ),
        Err((None, msg)) => (failure("error", &msg, None), BAD_INPUT),
        Ok((agent, checked)) => match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt.block_on(run(&agent, args.value("phone"), checked)),
            Err(e) => (failure("error", &e.to_string(), None), 1),
        },
    };
    println!("{}", v.as_str());
    ExitCode::from(code)
}

/// Bad arguments: the JSON result and exit code 64.
pub fn bad_input(message: &str) -> ExitCode {
    println!("{}", failure("error", message, None).as_str());
    ExitCode::from(BAD_INPUT)
}

fn prepare(
    args: &Args,
    agent: Result<Agent, String>,
) -> Result<(Agent, Checked), (Option<&'static str>, String)> {
    let plain = |e: String| (None, e);
    if !args.positional.is_empty() {
        return Err(plain(
            "nodkey card-fill takes no arguments; it reads the request on stdin".into(),
        ));
    }
    args.only("card-fill", &["phone"]).map_err(plain)?;
    let agent = agent.map_err(plain)?;
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(MAX_INPUT + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| plain(format!("cannot read stdin: {e}")))?;
    if bytes.len() as u64 > MAX_INPUT {
        return Err(plain("the request is larger than 16 KiB".into()));
    }
    Ok((agent, parse(&bytes)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(extra: &str) -> Vec<u8> {
        format!(
            r#"{{"version":1,"merchant":"shop.example.com","origin":"https://www.shop.example.com",
                "amount":{{"value":"499","currency":"nok"}}{extra}}}"#
        )
        .into_bytes()
    }

    #[test]
    fn parsing() {
        let c = parse(&input("")).unwrap();
        assert_eq!(c.card.mode, CardMode::Fill);
        assert_eq!(c.card.amount.as_ref().unwrap().currency, "NOK");
        assert_eq!(c.reason, "Pay 499 NOK at shop.example.com");
        let c = parse(&input(
            r#","page_total":{"value":"499,00","currency":"NOK"},"total_source":"page","reason":"Buy the cable",
               "requester":{"app":"Horizon","agent":"Claude Code"}"#,
        ))
        .unwrap();
        assert_eq!(c.card.page_total.as_ref().unwrap().value, "499.00");
        assert_eq!(c.app.as_deref(), Some("Horizon (Claude Code)"));
        let err = |extra: &str| parse(&input(extra)).unwrap_err();
        assert_eq!(
            err(r#","page_total":{"value":"4999","currency":"NOK"},"total_source":"page""#).0,
            Some("total_mismatch")
        );
        assert!(
            err(r#","page_total":{"value":"499","currency":"NOK"}"#)
                .1
                .contains("go together")
        );
        assert!(err(r#","number":"4242""#).1.contains("unknown field"));
        let no_amount =
            br#"{"version":1,"merchant":"shop.example.com","origin":"https://shop.example.com"}"#;
        assert_eq!(parse(no_amount).unwrap_err().0, Some("amount_missing"));
        let evil = br#"{"version":1,"merchant":"shop.example.com","origin":"https://shop.example.com.evil.io",
                        "amount":{"value":"1","currency":"NOK"}}"#;
        assert!(parse(evil).unwrap_err().1.contains("not on the merchant"));
        assert!(parse(b"{}").is_err());
    }

    #[test]
    fn brand_names() {
        assert_eq!(brand_name("visa"), "Visa");
        assert_eq!(brand_name("jcb"), "Jcb");
        assert_eq!(brand_name(""), "Card");
    }
}
