//! `nodkey card-fill`: the command a browser host (Horizon) calls to fill a checkout form with a
//! card from the phone. It reads one JSON request on stdin and writes one JSON result on stdout,
//! also when it fails (waiting notes go to stderr). The card goes to the host, which fills the
//! form and gives the model only `summary`. It runs only under the host's own profile (`--agent
//! horizon`, see `cli::host_agent`), so the user turns card fill on for the host and not for the
//! model. That keeps the number from the model only when the model cannot run `nodkey` or read the
//! agent folder (no shell, or a sandbox). With `purpose: setup` the host adds the card to a site
//! for later payments (no amount). See docs/agent-protocol.md, "The card fill command".

use std::{io::Read, process::ExitCode};

use nodkey_proto::{
    CardMode, CardPurpose, CardRequest, Decision, Kind, Money, Secret, TotalSource,
    card::errors::AMOUNT_MISSING,
};
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
    /// `pay` (when left out) or `setup`: add the card for later payments, with no amount.
    #[serde(default)]
    purpose: CardPurpose,
    /// The top-level page's site, never the payment frame's host.
    merchant: String,
    /// The payment frame's host, when the card form is in a frame from another site.
    via: Option<String>,
    /// The origin of the card form's frame, as the host saw it (never from the page or the model).
    origin: String,
    /// What will be paid: from the agent, or the page total when the user fills by hand. None for
    /// `setup`.
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
        purpose: input.purpose,
        merchant: merchant.clone(),
        via: input
            .via
            .map(|v| v.trim().to_ascii_lowercase())
            .filter(|v| !v.is_empty()),
        amount: normalize(input.amount).map_err(|e| (Some(AMOUNT_MISSING), e))?,
        origin: Some(input.origin.trim().to_owned()),
        page_total: normalize(input.page_total).map_err(|e| plain(format!("page_total: {e}")))?,
        total_source: input.total_source,
    };
    card.check(&merchant)?;
    let reason = match (input.reason.as_deref().map(str::trim), &card.amount) {
        (Some(r), _) if !r.is_empty() => r.to_owned(),
        (_, Some(amount)) => format!("Pay {amount} at {merchant}"),
        (_, None) => format!("Add your card at {merchant} for later payments"),
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
    /// Absent for `setup`.
    #[serde(skip_serializing_if = "Option::is_none")]
    approved_amount: Option<&'a Money>,
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
        "setup_off" => "setup_off",
        "no_passcode" => "no_passcode",
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
            let same = match (&checked.card.amount, &card.approved_amount) {
                (Some(asked), Some(approved)) => {
                    !asked.exceeds(approved) && !approved.exceeds(asked)
                }
                (asked, approved) => asked.is_none() && approved.is_none(),
            };
            if !same {
                let msg = "The phone approved a different amount than was asked; nothing to fill.";
                return (failure("error", msg, None), 1);
            }
            let brand = brand_name(&card.brand);
            let site = match &checked.card.via {
                Some(via) => format!("{} via {via}", checked.card.merchant),
                None => checked.card.merchant.clone(),
            };
            let summary = match &card.approved_amount {
                Some(amount) => format!(
                    "filled: {brand} \u{b7}\u{b7}\u{b7}\u{b7}{} on {site}, at most {amount}. One purchase; ask again for the next one.",
                    card.last4
                ),
                None => format!(
                    "filled: {brand} \u{b7}\u{b7}\u{b7}\u{b7}{} on {site}, to add the card for later payments. No purchase was approved; ask again for the next card.",
                    card.last4
                ),
            };
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
                approved_amount: card.approved_amount.as_ref(),
                summary,
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
            // An app that does not know `setup` reads a request without an amount.
            Some(AMOUNT_MISSING) if checked.card.purpose == CardPurpose::Setup => (
                failure(
                    "error",
                    "Nodkey on the iPhone does not know cards for later payments yet; update the app.",
                    error,
                ),
                1,
            ),
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
            None => {
                let msg = match checked.card.purpose {
                    CardPurpose::Pay => "The user denied the payment.",
                    CardPurpose::Setup => "The user did not add the card.",
                };
                (failure("denied", msg, None), DENIED)
            }
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
    // Read the request before the profile check, so a host that is refused can always write it.
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(MAX_INPUT + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| plain(format!("cannot read stdin: {e}")))?;
    let agent = agent.map_err(plain)?;
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
    fn setup_and_payment_frames() {
        let setup = br#"{"version":1,"purpose":"setup","merchant":"shop.example.com","via":" JS.Pay.Example ",
                         "origin":"https://js.pay.example"}"#;
        let c = parse(setup).unwrap();
        assert_eq!(c.card.purpose, CardPurpose::Setup);
        assert_eq!(c.card.via.as_deref(), Some("js.pay.example"));
        assert!(c.card.amount.is_none());
        assert_eq!(
            c.reason,
            "Add your card at shop.example.com for later payments"
        );
        // A setup request never carries an amount; a pay request always does.
        let with_amount = br#"{"version":1,"purpose":"setup","merchant":"shop.example.com",
                               "origin":"https://shop.example.com","amount":{"value":"1","currency":"NOK"}}"#;
        assert!(parse(with_amount).unwrap_err().1.contains("no amount"));
        let pay_via = br#"{"version":1,"purpose":"pay","merchant":"shop.example.com","via":"js.pay.example",
                           "origin":"https://js.pay.example","amount":{"value":"1","currency":"NOK"}}"#;
        assert_eq!(parse(pay_via).unwrap().card.purpose, CardPurpose::Pay);
        // The card goes only into the frame named in via.
        let other = br#"{"version":1,"purpose":"setup","merchant":"shop.example.com","via":"js.pay.example",
                         "origin":"https://evil.example"}"#;
        assert!(
            parse(other)
                .unwrap_err()
                .1
                .contains("not the payment frame")
        );
        let bad = br#"{"version":1,"purpose":"later","merchant":"shop.example.com","origin":"https://shop.example.com"}"#;
        assert!(parse(bad).is_err());
    }

    #[test]
    fn answers_to_a_setup_request() {
        let checked = parse(
            br#"{"version":1,"purpose":"setup","merchant":"shop.example.com","origin":"https://shop.example.com"}"#,
        )
        .unwrap();
        let answer = |a: nodkey_proto::Answer| Exchanged {
            answer: Some(a),
            request_id: "rid".into(),
            phone: "Test iPhone".into(),
            attachment_warning: None,
        };
        let denied = |error: Option<&str>| {
            let mut a = nodkey_proto::Answer::decision("rid", Decision::Denied);
            a.error = error.map(str::to_owned);
            let (v, code) = result(&checked, &answer(a));
            (serde_json::from_str::<serde_json::Value>(&v).unwrap(), code)
        };
        // An app that does not know setup refuses it as a request without an amount.
        let (v, code) = denied(Some("amount_missing"));
        assert_eq!(code, 1);
        assert!(v["message"].as_str().unwrap().contains("update the app"));
        let (v, code) = denied(Some("setup_off"));
        assert_eq!((code, v["status"].as_str()), (9, Some("setup_off")));
        let (v, code) = denied(Some("no_passcode"));
        assert_eq!((code, v["status"].as_str()), (10, Some("no_passcode")));
        assert!(v["message"].as_str().unwrap().contains("no passcode"));
        let (v, _) = denied(None);
        assert!(
            v["message"]
                .as_str()
                .unwrap()
                .contains("did not add the card")
        );
        // An approved setup answer with an amount does not match the request.
        let mut a = nodkey_proto::Answer::decision("rid", Decision::Approved);
        a.card = Some(nodkey_proto::CardAnswer {
            title: "Test Visa".into(),
            brand: "visa".into(),
            last4: "4242".into(),
            holder: None,
            number: Secret::new("4242424242424242"),
            exp_month: 12,
            exp_year: 2030,
            cvc: None,
            approved_amount: Some(Money::parse("1", "NOK").unwrap()),
        });
        assert_eq!(result(&checked, &answer(a.clone())).1, 1);
        a.card.as_mut().unwrap().approved_amount = None;
        let (v, code) = result(&checked, &answer(a));
        assert_eq!(code, 0);
        assert!(!v.contains("approved_amount"));
    }

    #[test]
    fn brand_names() {
        assert_eq!(brand_name("visa"), "Visa");
        assert_eq!(brand_name("jcb"), "Jcb");
        assert_eq!(brand_name(""), "Card");
    }
}
