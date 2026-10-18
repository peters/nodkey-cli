//! Payments: the `request_payment` tool and `nodkey pay` ask the phone for the full card for one
//! purchase (`kind: card`, `mode: reveal`). The user sees the shop and the amount and approves
//! with Face ID every time; the phone refuses at once above the user's limit or when full card
//! numbers are off for this agent. A browser host fills a card without the model seeing it with
//! `nodkey card-fill` instead (see `cardfill.rs`).

use nodkey_proto::{
    Answer, CardAnswer, CardMode, CardRequest, ClientInfo, Decision, Kind, Money, card::errors,
};
use serde::Serialize;
use serde_json::{Map, Value};

use crate::{
    agent::{Agent, Progress, Reported, Text, new_request, text},
    outcome::{OLD_PROTOCOL, Outcome, PAUSED},
};

/// The `merchant`, `amount` and `currency` of a `request_payment` call. `amount` may be a
/// string ("499.00") or a number.
pub fn from_args(args: &Map<String, Value>) -> Result<(String, Money), String> {
    let merchant = match args.get("merchant") {
        Some(Value::String(s)) if !s.trim().is_empty() => s.trim().to_owned(),
        _ => return Err("merchant is required: the shop's site, e.g. shop.example.com".into()),
    };
    let amount = match args.get("amount") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => return Err("amount is required: how much you will pay, e.g. \"499.00\"".into()),
    };
    let currency = match args.get("currency") {
        Some(Value::String(s)) => s.as_str(),
        _ => return Err("currency is required: a three-letter code like NOK, EUR or USD".into()),
    };
    Ok((merchant, Money::parse(&amount, currency)?))
}

/// The merchant and amount of `nodkey pay`, checked before anything is sent.
pub(crate) fn payment(a: &crate::cli::Args) -> Result<(String, nodkey_proto::Money), String> {
    let [merchant, amount, currency] = a.positional.as_slice() else {
        return Err(if a.positional.len() < 3 {
            "amount_missing: give the shop, the amount and the currency, e.g. nodkey pay shop.example.com 499 NOK".into()
        } else {
            "nodkey pay takes MERCHANT AMOUNT CURRENCY".into()
        });
    };
    let money = nodkey_proto::Money::parse(amount, currency)?;
    if !a.flag("reveal") {
        return Err(
            "nodkey pay prints the full card number, so it needs --reveal. The phone answers only when the user \
             turned full card numbers on for this agent. To fill a checkout page without seeing the number, use a \
             browser host (Horizon, or the Nodkey browser extension)."
                .into(),
        );
    }
    a.value("reason")
        .ok_or("nodkey pay needs --reason: say what you are buying and why")?;
    Ok((merchant.trim().to_owned(), money))
}

impl Agent {
    /// Asks the phone for the full card to pay `amount` at `merchant`, and waits for the answer.
    #[allow(clippy::too_many_arguments)]
    pub async fn pay(
        &self,
        merchant: &str,
        amount: Money,
        reason: &str,
        image_path: Option<&str>,
        phone_selector: Option<&str>,
        reported: Reported<'_>,
        progress: Progress<'_>,
    ) -> Result<Text, String> {
        let client = ClientInfo {
            model: reported.model.map(str::to_owned),
            effort: reported.effort.map(str::to_owned),
            ..self.client.lock().expect("lock").clone()
        };
        let mut request = new_request(Kind::Card, merchant, reason, client);
        request.card = Some(CardRequest {
            mode: CardMode::Reveal,
            merchant: merchant.trim().to_owned(),
            amount: Some(amount.clone()),
            origin: None,
            page_total: None,
            total_source: None,
        });
        let ex = self
            .exchange(request, image_path, phone_selector, progress)
            .await?;
        let v = match &ex.answer {
            Some(a) => serde_json::to_value(outcome(a, merchant, &amount, &ex.phone)),
            None => serde_json::to_value(Outcome::expired(
                &ex.request_id,
                &ex.phone,
                self.timing.request,
                ex.attachment_warning.clone(),
            )),
        }
        .map_err(|e| e.to_string())?;
        Ok(text(&v))
    }
}

/// What `request_payment` returns.
#[derive(Serialize)]
pub struct PaymentOutcome<'a> {
    decision: Decision,
    request_id: &'a str,
    phone: &'a str,
    merchant: &'a str,
    amount: &'a Money,
    #[serde(skip_serializing_if = "Option::is_none")]
    card: Option<&'a CardAnswer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
    message: String,
}

/// The message for a refusal the phone gave without asking, by its error code.
pub fn refusal(error: &str) -> Option<&'static str> {
    Some(match error {
        errors::OVER_LIMIT => {
            "The amount is above the user's limit for this agent, so the phone refused without asking them. Do \
             not retry, and never split the purchase into smaller ones to get under the limit. Tell the user."
        }
        errors::REVEAL_OFF => {
            "Full card numbers are off for this agent, so the phone refused without asking. The user can turn \
             them on under Agents in Nodkey. A browser that fills cards for you (Horizon, or the Nodkey browser \
             extension) can pay without the number entering this conversation."
        }
        errors::CARDS_OFF => {
            "Cards are off for this agent in Nodkey, so the phone refused without asking. The user can turn \
             them on under Agents."
        }
        errors::NO_CARD => {
            "No card on the phone may be used by this agent. The user picks the cards an agent may use under \
             Agents in Nodkey."
        }
        errors::AMOUNT_MISSING => "The phone needs the amount and the currency of the purchase.",
        errors::TOTAL_MISMATCH => {
            "The total on the checkout page is higher than the amount the user approved, so nothing was filled \
             in. Check the order with the user."
        }
        errors::BAD_CARD_REQUEST => "The phone refused the card request as malformed.",
        _ => return None,
    })
}

/// The tool result for a card answer.
pub fn outcome<'a>(
    a: &'a Answer,
    merchant: &'a str,
    amount: &'a Money,
    phone: &'a str,
) -> PaymentOutcome<'a> {
    let error = a.error.as_deref();
    let message = match a.decision {
        Decision::Approved if a.card.is_some() => format!(
            "The user approved ONE purchase at {merchant} of at most {amount}. Use this card only for that \
             purchase, now. Never store, log or repeat the card details, never use them again and never pay \
             more than the approved amount; for any other purchase, ask again."
        ),
        Decision::Approved => "The phone approved but sent no card.".to_owned(),
        Decision::Denied => match error {
            Some("paused") => PAUSED.to_owned(),
            Some("unsupported_version" | "unsupported_kind") => OLD_PROTOCOL.to_owned(),
            Some(e) => refusal(e)
                .unwrap_or("The phone refused the request.")
                .to_owned(),
            None => "The user denied the payment. Do not ask again unless they say so.".to_owned(),
        },
        Decision::Expired => "The request expired on the phone without an answer.".to_owned(),
        Decision::Queued | Decision::Rejected => crate::outcome::MISFIT.to_owned(),
    };
    PaymentOutcome {
        decision: a.decision,
        request_id: &a.request_id,
        phone,
        merchant,
        amount,
        card: a.card.as_ref().filter(|_| a.decision == Decision::Approved),
        error,
        message,
    }
}

/// The exit code of `nodkey pay` and `nodkey card-fill` for a refusal without asking.
pub fn exit_for_error(error: Option<&str>) -> Option<u8> {
    Some(match error? {
        errors::OVER_LIMIT => 5,
        errors::REVEAL_OFF => 6,
        errors::CARDS_OFF | errors::NO_CARD => 7,
        errors::TOTAL_MISMATCH => 8,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nodkey_proto::Secret;
    use serde_json::json;

    fn nok(v: &str) -> Money {
        Money::parse(v, "NOK").unwrap()
    }

    #[test]
    fn tool_arguments() {
        let args = |v: Value| v.as_object().unwrap().clone();
        let (m, a) = from_args(&args(
            json!({"merchant": " shop.example.com ", "amount": 499, "currency": "nok"}),
        ))
        .unwrap();
        assert_eq!((m.as_str(), a), ("shop.example.com", nok("499")));
        let (_, a) = from_args(&args(
            json!({"merchant": "s.example", "amount": "12,50", "currency": "EUR"}),
        ))
        .unwrap();
        assert_eq!(a.value, "12.50");
        for (bad, want) in [
            (json!({"amount": "1", "currency": "NOK"}), "merchant"),
            (
                json!({"merchant": "s.example", "currency": "NOK"}),
                "amount",
            ),
            (json!({"merchant": "s.example", "amount": "1"}), "currency"),
            (
                json!({"merchant": "s.example", "amount": "0", "currency": "NOK"}),
                "more than 0",
            ),
            (
                json!({"merchant": "s.example", "amount": "1 000", "currency": "NOK"}),
                "not a number",
            ),
        ] {
            assert!(from_args(&args(bad)).unwrap_err().contains(want), "{want}");
        }
    }

    #[test]
    fn command_line() {
        let check = |list: &[&str]| {
            let args =
                crate::cli::Args::parse(&list.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                    .unwrap();
            payment(&args)
        };
        let (m, a) = check(&[
            "shop.example.com",
            "499",
            "NOK",
            "--reason",
            "x",
            "--reveal",
        ])
        .unwrap();
        assert_eq!((m.as_str(), a), ("shop.example.com", nok("499")));
        for (bad, want) in [
            (
                &["shop.example.com", "--reason", "x", "--reveal"][..],
                "amount_missing",
            ),
            (
                &["shop.example.com", "499", "NOK", "--reason", "x"][..],
                "--reveal",
            ),
            (
                &["shop.example.com", "0", "NOK", "--reason", "x", "--reveal"][..],
                "more than 0",
            ),
            (
                &["shop.example.com", "499", "NOK", "--reveal"][..],
                "--reason",
            ),
            (
                &["s", "1", "NOK", "x", "--reason", "x", "--reveal"][..],
                "takes MERCHANT",
            ),
        ] {
            assert!(check(bad).unwrap_err().contains(want), "{want}");
        }
    }

    #[test]
    fn outcomes() {
        let amount = nok("499.00");
        let mut a = Answer::decision("rid", Decision::Approved);
        a.card = Some(CardAnswer {
            title: "Test Visa".into(),
            brand: "visa".into(),
            last4: "4242".into(),
            holder: None,
            number: Secret::new("4242424242424242"),
            exp_month: 12,
            exp_year: 2030,
            cvc: Some(Secret::new("123")),
            approved_amount: amount.clone(),
        });
        let v: Value =
            serde_json::from_str(&text(&outcome(&a, "shop.example.com", &amount, "P"))).unwrap();
        assert_eq!(v["card"]["number"], "4242424242424242");
        assert_eq!(v["amount"], json!({"value": "499.00", "currency": "NOK"}));
        let m = v["message"].as_str().unwrap();
        assert!(m.contains("ONE purchase") && m.contains("499.00 NOK") && m.contains("ask again"));

        for (error, want, code) in [
            (errors::OVER_LIMIT, "split", Some(5)),
            (errors::REVEAL_OFF, "Full card numbers are off", Some(6)),
            (errors::CARDS_OFF, "Cards are off", Some(7)),
            (errors::NO_CARD, "No card", Some(7)),
            (errors::TOTAL_MISMATCH, "higher", Some(8)),
            ("paused", "paused", None),
        ] {
            let mut d = Answer::decision("rid", Decision::Denied);
            d.error = Some(error.into());
            d.card = a.card.clone();
            let v: Value = serde_json::from_str(&text(&outcome(&d, "s", &amount, "P"))).unwrap();
            assert!(v["message"].as_str().unwrap().contains(want), "{error}");
            assert!(v.get("card").is_none(), "a refusal never passes a card on");
            assert_eq!(exit_for_error(Some(error)), code);
        }
        let d = Answer::decision("rid", Decision::Denied);
        let v: Value = serde_json::from_str(&text(&outcome(&d, "s", &amount, "P"))).unwrap();
        assert!(
            v["message"]
                .as_str()
                .unwrap()
                .contains("denied the payment")
        );
    }
}
