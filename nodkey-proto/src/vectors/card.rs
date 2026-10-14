//! Card vectors: fill and reveal requests, the approved answer, the refusals the phone gives
//! without asking, a card save (number and CVC sealed on their own), a list with cards, and a
//! `cards` section of checks every side runs the same way (amounts, request rules, Luhn, brand).
//! Test card numbers only.

use serde_json::{Value, json};

use super::{Ctx, Side, label_id, request, to_json};
use crate::{
    Answer, CardAnswer, CardEntry, CardMode, CardRequest, Decision, Kind, Money, Purpose, SaveCard,
    Secret, TotalSource, card,
};

/// The test card the vectors use.
pub const NUMBER: &str = "4242424242424242";
pub const CVC: &str = "123";
pub const MERCHANT: &str = "shop.example.com";

fn money(value: &str, currency: &str) -> Money {
    Money {
        value: value.into(),
        currency: currency.into(),
    }
}

fn fill() -> CardRequest {
    CardRequest {
        mode: CardMode::Fill,
        merchant: MERCHANT.into(),
        amount: Some(money("499.00", "NOK")),
        origin: Some("https://www.shop.example.com".into()),
        page_total: Some(money("499.00", "NOK")),
        total_source: Some(TotalSource::Page),
    }
}

fn reveal() -> CardRequest {
    CardRequest {
        mode: CardMode::Reveal,
        merchant: MERCHANT.into(),
        amount: Some(money("899.00", "NOK")),
        origin: None,
        page_total: None,
        total_source: None,
    }
}

pub(super) fn add(ctx: &mut Ctx, agent: &Side, phone: &Side) -> Value {
    let send = |ctx: &mut Ctx, name: &str, purpose: Purpose, rid: &str, json: Vec<u8>| {
        let (sender, recipient, second) = match purpose {
            Purpose::Answer => ("phone", agent, &phone.id),
            _ => ("agent", phone, &agent.id),
        };
        ctx.seal(
            name,
            purpose,
            sender,
            recipient,
            format!("{rid}{second}"),
            &json,
            true,
        );
    };

    let rid_fill = label_id("nodkey/v1/vectors/request/card_fill");
    let mut r = request(
        &rid_fill,
        Kind::Card,
        MERCHANT,
        "Buy the 2 m USB-C cable you asked for",
        None,
    );
    r.card = Some(fill());
    send(
        ctx,
        "request_card_fill",
        Purpose::Request,
        &rid_fill,
        to_json(&r),
    );

    let rid_reveal = label_id("nodkey/v1/vectors/request/card_reveal");
    let mut r = request(
        &rid_reveal,
        Kind::Card,
        MERCHANT,
        "Buy the game on your wish list",
        None,
    );
    r.card = Some(reveal());
    send(
        ctx,
        "request_card_reveal",
        Purpose::Request,
        &rid_reveal,
        to_json(&r),
    );

    let rid_missing = label_id("nodkey/v1/vectors/request/card_missing_amount");
    let mut r = request(&rid_missing, Kind::Card, MERCHANT, "Buy a cable", None);
    r.card = Some(CardRequest {
        amount: None,
        ..reveal()
    });
    send(
        ctx,
        "request_card_missing_amount",
        Purpose::Request,
        &rid_missing,
        to_json(&r),
    );

    let mut a = Answer::decision(&rid_fill, Decision::Approved);
    a.card = Some(CardAnswer {
        title: "Test Visa".into(),
        brand: "visa".into(),
        last4: "4242".into(),
        holder: Some("Alex Example".into()),
        number: Secret::new(NUMBER),
        exp_month: 12,
        exp_year: 2030,
        cvc: Some(Secret::new(CVC)),
        approved_amount: money("499.00", "NOK"),
    });
    send(ctx, "answer_card", Purpose::Answer, &rid_fill, to_json(&a));

    for (name, rid, error) in [
        (
            "answer_card_amount_missing",
            &rid_missing,
            card::errors::AMOUNT_MISSING,
        ),
        (
            "answer_card_over_limit",
            &rid_reveal,
            card::errors::OVER_LIMIT,
        ),
        (
            "answer_card_reveal_off",
            &rid_reveal,
            card::errors::REVEAL_OFF,
        ),
        ("answer_cards_off", &rid_fill, card::errors::CARDS_OFF),
        (
            "answer_card_total_mismatch",
            &rid_fill,
            card::errors::TOTAL_MISMATCH,
        ),
        ("answer_card_no_card", &rid_fill, card::errors::NO_CARD),
    ] {
        let mut a = Answer::decision(rid, Decision::Denied);
        a.error = Some(error.into());
        send(ctx, name, Purpose::Answer, rid, to_json(&a));
    }

    // Save: the browser seals the number and the CVC on their own, then the request.
    let rid_save = label_id("nodkey/v1/vectors/request/save_card");
    let number = ctx.seal(
        "save_card_number",
        Purpose::Card,
        "agent",
        phone,
        agent.id.clone(),
        NUMBER.as_bytes(),
        false,
    );
    let cvc = ctx.seal(
        "save_card_cvc",
        Purpose::Card,
        "agent",
        phone,
        agent.id.clone(),
        CVC.as_bytes(),
        false,
    );
    let mut r = request(
        &rid_save,
        Kind::Save,
        MERCHANT,
        "Save the card you just used on shop.example.com",
        None,
    );
    r.save_card = Some(SaveCard {
        number,
        cvc: Some(cvc),
        exp_month: 12,
        exp_year: 2030,
        holder: Some("Alex Example".into()),
        url: Some("https://www.shop.example.com/checkout".into()),
        last4: "4242".into(),
    });
    send(
        ctx,
        "request_save_card",
        Purpose::Request,
        &rid_save,
        to_json(&r),
    );
    let mut a = Answer::decision(&rid_save, Decision::Approved);
    a.saved = Some(crate::Saved::Added);
    send(
        ctx,
        "answer_save_card",
        Purpose::Answer,
        &rid_save,
        to_json(&a),
    );

    let rid_list = label_id("nodkey/v1/vectors/request/list_with_cards");
    let mut a = Answer::decision(&rid_list, Decision::Approved);
    a.accounts = Some(vec![]);
    a.cards = Some(vec![CardEntry {
        title: "Test Visa".into(),
        brand: "visa".into(),
        last4: "4242".into(),
    }]);
    send(
        ctx,
        "answer_list_with_cards",
        Purpose::Answer,
        &rid_list,
        to_json(&a),
    );

    checks()
}

/// The `cards` section: inputs and what every side must decide for them.
fn checks() -> Value {
    let amounts: Vec<Value> = [
        ("499.00", "NOK"),
        ("499,5", "nok"),
        ("1500", "JPY"),
        ("12.345", "KWD"),
        ("0", "NOK"),
        ("1 000", "NOK"),
        ("1.000,00", "NOK"),
        ("12.3456", "NOK"),
        ("5", "NO"),
    ]
    .into_iter()
    .map(|(value, currency)| match Money::parse(value, currency) {
        Ok(m) => json!({"value": value, "currency": currency, "ok": true,
                        "normalized": m, "thousandths": m.thousandths().expect("checked")}),
        Err(_) => json!({"value": value, "currency": currency, "ok": false}),
    })
    .collect();
    let case = |name: &str, r: CardRequest| {
        let error = r.check(MERCHANT).err().map(|(code, _)| code);
        json!({"name": name, "card": r, "target": MERCHANT,
               "ok": error.is_none(), "error": error.flatten()})
    };
    let requests = vec![
        case("fill", fill()),
        case("reveal", reveal()),
        case(
            "missing_amount",
            CardRequest {
                amount: None,
                ..reveal()
            },
        ),
        case(
            "page_total_higher",
            CardRequest {
                page_total: Some(money("4999.00", "NOK")),
                ..fill()
            },
        ),
        case(
            "page_total_other_currency",
            CardRequest {
                page_total: Some(money("499.00", "EUR")),
                ..fill()
            },
        ),
        case(
            "origin_lookalike",
            CardRequest {
                origin: Some("https://shop.example.com.evil.io".into()),
                ..fill()
            },
        ),
        case(
            "fill_without_origin",
            CardRequest {
                origin: None,
                ..fill()
            },
        ),
        case(
            "reveal_with_page_total",
            CardRequest {
                page_total: Some(money("899.00", "NOK")),
                ..reveal()
            },
        ),
    ];
    let numbers: Vec<Value> = [
        "4242 4242 4242 4242",
        "4242424242424241",
        "5555555555554444",
        "2223003122003222",
        "378282246310005",
        "6011111111111117",
        "36227206271667",
        "3566002020360505",
        "6200000000000005",
        "6759649826438453",
        "4242",
    ]
    .into_iter()
    .map(|n| json!({"number": n, "luhn": card::luhn(n), "brand": card::brand(n), "last4": card::last4(n)}))
    .collect();
    json!({"amounts": amounts, "requests": requests, "numbers": numbers})
}
