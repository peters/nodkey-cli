//! The fake phone's payment card and the rules it answers card requests by: cards on or off,
//! full card numbers on or off, cards for later payments on or off, and a limit per purchase.
//! Test card numbers only.

use nodkey_proto::{
    Answer, CardAnswer, CardMode, CardPurpose, Decision, Kind, Money, Purpose, Request, Secret,
    card::errors,
};
use serde::Deserialize;

use crate::Fake;

/// The fake phone's card: a test number.
pub const CARD_NUMBER: &str = "4242424242424242";
pub const CARD_CVC: &str = "123";

/// What the user allowed this phone's agents (one setting for all of them in the fake).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct FakeCards {
    /// "May use cards".
    pub enabled: bool,
    /// "Full card number": allowed.
    pub reveal: bool,
    /// "Add cards for later payments" (`purpose: setup`): allowed. On when left out.
    #[serde(default = "on")]
    pub setup: bool,
    /// Most per purchase; `None` means no limit.
    pub limit: Option<Money>,
}

fn on() -> bool {
    true
}

impl Default for FakeCards {
    fn default() -> Self {
        FakeCards {
            enabled: true,
            reveal: true,
            setup: true,
            limit: Some(Money {
                value: "1000.00".into(),
                currency: "NOK".into(),
            }),
        }
    }
}

fn denied(rid: &str, error: &str) -> Answer {
    let mut a = Answer::decision(rid, Decision::Denied);
    a.error = Some(error.into());
    a
}

/// A card request the phone refuses without asking the user, in the app's order.
pub(crate) fn refuse(fake: &Fake, rid: &str, request: &Request) -> Option<Answer> {
    if request.kind != Kind::Card {
        return None;
    }
    let settings = fake.cards.lock().unwrap().clone();
    if !settings.enabled {
        return Some(denied(rid, errors::CARDS_OFF));
    }
    if !*fake.passcode.lock().unwrap() {
        return Some(denied(rid, errors::NO_PASSCODE));
    }
    let Some(card) = &request.card else {
        return Some(denied(rid, errors::AMOUNT_MISSING));
    };
    if let Err((code, _)) = card.check(&request.target) {
        return Some(denied(rid, code.unwrap_or(errors::BAD_CARD_REQUEST)));
    }
    if card.mode == CardMode::Reveal && !settings.reveal {
        return Some(denied(rid, errors::REVEAL_OFF));
    }
    if card.purpose == CardPurpose::Setup && !settings.setup {
        return Some(denied(rid, errors::SETUP_OFF));
    }
    // A setup request has no amount, so no limit applies.
    let amount = card.amount.as_ref()?;
    if settings.limit.as_ref().is_some_and(|l| amount.exceeds(l)) {
        return Some(denied(rid, errors::OVER_LIMIT));
    }
    None
}

/// Fills in an approved card answer: the test card, for at most the amount asked (no amount for
/// `setup`).
pub(crate) fn approve(answer: &mut Answer, request: &Request) {
    let card = request.card.as_ref().expect("checked before asking");
    answer.lease = None;
    answer.card = Some(CardAnswer {
        title: "Test Visa".into(),
        brand: "visa".into(),
        last4: "4242".into(),
        holder: Some("Alex Example".into()),
        number: Secret::new(CARD_NUMBER),
        exp_month: 12,
        exp_year: 2030,
        cvc: Some(Secret::new(CARD_CVC)),
        approved_amount: card.amount.clone(),
    });
}

/// The number of a card `save`, opened as the phone would (test data only).
pub(crate) fn saved_number(fake: &Fake, request: &Request, agent_id: &str) -> Option<String> {
    let card = request.save_card.as_ref()?;
    let opened = Purpose::Card
        .open_box(fake.phone.kem_secret(), &card.number, agent_id.as_bytes())
        .expect("the card number opens with the phone key");
    Some(String::from_utf8(opened.to_vec()).expect("utf-8 number"))
}
