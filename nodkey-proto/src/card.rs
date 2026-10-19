//! Payment cards (`kind: card`): an agent or a browser asks the phone for a card to pay one
//! purchase. A card request always names the shop and the amount, so the user sees what money is
//! about to be spent. The phone answers with the card only after Face ID; it is never covered by a
//! lease, never part of a bundle, and the phone refuses at once when the amount is above the
//! user's limit for that agent.
//!
//! Two modes: `fill` (a browser host fills the checkout form; the model never sees the number) and
//! `reveal` (the agent gets the full card; off for every agent until the user turns it on).
//!
//! Two purposes: `pay` (one purchase of an amount, the default) and `setup` (a browser adds the
//! card to a site for later payments: no amount, `fill` only, off until the user turns it on for
//! that browser). `merchant` is always the top-level page's site; `via` names a payment frame from
//! another site.

use serde::{Deserialize, Serialize};

use crate::{SealedBox, Secret, client::MAX_TARGET};

/// Why the phone refused a card request without asking the user (`Answer.error`).
pub mod errors {
    /// The request did not say how much will be paid.
    pub const AMOUNT_MISSING: &str = "amount_missing";
    /// The amount is above the user's limit for this agent (per purchase or per 24 hours).
    pub const OVER_LIMIT: &str = "over_limit";
    /// `mode: reveal`, but full card numbers are off for this agent.
    pub const REVEAL_OFF: &str = "reveal_off";
    /// Cards are off for this agent.
    pub const CARDS_OFF: &str = "cards_off";
    /// The total on the checkout page is higher than the amount.
    pub const TOTAL_MISMATCH: &str = "total_mismatch";
    /// No card on the phone may be used by this agent.
    pub const NO_CARD: &str = "no_card";
    /// The card data breaks another rule of [`super::CardRequest::check`].
    pub const BAD_CARD_REQUEST: &str = "bad_card_request";
    /// `purpose: setup`, but adding cards for later payments is off for this agent.
    pub const SETUP_OFF: &str = "setup_off";
}

/// What the card is for.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CardPurpose {
    /// Pay one purchase of `amount`. The default: absent in the JSON.
    #[default]
    Pay,
    /// Add the card to a site for later payments (a billing page, a subscription): no amount.
    /// Only for a browser that fills the card (`mode: fill`), never for an agent's own profile.
    Setup,
}

impl CardPurpose {
    /// True for `pay`, which the JSON leaves out, so a pay request has the same bytes as before.
    pub fn is_pay(&self) -> bool {
        *self == CardPurpose::Pay
    }
}

/// How the card reaches the checkout page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CardMode {
    /// A browser host fills the form; the model only learns the brand and the last four digits.
    Fill,
    /// The agent gets the full card number, expiry and CVC.
    Reveal,
}

/// Where a `page_total` came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TotalSource {
    /// The host read it from the checkout page.
    Page,
    /// The host found no total and the user typed it.
    User,
}

/// Most digits before the decimal point.
const MAX_WHOLE_DIGITS: usize = 12;
/// Most digits after it (some currencies have three).
const MAX_DECIMALS: usize = 3;

/// An amount of money: a decimal string with a dot (`"499.00"`, `"1500"`, `"12.345"`) and an ISO
/// 4217 currency code (`"NOK"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Money {
    pub value: String,
    pub currency: String,
}

impl Money {
    /// Reads an amount as a person types it: a dot or a comma before the decimals, no thousands
    /// separators; the currency in any case.
    pub fn parse(value: &str, currency: &str) -> Result<Money, String> {
        let m = Money {
            value: value.trim().replace(',', "."),
            currency: currency.trim().to_ascii_uppercase(),
        };
        m.check()?;
        Ok(m)
    }

    /// The amount in thousandths of the currency unit, so amounts with different decimals compare.
    pub fn thousandths(&self) -> Result<u64, String> {
        let (whole, frac) = self.value.split_once('.').unwrap_or((&self.value, ""));
        let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
        if !digits(whole) || (self.value.contains('.') && !digits(frac)) {
            return Err(format!(
                "amount {:?} is not a number like 499.00 (no thousands separators)",
                self.value
            ));
        }
        if whole.len() > MAX_WHOLE_DIGITS || frac.len() > MAX_DECIMALS {
            return Err(format!("amount {:?} is too long", self.value));
        }
        let whole: u64 = whole
            .parse()
            .map_err(|_| "amount is too large".to_owned())?;
        let frac: u64 = format!("{frac:0<3}")
            .parse()
            .map_err(|_| "bad decimals".to_owned())?;
        Ok(whole * 1000 + frac)
    }

    /// A positive amount and a three-letter currency code.
    pub fn check(&self) -> Result<(), String> {
        if self.currency.len() != 3 || !self.currency.bytes().all(|b| b.is_ascii_uppercase()) {
            return Err(format!(
                "currency {:?} is not a three-letter code like NOK, EUR or USD",
                self.currency
            ));
        }
        if self.thousandths()? == 0 {
            return Err("the amount must be more than 0".into());
        }
        Ok(())
    }

    /// Whether `self` is more than `other` (same currency; a different currency counts as more,
    /// since the two cannot be compared).
    pub fn exceeds(&self, other: &Money) -> bool {
        self.currency != other.currency
            || match (self.thousandths(), other.thousandths()) {
                (Ok(a), Ok(b)) => a > b,
                _ => true,
            }
    }
}

impl std::fmt::Display for Money {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.value, self.currency)
    }
}

/// What a `card` request asks for. `target` is the same as `merchant`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CardRequest {
    pub mode: CardMode,
    /// `pay` (absent) or `setup`.
    #[serde(default, skip_serializing_if = "CardPurpose::is_pay")]
    pub purpose: CardPurpose,
    /// The site of the top-level page (the address bar), e.g. `shop.example.com`; never the host
    /// of a payment frame.
    pub merchant: String,
    /// `fill`: the host of the payment frame the card goes into (`js.pay.example`), when that
    /// frame is from another site than the merchant. Absent when the form is on the merchant's
    /// site.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    /// What will be paid. Required for `pay` (the phone answers `amount_missing` without it);
    /// absent for `setup`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<Money>,
    /// `fill`: the origin of the frame the card goes into, as the host saw it
    /// (`https://www.shop.example.com`, or `https://js.pay.example` with `via`), never from the
    /// page or the model. Required for `fill`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    /// `fill`: the order total the host read on the checkout page, or the user typed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_total: Option<Money>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_source: Option<TotalSource>,
}

impl CardRequest {
    /// The rules both sides check before anything is sent or shown. `Err` carries the refusal
    /// code from [`errors`] when one applies, and a sentence for the person or model.
    pub fn check(&self, target: &str) -> Result<(), (Option<&'static str>, String)> {
        let plain = |m: &str| (None, m.to_owned());
        let merchant = self.merchant.trim();
        if merchant.is_empty() || merchant.chars().count() > MAX_TARGET {
            return Err(plain(
                "merchant is required: the shop's site, e.g. shop.example.com",
            ));
        }
        if !merchant.eq_ignore_ascii_case(target.trim()) {
            return Err(plain("target must be the merchant"));
        }
        match self.purpose {
            CardPurpose::Pay => self.check_amount()?,
            CardPurpose::Setup => {
                if self.amount.is_some() || self.page_total.is_some() || self.total_source.is_some()
                {
                    return Err(plain(
                        "a setup request adds a card for later payments: no amount, page_total or total_source",
                    ));
                }
                if self.mode == CardMode::Reveal {
                    return Err(plain(
                        "a setup request is only for a browser that fills the card (mode fill)",
                    ));
                }
            }
        }
        match self.mode {
            CardMode::Reveal => {
                if self.origin.is_some()
                    || self.via.is_some()
                    || self.page_total.is_some()
                    || self.total_source.is_some()
                {
                    return Err(plain(
                        "origin, via, page_total and total_source belong to fill requests",
                    ));
                }
            }
            CardMode::Fill => {
                let origin = self.origin.as_deref().ok_or(plain(
                    "a fill request needs the origin of the card form's frame from the host",
                ))?;
                match self.via.as_deref() {
                    None => check_origin(origin, merchant),
                    Some(via) => check_via(origin, via, merchant),
                }
                .map_err(|e| (None, e))?;
                match (self.total_source, &self.page_total) {
                    (Some(_), None) | (None, Some(_)) => {
                        return Err(plain("page_total and total_source go together"));
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    /// `pay`: a valid amount, and a page total that is not more than it.
    fn check_amount(&self) -> Result<(), (Option<&'static str>, String)> {
        let amount = self.amount.as_ref().ok_or((
            Some(errors::AMOUNT_MISSING),
            "amount and currency are required: say how much will be paid".to_owned(),
        ))?;
        amount
            .check()
            .map_err(|e| (Some(errors::AMOUNT_MISSING), e))?;
        if let Some(total) = &self.page_total {
            total
                .check()
                .map_err(|e| (None, format!("page_total: {e}")))?;
            if total.exceeds(amount) {
                return Err((
                    Some(errors::TOTAL_MISMATCH),
                    format!("the checkout page shows {total}, more than the amount {amount}"),
                ));
            }
        }
        Ok(())
    }
}

/// `origin` is `https://<host>[:port]` with `host` the merchant or one of its subdomains, or
/// `http://localhost[:port]` with the merchant `localhost` (a shop running on this computer, as
/// for passkeys).
pub fn check_origin(origin: &str, merchant: &str) -> Result<(), String> {
    let host = origin_host(origin, merchant.eq_ignore_ascii_case("localhost"))?;
    let merchant = merchant.to_ascii_lowercase();
    if !host.as_deref().is_some_and(|h| on_site(h, &merchant)) {
        return Err(format!(
            "origin {origin:?} is not on the merchant's site {merchant}"
        ));
    }
    Ok(())
}

/// A payment frame from another site: `via` is a host that is not on the merchant's site
/// (`js.pay.example`), and `origin` is `https://<via>[:port]`.
pub fn check_via(origin: &str, via: &str, merchant: &str) -> Result<(), String> {
    let lower = via.to_ascii_lowercase();
    if !is_host(&lower) || via.chars().count() > MAX_TARGET {
        return Err(format!(
            "via {via:?} is not a host like js.pay.example: the payment frame's host"
        ));
    }
    if on_site(&lower, &merchant.to_ascii_lowercase()) {
        return Err(format!(
            "via {via} is on the merchant's site; leave via out when the card form is on the shop's own site"
        ));
    }
    if origin_host(origin, false)?.as_deref() != Some(lower.as_str()) {
        return Err(format!("origin {origin:?} is not the payment frame {via}"));
    }
    Ok(())
}

/// The host of `https://<host>[:port]` (also `http://` when `http`), in lower case; `None` when
/// the host is not a plain host name.
fn origin_host(origin: &str, http: bool) -> Result<Option<String>, String> {
    let rest = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://").filter(|_| http))
        .ok_or_else(|| format!("origin {origin:?} is not an https origin"))?;
    let host = match rest.rsplit_once(':') {
        Some((h, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => rest,
    };
    Ok(is_host(host).then(|| host.to_ascii_lowercase()))
}

/// Letters, digits, dots and dashes only.
fn is_host(host: &str) -> bool {
    !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

/// Whether lower-case `host` is `site` or one of its subdomains.
fn on_site(host: &str, site: &str) -> bool {
    host == site || host.ends_with(&format!(".{site}"))
}

/// The card in an approved answer. `fill`: the host fills it in and gives the model only the
/// brand and the last four digits. `reveal`: it goes to the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CardAnswer {
    /// The user's name for the card, e.g. "Private Visa".
    pub title: String,
    /// See [`brand`].
    pub brand: String,
    pub last4: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
    pub number: Secret,
    pub exp_month: u8,
    pub exp_year: u16,
    /// Present when the card has a CVC stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvc: Option<Secret>,
    /// The most the user approved for this one purchase: the request's amount. Absent for
    /// `setup`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_amount: Option<Money>,
}

/// A card in a `list` answer (only when cards are on for the agent): never the number.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CardEntry {
    pub title: String,
    pub brand: String,
    pub last4: String,
}

/// The card a `save` request asks the phone to keep. Number and CVC are sealed to the phone on
/// their own (`nodkey/v1/card`, `aad` = `agent_id`), the moment the browser reads them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaveCard {
    pub number: SealedBox,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvc: Option<SealedBox>,
    pub exp_month: u8,
    pub exp_year: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
    /// The page the card was typed on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// The last four digits, for the phone to show before it opens the number.
    pub last4: String,
}

impl SaveCard {
    /// What a save request needs.
    pub fn check(&self) -> Result<(), String> {
        if self.number.ct.is_empty() {
            return Err("a card save needs the sealed card number".into());
        }
        if !(1..=12).contains(&self.exp_month) || !(2000..=2099).contains(&self.exp_year) {
            return Err("the expiry month or year is not valid".into());
        }
        if self.last4.len() != 4 || !self.last4.bytes().all(|b| b.is_ascii_digit()) {
            return Err("last4 must be four digits".into());
        }
        if self.url.as_ref().is_some_and(|u| u.chars().count() > 2000) {
            return Err("the page address is too long".into());
        }
        Ok(())
    }
}

/// Whether `number` (digits, spaces and dashes allowed) passes the Luhn check and has 12 to 19
/// digits.
pub fn luhn(number: &str) -> bool {
    let Some(digits) = digits(number) else {
        return false;
    };
    if !(12..=19).contains(&digits.len()) {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            let d = u32::from(d);
            if i % 2 == 1 {
                if d * 2 > 9 { d * 2 - 9 } else { d * 2 }
            } else {
                d
            }
        })
        .sum();
    sum % 10 == 0
}

fn digits(number: &str) -> Option<Vec<u8>> {
    number
        .chars()
        .filter(|c| *c != ' ' && *c != '-')
        .map(|c| c.to_digit(10).map(|d| d as u8))
        .collect()
}

/// The brand from the number's first digits: `visa`, `mastercard`, `amex`, `discover`, `diners`,
/// `jcb`, `unionpay`, `maestro` or `other`.
pub fn brand(number: &str) -> &'static str {
    let Some(d) = digits(number) else {
        return "other";
    };
    let prefix = |n: usize| -> u32 { d.iter().take(n).fold(0, |acc, &x| acc * 10 + u32::from(x)) };
    let (p2, p3, p4, p6) = (prefix(2), prefix(3), prefix(4), prefix(6));
    match () {
        _ if d.first() == Some(&4) => "visa",
        _ if (51..=55).contains(&p2) || (222_100..=272_099).contains(&p6) => "mastercard",
        _ if p2 == 34 || p2 == 37 => "amex",
        _ if p4 == 6011 || p2 == 65 || (644..=649).contains(&p3) => "discover",
        _ if p2 == 36 || p2 == 38 || (300..=305).contains(&p3) => "diners",
        _ if (3528..=3589).contains(&p4) => "jcb",
        _ if p2 == 62 => "unionpay",
        _ if p2 == 50 || (56..=69).contains(&p2) => "maestro",
        _ => "other",
    }
}

/// The last four digits of a number, or `None` when it has fewer.
pub fn last4(number: &str) -> Option<String> {
    let d = digits(number)?;
    (d.len() >= 4).then(|| {
        d[d.len() - 4..]
            .iter()
            .map(|x| char::from(b'0' + x))
            .collect()
    })
}

#[cfg(test)]
mod tests;
