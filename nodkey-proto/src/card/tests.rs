use super::*;

fn money(value: &str, currency: &str) -> Money {
    Money {
        value: value.into(),
        currency: currency.into(),
    }
}

fn fill() -> CardRequest {
    CardRequest {
        mode: CardMode::Fill,
        merchant: "shop.example.com".into(),
        amount: Some(money("499.00", "NOK")),
        origin: Some("https://www.shop.example.com".into()),
        page_total: Some(money("499", "NOK")),
        total_source: Some(TotalSource::Page),
    }
}

#[test]
fn money_parses_and_compares() {
    assert_eq!(
        Money::parse(" 499,50 ", "nok").unwrap(),
        money("499.50", "NOK")
    );
    assert_eq!(money("499.5", "NOK").thousandths().unwrap(), 499_500);
    assert_eq!(money("12.345", "KWD").thousandths().unwrap(), 12_345);
    assert_eq!(money("1500", "JPY").thousandths().unwrap(), 1_500_000);
    for bad in [
        "", "abc", "1 000", "1.000,00", "1.", ".5", "-5", "1.2345", "0", "0.00",
    ] {
        assert!(Money::parse(bad, "NOK").is_err(), "{bad:?}");
    }
    for bad in ["NO", "NOKK", "n0k", ""] {
        assert!(Money::parse("1", bad).is_err(), "{bad:?}");
    }
    assert!(Money::parse(&"9".repeat(13), "NOK").is_err());
    assert!(money("500", "NOK").exceeds(&money("499.99", "NOK")));
    assert!(!money("499.990", "NOK").exceeds(&money("499.99", "NOK")));
    assert!(money("1", "EUR").exceeds(&money("1000", "NOK")));
    assert_eq!(money("499.00", "NOK").to_string(), "499.00 NOK");
}

#[test]
fn request_rules() {
    assert!(fill().check("shop.example.com").is_ok());
    let code = |r: CardRequest, target: &str| r.check(target).unwrap_err().0;
    let with = |f: &dyn Fn(&mut CardRequest)| {
        let mut r = fill();
        f(&mut r);
        r
    };
    assert_eq!(
        code(with(&|r| r.amount = None), "shop.example.com"),
        Some(errors::AMOUNT_MISSING)
    );
    assert_eq!(
        code(
            with(&|r| r.amount = Some(money("0", "NOK"))),
            "shop.example.com"
        ),
        Some(errors::AMOUNT_MISSING)
    );
    assert_eq!(
        code(
            with(&|r| r.page_total = Some(money("4999", "NOK"))),
            "shop.example.com"
        ),
        Some(errors::TOTAL_MISMATCH)
    );
    assert_eq!(
        code(
            with(&|r| r.page_total = Some(money("499", "EUR"))),
            "shop.example.com"
        ),
        Some(errors::TOTAL_MISMATCH)
    );
    assert!(fill().check("other.example").is_err());
    assert!(with(&|r| r.merchant = " ".into()).check(" ").is_err());
    assert!(
        with(&|r| r.origin = None)
            .check("shop.example.com")
            .is_err()
    );
    assert!(
        with(&|r| r.total_source = None)
            .check("shop.example.com")
            .is_err()
    );
    assert!(
        with(&|r| {
            r.total_source = None;
            r.page_total = None;
        })
        .check("shop.example.com")
        .is_ok()
    );
    for origin in [
        "http://shop.example.com",
        "https://shop.example.com.evil.io",
        "https://evilshop.example.com",
        "https://shop.example.com/pay",
        "https://user@shop.example.com",
    ] {
        assert!(
            with(&|r| r.origin = Some(origin.into()))
                .check("shop.example.com")
                .is_err(),
            "{origin}"
        );
    }
    assert!(
        with(&|r| r.origin = Some("https://Pay.Shop.Example.com:8443".into()))
            .check("shop.example.com")
            .is_ok()
    );
    let reveal = CardRequest {
        mode: CardMode::Reveal,
        merchant: "shop.example.com".into(),
        amount: Some(money("899", "NOK")),
        origin: None,
        page_total: None,
        total_source: None,
    };
    assert!(reveal.check("shop.example.com").is_ok());
    let mut r = reveal.clone();
    r.origin = Some("https://shop.example.com".into());
    assert!(r.check("shop.example.com").is_err());
}

#[test]
fn luhn_brand_last4() {
    assert!(luhn("4242 4242 4242 4242"));
    assert!(luhn("5555-5555-5555-4444"));
    assert!(luhn("378282246310005"));
    assert!(!luhn("4242 4242 4242 4241"));
    assert!(!luhn("4242"));
    assert!(!luhn("4242 4242 4242 424x"));
    assert_eq!(brand("4242424242424242"), "visa");
    assert_eq!(brand("5555555555554444"), "mastercard");
    assert_eq!(brand("2223003122003222"), "mastercard");
    assert_eq!(brand("378282246310005"), "amex");
    assert_eq!(brand("6011111111111117"), "discover");
    assert_eq!(brand("36227206271667"), "diners");
    assert_eq!(brand("3566002020360505"), "jcb");
    assert_eq!(brand("6200000000000005"), "unionpay");
    assert_eq!(brand("6759649826438453"), "maestro");
    assert_eq!(brand("9999"), "other");
    assert_eq!(last4("4242 4242 4242 4242").as_deref(), Some("4242"));
    assert_eq!(last4("123"), None);
}

#[test]
fn save_rules() {
    let mut s = SaveCard {
        number: SealedBox {
            enc: "e".into(),
            ct: "c".into(),
        },
        cvc: None,
        exp_month: 12,
        exp_year: 2030,
        holder: Some("Alex Example".into()),
        url: Some("https://shop.example.com/checkout".into()),
        last4: "4242".into(),
    };
    assert!(s.check().is_ok());
    s.exp_month = 13;
    assert!(s.check().is_err());
    s.exp_month = 1;
    s.last4 = "42a2".into();
    assert!(s.check().is_err());
    s.last4 = "4242".into();
    s.number.ct = String::new();
    assert!(s.check().is_err());
}

#[test]
fn answer_json_names() {
    let a = CardAnswer {
        title: "Test Visa".into(),
        brand: "visa".into(),
        last4: "4242".into(),
        holder: None,
        number: Secret::new("4242424242424242"),
        exp_month: 12,
        exp_year: 2030,
        cvc: Some(Secret::new("123")),
        approved_amount: money("499.00", "NOK"),
    };
    assert_eq!(
        serde_json::to_string(&a).unwrap(),
        r#"{"title":"Test Visa","brand":"visa","last4":"4242","number":"4242424242424242","exp_month":12,"exp_year":2030,"cvc":"123","approved_amount":{"value":"499.00","currency":"NOK"}}"#
    );
    assert!(!format!("{a:?}").contains("4242424242424242"));
}
