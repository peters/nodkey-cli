use super::*;

/// `credRandom` 00 01 .. 1f; the expected values come from Python's `hashlib` and `hmac`.
fn cred() -> [u8; LEN] {
    std::array::from_fn(|i| i as u8)
}

#[test]
fn derivation_matches_an_independent_implementation() {
    let cases: [(&[u8], &str, &str); 3] = [
        (
            b"",
            "6a7e64b2aa34c92736143a062fa149aff1bd8bb3f7ee6f346885481f9414a3d3",
            "48bece38d6fc9b3b113bcc29420cb0f575c258a83d37330c252ff5477dae419a",
        ),
        (
            b"nodkey prf test",
            "d62ee97c817ce439a5e7c29b0aaa8e3d36020219da54d5efa329ff771793963e",
            "48131fd4be84a79437aba711149dbf1a3adb94ef44e2f444b1a493d936e846c2",
        ),
        (
            &[0xa5; 32],
            "3e04c4bf01ce62284e7db1b3293078b65815ae947a0084c7af88f719f256a447",
            "524174fe7436ae6f00b8a4a983f0d7c696bfdb422b7f45d28343152523b59c04",
        ),
    ];
    for (input, s, out) in cases {
        assert_eq!(b64u::hex(&salt(input)), s);
        assert_eq!(b64u::hex(&*evaluate(&cred(), input)), out);
    }
}

#[test]
fn same_input_same_output_other_input_other_output() {
    let c = cred();
    assert_eq!(*evaluate(&c, b"salt one"), *evaluate(&c, b"salt one"));
    assert_ne!(*evaluate(&c, b"salt one"), *evaluate(&c, b"salt two"));
    let mut other = c;
    other[0] ^= 1;
    assert_ne!(*evaluate(&c, b"salt one"), *evaluate(&other, b"salt one"));
    let r = results(
        &c,
        &PrfValues {
            first: b64u::encode(b"salt one"),
            second: Some(b64u::encode(b"salt two")),
        },
    )
    .unwrap();
    assert_eq!(r.first.expose(), b64u::encode(&*evaluate(&c, b"salt one")));
    assert_eq!(
        r.second.unwrap().expose(),
        b64u::encode(&*evaluate(&c, b"salt two"))
    );
    assert_ne!(*random_cred_random(), *random_cred_random());
}

fn values(first: &[u8]) -> PrfValues {
    PrfValues {
        first: b64u::encode(first),
        second: None,
    }
}

#[test]
fn input_rules() {
    let id = b64u::encode(&[7; 16]);
    let other = b64u::encode(&[8; 16]);
    let by = |id: &str| PrfInput {
        eval: None,
        eval_by_credential: [(id.to_owned(), values(b"x"))].into(),
    };
    // Create: `{}` and `eval` pass, `eval_by_credential` does not.
    assert!(PrfInput::default().check(true, &[]).is_ok());
    let eval = PrfInput {
        eval: Some(values(b"x")),
        ..Default::default()
    };
    assert!(eval.check(true, &[]).is_ok());
    assert!(by(&id).check(true, std::slice::from_ref(&id)).is_err());
    // Get: needs inputs; keys of eval_by_credential must be allowed.
    assert!(PrfInput::default().check(false, &[]).is_err());
    assert!(eval.check(false, &[]).is_ok());
    assert!(by(&id).check(false, std::slice::from_ref(&id)).is_ok());
    assert!(by(&id).check(false, &[]).is_err());
    assert!(by(&id).check(false, std::slice::from_ref(&other)).is_err());
    assert!(
        by("not b64u!")
            .check(false, std::slice::from_ref(&id))
            .is_err()
    );
    // Input size and encoding.
    let long = PrfInput {
        eval: Some(values(&[0; MAX_INPUT + 1])),
        ..Default::default()
    };
    assert!(long.check(false, &[]).is_err());
    let bad = PrfInput {
        eval: Some(PrfValues {
            first: "x".into(),
            second: Some("+/".into()),
        }),
        ..Default::default()
    };
    assert!(bad.check(false, &[]).is_err());

    // values_for: the credential's own entry first, else eval.
    let both = PrfInput {
        eval: Some(values(b"any")),
        eval_by_credential: [(id.clone(), values(b"mine"))].into(),
    };
    assert_eq!(both.values_for(&id).unwrap().first, b64u::encode(b"mine"));
    assert_eq!(both.values_for(&other).unwrap().first, b64u::encode(b"any"));
    assert!(by(&id).values_for(&other).is_none());
}

#[test]
fn output_rules() {
    let asked = values(b"x");
    let good = Secret::new(b64u::encode(&[1; LEN]));
    let out = |first: Secret, second: Option<Secret>| PrfOutput {
        enabled: None,
        results: Some(PrfResults { first, second }),
    };
    assert!(check_output(Some(&asked), &out(good.clone(), None)).is_ok());
    assert!(check_output(Some(&asked), &PrfOutput::default()).is_ok());
    assert!(check_output(None, &out(good.clone(), None)).is_err());
    assert!(check_output(Some(&asked), &out(Secret::new("AAEC"), None)).is_err());
    assert!(check_output(Some(&asked), &out(good.clone(), Some(good.clone()))).is_err());
    let two = PrfValues {
        second: Some(b64u::encode(b"y")),
        ..asked.clone()
    };
    assert!(check_output(Some(&two), &out(good.clone(), None)).is_err());
    assert!(check_output(Some(&two), &out(good.clone(), Some(good))).is_ok());
    // Results are redacted in Debug.
    assert!(!format!("{:?}", out(Secret::new("AAEC"), None)).contains("AAEC"));
}
