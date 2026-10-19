use super::*;
use crate::passkey::{PasskeyGet, Requirement};

fn key() -> SigningKey {
    signing_key(&[7u8; 32]).unwrap()
}

#[test]
fn authenticator_data_layout() {
    let k = key();
    let plain = authenticator_data("webauthn.io", None);
    assert_eq!(plain.len(), 37);
    assert_eq!(&plain[..32], &Sha256::digest(b"webauthn.io")[..]);
    assert_eq!(plain[32], 0x1d);
    assert_eq!(&plain[33..], &[0, 0, 0, 0]);
    // A get that a lease or a task session answered: no Face ID, so no UV.
    let leased = authenticator_data_without_uv("webauthn.io");
    assert_eq!(leased[32], 0x19);
    assert_eq!(leased[..32], plain[..32]);
    assert_eq!(leased[33..], plain[33..]);

    let cred = [9u8; 16];
    let attested = authenticator_data("webauthn.io", Some((&cred, k.verifying_key())));
    assert_eq!(attested[32], 0x5d);
    assert_eq!(&attested[37..53], &AAGUID);
    assert_eq!(&attested[53..55], &[0, 16]);
    assert_eq!(&attested[55..71], &cred);
    let cose = cose_key(k.verifying_key());
    assert_eq!(&attested[71..], &cose[..]);
    // {1: 2, 3: -7, -1: 1, -2: bstr(32), -3: bstr(32)}
    assert_eq!(
        &cose[..9],
        &[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58]
    );
    assert_eq!(cose.len(), 77);

    let att = attestation_object(&plain);
    assert_eq!(&att[..1], &[0xa3]);
    assert!(att.ends_with(&plain));
}

#[test]
fn sign_verify_and_der() {
    let k = key();
    let auth = authenticator_data("webauthn.io", None);
    let cd = br#"{"type":"webauthn.get","challenge":"AAEC","origin":"https://webauthn.io","crossOrigin":false}"#;
    let sig = sign(&k, &auth, cd);
    assert_eq!(sig, sign(&k, &auth, cd), "deterministic");
    let spki = spki_der(k.verifying_key());
    assert_eq!(spki.len(), 91);
    let pk = key_from_spki(&spki).unwrap();
    verify(&pk, &auth, cd, &sig).unwrap();
    assert!(verify(&pk, &auth, b"{}", &sig).is_err());
    assert!(key_from_spki(&spki[1..]).is_err());

    // DER: round trip, and the strict rules.
    let rs = der::decode(&sig).unwrap();
    assert_eq!(der::encode(&rs), sig);
    let mut small = [0u8; 64];
    small[31] = 1;
    small[32] = 0x80;
    let enc = der::encode(&small);
    assert_eq!(
        enc,
        [0x30, 0x26, 0x02, 0x01, 0x01, 0x02, 0x21, 0x00, 0x80]
            .iter()
            .copied()
            .chain(std::iter::repeat_n(0, 31))
            .collect::<Vec<_>>()
    );
    assert_eq!(der::decode(&enc).unwrap(), small);
    assert!(der::decode(&[0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01]).is_none());
    assert!(der::decode(&[0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01]).is_none());
    assert!(der::decode(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00]).is_none());
}

#[test]
fn answer_check() {
    let k = key();
    let cd = crate::passkey::build_client_data_json(
        crate::passkey::PasskeyOp::Get,
        "AAEC",
        "https://webauthn.io",
    );
    let request = PasskeyRequest::Get(PasskeyGet {
        rp_id: "webauthn.io".into(),
        client_data_json: b64u::encode(cd.as_bytes()),
        allow_credentials: vec![],
        user_verification: Requirement::Required,
        prf: None,
    });
    let auth = authenticator_data("webauthn.io", None);
    let mut answer = PasskeyAnswer {
        credential_id: b64u::encode(&[1; 16]),
        attestation_object: None,
        authenticator_data: b64u::encode(&auth),
        signature: Some(b64u::encode(&sign(&k, &auth, cd.as_bytes()))),
        user_handle: Some(b64u::encode(&[2; 16])),
        user_name: Some("alex".into()),
        public_key: None,
        public_key_algorithm: None,
        prf: None,
    };
    check_answer(&request, &answer).unwrap();
    answer.authenticator_data = b64u::encode(&authenticator_data("other.example", None));
    assert!(check_answer(&request, &answer).is_err());
    answer.authenticator_data = b64u::encode(&auth);
    answer.signature = None;
    assert!(check_answer(&request, &answer).is_err());

    // Without UV: refused when the site requires user verification, fine otherwise.
    let leased = authenticator_data_without_uv("webauthn.io");
    answer.authenticator_data = b64u::encode(&leased);
    answer.signature = Some(b64u::encode(&sign(&k, &leased, cd.as_bytes())));
    assert!(
        check_answer(&request, &answer)
            .unwrap_err()
            .contains("user verification")
    );
    let PasskeyRequest::Get(mut g) = request else {
        unreachable!()
    };
    g.user_verification = Requirement::Preferred;
    check_answer(&PasskeyRequest::Get(g), &answer).unwrap();
}
