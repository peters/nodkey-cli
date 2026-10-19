//! WebAuthn PRF vectors: sealed passkey requests and answers with `prf`, a refusal for a passkey
//! made before PRF support, and the `prf` section with a fixed `credRandom`, inputs, salts and
//! outputs, and the input checks.

use serde_json::{Value, json};

use super::{
    Ctx, Side, TS, label_id, label32,
    passkey::{ORIGIN, RP_ID, test_passkey},
    to_json,
};
use crate::{
    Answer, Decision, Kind, PasskeyAnswer, PasskeyCreate, PasskeyGet, PasskeyOp, PasskeyRequest,
    PasskeyUser, PrfInput, PrfOutput, PrfValues, Purpose, Request, Requirement, VERSION, b64u,
    passkey::{ES256, build_client_data_json, errors},
    prf, webauthn,
};

/// The fixed `credRandom` of the vectors' passkey (the fake phone gives it to new passkeys).
pub fn cred_random() -> [u8; prf::LEN] {
    label32("nodkey/v1/vectors/prf/cred_random")
}

fn input(name: &str) -> Vec<u8> {
    label32(&format!("nodkey/v1/vectors/prf/input/{name}")).to_vec()
}

fn values(first: &[u8], second: Option<&[u8]>) -> PrfValues {
    PrfValues {
        first: b64u::encode(first),
        second: second.map(b64u::encode),
    }
}

fn request(name: &str, passkey: PasskeyRequest, reason: &str) -> Request {
    Request {
        v: VERSION,
        request_id: label_id(&format!("nodkey/v1/vectors/request/{name}")),
        kind: Kind::Passkey,
        target: RP_ID.into(),
        reason: reason.into(),
        agent: "Agent \u{b7} Horizon".into(),
        ts: TS,
        attachment: None,
        filter: None,
        save: None,
        passkey: Some(passkey),
        bundle: None,
        card: None,
        save_card: None,
        client: None,
        session_id: None,
        suggest: None,
        wait_seconds: None,
        save_secret: None,
        project: None,
        nonce: None,
    }
}

fn get(cd: &str, allow: &[u8], prf: PrfInput) -> PasskeyRequest {
    PasskeyRequest::Get(PasskeyGet {
        rp_id: RP_ID.into(),
        client_data_json: b64u::encode(cd.as_bytes()),
        allow_credentials: vec![b64u::encode(allow)],
        user_verification: Requirement::Required,
        prf: Some(prf),
    })
}

/// The cases of `prf.input_checks`: name, op, allow_credentials, prf, whether the agent passes it.
fn check_cases(credential: &str) -> Vec<(&'static str, PasskeyOp, Vec<String>, Value, bool)> {
    let other = b64u::encode(&[0x11; 16]);
    let x = b64u::encode(b"x");
    let get = PasskeyOp::Get;
    let create = PasskeyOp::Create;
    let one = || vec![credential.to_owned()];
    vec![
        ("create_empty", create, vec![], json!({}), true),
        (
            "create_eval",
            create,
            vec![],
            json!({"eval": {"first": x}}),
            true,
        ),
        (
            "create_eval_by_credential",
            create,
            vec![],
            json!({"eval_by_credential": {credential: {"first": x}}}),
            false,
        ),
        (
            "get_eval",
            get,
            vec![],
            json!({"eval": {"first": x, "second": x}}),
            true,
        ),
        ("get_empty", get, vec![], json!({}), false),
        (
            "get_by_allowed_credential",
            get,
            one(),
            json!({"eval_by_credential": {credential: {"first": x}}}),
            true,
        ),
        (
            "get_by_credential_without_allow_list",
            get,
            vec![],
            json!({"eval_by_credential": {credential: {"first": x}}}),
            false,
        ),
        (
            "get_by_credential_not_allowed",
            get,
            one(),
            json!({"eval_by_credential": {other: {"first": x}}}),
            false,
        ),
        (
            "get_input_256_bytes",
            get,
            vec![],
            json!({"eval": {"first": b64u::encode(&[7; prf::MAX_INPUT])}}),
            true,
        ),
        (
            "get_input_257_bytes",
            get,
            vec![],
            json!({"eval": {"first": b64u::encode(&[7; prf::MAX_INPUT + 1])}}),
            false,
        ),
        (
            "get_input_not_b64u",
            get,
            vec![],
            json!({"eval": {"first": "a+b/"}}),
            false,
        ),
    ]
}

/// Seals the PRF requests and answers into `ctx` and returns the `prf` section.
pub(super) fn add(ctx: &mut Ctx, agent: &Side, phone: &Side) -> Value {
    let (key, credential_id, user_handle) = test_passkey();
    let credential = b64u::encode(&credential_id);
    let cred = cred_random();
    let challenge =
        |op: &str| b64u::encode(&label32(&format!("nodkey/v1/vectors/prf/challenge/{op}")));
    let (first, second, mine) = (input("first"), input("second"), input("by_credential"));

    let cd_create = build_client_data_json(PasskeyOp::Create, &challenge("create"), ORIGIN);
    let cd_get = build_client_data_json(PasskeyOp::Get, &challenge("get"), ORIGIN);
    let cd_by = build_client_data_json(PasskeyOp::Get, &challenge("by_credential"), ORIGIN);

    let r_create = request(
        "passkey_create_prf",
        PasskeyRequest::Create(PasskeyCreate {
            rp_id: RP_ID.into(),
            rp_name: "WebAuthn.io".into(),
            client_data_json: b64u::encode(cd_create.as_bytes()),
            user: PasskeyUser {
                id: b64u::encode(&user_handle),
                name: "alex".into(),
                display_name: "Alex".into(),
            },
            algorithms: vec![ES256],
            exclude_credentials: vec![],
            resident_key: Requirement::Required,
            user_verification: Requirement::Required,
            prf: Some(PrfInput {
                eval: Some(values(&first, None)),
                ..Default::default()
            }),
        }),
        "Create a passkey for webauthn.io",
    );
    let r_get = request(
        "passkey_get_prf",
        get(
            &cd_get,
            &credential_id,
            PrfInput {
                eval: Some(values(&first, Some(&second))),
                ..Default::default()
            },
        ),
        "Unlock a key for webauthn.io",
    );
    let r_by = request(
        "passkey_get_prf_by_credential",
        get(
            &cd_by,
            &credential_id,
            PrfInput {
                eval: Some(values(&first, None)),
                eval_by_credential: [(credential.clone(), values(&mine, None))].into(),
            },
        ),
        "Unlock a key for webauthn.io",
    );
    for (name, r) in [
        ("request_passkey_create_prf", &r_create),
        ("request_passkey_get_prf", &r_get),
        ("request_passkey_get_prf_by_credential", &r_by),
    ] {
        r.passkey.as_ref().unwrap().check(RP_ID).expect("valid");
        ctx.seal(
            name,
            Purpose::Request,
            "agent",
            phone,
            format!("{}{}", r.request_id, agent.id),
            &to_json(r),
            true,
        );
    }

    let public = key.verifying_key();
    let auth_create = webauthn::authenticator_data(RP_ID, Some((&credential_id, public)));
    let auth_get = webauthn::authenticator_data(RP_ID, None);
    let signed = |cd: &str, prf: PrfOutput| PasskeyAnswer {
        credential_id: credential.clone(),
        attestation_object: None,
        authenticator_data: b64u::encode(&auth_get),
        signature: Some(b64u::encode(&webauthn::sign(
            &key,
            &auth_get,
            cd.as_bytes(),
        ))),
        user_handle: Some(b64u::encode(&user_handle)),
        user_name: Some("alex".into()),
        public_key: None,
        public_key_algorithm: None,
        prf: Some(prf),
    };
    let results = |v: &PrfValues| Some(prf::results(&cred, v).expect("valid inputs"));
    let mut a_create = Answer::decision(&r_create.request_id, Decision::Approved);
    a_create.passkey = Some(PasskeyAnswer {
        credential_id: credential.clone(),
        attestation_object: Some(b64u::encode(&webauthn::attestation_object(&auth_create))),
        authenticator_data: b64u::encode(&auth_create),
        signature: None,
        user_handle: None,
        user_name: None,
        public_key: Some(b64u::encode(&webauthn::spki_der(public))),
        public_key_algorithm: Some(ES256),
        prf: Some(PrfOutput {
            enabled: Some(true),
            results: results(&values(&first, None)),
        }),
    });
    let mut a_get = Answer::decision(&r_get.request_id, Decision::Approved);
    a_get.passkey = Some(signed(
        &cd_get,
        PrfOutput {
            enabled: None,
            results: results(&values(&first, Some(&second))),
        },
    ));
    let mut a_by = Answer::decision(&r_by.request_id, Decision::Approved);
    a_by.passkey = Some(signed(
        &cd_by,
        PrfOutput {
            enabled: None,
            results: results(&values(&mine, None)),
        },
    ));
    let mut a_unsupported = Answer::decision(&r_get.request_id, Decision::Denied);
    a_unsupported.error = Some(errors::PRF_UNSUPPORTED.into());
    for (name, r, a) in [
        ("answer_passkey_create_prf", &r_create, &a_create),
        ("answer_passkey_get_prf", &r_get, &a_get),
        ("answer_passkey_get_prf_by_credential", &r_by, &a_by),
        ("answer_passkey_prf_unsupported", &r_get, &a_unsupported),
    ] {
        if let Some(p) = &a.passkey {
            webauthn::check_answer(r.passkey.as_ref().unwrap(), p).expect("valid answer");
        }
        ctx.seal(
            name,
            Purpose::Answer,
            "phone",
            agent,
            format!("{}{}", a.request_id, phone.id),
            &to_json(a),
            true,
        );
    }

    let derivation = |name: &str, input: &[u8]| {
        json!({
            "name": name,
            "input": b64u::encode(input),
            "salt": b64u::encode(&prf::salt(input)),
            "output": b64u::encode(&*prf::evaluate(&cred, input)),
        })
    };
    let mut text = derivation("text", b"nodkey prf test");
    text["input_text"] = json!("nodkey prf test");
    let checks: Vec<Value> = check_cases(&credential)
        .into_iter()
        .map(|(name, op, allow, prf, ok)| {
            let input: PrfInput = serde_json::from_value(prf.clone()).expect("prf input");
            assert_eq!(
                input.check(op == PasskeyOp::Create, &allow).is_ok(),
                ok,
                "{name}"
            );
            json!({"name": name, "op": op, "allow_credentials": allow, "prf": prf, "ok": ok})
        })
        .collect();
    json!({
        "about": "WebAuthn PRF (CTAP2 hmac-secret) the way Nodkey does it: salt = SHA-256(\"WebAuthn \
                  PRF\" || 0x00 || input), output = HMAC-SHA256(cred_random, salt), 32 bytes. \
                  cred_random is a fixed test value of the vectors' passkey (credential_id), never \
                  a real one. The same passkey and input always give the same output.",
        "label": "WebAuthn PRF",
        "credential_id": credential,
        "cred_random": b64u::encode(&cred),
        "derivations": [
            derivation("empty", b""),
            text,
            derivation("first", &first),
            derivation("second", &second),
            derivation("by_credential", &mine),
            derivation("max_length", &[0x5a; prf::MAX_INPUT]),
        ],
        "input_checks": checks,
    })
}
