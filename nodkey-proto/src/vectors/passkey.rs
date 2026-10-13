//! Passkey vectors: the sealed `passkey` requests and answers, and a `webauthn` section with a
//! fixed P-256 test key, the client data, the authenticator data and a signature to verify.

use serde_json::{Value, json};

use super::{Ctx, Side, TS, label_id, label32, to_json};
use crate::{
    Answer, Decision, Kind, PasskeyAnswer, PasskeyCreate, PasskeyGet, PasskeyOp, PasskeyRequest,
    PasskeyUser, Purpose, Request, Requirement, VERSION, b64u,
    passkey::{ES256, build_client_data_json, check_client_data, client_data_hash},
    webauthn,
};

pub const RP_ID: &str = "webauthn.io";
pub const ORIGIN: &str = "https://webauthn.io";

/// The cases of `client_data_checks`: name, op, rp_id, client data JSON, whether it passes.
fn client_data_cases() -> Vec<(&'static str, PasskeyOp, &'static str, String, bool)> {
    let cd = |kind: &str, origin: &str| {
        format!(r#"{{"type":"{kind}","challenge":"AAEC","origin":"{origin}","crossOrigin":false}}"#)
    };
    let get = "webauthn.get";
    vec![
        ("same_host", PasskeyOp::Get, RP_ID, cd(get, ORIGIN), true),
        (
            "subdomain",
            PasskeyOp::Get,
            RP_ID,
            cd(get, "https://www.webauthn.io"),
            true,
        ),
        (
            "https_port",
            PasskeyOp::Get,
            RP_ID,
            cd(get, "https://webauthn.io:8443"),
            true,
        ),
        (
            "localhost_http",
            PasskeyOp::Get,
            "localhost",
            cd(get, "http://localhost:8080"),
            true,
        ),
        (
            "cross_origin_absent",
            PasskeyOp::Get,
            RP_ID,
            format!(r#"{{"type":"webauthn.get","challenge":"AAEC","origin":"{ORIGIN}"}}"#),
            true,
        ),
        (
            "create_type_for_create",
            PasskeyOp::Create,
            RP_ID,
            cd("webauthn.create", ORIGIN),
            true,
        ),
        (
            "get_type_for_create",
            PasskeyOp::Create,
            RP_ID,
            cd(get, ORIGIN),
            false,
        ),
        (
            "create_type_for_get",
            PasskeyOp::Get,
            RP_ID,
            cd("webauthn.create", ORIGIN),
            false,
        ),
        (
            "cross_origin_true",
            PasskeyOp::Get,
            RP_ID,
            format!(
                r#"{{"type":"webauthn.get","challenge":"AAEC","origin":"{ORIGIN}","crossOrigin":true}}"#
            ),
            false,
        ),
        (
            "no_challenge",
            PasskeyOp::Get,
            RP_ID,
            format!(r#"{{"type":"webauthn.get","origin":"{ORIGIN}"}}"#),
            false,
        ),
        (
            "http_not_localhost",
            PasskeyOp::Get,
            RP_ID,
            cd(get, "http://webauthn.io"),
            false,
        ),
        (
            "suffix_without_dot",
            PasskeyOp::Get,
            RP_ID,
            cd(get, "https://evilwebauthn.io"),
            false,
        ),
        (
            "rp_id_as_prefix",
            PasskeyOp::Get,
            RP_ID,
            cd(get, "https://webauthn.io.evil.example"),
            false,
        ),
        (
            "rp_id_below_host",
            PasskeyOp::Get,
            "www.webauthn.io",
            cd(get, ORIGIN),
            false,
        ),
        (
            "rp_id_without_dot",
            PasskeyOp::Get,
            "io",
            cd(get, ORIGIN),
            false,
        ),
        (
            "rp_id_ip_address",
            PasskeyOp::Get,
            "127.0.0.1",
            cd(get, "https://127.0.0.1"),
            false,
        ),
        (
            "origin_with_path",
            PasskeyOp::Get,
            RP_ID,
            cd(get, "https://webauthn.io/login"),
            false,
        ),
        (
            "not_json",
            PasskeyOp::Get,
            RP_ID,
            "type=webauthn.get".to_owned(),
            false,
        ),
    ]
}

/// Seals the passkey requests and answers into `ctx` and returns the `webauthn` section.
pub(super) fn add(ctx: &mut Ctx, agent: &Side, phone: &Side) -> Value {
    let key = webauthn::signing_key(&label32("nodkey/v1/vectors/passkey/key")).expect("valid key");
    let public = key.verifying_key();
    let credential_id = label32("nodkey/v1/vectors/passkey/credential")[..16].to_vec();
    let user_handle = label32("nodkey/v1/vectors/passkey/user")[..16].to_vec();
    let challenge = |op: &str| {
        b64u::encode(&label32(&format!(
            "nodkey/v1/vectors/passkey/challenge/{op}"
        )))
    };

    let cd_create = build_client_data_json(PasskeyOp::Create, &challenge("create"), ORIGIN);
    let cd_get = build_client_data_json(PasskeyOp::Get, &challenge("get"), ORIGIN);
    let auth_create = webauthn::authenticator_data(RP_ID, Some((&credential_id, public)));
    let attestation = webauthn::attestation_object(&auth_create);
    let auth_get = webauthn::authenticator_data(RP_ID, None);
    let signature = webauthn::sign(&key, &auth_get, cd_get.as_bytes());
    let spki = webauthn::spki_der(public);

    let request = |name: &str, passkey: PasskeyRequest, reason: &str| Request {
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
        client: None,
    };
    let r_create = request(
        "passkey_create",
        PasskeyRequest::Create(PasskeyCreate {
            rp_id: RP_ID.into(),
            rp_name: "WebAuthn.io".into(),
            client_data_json: b64u::encode(cd_create.as_bytes()),
            user: PasskeyUser {
                id: b64u::encode(&user_handle),
                name: "alex".into(),
                display_name: "Alex".into(),
            },
            algorithms: vec![ES256, -257],
            exclude_credentials: vec![],
            resident_key: Requirement::Required,
            user_verification: Requirement::Required,
        }),
        "Create a passkey for webauthn.io",
    );
    let r_get = request(
        "passkey_get",
        PasskeyRequest::Get(PasskeyGet {
            rp_id: RP_ID.into(),
            client_data_json: b64u::encode(cd_get.as_bytes()),
            allow_credentials: vec![b64u::encode(&credential_id)],
            user_verification: Requirement::Required,
        }),
        "Sign in to webauthn.io",
    );
    for (name, r) in [
        ("request_passkey_get", &r_get),
        ("request_passkey_create", &r_create),
    ] {
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

    let mut a_get = Answer::decision(&r_get.request_id, Decision::Approved);
    a_get.passkey = Some(PasskeyAnswer {
        credential_id: b64u::encode(&credential_id),
        attestation_object: None,
        authenticator_data: b64u::encode(&auth_get),
        signature: Some(b64u::encode(&signature)),
        user_handle: Some(b64u::encode(&user_handle)),
        user_name: Some("alex".into()),
        public_key: None,
        public_key_algorithm: None,
    });
    let mut a_create = Answer::decision(&r_create.request_id, Decision::Approved);
    a_create.passkey = Some(PasskeyAnswer {
        credential_id: b64u::encode(&credential_id),
        attestation_object: Some(b64u::encode(&attestation)),
        authenticator_data: b64u::encode(&auth_create),
        signature: None,
        user_handle: None,
        user_name: None,
        public_key: Some(b64u::encode(&spki)),
        public_key_algorithm: Some(ES256),
    });
    for (name, a) in [
        ("answer_passkey_get", &a_get),
        ("answer_passkey_create", &a_create),
    ] {
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

    let checks: Vec<Value> = client_data_cases()
        .into_iter()
        .map(|(name, op, rp_id, text, ok)| {
            assert_eq!(
                check_client_data(op, rp_id, text.as_bytes()).is_ok(),
                ok,
                "{name}"
            );
            json!({"name": name, "op": op, "rp_id": rp_id, "client_data_json": text, "ok": ok})
        })
        .collect();
    let point = public.to_sec1_point(false);
    let client_data = |text: &str| {
        json!({
            "client_data_json": text,
            "client_data_json_b64u": b64u::encode(text.as_bytes()),
            "client_data_hash": b64u::encode(&client_data_hash(text.as_bytes())),
        })
    };
    let mut get = client_data(&cd_get);
    get["authenticator_data"] = json!(b64u::encode(&auth_get));
    get["signed_data"] = json!(b64u::encode(&webauthn::signed_data(
        &auth_get,
        cd_get.as_bytes()
    )));
    get["signature"] = json!(b64u::encode(&signature));
    let mut create = client_data(&cd_create);
    create["authenticator_data"] = json!(b64u::encode(&auth_create));
    create["attestation_object"] = json!(b64u::encode(&attestation));
    json!({
        "about": "A passkey made and used the way Nodkey does it: ES256, flags UP|UV|BE|BS (0x1d; 0x5d \
                  with attested credential data), sign count 0, \"none\" attestation. The signature is \
                  DER over authenticator_data || SHA-256(client_data_json) with RFC 6979 nonces, so it \
                  is reproducible; a recipient verifies it with public_key_spki. The private key is a \
                  fixed test key, never a real one.",
        "aaguid": "97531e9d-ff39-4e63-aaec-b1d68400c3c9",
        "aaguid_b64u": b64u::encode(&webauthn::AAGUID),
        "rp_id": RP_ID,
        "origin": ORIGIN,
        "private_key": b64u::encode(&key.to_bytes()),
        "public_key_x963": b64u::encode(point.as_bytes()),
        "public_key_spki": b64u::encode(&spki),
        "cose_key": b64u::encode(&webauthn::cose_key(public)),
        "credential_id": b64u::encode(&credential_id),
        "user_handle": b64u::encode(&user_handle),
        "user_name": "alex",
        "get": get,
        "create": create,
        "client_data_checks": checks,
    })
}
