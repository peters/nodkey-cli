//! Pairing with a commitment and signed requests and answers (nodkey-cli#16, #18): the grant with
//! `commit`, the `pairing_check` request and answer, a signed code request and answer, and a
//! signed login request whose picture has its hash. Returns the `pairing` and `signed` sections.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{Ctx, PNG, Side, TS, label_id, label32, request, to_json};
use crate::{
    Account, Answer, Decision, ImageType, Kind, PairingGrant, Purpose, Scope, Secret, VERSION,
    b64u, check, client, pairing,
    signed::{self, Direction},
};

/// One signed message: what was signed, the signature and the plaintext that went into HPKE.
pub(super) fn signed_vector(
    name: &str,
    hpke: &str,
    direction: Direction,
    signer: &Side,
    agent: &Side,
    phone: &Side,
    body: &[u8],
) -> (Value, Vec<u8>) {
    let plain = signed::sign(
        direction,
        &agent.id,
        &phone.id,
        body,
        &signer.keys.signing_key(),
    )
    .expect("sign");
    let split = signed::split(&plain).expect("signed");
    let text = |b: &[u8]| String::from_utf8(b.to_vec()).expect("utf-8");
    let v = json!({
        "name": name,
        "hpke": hpke,
        "direction": direction.name(),
        "agent_id": agent.id,
        "phone_id": phone.id,
        "sign_pk": signer.keys.public().sign_b64u(),
        "body": text(body),
        "message": text(&signed::message(direction, &agent.id, &phone.id, body)),
        "sig": b64u::encode(&split.sig),
        "plaintext": text(&plain),
    });
    (v, plain)
}

/// Adds the HPKE vectors and returns the `pairing` and `signed` sections.
pub(super) fn add(ctx: &mut Ctx, agent: &Side, phone: &Side) -> (Value, Value) {
    let (ap, pp) = (agent.keys.public(), phone.keys.public());
    let agent_nonce = label32("nodkey/v1/vectors/pairing/agent_nonce");
    let phone_nonce = label32("nodkey/v1/vectors/pairing/phone_nonce");
    let commit = pairing::commit(&pp, &phone_nonce);
    let number = pairing::check_number(&ap, &pp, &agent_nonce, &phone_nonce);

    let grant = PairingGrant {
        v: VERSION,
        phone_name: "Test iPhone".into(),
        scope: Scope::Selected,
        check: None,
        commit: Some(b64u::encode(&commit)),
    };
    ctx.seal(
        "pairing_grant_commit",
        Purpose::Pairing,
        "phone",
        agent,
        format!("{}{}", super::CODE, phone.id),
        &to_json(&grant),
        true,
    );

    let mut check_req = pairing::check_request("Agent \u{b7} Horizon", &agent_nonce, TS);
    check_req.request_id = label_id("nodkey/v1/vectors/request/pairing_check");
    let check_ans = pairing::check_answer(&check_req.request_id, &phone_nonce);

    let rid_code = label_id("nodkey/v1/vectors/request/code_signed");
    let r_code = request(
        &rid_code,
        Kind::Code,
        "github.com/alex",
        "Merge PR #42",
        None,
    );
    let mut a_code = Answer::decision(&rid_code, Decision::Approved);
    a_code.account = Some(Account {
        issuer: "GitHub".into(),
        name: "alex".into(),
        site: Some("github.com".into()),
        sites: None,
    });
    a_code.code = Some(Secret::new("190274"));
    a_code.seconds_left = Some(12);

    // The picture of the attachment vector, with its hash; same request id, so `attachment_png`
    // is this request's picture too.
    let rid_login = label_id("nodkey/v1/vectors/request/login");
    let r_login = request(
        &rid_login,
        Kind::Login,
        "vg.no",
        "Sign in to read the article a friend sent",
        Some(client::attachment_info(
            ImageType::Png,
            &PNG,
            Some("vg.no login page".into()),
        )),
    );

    let mut signed_list = Vec::new();
    for (name, direction, json) in [
        (
            "request_pairing_check",
            Direction::Request,
            to_json(&check_req),
        ),
        (
            "answer_pairing_check",
            Direction::Answer,
            to_json(&check_ans),
        ),
        ("request_code_signed", Direction::Request, to_json(&r_code)),
        ("answer_code_signed", Direction::Answer, to_json(&a_code)),
        (
            "request_login_signed_with_attachment",
            Direction::Request,
            to_json(&r_login),
        ),
    ] {
        let (signer, recipient, purpose, aad_id) = match direction {
            Direction::Request => (agent, phone, Purpose::Request, &agent.id),
            Direction::Answer => (phone, agent, Purpose::Answer, &phone.id),
        };
        let (v, plain) = signed_vector(name, name, direction, signer, agent, phone, &json);
        let rid: Value = serde_json::from_slice(&json).expect("json");
        let rid = rid["request_id"].as_str().expect("request_id");
        ctx.seal(
            name,
            purpose,
            if direction == Direction::Request {
                "agent"
            } else {
                "phone"
            },
            recipient,
            format!("{rid}{aad_id}"),
            &plain,
            true,
        );
        signed_list.push(v);
    }

    let section = json!({
        "agent_nonce": b64u::encode(&agent_nonce),
        "phone_nonce": b64u::encode(&phone_nonce),
        "commit": b64u::encode(&commit),
        "number": number,
        "digits": check::digits(number),
        "display": check::display(number),
        "grant": "pairing_grant_commit",
        "check_request": "request_pairing_check",
        "check_answer": "answer_pairing_check",
        "attachment_sha256": b64u::encode(&Sha256::digest(PNG)),
    });
    (section, Value::Array(signed_list))
}
