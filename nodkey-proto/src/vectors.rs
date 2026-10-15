//! Deterministic test vectors (`vectors/v1.json`), shared with the iOS tests.
//!
//! Private keys are fixed (SHA-256 of a label) and HPKE ephemeral keys come from a seeded
//! [`DetRng`], so the file is byte-for-byte reproducible. A recipient (the phone, or CryptoKit in
//! the iOS tests) checks each HPKE vector by opening `enc`/`ct` with `recipient_kem_sk`, `info` and
//! `aad` and comparing with the plaintext; a sender cannot reproduce `enc` without fixing the
//! ephemeral key, which `ikm_e` (RFC 9180 `ikmE`, the input to DeriveKeyPair) allows where the
//! library supports it.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    Account, AccountEntry, Answer, AttachmentInfo, CleanupFilter, Decision, ImageType, KeyPair,
    Kind, Lease, LeaseKind, PairingGrant, Purpose, Request, Scope, Secret, VERSION, auth, b64u,
    check, code,
    seal::{ENC_LEN, seal_with_rng},
    testing::DetRng,
};

/// Timestamp used throughout the vectors.
pub const TS: u64 = 1_791_620_000;

/// Pairing code used in the vectors (canonical form).
pub const CODE: &str = "K7P2QX";

/// A 2×2 PNG (76 bytes), the attachment in the vectors.
pub const PNG: [u8; 76] = [
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x08, 0x02, 0x00, 0x00, 0x00, 0xfd, 0xd4, 0x9a,
    0x73, 0x00, 0x00, 0x00, 0x13, 0x49, 0x44, 0x41, 0x54, 0x78, 0xda, 0x63, 0x90, 0x9d, 0x1d, 0x07,
    0x44, 0x0c, 0x5f, 0x3e, 0xbe, 0x01, 0x22, 0x00, 0x2a, 0x21, 0x07, 0xcf, 0x19, 0x1b, 0xa8, 0x4c,
    0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
];

mod bundle;
mod card;
mod matching;
pub mod passkey;
mod save;
mod session;
fn label32(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

fn label_id(label: &str) -> String {
    b64u::encode(&label32(label)[..crate::ID_LEN])
}

/// Fixed keys and id of one side.
pub struct Side {
    pub id: String,
    pub keys: KeyPair,
}

impl Side {
    /// The vectors' agent or phone (`who` = `"agent"` or `"phone"`).
    pub fn fixed(who: &str) -> Self {
        Side {
            id: label_id(&format!("nodkey/v1/vectors/{who}/id")),
            keys: KeyPair::from_bytes(
                label32(&format!("nodkey/v1/vectors/{who}/kem")),
                label32(&format!("nodkey/v1/vectors/{who}/sign")),
            ),
        }
    }

    fn to_json(&self) -> Value {
        let p = self.keys.public();
        json!({
            "id": self.id,
            "kem_sk": b64u::encode(self.keys.kem_secret()),
            "kem_pk": p.kem_b64u(),
            "sign_sk": b64u::encode(self.keys.sign_secret()),
            "sign_pk": p.sign_b64u(),
        })
    }
}

struct Ctx {
    rng: DetRng,
    hpke: Vec<Value>,
}

impl Ctx {
    #[allow(clippy::too_many_arguments)]
    fn seal(
        &mut self,
        name: &str,
        purpose: Purpose,
        sender: &str,
        recipient: &Side,
        aad_str: String,
        plaintext: &[u8],
        text: bool,
    ) -> crate::SealedBox {
        let ikm_e: [u8; 32] = self.rng.clone().take();
        let pk = recipient.keys.public().kem;
        let s = seal_with_rng(
            purpose.info().as_bytes(),
            &pk,
            aad_str.as_bytes(),
            plaintext,
            &mut self.rng,
        )
        .expect("seal");
        let mut v = json!({
            "name": name,
            "purpose": format!("{purpose:?}").to_lowercase(),
            "sender": sender,
            "info": purpose.info(),
            "aad": aad_str,
            "recipient_kem_sk": b64u::encode(recipient.keys.kem_secret()),
            "recipient_kem_pk": b64u::encode(&pk),
            "ikm_e": b64u::encode(&ikm_e),
            "enc": b64u::encode(&s.enc),
            "ct": b64u::encode(&s.ct),
            "plaintext_b64u": b64u::encode(plaintext),
        });
        if text {
            v["plaintext"] = Value::String(String::from_utf8(plaintext.to_vec()).expect("utf-8"));
        }
        if purpose == Purpose::Attachment {
            let mut body = Vec::with_capacity(ENC_LEN + s.ct.len());
            body.extend_from_slice(&s.enc);
            body.extend_from_slice(&s.ct);
            v["body_b64u"] = Value::String(b64u::encode(&body));
        }
        self.hpke.push(v);
        s.to_box()
    }
}

fn auth_vector(name: &str, signer: &Side, method: &str, path: &str, ts: u64, body: &[u8]) -> Value {
    json!({
        "name": name,
        "id": signer.id,
        "sign_pk": signer.keys.public().sign_b64u(),
        "method": method,
        "path": path,
        "ts": ts,
        "body": String::from_utf8(body.to_vec()).expect("utf-8"),
        "body_sha256": b64u::hex(&Sha256::digest(body)),
        "message": auth::message(method, path, ts, body),
        "header": auth::sign(&signer.keys.signing_key(), &signer.id, method, path, ts, body),
    })
}

fn to_json<T: serde::Serialize>(v: &T) -> Vec<u8> {
    serde_json::to_vec(v).expect("serialize")
}

/// Builds the whole vector document.
/// A request as the vectors' agent sends it.
fn request(
    rid: &str,
    kind: Kind,
    target: &str,
    reason: &str,
    attachment: Option<AttachmentInfo>,
) -> Request {
    Request {
        v: VERSION,
        request_id: rid.to_owned(),
        kind,
        target: target.into(),
        reason: reason.into(),
        agent: "Agent \u{b7} Horizon".into(),
        ts: TS,
        attachment,
        filter: None,
        save: None,
        passkey: None,
        bundle: None,
        card: None,
        save_card: None,
        client: None,
        session_id: None,
    }
}

pub fn build() -> Value {
    let agent = Side::fixed("agent");
    let phone = Side::fixed("phone");
    let ap = agent.keys.public();
    let pp = phone.keys.public();
    let check_n = check::check_number(&ap, &pp);

    let mut ctx = Ctx {
        rng: DetRng::new(b"nodkey/v1/vectors"),
        hpke: Vec::new(),
    };

    // Pairing grant, phone -> agent.
    let grant = PairingGrant {
        v: VERSION,
        phone_name: "Test iPhone".into(),
        scope: Scope::Selected,
        check: check::digits(check_n),
    };
    ctx.seal(
        "pairing_grant",
        Purpose::Pairing,
        "phone",
        &agent,
        format!("{CODE}{}", phone.id),
        &to_json(&grant),
        true,
    );

    // Requests, agent -> phone.
    let rid_code = label_id("nodkey/v1/vectors/request/code");
    let rid_login = label_id("nodkey/v1/vectors/request/login");
    let rid_list = label_id("nodkey/v1/vectors/request/list");
    let r_code = request(
        &rid_code,
        Kind::Code,
        "github.com/alex",
        "Merge PR #42",
        None,
    );
    let r_login = request(
        &rid_login,
        Kind::Login,
        "vg.no",
        "Sign in to read the article a friend sent",
        Some(AttachmentInfo {
            kind: ImageType::Png,
            bytes: PNG.len() as u64,
            caption: Some("vg.no login page".into()),
        }),
    );
    let r_list = request(
        &rid_list,
        Kind::List,
        "",
        "See which accounts I may ask for",
        None,
    );
    for (name, r) in [
        ("request_code", &r_code),
        ("request_login_with_attachment", &r_login),
        ("request_list", &r_list),
    ] {
        ctx.seal(
            name,
            Purpose::Request,
            "agent",
            &phone,
            format!("{}{}", r.request_id, agent.id),
            &to_json(r),
            true,
        );
    }
    ctx.seal(
        "attachment_png",
        Purpose::Attachment,
        "agent",
        &phone,
        format!("{rid_login}{}", agent.id),
        &PNG,
        false,
    );

    // Answers, phone -> agent.
    let github = Account {
        issuer: "GitHub".into(),
        name: "alex".into(),
        site: Some("github.com".into()),
        sites: None,
    };
    let mut a_code = Answer::decision(&rid_code, Decision::Approved);
    a_code.lease = Some(Lease {
        kind: LeaseKind::Once,
        until: None,
    });
    a_code.account = Some(github.clone());
    a_code.code = Some(Secret::new("190274"));
    a_code.seconds_left = Some(12);

    let mut a_login = Answer::decision(&rid_login, Decision::Approved);
    a_login.lease = Some(Lease {
        kind: LeaseKind::Day,
        until: Some(TS + 86_400),
    });
    a_login.account = Some(Account {
        issuer: "VG".into(),
        name: "alex@example.com".into(),
        site: Some("vg.no".into()),
        sites: None,
    });
    a_login.username = Some("alex@example.com".into());
    a_login.password = Some(Secret::new("correct horse battery staple"));

    let a_denied = Answer::decision(&rid_code, Decision::Denied);
    let a_expired = Answer::decision(&rid_code, Decision::Expired);

    let mut a_list = Answer::decision(&rid_list, Decision::Approved);
    a_list.lease = Some(Lease {
        kind: LeaseKind::Always,
        until: None,
    });
    a_list.accounts = Some(vec![
        AccountEntry {
            issuer: "GitHub".into(),
            name: "alex".into(),
            site: Some("github.com".into()),
            has_code: true,
            has_password: true,
            sites: None,
        },
        AccountEntry {
            issuer: "VG".into(),
            name: "alex@example.com".into(),
            site: Some("vg.no".into()),
            has_code: false,
            has_password: true,
            sites: None,
        },
    ]);
    for (name, a) in [
        ("answer_code_approved", &a_code),
        ("answer_login_approved_day_lease", &a_login),
        ("answer_denied", &a_denied),
        ("answer_expired", &a_expired),
        ("answer_list", &a_list),
    ] {
        ctx.seal(
            name,
            Purpose::Answer,
            "phone",
            &agent,
            format!("{}{}", a.request_id, phone.id),
            &to_json(a),
            true,
        );
    }

    // Clean-up: a request with a filter, the answer listing what was moved, and the phone's
    // refusal of an empty filter. Sealed after the others so their bytes stay the same.
    let rid_cleanup = label_id("nodkey/v1/vectors/request/cleanup");
    let mut r_cleanup = request(
        &rid_cleanup,
        Kind::Cleanup,
        "",
        "Remove saved logins for old router addresses",
        None,
    );
    r_cleanup.filter = Some(CleanupFilter {
        ip_only: Some(true),
        last_used_before: Some(TS - 365 * 86_400),
        ..Default::default()
    });
    ctx.seal(
        "request_cleanup",
        Purpose::Request,
        "agent",
        &phone,
        format!("{rid_cleanup}{}", agent.id),
        &to_json(&r_cleanup),
        true,
    );
    let moved = |issuer: &str, name: &str, site: &str| AccountEntry {
        issuer: issuer.into(),
        name: name.into(),
        site: Some(site.into()),
        has_code: false,
        has_password: true,
        sites: None,
    };
    let mut a_cleanup = Answer::decision(&rid_cleanup, Decision::Approved);
    a_cleanup.moved = Some(2);
    a_cleanup.accounts = Some(vec![
        moved("192.168.1.1", "admin", "192.168.1.1"),
        moved("Printer", "demo", "10.0.0.138"),
    ]);
    let mut a_refused = Answer::decision(&rid_cleanup, Decision::Denied);
    a_refused.error = Some("empty_filter".into());
    for (name, a) in [
        ("answer_cleanup", &a_cleanup),
        ("answer_cleanup_empty_filter", &a_refused),
    ] {
        ctx.seal(
            name,
            Purpose::Answer,
            "phone",
            &agent,
            format!("{}{}", a.request_id, phone.id),
            &to_json(a),
            true,
        );
    }

    save::add(&mut ctx, &agent, &phone);
    let webauthn = passkey::add(&mut ctx, &agent, &phone); // After the others: their bytes stay.
    matching::add(&mut ctx, &agent, &phone);
    bundle::add(&mut ctx, &agent, &phone);
    let cards = card::add(&mut ctx, &agent, &phone); // Last: earlier bytes stay the same.
    session::add(&mut ctx, &agent, &phone); // After cards: earlier bytes stay the same.

    // Signed relay calls.
    let agent_info = crate::AgentInfo {
        agent_id: agent.id.clone(),
        name: "Coding agent @ dev-laptop".into(),
        sign: ap.sign_b64u(),
        kem: ap.kem_b64u(),
    };
    let reg = crate::PhoneRegistration {
        sign: pp.sign_b64u(),
        kem: pp.kem_b64u(),
        apns_token: None,
        apns_sandbox: None,
    };
    let by_name = |name: &str| {
        ctx.hpke
            .iter()
            .find(|v| v["name"] == name)
            .expect("vector")
            .clone()
    };
    let grant_v = by_name("pairing_grant");
    let claim = json!({"enc": grant_v["enc"], "ct": grant_v["ct"]});
    let req_v = by_name("request_code");
    let envelope = |v: &Value, rid: &str, attachment: Option<bool>| crate::RequestEnvelope {
        request_id: rid.to_owned(),
        enc: v["enc"].as_str().expect("enc").to_owned(),
        ct: v["ct"].as_str().expect("ct").to_owned(),
        attachment,
    };
    let env_code = envelope(&req_v, &rid_code, None);
    let env_login = envelope(
        &by_name("request_login_with_attachment"),
        &rid_login,
        Some(true),
    );
    let ans_v = by_name("answer_code_approved");
    let answer_box = json!({"enc": ans_v["enc"], "ct": ans_v["ct"]});
    let pid = &phone.id;
    let mut auth = vec![
        auth_vector(
            "register_phone",
            &phone,
            "PUT",
            &format!("/v1/phones/{pid}"),
            TS,
            &to_json(&reg),
        ),
        auth_vector(
            "start_pairing",
            &agent,
            "POST",
            "/v1/pairings",
            TS,
            &to_json(&agent_info),
        ),
        auth_vector(
            "claim_pairing",
            &phone,
            "POST",
            &format!("/v1/pairings/{CODE}/claim"),
            TS,
            &to_json(&claim),
        ),
        auth_vector(
            "wait_pairing",
            &agent,
            "GET",
            &format!("/v1/pairings/{CODE}?wait=60"),
            TS + 1,
            b"",
        ),
        auth_vector(
            "post_request",
            &agent,
            "POST",
            &format!("/v1/phones/{pid}/requests"),
            TS + 2,
            &to_json(&env_code),
        ),
        auth_vector(
            "post_request_with_attachment",
            &agent,
            "POST",
            &format!("/v1/phones/{pid}/requests"),
            TS + 2,
            &to_json(&env_login),
        ),
        auth_vector(
            "poll_requests",
            &phone,
            "GET",
            &format!("/v1/phones/{pid}/requests?wait=25"),
            TS + 3,
            b"",
        ),
        auth_vector(
            "post_answer",
            &phone,
            "POST",
            &format!("/v1/requests/{rid_code}/answer"),
            TS + 4,
            &to_json(&answer_box),
        ),
        auth_vector(
            "wait_answer",
            &agent,
            "GET",
            &format!("/v1/requests/{rid_code}?wait=60"),
            TS + 5,
            b"",
        ),
        auth_vector(
            "remove_agent",
            &phone,
            "DELETE",
            &format!("/v1/phones/{pid}/agents/{}", agent.id),
            TS + 6,
            b"",
        ),
        auth_vector(
            "agent_leaves",
            &agent,
            "DELETE",
            &format!("/v1/agents/{}/phones/{pid}", agent.id),
            TS + 7,
            b"",
        ),
    ];
    // The attachment upload has a binary body; give the body as b64u instead of text.
    let att = by_name("attachment_png");
    let att_body = b64u::decode(att["body_b64u"].as_str().expect("body")).expect("b64u");
    let att_path = format!("/v1/requests/{rid_login}/attachment");
    let auth_att = json!({
        "name": "put_attachment",
        "id": agent.id,
        "sign_pk": ap.sign_b64u(),
        "method": "PUT",
        "path": att_path,
        "ts": TS + 2,
        "body_b64u": att["body_b64u"],
        "body_sha256": b64u::hex(&Sha256::digest(&att_body)),
        "message": auth::message("PUT", &att_path, TS + 2, &att_body),
        "header": auth::sign(&agent.keys.signing_key(), &agent.id, "PUT", &att_path, TS + 2, &att_body),
    });
    auth.push(auth_att);

    json!({
        "version": 1,
        "about": "Nodkey agent protocol v1 test vectors (docs/agent-protocol.md). Generated by \
                  `cargo run -p nodkey-proto --example vectors`; do not edit by hand. Binary values \
                  are base64url without padding. Private keys are fixed test keys, never real ones.",
        "suite": {
            "mode": "base",
            "kem": "DHKEM(X25519, HKDF-SHA256)", "kem_id": 32,
            "kdf": "HKDF-SHA256", "kdf_id": 1,
            "aead": "ChaCha20-Poly1305", "aead_id": 3,
        },
        "keys": { "agent": agent.to_json(), "phone": phone.to_json() },
        "check": {
            "agent_sign": ap.sign_b64u(),
            "agent_kem": ap.kem_b64u(),
            "phone_sign": pp.sign_b64u(),
            "phone_kem": pp.kem_b64u(),
            "number": check_n,
            "digits": check::digits(check_n),
            "display": check::display(check_n),
        },
        "pairing_code": {
            "code": CODE,
            "display": code::display(CODE),
            "normalize": [
                {"input": "K7P-2QX", "code": "K7P2QX"},
                {"input": " k7p 2qx ", "code": "K7P2QX"},
                {"input": "OIL-abc", "code": "011ABC"},
            ],
            "invalid": ["K7P-2QU", "K7P-2Q", "K7P-2QXX", "K7P_2QX"],
        },
        "hpke": ctx.hpke,
        "auth": auth,
        "webauthn": webauthn,
        "cards": cards,
    })
}
