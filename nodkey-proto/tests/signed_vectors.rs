//! Checks the pairing and signature vectors in `vectors/v1.json`: the commitment and check number,
//! and every signed request and answer verifies with its sender's key, and only with it.

use nodkey_proto::{PublicKeys, b64u, check};
use serde_json::Value;

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/v1.json");

fn load() -> Value {
    serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap()
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or_else(|| panic!("{k} missing"))
}

fn arr32(v: &Value, k: &str) -> [u8; 32] {
    b64u::decode_array(s(v, k)).unwrap()
}

#[test]
fn pairing_and_signed_vectors() {
    use nodkey_proto::{
        Answer, Request, pairing,
        signed::{self, Direction},
    };
    let v = load();
    let keys = |side: &str| {
        let k = &v["keys"][side];
        (
            s(k, "id").to_owned(),
            PublicKeys::from_b64u(s(k, "sign_pk"), s(k, "kem_pk")).unwrap(),
        )
    };
    let ((agent_id, ap), (phone_id, pp)) = (keys("agent"), keys("phone"));
    let hpke = |name: &str| {
        v["hpke"]
            .as_array()
            .unwrap()
            .iter()
            .find(|h| h["name"] == name)
            .unwrap_or_else(|| panic!("{name}"))
            .clone()
    };
    let p = &v["pairing"];
    let (an, pn) = (arr32(p, "agent_nonce"), arr32(p, "phone_nonce"));
    assert_eq!(b64u::encode(&pairing::commit(&pp, &pn)), s(p, "commit"));
    let n = pairing::check_number(&ap, &pp, &an, &pn);
    assert_eq!(u64::from(n), p["number"].as_u64().unwrap());
    assert_eq!(check::display(n), s(p, "display"));
    let grant = pairing::read_grant(s(&hpke(s(p, "grant")), "plaintext").as_bytes()).unwrap();
    assert_eq!(b64u::encode(&grant.commit), s(p, "commit"));

    for sv in v["signed"].as_array().unwrap() {
        let name = s(sv, "name");
        let direction = match s(sv, "direction") {
            "request" => Direction::Request,
            _ => Direction::Answer,
        };
        let body = s(sv, "body").as_bytes();
        assert_eq!(s(sv, "agent_id"), agent_id);
        assert_eq!(s(sv, "phone_id"), phone_id);
        assert_eq!(
            signed::message(direction, &agent_id, &phone_id, body),
            s(sv, "message").as_bytes(),
            "{name}"
        );
        let plain = s(sv, "plaintext").as_bytes();
        assert_eq!(
            s(&hpke(s(sv, "hpke")), "plaintext").as_bytes(),
            plain,
            "{name}"
        );
        let sender = match direction {
            Direction::Request => ap.sign,
            Direction::Answer => pp.sign,
        };
        assert_eq!(b64u::encode(&sender), s(sv, "sign_pk"));
        let opened = signed::open(direction, &agent_id, &phone_id, plain, &sender, true).unwrap();
        assert!(opened.signed, "{name}");
        assert_eq!(&opened.body[..], body, "{name}");
        assert_eq!(
            b64u::encode(&signed::split(plain).unwrap().sig),
            s(sv, "sig")
        );
        // The other side's key, or the ids swapped, do not verify.
        let other = if sender == ap.sign { pp.sign } else { ap.sign };
        assert!(signed::open(direction, &agent_id, &phone_id, plain, &other, true).is_err());
        assert!(signed::open(direction, &phone_id, &agent_id, plain, &sender, true).is_err());
    }

    let req: Request =
        nodkey_proto::parse_plaintext(s(&hpke(s(p, "check_request")), "plaintext").as_bytes())
            .unwrap();
    assert_eq!(req.nonce.as_deref(), Some(s(p, "agent_nonce")));
    let ans: Answer =
        nodkey_proto::parse_plaintext(s(&hpke(s(p, "check_answer")), "plaintext").as_bytes())
            .unwrap();
    assert_eq!(pairing::finish(&ans, &grant, &ap, &pp, &an).unwrap(), n);

    let login: Request = nodkey_proto::parse_plaintext(
        s(&hpke("request_login_signed_with_attachment"), "plaintext").as_bytes(),
    )
    .unwrap();
    let picture = b64u::decode(s(&hpke("attachment_png"), "plaintext_b64u")).unwrap();
    use sha2::Digest;
    let hash = b64u::encode(&sha2::Sha256::digest(&picture));
    assert_eq!(
        login.attachment.unwrap().sha256.as_deref(),
        Some(hash.as_str())
    );
    assert_eq!(s(p, "attachment_sha256"), hash);
}
