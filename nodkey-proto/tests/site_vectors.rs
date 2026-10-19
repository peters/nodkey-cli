//! Checks the `sites` section of `vectors/v1.json` the way the phone and every agent must: the
//! public suffix list snapshot is the file in `nodkey-proto/data`, and each case comes out the
//! same from `nodkey_proto::site` and `nodkey_proto::signin`.

use nodkey_proto::{Account, MatchKind, Provider, SignInMethod, Via, b64u, signin, site};
use serde_json::Value;
use sha2::{Digest, Sha256};

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/v1.json");
const PSL: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/data/public_suffix_list.dat");

fn sites() -> Value {
    let v: Value = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    v["sites"].clone()
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str()
        .unwrap_or_else(|| panic!("{k} missing in {v}"))
}

fn list(v: &Value) -> Vec<String> {
    serde_json::from_value(v.clone()).unwrap()
}

#[test]
fn snapshot_is_the_bundled_file() {
    let c = sites();
    let bytes = std::fs::read(PSL).unwrap();
    assert_eq!(b64u::hex(&Sha256::digest(&bytes)), s(&c["psl"], "sha256"));
    let (version, commit) = site::version();
    assert_eq!(version, s(&c["psl"], "version"));
    assert_eq!(commit, s(&c["psl"], "commit"));
    assert_eq!(
        site::rule_count() as u64,
        c["psl"]["rules"].as_u64().unwrap()
    );
}

#[test]
fn hosts_registrable_domains_and_same_site() {
    let c = sites();
    for h in c["hosts"].as_array().unwrap() {
        assert_eq!(
            site::host(s(h, "input")).as_deref(),
            h["host"].as_str(),
            "{h}"
        );
    }
    for r in c["registrable"].as_array().unwrap() {
        let host = s(r, "host");
        assert_eq!(
            site::registrable_domain(host).as_deref(),
            r["registrable_domain"].as_str(),
            "{r}"
        );
        assert_eq!(
            site::public_suffix(host).as_deref(),
            r["public_suffix"].as_str(),
            "{r}"
        );
        assert_eq!(
            site::is_public_suffix(host),
            r["is_public_suffix"].as_bool().unwrap(),
            "{r}"
        );
    }
    for p in c["same_site"].as_array().unwrap() {
        assert_eq!(
            site::same_site(s(p, "a"), s(p, "b")),
            p["same"].as_bool().unwrap(),
            "{p}"
        );
    }
}

#[test]
fn fill_rules() {
    let c = sites();
    for f in c["fill_only_on"].as_array().unwrap() {
        let account: Account = serde_json::from_value(f["account"].clone()).unwrap();
        let kind: Option<MatchKind> = serde_json::from_value(f["match"].clone()).unwrap();
        assert_eq!(
            site::fill_only_on(s(f, "target"), &account, kind),
            list(&f["fill_only_on"]),
            "{f}"
        );
    }
    for m in c["may_fill"].as_array().unwrap() {
        assert_eq!(
            site::may_fill(s(m, "page"), &list(&m["sites"])),
            m["allowed"].as_bool().unwrap(),
            "{m}"
        );
    }
    for f in c["via_fill"].as_array().unwrap() {
        let method: SignInMethod = serde_json::from_value(f["method"].clone()).unwrap();
        let via: Via = serde_json::from_value(serde_json::json!({
            "account": {"issuer": "Provider", "name": "alex@example.com", "site": f["via_site"]}
        }))
        .unwrap();
        assert_eq!(
            signin::may_fill_via(s(f, "host"), s(f, "target"), &method, &via),
            f["allowed"].as_bool().unwrap(),
            "{f}"
        );
    }
    for p in c["provider_sign_in_hosts"].as_array().unwrap() {
        let provider: Provider = serde_json::from_value(p["provider"].clone()).unwrap();
        assert_eq!(provider.sign_in_hosts(), list(&p["hosts"]).as_slice());
    }
}
