//! Task session vectors: a plan with a login, a code and a passkey for 30 minutes and the phone's
//! answer that starts the session, a code request inside the session answered under it (with the
//! next code, because the current one is about to run out), and the request that ends it.

use super::{Ctx, Side, label_id, request, to_json};
use crate::{
    Account, Answer, BundleItem, BundleItemAnswer, BundleRequest, Decision, Kind, Lease, LeaseKind,
    MatchKind, Purpose, Secret, SessionInfo,
};

const SESSION_ID: &str = "Qm9vdHN0cmFwU2Vzc2lvbg";
const UNTIL: u64 = super::TS + 1800;

fn item(id: &str, kind: Kind, target: &str) -> BundleItem {
    BundleItem {
        id: id.into(),
        kind,
        target: target.into(),
    }
}

fn account(issuer: &str, name: &str, site: &str) -> Account {
    Account {
        issuer: issuer.into(),
        name: name.into(),
        site: Some(site.into()),
        sites: None,
    }
}

fn session_lease() -> Lease {
    Lease {
        kind: LeaseKind::Session,
        until: Some(UNTIL),
    }
}

pub(super) fn add(ctx: &mut Ctx, agent: &Side, phone: &Side) {
    let rid = label_id("nodkey/v1/vectors/request/bundle_session");
    let mut r = request(
        &rid,
        Kind::Bundle,
        "",
        "Upload the release to the add-on store",
        None,
    );
    r.bundle = Some(BundleRequest {
        items: vec![
            item("1", Kind::Login, "accounts.example.com"),
            item("2", Kind::Code, "accounts.example.com"),
            item("3", Kind::Passkey, "github.com"),
        ],
        follow_up: None,
        session: Some(1800),
    });
    let to_phone = |rid: &str| format!("{rid}{}", agent.id);
    let to_agent = |rid: &str| format!("{rid}{}", phone.id);
    ctx.seal(
        "request_bundle_session",
        Purpose::Request,
        "agent",
        phone,
        to_phone(&rid),
        &to_json(&r),
        true,
    );

    let mut login = BundleItemAnswer::decision("1", Decision::Approved);
    login.account = Some(account(
        "Example",
        "alex@example.com",
        "accounts.example.com",
    ));
    login.match_kind = Some(MatchKind::Direct);
    login.username = Some("alex@example.com".into());
    login.password = Some(Secret::new("correct horse battery staple"));
    login.lease = Some(session_lease());
    let mut code = BundleItemAnswer::decision("2", Decision::Approved);
    code.account = Some(account(
        "Example",
        "alex@example.com",
        "accounts.example.com",
    ));
    code.match_kind = Some(MatchKind::Direct);
    code.code = Some(Secret::new("190274"));
    code.seconds_left = Some(21);
    code.lease = Some(session_lease());
    let mut passkey = BundleItemAnswer::decision("3", Decision::Approved);
    passkey.account = Some(account("github.com", "alex", "github.com"));
    let mut a = Answer::decision(&rid, Decision::Approved);
    a.items = Some(vec![login, code, passkey]);
    a.session = Some(SessionInfo {
        id: SESSION_ID.into(),
        until: UNTIL,
    });
    ctx.seal(
        "answer_bundle_session",
        Purpose::Answer,
        "phone",
        agent,
        to_agent(&rid),
        &to_json(&a),
        true,
    );

    let rid = label_id("nodkey/v1/vectors/request/code_in_session");
    let mut r = request(
        &rid,
        Kind::Code,
        "accounts.example.com",
        "A fresh code for the second sign-in step",
        None,
    );
    r.session_id = Some(SESSION_ID.into());
    ctx.seal(
        "request_code_in_session",
        Purpose::Request,
        "agent",
        phone,
        to_phone(&rid),
        &to_json(&r),
        true,
    );
    let mut a = Answer::decision(&rid, Decision::Approved);
    a.account = Some(account(
        "Example",
        "alex@example.com",
        "accounts.example.com",
    ));
    a.match_kind = Some(MatchKind::Direct);
    a.code = Some(Secret::new("944570"));
    a.seconds_left = Some(4);
    a.next_code = Some(Secret::new("582911"));
    a.next_seconds_left = Some(34);
    a.lease = Some(session_lease());
    ctx.seal(
        "answer_code_in_session",
        Purpose::Answer,
        "phone",
        agent,
        to_agent(&rid),
        &to_json(&a),
        true,
    );

    let rid = label_id("nodkey/v1/vectors/request/session_end");
    let mut r = request(&rid, Kind::SessionEnd, "", "The upload is done", None);
    r.session_id = Some(SESSION_ID.into());
    ctx.seal(
        "request_session_end",
        Purpose::Request,
        "agent",
        phone,
        to_phone(&rid),
        &to_json(&r),
        true,
    );
}
