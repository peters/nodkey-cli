//! Bundle vectors: a request for a login and a code at once, and the phone's answer with the login
//! approved through an extra website and the code left out.

use super::{Ctx, Side, label_id, request, to_json};
use crate::{
    Account, Answer, BundleItem, BundleItemAnswer, BundleRequest, Decision, Kind, Lease, LeaseKind,
    MatchKind, Purpose, Secret,
};

pub(super) fn add(ctx: &mut Ctx, agent: &Side, phone: &Side) {
    let rid = label_id("nodkey/v1/vectors/request/bundle");
    let mut r = request(
        &rid,
        Kind::Bundle,
        "",
        "Sign in to ChatGPT and GitHub to compare the notes",
        None,
    );
    r.bundle = Some(BundleRequest {
        items: vec![
            BundleItem {
                id: "1".into(),
                kind: Kind::Login,
                target: "chatgpt.com".into(),
            },
            BundleItem {
                id: "2".into(),
                kind: Kind::Code,
                target: "github.com/alex".into(),
            },
        ],
        follow_up: Some(300),
    });
    ctx.seal(
        "request_bundle",
        Purpose::Request,
        "agent",
        phone,
        format!("{rid}{}", agent.id),
        &to_json(&r),
        true,
    );
    let mut login = BundleItemAnswer::decision("1", Decision::Approved);
    login.lease = Some(Lease {
        kind: LeaseKind::Once,
        until: None,
    });
    login.account = Some(Account {
        issuer: "OpenAI".into(),
        name: "alex@example.com".into(),
        site: Some("openai.com".into()),
        sites: Some(vec!["chatgpt.com".into()]),
    });
    login.match_kind = Some(MatchKind::Alias);
    login.username = Some("alex@example.com".into());
    login.password = Some(Secret::new("correct horse battery staple"));
    let mut a = Answer::decision(&rid, Decision::Approved);
    a.items = Some(vec![
        login,
        BundleItemAnswer::decision("2", Decision::Denied),
    ]);
    ctx.seal(
        "answer_bundle",
        Purpose::Answer,
        "phone",
        agent,
        format!("{rid}{}", phone.id),
        &to_json(&a),
        true,
    );
}
