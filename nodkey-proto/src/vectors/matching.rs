//! Extra websites: a login answered with an account the user picked by hand (`match: chosen`,
//! with the account's extra websites), and a list answer that names extra websites.

use super::{Ctx, Side, label_id, request, to_json};
use crate::{
    Account, AccountEntry, Answer, Decision, Kind, Lease, LeaseKind, MatchKind, Purpose, Secret,
};

pub(super) fn add(ctx: &mut Ctx, agent: &Side, phone: &Side) {
    let rid = label_id("nodkey/v1/vectors/request/login_chosen");
    let r_login = request(
        &rid,
        Kind::Login,
        "chatgpt.com",
        "Sign in to ChatGPT to export the project notes",
        None,
    );
    ctx.seal(
        "request_login_chosen",
        Purpose::Request,
        "agent",
        phone,
        format!("{rid}{}", agent.id),
        &to_json(&r_login),
        true,
    );
    let mut a_login = Answer::decision(&rid, Decision::Approved);
    a_login.lease = Some(Lease {
        kind: LeaseKind::Once,
        until: None,
    });
    a_login.account = Some(Account {
        issuer: "OpenAI".into(),
        name: "alex@example.com".into(),
        site: Some("openai.com".into()),
        sites: Some(vec!["chatgpt.com".into()]),
    });
    a_login.match_kind = Some(MatchKind::Chosen);
    a_login.username = Some("alex@example.com".into());
    a_login.password = Some(Secret::new("correct horse battery staple"));

    let rid_list = label_id("nodkey/v1/vectors/request/list");
    let mut a_list = Answer::decision(&rid_list, Decision::Approved);
    a_list.accounts = Some(vec![AccountEntry {
        issuer: "OpenAI".into(),
        name: "alex@example.com".into(),
        site: Some("openai.com".into()),
        has_code: false,
        has_password: true,
        sites: Some(vec!["chatgpt.com".into(), "sora.com".into()]),
    }]);
    for (name, a) in [
        ("answer_login_chosen", &a_login),
        ("answer_list_with_sites", &a_list),
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
}
