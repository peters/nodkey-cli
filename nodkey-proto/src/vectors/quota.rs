//! Agent limit vectors: answers the phone sends with the limit warning (a code, a login under the
//! burst rule, a bundle), a pause by the user and a pause by the limit, and the `quota` section with
//! the numbers both sides use.

use serde_json::{Value, json};

use super::{Ctx, Side, label_id, to_json};
use crate::{
    Account, Answer, BundleItemAnswer, Decision, Lease, LeaseKind, Purpose, Quota, Secret, quota,
};

fn github() -> Account {
    Account {
        issuer: "GitHub".into(),
        name: "alex".into(),
        site: Some("github.com".into()),
        sites: None,
    }
}

fn warned(a: &mut Answer, new_today: u32, burst: bool) {
    a.error = Some(quota::errors::QUOTA_WARNING.into());
    a.quota = Some(Quota {
        new_today,
        limit: quota::DEFAULT_LIMIT,
        burst,
    });
}

/// Adds the HPKE vectors and returns the `quota` section.
pub(super) fn add(ctx: &mut Ctx, agent: &Side, phone: &Side) -> Value {
    let rid_code = label_id("nodkey/v1/vectors/request/code");
    let rid_login = label_id("nodkey/v1/vectors/request/login");
    let rid_bundle = label_id("nodkey/v1/vectors/request/bundle");
    let once = || Lease {
        kind: LeaseKind::Once,
        until: None,
    };
    let mut answers = Vec::new();

    let mut a = Answer::decision(&rid_code, Decision::Approved);
    a.lease = Some(once());
    a.account = Some(github());
    a.code = Some(Secret::new("190274"));
    a.seconds_left = Some(12);
    warned(&mut a, 12, false);
    answers.push(("answer_code_quota_warning", a));

    let mut a = Answer::decision(&rid_login, Decision::Approved);
    a.lease = Some(once());
    a.account = Some(Account {
        issuer: "VG".into(),
        name: "alex@example.com".into(),
        site: Some("vg.no".into()),
        sites: None,
    });
    a.username = Some("alex@example.com".into());
    a.password = Some(Secret::new("correct horse battery staple"));
    warned(&mut a, 6, true);
    answers.push(("answer_login_quota_warning_burst", a));

    // A plan above the limit: asked as a bundle without a session; the user left out one item.
    let mut item = BundleItemAnswer::decision("1", Decision::Approved);
    item.lease = Some(once());
    item.account = Some(github());
    item.code = Some(Secret::new("190274"));
    item.seconds_left = Some(12);
    let mut a = Answer::decision(&rid_bundle, Decision::Approved);
    a.items = Some(vec![
        item,
        BundleItemAnswer::decision("2", Decision::Denied),
    ]);
    warned(&mut a, 11, false);
    answers.push(("answer_bundle_quota_warning", a));

    let mut a = Answer::decision(&rid_code, Decision::Denied);
    a.error = Some(quota::errors::PAUSED.into());
    answers.push(("answer_paused", a.clone()));
    a.quota = Some(Quota {
        new_today: quota::PAUSE_ABOVE,
        limit: quota::DEFAULT_LIMIT,
        burst: false,
    });
    answers.push(("answer_paused_by_limit", a));

    for (name, a) in &answers {
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

    json!({
        "default_limit": quota::DEFAULT_LIMIT,
        "limit_choices": quota::LIMIT_CHOICES,
        "pause_above": quota::PAUSE_ABOVE,
        "window_seconds": quota::WINDOW_SECONDS,
        "new_after_seconds": quota::NEW_AFTER_SECONDS,
        "burst_count": quota::BURST_COUNT,
        "burst_seconds": quota::BURST_SECONDS,
        "ok_for_today_seconds": quota::OK_FOR_TODAY_SECONDS,
        "errors": [quota::errors::QUOTA_WARNING, quota::errors::PAUSED],
    })
}
