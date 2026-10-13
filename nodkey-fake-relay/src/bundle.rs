//! The fake phone's answer to a `bundle`: each item as the single code or login answer would be,
//! except items whose target starts with `deny.`, which the user leaves out. The bundle is
//! `approved` when at least one item is.

use nodkey_proto::{
    Account, Answer, BundleItemAnswer, Decision, Kind, Lease, LeaseKind, MatchKind, Request, Secret,
};

use crate::{CODE, PASSWORD, USERNAME};

pub fn answer(request: &Request, rid: &str) -> Answer {
    let items: Vec<BundleItemAnswer> = request
        .bundle
        .iter()
        .flat_map(|b| &b.items)
        .map(|item| {
            if item.target.starts_with("deny.") {
                return BundleItemAnswer::decision(&item.id, Decision::Denied);
            }
            let mut a = BundleItemAnswer::decision(&item.id, Decision::Approved);
            a.lease = Some(Lease {
                kind: LeaseKind::Once,
                until: None,
            });
            a.match_kind = Some(MatchKind::Direct);
            let site = item.target.split('/').next().unwrap_or_default().to_owned();
            a.account = Some(Account {
                issuer: site.clone(),
                name: USERNAME.into(),
                site: Some(site),
                sites: None,
            });
            if item.kind == Kind::Login {
                a.username = Some(USERNAME.into());
                a.password = Some(Secret::new(PASSWORD));
            } else {
                a.code = Some(Secret::new(CODE));
                a.seconds_left = Some(17);
            }
            a
        })
        .collect();
    let approved = items.iter().any(|i| i.decision == Decision::Approved);
    let mut answer = Answer::decision(
        rid,
        if approved {
            Decision::Approved
        } else {
            Decision::Denied
        },
    );
    answer.items = Some(items);
    answer
}
