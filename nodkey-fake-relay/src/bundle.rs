//! The fake phone's answer to a `bundle`: each item as the single code or login answer would be,
//! except items whose target starts with `deny.`, which the user leaves out. The bundle is
//! `approved` when at least one item is.

use nodkey_proto::{Answer, BundleItemAnswer, Decision, Kind, Lease, LeaseKind, Request, Secret};

use crate::{CODE, Fake, PASSWORD, USERNAME};

pub fn answer(fake: &Fake, request: &Request, rid: &str) -> Answer {
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
            let site = item.target.split('/').next().unwrap_or_default();
            let (account, match_kind) = crate::phone::account(fake, site, &item.target);
            a.account = Some(account);
            a.match_kind = match_kind;
            if item.kind == Kind::Secret {
                a.account = None;
                a.match_kind = None;
                match crate::secrets::find(fake, &item.target, request.project.as_deref()) {
                    Some(key) => a.secret = Some(key),
                    None => {
                        let mut no = BundleItemAnswer::decision(&item.id, Decision::Denied);
                        no.error = Some(nodkey_proto::apikey::errors::NO_SECRET.into());
                        return no;
                    }
                }
                return a;
            }
            if item.kind == Kind::Login {
                a.username = Some(USERNAME.into());
                a.password = Some(Secret::new(PASSWORD));
            } else {
                a.code = Some(Secret::new(CODE));
                a.seconds_left = Some(17);
            }
            (a.method, a.via, a.second_step) = crate::signin::extras(fake, item.kind, &item.target);
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
