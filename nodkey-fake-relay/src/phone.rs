//! What the fake phone holds and how it answers an approved request.

use nodkey_proto::{
    Account, AccountEntry, Answer, CleanupFilter, Kind, Lease, LeaseKind, Request, Secret,
};

use crate::{CODE, Fake, PASSWORD, USERNAME};

/// The fake phone's saved logins for clean-up requests (title, user name, site). Invented.
pub const SAVED_LOGINS: [(&str, &str, &str); 5] = [
    ("Router", "admin", "192.168.1.1"),
    ("Printer", "demo", "10.0.0.138:8080"),
    ("NAS", "admin", "[fe80::1]"),
    (
        "Old company mail",
        "alex@old-company.example",
        "mail.old-company.example",
    ),
    ("VG", USERNAME, "vg.no"),
];

/// The fake phone's clean-up: a small stand-in for the app's filter (ip_only, exact user name,
/// domain with subdomains).
pub fn cleanup_matches(filter: &CleanupFilter) -> Vec<AccountEntry> {
    let is_ip = |site: &str| {
        let host = site
            .trim_start_matches('[')
            .split([']', ':'])
            .next()
            .unwrap_or("");
        host.parse::<std::net::Ipv4Addr>().is_ok() || site.starts_with('[')
    };
    SAVED_LOGINS
        .iter()
        .filter(|(_, _, site)| filter.ip_only != Some(true) || is_ip(site))
        .filter(|(_, user, _)| {
            filter
                .username
                .as_deref()
                .is_none_or(|u| u.eq_ignore_ascii_case(user))
        })
        .filter(|(_, _, site)| {
            filter
                .domain
                .as_deref()
                .is_none_or(|d| *site == d || site.ends_with(&format!(".{d}")))
        })
        .map(|(title, user, site)| AccountEntry {
            issuer: (*title).into(),
            name: (*user).into(),
            site: Some((*site).into()),
            has_code: false,
            has_password: true,
            sites: None,
        })
        .collect()
}

/// Fills in an approved answer the way the phone would.
pub(crate) fn approve(fake: &Fake, answer: &mut Answer, request: &Request) {
    answer.lease = Some(Lease {
        kind: LeaseKind::Once,
        until: None,
    });
    match request.kind {
        Kind::Code => {
            answer.account = Some(Account {
                issuer: "GitHub".into(),
                name: "alex".into(),
                site: Some("github.com".into()),
                sites: None,
            });
            answer.code = Some(Secret::new(CODE));
            answer.seconds_left = Some(17);
        }
        Kind::Login => {
            answer.account = Some(Account {
                issuer: "VG".into(),
                name: USERNAME.into(),
                site: Some("vg.no".into()),
                sites: None,
            });
            answer.username = Some(USERNAME.into());
            answer.password = Some(Secret::new(PASSWORD));
        }
        Kind::List => {
            answer.cards = fake.cards.lock().unwrap().enabled.then(|| {
                vec![nodkey_proto::CardEntry {
                    title: "Test Visa".into(),
                    brand: "visa".into(),
                    last4: "4242".into(),
                }]
            });
            answer.accounts = Some(vec![AccountEntry {
                issuer: "GitHub".into(),
                name: "alex".into(),
                site: Some("github.com".into()),
                has_code: true,
                has_password: false,
                sites: None,
            }]);
        }
        Kind::Insights => {
            answer.insights = Some(serde_json::json!({
                "total": 712, "with_code": 40,
                "ages": {"never": 300, "over_5y": 50, "over_2y": 80, "over_1y": 60, "recent": 222},
                "ip_or_local": 23, "test_hosts": 7, "no_site": 4,
                "sites": [{"group": "d_3fa9c21b07e4", "logins": 47, "spread": 3, "last_used_year": 2019,
                           "never_used": 40, "added_year": 2017}],
                "usernames": [{"group": "u_19c2ab5f0d11", "logins": 31, "spread": 29, "never_used": 31,
                               "added_year": 2016, "email": true}]
            }));
        }
        Kind::Save => {
            // Never a lease: the user confirms every save.
            answer.lease = None;
            answer.saved = Some(nodkey_proto::Saved::Added);
        }
        Kind::Card => crate::cards::approve(answer, request),
        Kind::Passkey => {
            let passkey = request.passkey.as_ref().expect("checked before asking");
            crate::passkeys::approve(fake, answer, passkey);
        }
        Kind::Bundle => *answer = crate::bundle::answer(request, &answer.request_id.clone()),
        Kind::Cleanup => {
            // Never a lease: the user confirms every clean-up.
            answer.lease = None;
            let moved = cleanup_matches(request.filter.as_ref().expect("checked above"));
            answer.moved = Some(moved.len() as u32);
            answer.accounts = Some(moved);
        }
    }
}
