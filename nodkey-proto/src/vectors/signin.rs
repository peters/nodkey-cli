//! Sign-in method vectors: a login answer for a site signed in to with Google (the method, the
//! Google login as `via` and the second step order), a login answer with a password method, a
//! code answer with a second step order, a `suggest` request with its `queued` and `rejected`
//! answers, an `sms_code` request with its answers, and the `signin` section: how methods read,
//! which rules a suggestion breaks, which second step to pick and where `via` may be filled.

use serde_json::{Value, json};

use super::{Ctx, Side, label_id, request, to_json};
use crate::{
    Account, Answer, Certainty, Decision, Kind, Lease, LeaseKind, MatchKind, MethodSource,
    Provider, Purpose, Request, SecondStep, SecondStepOrder, Secret, SignInKind, SignInMethod,
    SuggestOutcome, Suggestion, Via, client, signin,
};

fn account(issuer: &str, name: &str, site: &str) -> Account {
    Account {
        issuer: issuer.into(),
        name: name.into(),
        site: Some(site.into()),
        sites: None,
    }
}

fn google(certainty: Certainty) -> SignInMethod {
    SignInMethod {
        certainty: Some(certainty),
        ..SignInMethod::federated(Provider::Google, None)
    }
}

/// Adds the HPKE vectors and returns the `signin` section and the signed relay call of the
/// `sms_code` request (its envelope carries `ttl`).
pub(super) fn add(ctx: &mut Ctx, agent: &Side, phone: &Side) -> (Value, Value) {
    let to_phone = |rid: &str| format!("{rid}{}", agent.id);
    let to_agent = |rid: &str| format!("{rid}{}", phone.id);
    let send_request = |ctx: &mut Ctx, name: &str, r: &Request| {
        ctx.seal(
            name,
            Purpose::Request,
            "agent",
            phone,
            to_phone(&r.request_id),
            &to_json(r),
            true,
        )
    };

    // A site signed in to with Google: no password for the site itself, the Google login as via.
    let rid = label_id("nodkey/v1/vectors/request/login_federated");
    let r = request(
        &rid,
        Kind::Login,
        "renderfarm.example",
        "Sign in to the render farm to start the job",
        None,
    );
    send_request(ctx, "request_login_federated", &r);
    let mut a = Answer::decision(&rid, Decision::Approved);
    a.lease = Some(Lease {
        kind: LeaseKind::Once,
        until: None,
    });
    a.match_kind = Some(MatchKind::Direct);
    a.method = Some(google(Certainty::Confirmed));
    a.via = Some(Via {
        account: account("Google", "alex@example.com", "accounts.google.com"),
        username: Some("alex@example.com".into()),
        password: Some(Secret::new("correct horse battery staple")),
        code: Some(Secret::new("190274")),
        seconds_left: Some(21),
        next_code: None,
        next_seconds_left: None,
    });
    a.second_step = Some(SecondStepOrder::default());
    let mut answers = vec![("answer_login_federated", a)];

    // A password site with the method and the user's own second step order.
    let rid_login = label_id("nodkey/v1/vectors/request/login");
    let mut a = Answer::decision(&rid_login, Decision::Approved);
    a.account = Some(account("VG", "alex@example.com", "vg.no"));
    a.match_kind = Some(MatchKind::Direct);
    a.username = Some("alex@example.com".into());
    a.password = Some(Secret::new("correct horse battery staple"));
    a.method = Some(SignInMethod {
        certainty: Some(Certainty::Confirmed),
        source: Some(MethodSource::Manual),
        ..SignInMethod::new(SignInKind::Password)
    });
    a.second_step = Some(SecondStepOrder {
        prefer: vec![SecondStep::Totp, SecondStep::Passkey],
        avoid: vec![SecondStep::Sms],
    });
    answers.push(("answer_login_with_method", a));

    let rid_code = label_id("nodkey/v1/vectors/request/code");
    let mut a = Answer::decision(&rid_code, Decision::Approved);
    a.account = Some(account("GitHub", "alex", "github.com"));
    a.match_kind = Some(MatchKind::Direct);
    a.code = Some(Secret::new("190274"));
    a.seconds_left = Some(12);
    a.second_step = Some(SecondStepOrder::default());
    answers.push(("answer_code_second_step", a));

    // A suggestion, queued, and the same refused for too many suggestions.
    let rid = label_id("nodkey/v1/vectors/request/suggest");
    let mut r = request(
        &rid,
        Kind::Suggest,
        "renderfarm.example",
        "Signed in with Google; Nodkey did not know this method",
        None,
    );
    r.suggest = Some(Suggestion {
        method: SignInMethod {
            source: Some(MethodSource::Agent),
            ..google(Certainty::Seen)
        },
        outcome: SuggestOutcome::SignedIn,
    });
    send_request(ctx, "request_suggest", &r);
    answers.push((
        "answer_suggest_queued",
        Answer::decision(&rid, Decision::Queued),
    ));
    let mut a = Answer::decision(&rid, Decision::Rejected);
    a.error = Some(signin::errors::RATE_LIMITED.into());
    answers.push(("answer_suggest_rejected", a));

    let rid = label_id("nodkey/v1/vectors/request/suggest_failed");
    let mut r = request(
        &rid,
        Kind::Suggest,
        "mail.example.com",
        "The password failed; the site now sends a code by e-mail",
        None,
    );
    r.suggest = Some(Suggestion {
        method: SignInMethod::new(SignInKind::Password),
        outcome: SuggestOutcome::Failed,
    });
    send_request(ctx, "request_suggest_failed", &r);

    // An SMS code: the request (the envelope keeps it at the relay for 180 s), the code and an
    // expired wait.
    let rid_sms = label_id("nodkey/v1/vectors/request/sms_code");
    let mut r = request(
        &rid_sms,
        Kind::SmsCode,
        "account.example.com",
        "The site sent a sign-in code by SMS",
        None,
    );
    r.wait_seconds = Some(120);
    let sealed = send_request(ctx, "request_sms_code", &r);
    let mut a = Answer::decision(&rid_sms, Decision::Approved);
    a.code = Some(Secret::new("482913"));
    answers.push(("answer_sms_code", a));
    answers.push((
        "answer_sms_code_expired",
        Answer::decision(&rid_sms, Decision::Expired),
    ));

    for (name, a) in &answers {
        ctx.seal(
            name,
            Purpose::Answer,
            "phone",
            agent,
            to_agent(&a.request_id),
            &to_json(a),
            true,
        );
    }

    let envelope = crate::RequestEnvelope {
        request_id: rid_sms.clone(),
        enc: sealed.enc,
        ct: sealed.ct,
        attachment: None,
        ttl: client::relay_ttl(&r),
    };
    let auth = super::auth_vector(
        "post_request_sms_code",
        agent,
        "POST",
        &format!("/v1/phones/{}/requests", phone.id),
        super::TS + 2,
        &to_json(&envelope),
    );
    (checks(), auth)
}

/// The `signin` section: inputs and what every side must decide for them.
fn checks() -> Value {
    let methods: Vec<Value> = [
        r#"{"kind":"federated","provider":"google","certainty":"confirmed"}"#,
        r#"{"kind":"federated","provider":"Okta","certainty":"seen"}"#,
        r#"{"kind":"federated","provider":"other","provider_name":"Okta"}"#,
        r#"{"kind":"email_code","mailbox":"alex@example.com","certainty":"sure"}"#,
        r#"{"kind":"passkey","source":"robot"}"#,
        r#"{"kind":"magic_link"}"#,
    ]
    .into_iter()
    .map(|input| match serde_json::from_str::<SignInMethod>(input) {
        Ok(m) => json!({"input": input, "reads_as": m}),
        Err(_) => json!({"input": input, "reads_as": null}),
    })
    .collect();

    let case = |name: &str, target: &str, method: SignInMethod| {
        let s = Suggestion {
            method,
            outcome: SuggestOutcome::SignedIn,
        };
        let clean = signin::site(target).as_deref() == Some(target);
        let ok = clean && s.check().is_ok();
        json!({"name": name, "target": target, "suggest": s, "ok": ok})
    };
    let mut no_provider = SignInMethod::new(SignInKind::Federated);
    no_provider.certainty = Some(Certainty::Seen);
    let mut mailbox_on_sms = SignInMethod::new(SignInKind::Sms);
    mailbox_on_sms.mailbox = Some("alex@example.com".into());
    let suggestions = vec![
        case("google_seen", "renderfarm.example", google(Certainty::Seen)),
        case(
            "confirmed",
            "renderfarm.example",
            google(Certainty::Confirmed),
        ),
        case("no_provider", "renderfarm.example", no_provider),
        case(
            "other_without_name",
            "tools.example.com",
            SignInMethod::federated(Provider::Other, None),
        ),
        case("mailbox_on_sms", "bank.example", mailbox_on_sms),
        case(
            "target_with_path",
            "https://renderfarm.example/login",
            google(Certainty::Seen),
        ),
        case(
            "import_source",
            "renderfarm.example",
            SignInMethod {
                source: Some(MethodSource::Import),
                ..google(Certainty::Likely)
            },
        ),
    ];

    use SecondStep::*;
    let order = SecondStepOrder::default();
    let picks: Vec<Value> = [
        vec![Sms, Totp, Passkey],
        vec![AppPrompt, Totp],
        vec![AppPrompt, Email],
        vec![AppPrompt, Sms],
    ]
    .into_iter()
    .map(|offered| json!({"order": order, "offered": offered, "pick": order.pick(&offered)}))
    .collect();

    let via = |site: &str| Via {
        account: account("Provider", "alex@example.com", site),
        username: Some("alex@example.com".into()),
        password: None,
        code: None,
        seconds_left: None,
        next_code: None,
        next_seconds_left: None,
    };
    let fill: Vec<Value> = [
        (
            "accounts.google.com",
            "renderfarm.example",
            Provider::Google,
            "accounts.google.com",
        ),
        (
            "renderfarm.example",
            "renderfarm.example",
            Provider::Google,
            "accounts.google.com",
        ),
        (
            "accounts.google.com.evil.example",
            "renderfarm.example",
            Provider::Google,
            "accounts.google.com",
        ),
        (
            "login.microsoftonline.com",
            "tools.example.com",
            Provider::Microsoft,
            "login.live.com",
        ),
        (
            "appleid.apple.com",
            "tools.example.com",
            Provider::Github,
            "github.com",
        ),
        (
            "acme.okta.example",
            "tools.example.com",
            Provider::Other,
            "acme.okta.example",
        ),
        (
            "okta.example",
            "tools.example.com",
            Provider::Other,
            "acme.okta.example",
        ),
    ]
    .into_iter()
    .map(|(host, target, provider, via_site)| {
        let method =
            SignInMethod::federated(provider, (provider == Provider::Other).then_some("Okta"));
        let v = via(via_site);
        json!({"host": host, "target": target, "method": method, "via_site": via_site,
               "allowed": signin::may_fill_via(host, target, &method, &v)})
    })
    .collect();

    let sites: Vec<Value> = [
        "https://www.Example.com/login?x=1",
        "alex@accounts.example.com:8443",
        "localhost:3000",
        "Example",
        "a..b",
    ]
    .into_iter()
    .map(|input| json!({"input": input, "site": signin::site(input)}))
    .collect();

    let provider_sites: Vec<Value> = [
        Provider::Google,
        Provider::Apple,
        Provider::Github,
        Provider::Microsoft,
        Provider::Facebook,
    ]
    .map(|p| json!({"provider": p, "sites": p.sites()}))
    .into();
    json!({
        "methods": methods,
        "suggestions": suggestions,
        "second_step_picks": picks,
        "via_fill": fill,
        "sites": sites,
        "provider_sites": provider_sites,
        "sms_wait": {"default": signin::SMS_WAIT_DEFAULT, "min": signin::SMS_WAIT_MIN,
                     "max": signin::SMS_WAIT_MAX, "approve_margin": signin::SMS_APPROVE_MARGIN},
        "suggest_limits": {"per_hour": signin::SUGGEST_PER_HOUR, "per_day": signin::SUGGEST_PER_DAY},
    })
}
