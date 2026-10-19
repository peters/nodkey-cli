//! The `sites` section (docs/agent-protocol.md, "Websites"): the public suffix list snapshot the
//! rules use, how addresses read as hosts, registrable domains and public suffixes, which pairs
//! are the same website, where a provider login may be filled, and `fill_only_on`. No HPKE: the
//! phone and every agent must give the same answers for the same inputs.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    Account, MatchKind, Provider, SignInMethod, Via, b64u, signin,
    site::{self, PUBLIC_SUFFIX_LIST},
};

pub(super) fn add() -> Value {
    let (version, commit) = site::version();
    let psl = json!({
        "file": "nodkey-proto/data/public_suffix_list.dat",
        "version": version,
        "commit": commit,
        "sha256": b64u::hex(&Sha256::digest(PUBLIC_SUFFIX_LIST.as_bytes())),
        "rules": site::rule_count(),
    });

    let hosts: Vec<Value> = [
        "https://www.Example.com/login?x=1",
        "github.com/alex",
        "github.com.",
        "https://alex:pw@accounts.example.com:8443/x",
        "https://evil.example\\@github.com",
        "localhost:3000",
        "http://192.168.1.1/admin",
        "http://[FE80::1]:8080/",
        "bücher.de",
        "GitHub",
        "a..b",
        "github%2ecom",
        "0x7f.0.0.1",
        "010.0.0.1",
    ]
    .into_iter()
    .map(|input| json!({"input": input, "host": site::host(input)}))
    .collect();

    let registrable: Vec<Value> = [
        "github.com",
        "login.github.com",
        "github.xyz",
        "www.bbc.co.uk",
        "co.uk",
        "alice.github.io",
        "docs.alice.github.io",
        "github.io",
        "app.herokuapp.com",
        "my-site.pages.dev",
        "shop.example.com.au",
        "a.b.ck",
        "www.ck",
        "renderfarm.example",
        "localhost",
        "192.168.1.1",
        "xn--bcher-kva.de",
        "shop.公司.cn",
    ]
    .into_iter()
    .map(|host| {
        json!({
            "host": host,
            "registrable_domain": site::registrable_domain(host),
            "public_suffix": site::public_suffix(host),
            "is_public_suffix": site::is_public_suffix(host),
        })
    })
    .collect();

    let same_site: Vec<Value> = [
        ("github.com", "login.github.com"),
        ("https://github.com/login", "github.com."),
        ("www.bbc.co.uk", "bbc.co.uk"),
        ("localhost:3000", "localhost:8080"),
        ("github.com", "github.xyz"),
        ("github.com", "login.github.xyz"),
        ("github.com", "git-hub.com"),
        ("github.com", "anyone.github.io"),
        ("alice.github.io", "bob.github.io"),
        ("bbc.co.uk", "other.co.uk"),
        ("github.com", "github.com.evil.example"),
        ("github.com", "evil.example\\@github.com"),
        ("github.com", "GitHub"),
        ("192.168.1.1", "192.168.1.2"),
    ]
    .into_iter()
    .map(|(a, b)| json!({"a": a, "b": b, "same": site::same_site(a, b)}))
    .collect();

    let openai = Account {
        issuer: "OpenAI".into(),
        name: "alex@example.com".into(),
        site: Some("auth.openai.com".into()),
        sites: Some(vec!["chatgpt.com".into()]),
    };
    let code_only = Account {
        issuer: "GitHub".into(),
        name: "alex".into(),
        site: None,
        sites: None,
    };
    let fill_only_on: Vec<Value> = [
        ("chatgpt.com", &openai, Some(MatchKind::Alias)),
        ("openai.com", &openai, Some(MatchKind::Direct)),
        ("https://sora.com/login", &openai, Some(MatchKind::Chosen)),
        ("github.com/alex", &code_only, Some(MatchKind::Chosen)),
        ("GitHub", &code_only, Some(MatchKind::Chosen)),
    ]
    .into_iter()
    .map(|(target, account, kind)| {
        json!({"target": target, "account": account, "match": kind,
               "fill_only_on": site::fill_only_on(target, account, kind)})
    })
    .collect();

    let pages = |sites: &[&str]| sites.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    let may_fill: Vec<Value> = [
        ("https://chatgpt.com/auth", pages(&["openai.com", "chatgpt.com"])),
        ("auth.openai.com", pages(&["openai.com", "chatgpt.com"])),
        ("chatgpt.com.evil.example", pages(&["openai.com", "chatgpt.com"])),
        ("evil.example\\@chatgpt.com", pages(&["chatgpt.com"])),
        ("alice.github.io", pages(&["github.io"])),
        ("http://localhost:3000", pages(&["localhost"])),
        ("evil.localhost", pages(&["localhost"])),
    ]
    .into_iter()
    .map(|(page, sites)| {
        json!({"page": page, "sites": sites, "allowed": site::may_fill(page, &sites)})
    })
    .collect();

    let via = |site: &str| Via {
        account: Account {
            issuer: "Provider".into(),
            name: "alex@example.com".into(),
            site: Some(site.into()),
            sites: None,
        },
        username: None,
        password: None,
        code: None,
        seconds_left: None,
        next_code: None,
        next_seconds_left: None,
    };
    let via_fill: Vec<Value> = [
        (
            "accounts.google.com",
            Provider::Google,
            "accounts.google.com",
        ),
        ("sites.google.com", Provider::Google, "accounts.google.com"),
        ("mail.google.com", Provider::Google, "accounts.google.com"),
        ("login.live.com", Provider::Microsoft, "login.live.com"),
        ("outlook.live.com", Provider::Microsoft, "login.live.com"),
        ("appleid.apple.com", Provider::Apple, "appleid.apple.com"),
        ("www.apple.com", Provider::Apple, "appleid.apple.com"),
        ("alice.github.io", Provider::Github, "github.com"),
    ]
    .into_iter()
    .map(|(host, provider, via_site)| {
        let method = SignInMethod::federated(provider, None);
        json!({"host": host, "target": "tools.example.com", "method": method, "via_site": via_site,
               "allowed": signin::may_fill_via(host, "tools.example.com", &method, &via(via_site))})
    })
    .collect();

    let sign_in_hosts: Vec<Value> = [
        Provider::Google,
        Provider::Apple,
        Provider::Github,
        Provider::Microsoft,
        Provider::Facebook,
    ]
    .map(|p| json!({"provider": p, "hosts": p.sign_in_hosts()}))
    .into();

    json!({
        "psl": psl,
        "hosts": hosts,
        "registrable": registrable,
        "same_site": same_site,
        "fill_only_on": fill_only_on,
        "may_fill": may_fill,
        "via_fill": via_fill,
        "provider_sign_in_hosts": sign_in_hosts,
    })
}
