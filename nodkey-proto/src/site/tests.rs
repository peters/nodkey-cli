use super::*;

#[test]
fn punycode_matches_rfc_3492() {
    for (label, code) in [
        ("bücher", "bcher-kva"),
        ("münchen", "mnchen-3ya"),
        ("中国", "fiqs8s"),
        ("公司", "55qx5d"),
        ("пример", "e1afmkfd"),
        ("日本語", "wgv71a119e"),
        ("été", "t-9fab"),
    ] {
        assert_eq!(punycode::encode(label).as_deref(), Some(code), "{label}");
    }
    assert_eq!(
        punycode::to_ascii("Bücher").as_deref(),
        Some("xn--bcher-kva")
    );
    assert_eq!(punycode::to_ascii("GitHub").as_deref(), Some("github"));
}

#[test]
fn hosts_read_like_a_browser() {
    let cases = [
        ("https://www.Example.com/login?x=1", Some("www.example.com")),
        ("github.com/alex", Some("github.com")),
        ("github.com.", Some("github.com")),
        (
            "https://alex:pw@accounts.example.com:8443/x",
            Some("accounts.example.com"),
        ),
        // A backslash ends the host, so the part after @ is not the host.
        ("https://evil.example\\@github.com", Some("evil.example")),
        ("evil.example\\@github.com", Some("evil.example")),
        ("localhost:3000", Some("localhost")),
        ("http://192.168.1.1/admin", Some("192.168.1.1")),
        ("http://[FE80::1]:8080/", Some("[fe80::1]")),
        ("bücher.de", Some("xn--bcher-kva.de")),
        ("xn--bcher-kva.de", Some("xn--bcher-kva.de")),
        ("GitHub", None),
        ("a..b", None),
        ("github.com..", None),
        ("exa mple.com", None),
        ("github%2ecom", None),
        ("0x7f.0.0.1", None),
        ("010.0.0.1", None),
        ("1.2.3", None),
        ("example.com:http", None),
        ("", None),
    ];
    for (input, want) in cases {
        assert_eq!(host(input).as_deref(), want, "{input}");
    }
}

#[test]
fn registrable_domains_from_the_list() {
    let cases = [
        ("github.com", Some("github.com")),
        ("login.github.com", Some("github.com")),
        ("github.xyz", Some("github.xyz")),
        ("www.bbc.co.uk", Some("bbc.co.uk")),
        ("other.co.uk", Some("other.co.uk")),
        ("co.uk", None),
        ("alice.github.io", Some("alice.github.io")),
        ("docs.alice.github.io", Some("alice.github.io")),
        ("github.io", None),
        ("app.herokuapp.com", Some("app.herokuapp.com")),
        ("shop.example.com.au", Some("example.com.au")),
        ("com.au", None),
        // A wildcard rule (*.ck) with an exception (!www.ck).
        ("a.b.ck", Some("a.b.ck")),
        ("www.ck", Some("www.ck")),
        // No rule: the last label is the ending.
        ("renderfarm.example", Some("renderfarm.example")),
        ("localhost", None),
        ("192.168.1.1", None),
        ("[::1]", None),
        ("xn--bcher-kva.de", Some("xn--bcher-kva.de")),
        ("shop.公司.cn", Some("shop.xn--55qx5d.cn")),
        ("GitHub", None),
    ];
    for (input, want) in cases {
        assert_eq!(registrable_domain(input).as_deref(), want, "{input}");
    }
    assert!(is_public_suffix("github.io"));
    assert!(is_public_suffix("co.uk"));
    assert!(is_public_suffix("com"));
    assert!(is_public_suffix("localhost"));
    assert!(!is_public_suffix("github.com"));
    assert!(!is_public_suffix("192.168.1.1"));
    assert_eq!(
        public_suffix("alice.github.io").as_deref(),
        Some("github.io")
    );
    assert_eq!(public_suffix("www.bbc.co.uk").as_deref(), Some("co.uk"));
}

#[test]
fn same_website() {
    let same = [
        ("github.com", "login.github.com"),
        ("https://github.com/login", "github.com."),
        ("www.bbc.co.uk", "bbc.co.uk"),
        ("localhost:3000", "localhost:8080"),
        ("192.168.1.1", "http://192.168.1.1/admin"),
    ];
    for (a, b) in same {
        assert!(same_site(a, b), "{a} {b}");
    }
    let other = [
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
    ];
    for (a, b) in other {
        assert!(!same_site(a, b), "{a} {b}");
    }
}

fn account(site: Option<&str>, sites: &[&str]) -> Account {
    Account {
        issuer: "Example".into(),
        name: "alex".into(),
        site: site.map(Into::into),
        sites: (!sites.is_empty()).then(|| sites.iter().map(|s| (*s).to_owned()).collect()),
    }
}

#[test]
fn fill_only_on_the_accounts_sites() {
    let openai = account(Some("auth.openai.com"), &["chatgpt.com", "openai.com"]);
    assert_eq!(
        fill_only_on("chatgpt.com", &openai, Some(MatchKind::Alias)),
        vec!["openai.com", "chatgpt.com"]
    );
    // Picked by hand: only the site that was asked for.
    assert_eq!(
        fill_only_on("https://sora.com/login", &openai, Some(MatchKind::Chosen)),
        vec!["sora.com"]
    );
    assert_eq!(
        fill_only_on("sora.com/alex", &openai, Some(MatchKind::Chosen)),
        vec!["sora.com"]
    );
    let code = account(None, &[]);
    assert!(fill_only_on("GitHub", &code, Some(MatchKind::Chosen)).is_empty());
    assert_eq!(
        fill_only_on("github.com", &code, Some(MatchKind::Chosen)),
        vec!["github.com"]
    );

    let sites = vec!["openai.com".to_owned(), "chatgpt.com".to_owned()];
    assert!(may_fill("https://chatgpt.com/auth", &sites));
    assert!(may_fill("auth.openai.com", &sites));
    assert!(!may_fill("chatgpt.com.evil.example", &sites));
    assert!(!may_fill("openai.co", &sites));
    assert!(!may_fill("evil.example\\@chatgpt.com", &sites));
    // Below a public suffix never counts; the host itself does.
    let shared = vec!["github.io".to_owned(), "localhost".to_owned()];
    assert!(!may_fill("alice.github.io", &shared));
    assert!(may_fill("http://localhost:3000", &shared));
    assert!(!may_fill("evil.localhost", &shared));
}

#[test]
fn the_snapshot_names_its_version() {
    let (version, commit) = version();
    assert!(
        !version.is_empty() && commit.len() == 40,
        "{version} {commit}"
    );
    assert!(rule_count() > 9000);
}
