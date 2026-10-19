//! Which agent is asking. Every agent (Claude Code, Codex, the terminal, ...) has its own identity
//! and pairing, so the phone shows each one by name and the user can turn one off without the
//! others.

/// An agent profile: a short slug for the folder and the name the user sees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    /// Folder name under `agents/`: lowercase letters, digits and `-`, at most 32 characters.
    pub slug: String,
    /// The app part of the name the phone shows, e.g. "Claude Code".
    pub display: String,
}

/// The agents `nodkey` knows by name: (slug, name the user sees).
pub const KNOWN: [(&str, &str); 5] = [
    ("claude-code", "Claude Code"),
    ("codex", "Codex"),
    ("cursor", "Cursor"),
    ("claude-desktop", "Claude Desktop"),
    ("terminal", "Terminal"),
];

/// The profile of the command line.
pub const TERMINAL: &str = "terminal";

/// The agent whose shell runs this command, from what that agent sets in the shells it starts:
/// Claude Code sets `CLAUDECODE=1`, Codex sets `CODEX_SANDBOX` or `CODEX_SANDBOX_NETWORK_DISABLED`
/// for a command in its sandbox. `None` for any other program (`NODKEY_AGENT` names it).
///
/// This only names the asker, so the phone shows the right agent. It is no separation: a program
/// that runs as the user can ask under any profile.
pub fn calling_agent(var: impl Fn(&str) -> Option<String>) -> Option<&'static str> {
    let set = |name: &str| var(name).is_some_and(|v| !v.trim().is_empty());
    if var("CLAUDECODE").is_some_and(|v| v.trim() == "1") {
        Some("claude-code")
    } else if set("CODEX_SANDBOX") || set("CODEX_SANDBOX_NETWORK_DISABLED") {
        Some("codex")
    } else {
        None
    }
}

/// The profile of an MCP server whose client did not say who it is.
pub const UNKNOWN_MCP: &str = "mcp";

impl Profile {
    /// The profile for `slug` (`--agent`). Known slugs get their usual name; others show the slug.
    pub fn named(slug: &str) -> Result<Self, String> {
        let slug = slug.trim().to_ascii_lowercase();
        if !is_slug(&slug) {
            return Err(format!(
                "agent name {slug:?} must be 1 to 32 lowercase letters, digits or '-', e.g. claude-code"
            ));
        }
        let display = KNOWN
            .iter()
            .find(|(s, _)| *s == slug)
            .map(|(_, d)| (*d).to_owned())
            .unwrap_or_else(|| slug.clone());
        Ok(Profile { slug, display })
    }

    /// The profile for an MCP client, from `clientInfo` in `initialize` (`name`, `title`).
    pub fn from_client(name: &str, title: Option<&str>) -> Self {
        let n = name.trim().to_ascii_lowercase();
        let known = match n.as_str() {
            "claude-code" | "claude code" => Some("claude-code"),
            "codex" | "codex-mcp-client" | "codex_mcp_client" => Some("codex"),
            "cursor" | "cursor-vscode" => Some("cursor"),
            "claude-ai" | "claude desktop" | "claude-desktop" => Some("claude-desktop"),
            _ => None,
        };
        if let Some(slug) = known {
            return Profile::named(slug).expect("known slug");
        }
        let slug = slugify(&n);
        if slug.is_empty() {
            return Profile::named(UNKNOWN_MCP).expect("valid slug");
        }
        let display = title
            .or(Some(name))
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(|t| t.chars().take(40).collect())
            .unwrap_or_else(|| slug.clone());
        Profile { slug, display }
    }

    /// The name the phone shows: "Claude Code @ my-laptop".
    pub fn agent_name(&self, host: &str) -> String {
        format!("{} @ {host}", self.display)
    }
}

/// True for 1 to 32 characters of `a-z`, `0-9` and `-`, not starting with `-`.
pub fn is_slug(s: &str) -> bool {
    (1..=32).contains(&s.len())
        && !s.starts_with('-')
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Lowercase letters and digits of `s`, other runs as one `-`, at most 32 characters.
pub fn slugify(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars().flat_map(char::to_lowercase) {
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            out.push(c);
        } else if !out.is_empty() && !out.ends_with('-') {
            out.push('-');
        }
    }
    out.truncate(32);
    out.trim_end_matches('-').to_owned()
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_calling_agent_from_its_environment() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |name: &str| {
                pairs
                    .iter()
                    .find(|(k, _)| *k == name)
                    .map(|(_, v)| (*v).to_owned())
            }
        };
        assert_eq!(
            calling_agent(env(&[("CLAUDECODE", "1")])),
            Some("claude-code")
        );
        assert_eq!(
            calling_agent(env(&[("CODEX_SANDBOX", "seatbelt")])),
            Some("codex")
        );
        assert_eq!(
            calling_agent(env(&[("CODEX_SANDBOX_NETWORK_DISABLED", "1")])),
            Some("codex")
        );
        assert_eq!(calling_agent(env(&[("CLAUDECODE", "0")])), None);
        assert_eq!(calling_agent(env(&[("CODEX_SANDBOX", " ")])), None);
        assert_eq!(calling_agent(env(&[])), None);
    }

    use super::*;

    #[test]
    fn named_profiles() {
        assert_eq!(Profile::named("codex").unwrap().display, "Codex");
        assert_eq!(Profile::named(" Terminal ").unwrap().slug, "terminal");
        assert_eq!(Profile::named("ci-bot").unwrap().display, "ci-bot");
        for bad in ["", "-x", "has space", "a/b", "..", &"x".repeat(33)] {
            assert!(Profile::named(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn profiles_from_mcp_clients() {
        let p = Profile::from_client("claude-code", Some("Claude Code"));
        assert_eq!(
            (p.slug.as_str(), p.display.as_str()),
            ("claude-code", "Claude Code")
        );
        assert_eq!(Profile::from_client("codex-mcp-client", None).slug, "codex");
        assert_eq!(
            Profile::from_client("cursor-vscode", None).display,
            "Cursor"
        );
        assert_eq!(
            Profile::from_client("claude-ai", None).slug,
            "claude-desktop"
        );
        let p = Profile::from_client("Zed Agent", Some("Zed"));
        assert_eq!((p.slug.as_str(), p.display.as_str()), ("zed-agent", "Zed"));
        assert_eq!(Profile::from_client("  ", None).slug, UNKNOWN_MCP);
        assert_eq!(
            Profile::named("terminal").unwrap().agent_name("box"),
            "Terminal @ box"
        );
    }

    #[test]
    fn slugs() {
        assert_eq!(slugify("Claude Code"), "claude-code");
        assert_eq!(slugify("  --A__b  "), "a-b");
        assert!(is_slug(&slugify(&"ab ".repeat(30))));
    }
}
