use std::cell::RefCell;

use super::*;
use crate::store::{Home, Store};

struct Fixture {
    root: PathBuf,
    calls: RefCell<Vec<String>>,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        let root = crate::test_dir(&format!("setup-{tag}"));
        for dir in [".claude", ".codex", ".cursor", ".config/Claude"] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        Fixture {
            root,
            calls: RefCell::new(Vec::new()),
        }
    }

    fn with<T>(&self, dry_run: bool, f: impl FnOnce(&Env) -> T) -> T {
        let has = |p: &str| p == "claude" || p == "codex";
        let run = |p: &str, args: &[String]| {
            self.calls
                .borrow_mut()
                .push(format!("{p} {}", args.join(" ")));
            Ok(())
        };
        let env = Env {
            home: self.root.clone(),
            agent_dir: self.root.join(".config/nodkey-agent"),
            exe: PathBuf::from("/opt/bin/nodkey"),
            claude_desktop: Some(self.root.join(".config/Claude")),
            has: &has,
            run: &run,
            dry_run,
        };
        f(&env)
    }

    fn json(&self, rel: &str) -> Value {
        serde_json::from_slice(&std::fs::read(self.root.join(rel)).unwrap()).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn install_and_remove() {
    let fx = Fixture::new("install");
    std::fs::write(
        fx.root.join(".config/Claude/claude_desktop_config.json"),
        r#"{"theme": "dark", "mcpServers": {"other": {"command": "x"}}}"#,
    )
    .unwrap();
    let lines = fx.with(false, install);
    assert!(
        lines.iter().any(|l| l.starts_with("Claude Code: added")),
        "{lines:?}"
    );

    let calls = fx.calls.borrow().clone();
    assert_eq!(
        calls,
        [
            "claude mcp remove --scope user nodkey",
            "claude mcp add --scope user nodkey -- /opt/bin/nodkey mcp --agent claude-code",
            "codex mcp remove nodkey",
            "codex mcp add nodkey -- /opt/bin/nodkey mcp --agent codex",
        ]
    );
    let cursor = fx.json(".cursor/mcp.json");
    assert_eq!(
        cursor["mcpServers"]["nodkey"],
        json!({"command": "/opt/bin/nodkey", "args": ["mcp", "--agent", "cursor"]})
    );
    let desktop = fx.json(".config/Claude/claude_desktop_config.json");
    assert_eq!(desktop["theme"], "dark");
    assert_eq!(desktop["mcpServers"]["other"]["command"], "x");
    assert_eq!(desktop["mcpServers"]["nodkey"]["args"][2], "claude-desktop");
    for folder in [".claude", ".codex"] {
        let skill = std::fs::read_to_string(fx.root.join(folder).join("skills/nodkey/SKILL.md"));
        assert_eq!(skill.unwrap(), crate::SKILL);
    }
    // ~/.agents does not exist here, so no skill is written there.
    assert!(!fx.root.join(".agents").exists());

    // A second run changes nothing in the JSON files.
    let again = fx.with(false, install);
    assert!(
        again
            .iter()
            .any(|l| l.starts_with("Cursor: already up to date"))
    );

    fx.calls.borrow_mut().clear();
    let lines = fx.with(false, remove);
    assert!(
        lines
            .iter()
            .any(|l| l.contains("removed the nodkey MCP server"))
    );
    assert_eq!(
        fx.calls.borrow().clone(),
        [
            "claude mcp remove --scope user nodkey",
            "codex mcp remove nodkey"
        ]
    );
    assert!(
        fx.json(".cursor/mcp.json")["mcpServers"]
            .get("nodkey")
            .is_none()
    );
    let desktop = fx.json(".config/Claude/claude_desktop_config.json");
    assert!(desktop["mcpServers"].get("nodkey").is_none());
    assert_eq!(desktop["mcpServers"]["other"]["command"], "x");
    assert!(!fx.root.join(".claude/skills/nodkey").exists());

    // A skill with Windows line endings is still recognised as Nodkey's.
    let dir = fx.root.join(".codex/skills/nodkey");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("SKILL.md"), "---\r\nname: nodkey\r\n---\r\n").unwrap();
    fx.with(false, remove);
    assert!(!dir.exists());
}

#[test]
fn dry_run_changes_nothing() {
    let fx = Fixture::new("dry");
    let lines = fx.with(true, install);
    assert!(fx.calls.borrow().is_empty());
    assert!(!fx.root.join(".cursor/mcp.json").exists());
    assert!(!fx.root.join(".claude/skills").exists());
    assert!(
        lines
            .iter()
            .any(|l| l.contains("would run `claude mcp add"))
    );
}

#[test]
fn broken_json_is_left_alone() {
    let fx = Fixture::new("broken");
    std::fs::write(fx.root.join(".cursor/mcp.json"), "{ not json").unwrap();
    let lines = fx.with(false, install);
    assert!(
        lines.iter().any(|l| l.contains("left it alone")),
        "{lines:?}"
    );
    assert_eq!(
        std::fs::read_to_string(fx.root.join(".cursor/mcp.json")).unwrap(),
        "{ not json"
    );
}

#[test]
fn foreign_skill_is_kept() {
    let fx = Fixture::new("foreign");
    let dir = fx.root.join(".codex/skills/nodkey");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("SKILL.md"), "---\nname: something-else\n---\n").unwrap();
    let lines = fx.with(false, remove);
    assert!(lines.iter().any(|l| l.contains("is not Nodkey's")));
    assert!(dir.join("SKILL.md").exists());
}

#[test]
fn old_pairing_is_kept_for_its_agent() {
    let fx = Fixture::new("legacy");
    let agent_dir = fx.root.join(".config/nodkey-agent");
    let old = Store::at(&agent_dir)
        .identity_or_create("Coding agent @ box", None)
        .unwrap();
    let lines = fx.with(false, install);
    assert!(
        lines
            .iter()
            .any(|l| l.contains("kept the existing pairing for the claude-code agent"))
    );
    let moved = Home::at(&agent_dir)
        .agent("claude-code")
        .unwrap()
        .identity()
        .unwrap()
        .unwrap();
    assert_eq!(moved.agent_id, old.agent_id);
}
