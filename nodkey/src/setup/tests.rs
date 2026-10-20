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
        let move_in = fx.root.join(folder).join("skills/nodkey-move-in/SKILL.md");
        assert_eq!(
            std::fs::read_to_string(move_in).unwrap(),
            crate::MOVE_IN_SKILL
        );
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
    assert!(!fx.root.join(".claude/skills/nodkey-move-in").exists());

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

#[cfg(unix)]
#[test]
fn config_files_keep_their_mode_and_links() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let fx = Fixture::new("modes");
    let mode = |rel: &str| {
        std::fs::metadata(fx.root.join(rel))
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    };
    // Claude Desktop's file holds a token and is 0600; Cursor's file is a link into a dotfiles folder.
    let desktop = ".config/Claude/claude_desktop_config.json";
    std::fs::write(fx.root.join(desktop), r#"{"token": "test-token"}"#).unwrap();
    std::fs::set_permissions(
        fx.root.join(desktop),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    std::fs::create_dir_all(fx.root.join("dotfiles")).unwrap();
    std::fs::write(fx.root.join("dotfiles/mcp.json"), "{}").unwrap();
    std::fs::set_permissions(
        fx.root.join("dotfiles/mcp.json"),
        std::fs::Permissions::from_mode(0o640),
    )
    .unwrap();
    symlink(
        fx.root.join("dotfiles/mcp.json"),
        fx.root.join(".cursor/mcp.json"),
    )
    .unwrap();

    fx.with(false, install);
    assert_eq!(mode(desktop), 0o600);
    assert_eq!(fx.json(desktop)["token"], "test-token");
    assert!(
        std::fs::symlink_metadata(fx.root.join(".cursor/mcp.json"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(mode("dotfiles/mcp.json"), 0o640);
    assert!(fx.json("dotfiles/mcp.json")["mcpServers"]["nodkey"].is_object());

    // A file setup makes is 0600, whatever the umask.
    let fresh = Fixture::new("modes-new");
    fresh.with(false, install);
    assert_eq!(
        std::fs::metadata(fresh.root.join(desktop))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    fx.with(false, remove);
    assert_eq!(mode(desktop), 0o600);
    assert!(
        std::fs::symlink_metadata(fx.root.join(".cursor/mcp.json"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
}
