//! `nodkey setup`: registers `nodkey mcp` in the agents found on this computer and writes the
//! skill where they read skills. `--remove` takes both away again; pairings stay.
//!
//! Each agent gets `nodkey mcp --agent <profile>`, so it pairs with its own name. Claude Code and
//! Codex are changed through their own command line (`claude mcp`, `codex mcp`); Cursor and Claude
//! Desktop through their JSON config files.

use std::{
    path::{Path, PathBuf},
    process::Command,
};

use serde_json::{Map, Value, json};

use crate::{cli::Args, store::home_dir};

/// The MCP server's name in every agent.
const SERVER: &str = "nodkey";

/// The skills setup installs: (folder and `name:` of the skill, its text).
const SKILLS: [(&str, &str); 2] = [
    ("nodkey", crate::SKILL),
    ("nodkey-move-in", crate::MOVE_IN_SKILL),
];

/// Folders under the home folder whose `skills/` the agents read: (folder, who).
const SKILL_HOMES: [(&str, &str); 3] = [
    (".claude", "Claude Code"),
    (".codex", "Codex"),
    (".agents", "agents that read ~/.agents"),
];

/// Runs a program with arguments; `Err` carries its error output.
pub type Run<'a> = &'a dyn Fn(&str, &[String]) -> Result<(), String>;

/// What setup touches on this computer. Tests point it at a scratch folder and fake commands.
pub struct Env<'a> {
    pub home: PathBuf,
    /// The agent directory (`~/.config/nodkey-agent`).
    pub agent_dir: PathBuf,
    /// The `nodkey` binary the agents start.
    pub exe: PathBuf,
    /// Claude Desktop's config folder on this OS.
    pub claude_desktop: Option<PathBuf>,
    /// Whether a program is on `PATH`.
    pub has: &'a dyn Fn(&str) -> bool,
    pub run: Run<'a>,
    pub dry_run: bool,
}

pub fn main(a: &Args) -> Result<(), String> {
    for key in ["agent", "relay"] {
        if a.value(key).is_some() {
            return Err(format!("nodkey setup does not take --{key}"));
        }
    }
    if !a.positional.is_empty() {
        return Err("nodkey setup takes no arguments (only --remove and --dry-run)".into());
    }
    let home = home_dir().ok_or("cannot find your home folder")?;
    let exe = std::env::current_exe().map_err(|e| format!("cannot find nodkey itself: {e}"))?;
    let exe = exe.canonicalize().unwrap_or(exe);
    let agent_dir = crate::store::Home::from_env()
        .map_err(|e| e.to_string())?
        .dir()
        .to_path_buf();
    let env = Env {
        claude_desktop: claude_desktop_dir(&home),
        agent_dir,
        home,
        exe,
        has: &on_path,
        run: &run,
        dry_run: a.flag("dry-run"),
    };
    let lines = if a.flag("remove") {
        remove(&env)
    } else {
        install(&env)
    };
    for line in &lines {
        println!("{line}");
    }
    if env.dry_run {
        println!("\nDry run: nothing was changed.");
    }
    Ok(())
}

/// Adds the MCP server and the skill to every agent found; returns what happened, one line each.
pub fn install(env: &Env) -> Vec<String> {
    let mut out = Vec::new();
    let exe = env.exe.to_string_lossy().into_owned();
    let args = |profile: &str| vec!["mcp".to_owned(), "--agent".to_owned(), profile.to_owned()];

    // Claude Code
    if (env.has)("claude") {
        let mut add = vec!["mcp", "add", "--scope", "user", SERVER, "--"]
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        add.push(exe.clone());
        add.extend(args("claude-code"));
        out.push(command_step(
            env,
            "Claude Code",
            "claude",
            &remove_args("claude"),
            &add,
        ));
    } else if env.home.join(".claude").is_dir() {
        out.push(format!(
            "Claude Code: the claude command is not on PATH; run `claude mcp add --scope user {SERVER} -- {exe} mcp --agent claude-code`"
        ));
    }

    // Codex
    if (env.has)("codex") {
        let mut add = vec![
            "mcp".to_owned(),
            "add".to_owned(),
            SERVER.to_owned(),
            "--".to_owned(),
        ];
        add.push(exe.clone());
        add.extend(args("codex"));
        out.push(command_step(
            env,
            "Codex",
            "codex",
            &remove_args("codex"),
            &add,
        ));
    }

    // Cursor and Claude Desktop read JSON files.
    let entry = json!({ "command": exe, "args": args("cursor") });
    if env.home.join(".cursor").is_dir() {
        out.push(json_step(
            env,
            "Cursor",
            &env.home.join(".cursor/mcp.json"),
            Some(entry),
        ));
    }
    if let Some(dir) = env.claude_desktop.as_deref().filter(|d| d.is_dir()) {
        let entry = json!({ "command": exe, "args": args("claude-desktop") });
        out.push(json_step(
            env,
            "Claude Desktop",
            &dir.join("claude_desktop_config.json"),
            Some(entry),
        ));
    }

    out.extend(skills(env, false));
    if let Some(line) = adopt_legacy(env) {
        out.push(line);
    }
    out.push(String::new());
    out.push(
        "Next: restart your agents, then ask each one to pair with Nodkey (or run `nodkey pair` for the terminal). \
         Each agent pairs once and shows in Nodkey with its own name."
            .to_owned(),
    );
    out
}

/// Takes the MCP server and the skill away from every agent; pairings stay.
pub fn remove(env: &Env) -> Vec<String> {
    let mut out = Vec::new();
    for (agent, program) in [("Claude Code", "claude"), ("Codex", "codex")] {
        if (env.has)(program) {
            let line = if env.dry_run {
                format!("{agent}: would remove the {SERVER} MCP server")
            } else {
                match (env.run)(program, &remove_args(program)) {
                    Ok(()) => format!("{agent}: removed the {SERVER} MCP server"),
                    Err(_) => format!("{agent}: no {SERVER} MCP server to remove"),
                }
            };
            out.push(line);
        }
    }
    if env.home.join(".cursor").is_dir() {
        out.push(json_step(
            env,
            "Cursor",
            &env.home.join(".cursor/mcp.json"),
            None,
        ));
    }
    if let Some(dir) = env.claude_desktop.as_deref().filter(|d| d.is_dir()) {
        out.push(json_step(
            env,
            "Claude Desktop",
            &dir.join("claude_desktop_config.json"),
            None,
        ));
    }
    out.extend(skills(env, true));
    out.push(String::new());
    out.push(
        "Your pairings stay in ~/.config/nodkey-agent. To end one, run `nodkey unpair PHONE --agent NAME` \
         or remove the agent under Agents in Nodkey."
            .to_owned(),
    );
    out
}

fn remove_args(program: &str) -> Vec<String> {
    let args: &[&str] = if program == "claude" {
        &["mcp", "remove", "--scope", "user", SERVER]
    } else {
        &["mcp", "remove", SERVER]
    };
    args.iter().map(|s| (*s).to_owned()).collect()
}

/// Replaces the server through the agent's own command: remove (it may not exist), then add.
fn command_step(
    env: &Env,
    agent: &str,
    program: &str,
    remove: &[String],
    add: &[String],
) -> String {
    if env.dry_run {
        return format!("{agent}: would run `{program} {}`", add.join(" "));
    }
    let _ = (env.run)(program, remove);
    match (env.run)(program, add) {
        Ok(()) => format!("{agent}: added the {SERVER} MCP server"),
        Err(e) => format!("{agent}: could not add the MCP server: {e}"),
    }
}

/// Sets (`Some`) or removes (`None`) `mcpServers.nodkey` in a JSON config file. A file that is not
/// valid JSON is left alone.
fn json_step(env: &Env, agent: &str, file: &Path, entry: Option<Value>) -> String {
    let mut config = match std::fs::read(file) {
        Ok(bytes) if bytes.iter().all(u8::is_ascii_whitespace) => json!({}),
        Ok(bytes) => match serde_json::from_slice::<Value>(&bytes) {
            Ok(v @ Value::Object(_)) => v,
            _ => {
                return format!(
                    "{agent}: {} is not a JSON object; left it alone",
                    file.display()
                );
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => json!({}),
        Err(e) => return format!("{agent}: {}: {e}", file.display()),
    };
    let servers = config
        .as_object_mut()
        .expect("object")
        .entry("mcpServers")
        .or_insert_with(|| Value::Object(Map::new()));
    let Some(servers) = servers.as_object_mut() else {
        return format!("{agent}: mcpServers in {} is not an object", file.display());
    };
    let (changed, done) = match entry {
        Some(e) => (servers.insert(SERVER.into(), e.clone()) != Some(e), "added"),
        None => (servers.remove(SERVER).is_some(), "removed"),
    };
    if !changed {
        return format!("{agent}: already up to date ({})", file.display());
    }
    if env.dry_run {
        return format!("{agent}: would update {}", file.display());
    }
    let mut text = serde_json::to_vec_pretty(&config).expect("serializable");
    text.push(b'\n');
    match write_atomic(file, &text) {
        Ok(()) => format!(
            "{agent}: {done} the {SERVER} MCP server in {}",
            file.display()
        ),
        Err(e) => format!("{agent}: {}: {e}", file.display()),
    }
}

/// Replaces `file` through a temporary file and a rename. Agent config files often hold other
/// tools' tokens, so the new file keeps the old file's permissions (0600 for a new file on Unix),
/// and a symlink stays a symlink: the text goes to the file it points to.
fn write_atomic(file: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let file = match std::fs::symlink_metadata(file) {
        Ok(m) if m.file_type().is_symlink() => std::fs::canonicalize(file)?,
        _ => file.to_owned(),
    };
    if let Some(dir) = file.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = file.with_extension(format!("nodkey-{}.tmp", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let written = write_new(&tmp, bytes, std::fs::metadata(&file).ok().as_ref())
        .and_then(|()| std::fs::rename(&tmp, &file));
    written.inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

/// Writes a new file that only this user can read while it is written, then gives it the
/// permissions of `like` (the file it replaces), or keeps 0600.
#[cfg(unix)]
fn write_new(path: &Path, bytes: &[u8], like: Option<&std::fs::Metadata>) -> std::io::Result<()> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    match like {
        Some(m) => std::fs::set_permissions(path, m.permissions()),
        None => Ok(()),
    }
}

#[cfg(not(unix))]
fn write_new(path: &Path, bytes: &[u8], _like: Option<&std::fs::Metadata>) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

/// Writes (or removes) `skills/<name>/SKILL.md` of each of [`SKILLS`] for every agent folder that
/// exists.
fn skills(env: &Env, remove: bool) -> Vec<String> {
    let mut out = Vec::new();
    for (folder, who) in SKILL_HOMES {
        if !env.home.join(folder).is_dir() {
            continue;
        }
        for (name, content) in SKILLS {
            let dir = env.home.join(folder).join("skills").join(name);
            out.extend(skill(env, remove, &dir, name, content, who));
        }
    }
    out
}

/// Writes or removes one skill in `dir`; `None` when there is nothing to remove.
fn skill(
    env: &Env,
    remove: bool,
    dir: &Path,
    name: &str,
    content: &str,
    who: &str,
) -> Option<String> {
    let file = dir.join("SKILL.md");
    let label = if name == SERVER {
        format!("Skill for {who}")
    } else {
        format!("Skill {name} for {who}")
    };
    if remove {
        if !file.exists() {
            return None;
        }
        // Line by line, so a skill written with Windows line endings is recognised too.
        let marker = format!("name: {name}");
        let ours =
            std::fs::read_to_string(&file).is_ok_and(|s| s.lines().any(|l| l.trim_end() == marker));
        return Some(if !ours {
            format!("{label}: {} is not Nodkey's; left it", file.display())
        } else if env.dry_run {
            format!("{label}: would remove {}", dir.display())
        } else {
            match std::fs::remove_dir_all(dir) {
                Ok(()) => format!("{label}: removed {}", dir.display()),
                Err(e) => format!("{label}: {}: {e}", dir.display()),
            }
        });
    }
    if env.dry_run {
        return Some(format!("{label}: would write {}", file.display()));
    }
    let result = std::fs::create_dir_all(dir).and_then(|()| std::fs::write(&file, content));
    Some(match result {
        Ok(()) => format!("{label}: wrote {}", file.display()),
        Err(e) => format!("{label}: {}: {e}", file.display()),
    })
}

/// A pairing made by the old nodkey-mcp sits in the top of the agent directory. Moves it to the
/// profile its name belongs to, or to Claude Code (the only agent nodkey-mcp was set up for).
fn adopt_legacy(env: &Env) -> Option<String> {
    let home = crate::store::Home::at(&env.agent_dir);
    let profile = home.legacy_profile().ok().flatten()?;
    let known = crate::profile::KNOWN.iter().any(|(s, _)| *s == profile);
    let target = if known {
        profile
    } else {
        "claude-code".to_owned()
    };
    if env.dry_run {
        return Some(format!(
            "Pairing: would keep the existing pairing for the {target} agent"
        ));
    }
    match home.adopt_legacy(&target) {
        Ok(true) => Some(format!(
            "Pairing: kept the existing pairing for the {target} agent (no new pairing needed)"
        )),
        Ok(false) => None,
        Err(e) => Some(format!("Pairing: could not move the existing pairing: {e}")),
    }
}

/// Claude Desktop's config folder: `~/Library/Application Support/Claude` on macOS,
/// `%APPDATA%\Claude` on Windows, `~/.config/Claude` elsewhere.
fn claude_desktop_dir(home: &Path) -> Option<PathBuf> {
    if cfg!(target_os = "macos") {
        Some(home.join("Library/Application Support/Claude"))
    } else if cfg!(windows) {
        std::env::var_os("APPDATA").map(|a| PathBuf::from(a).join("Claude"))
    } else {
        Some(home.join(".config/Claude"))
    }
}

fn on_path(program: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    let names: Vec<String> = if cfg!(windows) {
        ["exe", "cmd", "bat"]
            .iter()
            .map(|ext| format!("{program}.{ext}"))
            .collect()
    } else {
        vec![program.to_owned()]
    };
    std::env::split_paths(&path).any(|dir| names.iter().any(|n| dir.join(n).is_file()))
}

fn run(program: &str, args: &[String]) -> Result<(), String> {
    let out = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&out.stderr);
        let text = if err.trim().is_empty() {
            String::from_utf8_lossy(&out.stdout).into_owned()
        } else {
            err.into_owned()
        };
        Err(text.trim().lines().last().unwrap_or("failed").to_owned())
    }
}

#[cfg(test)]
mod tests;
