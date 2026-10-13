//! nodkey: ask Nodkey on the user's iPhone for one-time codes and logins, from the terminal
//! (`nodkey code`, `nodkey login`, ...) or as an MCP server (`nodkey mcp`). See the README.

pub mod agent;
pub mod bundle;
pub mod cli;
pub mod commands;
pub mod filter;
pub mod host;
pub mod image;
pub mod mcp;
pub mod outcome;
pub mod profile;
pub mod relay;
pub mod setup;
pub mod store;
pub mod tools;
pub mod webauthn;

/// The agent skill, installed by `nodkey setup`.
pub const SKILL: &str = include_str!("../../skills/nodkey/SKILL.md");

/// A fresh directory for one test under `target/test-tmp` (never the system temp dir).
#[cfg(test)]
pub(crate) fn test_dir(tag: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../target/test-tmp")
        .join(format!("{tag}-{}", nodkey_proto::random_id()))
}
