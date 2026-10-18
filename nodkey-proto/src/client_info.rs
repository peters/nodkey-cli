//! [`ClientInfo`]: who is asking, as the agent reports it (`client` in every request).

use serde::{Deserialize, Serialize};

/// What the agent says about itself, for the history on the phone. Self-reported: the phone shows
/// it as such and never decides anything on it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientInfo {
    /// The MCP client, e.g. "Claude Code".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_version: Option<String>,
    /// The model the agent runs on, as it says, e.g. "claude-opus-5-5".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Reasoning effort, as the agent says, e.g. "high".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effort: Option<String>,
    /// Operating system and version, e.g. "linux 7.0.0 x86_64".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    /// The computer's name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// The last component of the working directory (the project), never the full path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workdir: Option<String>,
    /// nodkey-mcp's version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_version: Option<String>,
}

impl ClientInfo {
    /// Trims every field to at most 80 characters and drops empty ones.
    pub fn tidy(mut self) -> Self {
        for field in [
            &mut self.app,
            &mut self.app_version,
            &mut self.model,
            &mut self.effort,
            &mut self.os,
            &mut self.host,
            &mut self.workdir,
            &mut self.mcp_version,
        ] {
            *field = field
                .take()
                .map(|v| v.trim().chars().take(80).collect::<String>())
                .filter(|v| !v.is_empty());
        }
        self
    }
}
