//! The agent limit (docs/agent-protocol.md, "Agent limit"): the phone counts the new logins and
//! codes each agent receives, warns above the user's limit and pauses the agent above
//! [`PAUSE_ABOVE`]. The phone decides; the agent only reads `quota_warning` and `paused`.

use serde::{Deserialize, Serialize};

/// The `error` values of the agent limit.
pub mod errors {
    /// Informational: the phone asked the user with the limit warning. It may come with any
    /// decision, also `approved`.
    pub const QUOTA_WARNING: &str = "quota_warning";
    /// The agent is paused: by the user under Agents, or by the phone above [`super::PAUSE_ABOVE`]
    /// (then the answer carries `quota`). Refused at once.
    pub const PAUSED: &str = "paused";
}

/// The limit of new items per 24 hours when the user did not choose one.
pub const DEFAULT_LIMIT: u32 = 10;
/// The limits the user may choose for an agent.
pub const LIMIT_CHOICES: [u32; 3] = [5, 10, 25];
/// Above this many new items in 24 hours the phone pauses the agent.
pub const PAUSE_ABOVE: u32 = 25;
/// The rolling window of the count, in seconds.
pub const WINDOW_SECONDS: u64 = 86_400;
/// An item this agent received within this many seconds is not new (30 days).
pub const NEW_AFTER_SECONDS: u64 = 30 * 86_400;
/// More than this many new items within [`BURST_SECONDS`] warns at once.
pub const BURST_COUNT: u32 = 5;
pub const BURST_SECONDS: u64 = 600;
/// How long "OK for today" lifts the warning, in seconds.
pub const OK_FOR_TODAY_SECONDS: u64 = 86_400;

/// The count behind a `quota_warning`, or behind a `paused` that the limit caused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quota {
    /// New logins and codes this agent received in the last 24 hours, after this answer (the
    /// new items of an approved answer count, nothing of a refused one).
    pub new_today: u32,
    /// The user's limit for this agent (5, 10 or 25).
    pub limit: u32,
    /// The warning came from the burst rule (more than 5 new items in 10 minutes).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub burst: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quota_wire_form() {
        let q = Quota {
            new_today: 12,
            limit: 10,
            burst: false,
        };
        assert_eq!(
            serde_json::to_string(&q).unwrap(),
            r#"{"new_today":12,"limit":10}"#
        );
        let b: Quota = serde_json::from_str(r#"{"new_today":6,"limit":10,"burst":true}"#).unwrap();
        assert!(b.burst);
        assert!(LIMIT_CHOICES.contains(&DEFAULT_LIMIT));
        assert!(LIMIT_CHOICES.iter().all(|l| *l <= PAUSE_ABOVE));
    }
}
