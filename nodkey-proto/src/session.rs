//! Task sessions: one approval of a bundle with `session` covers later requests for the approved
//! items until the session ends (docs/agent-protocol.md, "Task sessions"), and the next code that
//! comes with a code that is about to run out.

use serde::{Deserialize, Serialize};

/// The session lengths an agent may ask for, in seconds (15, 30 and 60 minutes).
pub const SESSION_LENGTHS: [u32; 3] = [900, 1800, 3600];

/// A code with fewer seconds left than this comes with the next one (`next_code`).
pub const NEXT_CODE_BELOW: u32 = 8;

/// Length of a session id: 16 random bytes in base64url.
pub const SESSION_ID_LEN: usize = 22;

/// The task session an approved bundle started.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInfo {
    /// 16 random bytes, base64url without padding.
    pub id: String,
    /// When the session ends (Unix seconds).
    pub until: u64,
}

/// Whether `seconds` is a session length the protocol allows.
pub fn valid_length(seconds: u32) -> bool {
    SESSION_LENGTHS.contains(&seconds)
}

/// Whether a session id has the right shape (22 base64url characters).
pub fn valid_id(id: &str) -> bool {
    id.len() == SESSION_ID_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The session length (seconds) for a number of minutes, if it is one of 15, 30 or 60.
pub fn length_for_minutes(minutes: u32) -> Option<u32> {
    let seconds = minutes.checked_mul(60)?;
    valid_length(seconds).then_some(seconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_and_ids() {
        assert!(valid_length(900) && valid_length(1800) && valid_length(3600));
        assert!(!valid_length(600) && !valid_length(7200));
        assert_eq!(length_for_minutes(30), Some(1800));
        assert_eq!(length_for_minutes(45), None);
        assert!(valid_id("Qm9vdHN0cmFwU2Vzc2lvbg"));
        assert!(!valid_id("short"));
        assert!(!valid_id("Qm9vdHN0cmFwU2Vzc2lvb="));
    }

    #[test]
    fn session_info_round_trip() {
        let info = SessionInfo {
            id: "Qm9vdHN0cmFwU2Vzc2lvbg".into(),
            until: 1_791_621_800,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert_eq!(
            json,
            r#"{"id":"Qm9vdHN0cmFwU2Vzc2lvbg","until":1791621800}"#
        );
        assert_eq!(serde_json::from_str::<SessionInfo>(&json).unwrap(), info);
    }
}
