//! [`Secret`]: a code or a password from the phone, redacted in `Debug` and wiped on drop.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// A secret string from the phone (a code or a password). Its `Debug` output is redacted and its
/// memory is wiped on drop; serialising it writes the value (that is how it reaches the model).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    /// Wraps a value.
    pub fn new(s: impl Into<String>) -> Self {
        Secret(s.into())
    }

    /// The value.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
