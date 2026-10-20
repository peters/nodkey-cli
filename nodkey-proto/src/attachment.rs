//! What travels next to a request: a picture of what the agent is about to sign in to (a
//! screenshot, a short GIF), described in the request and uploaded sealed on its own.

use serde::{Deserialize, Serialize};

/// Media type of an attachment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImageType {
    #[serde(rename = "image/png")]
    Png,
    #[serde(rename = "image/jpeg")]
    Jpeg,
    #[serde(rename = "image/gif")]
    Gif,
}

impl ImageType {
    /// Detects the type from the file's first bytes (never from its name).
    pub fn sniff(bytes: &[u8]) -> Option<Self> {
        if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
            Some(ImageType::Png)
        } else if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
            Some(ImageType::Jpeg)
        } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
            Some(ImageType::Gif)
        } else {
            None
        }
    }

    /// The media type string.
    pub const fn mime(self) -> &'static str {
        match self {
            ImageType::Png => "image/png",
            ImageType::Jpeg => "image/jpeg",
            ImageType::Gif => "image/gif",
        }
    }
}

/// Description of an attachment inside the request plaintext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentInfo {
    #[serde(rename = "type")]
    pub kind: ImageType,
    /// Size of the image in bytes (before sealing).
    pub bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caption: Option<String>,
    /// b64u of SHA-256 of the image bytes; the phone shows only an image that matches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}
