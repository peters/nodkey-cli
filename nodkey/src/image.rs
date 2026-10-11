//! The optional picture of a request: checked here, sealed to the phone by the caller.

use nodkey_proto::{
    ImageType,
    seal::{ENC_LEN, TAG_LEN},
};

/// Largest attachment body the relay accepts (`enc ‖ ct`).
pub const MAX_ATTACHMENT_BODY: usize = 1024 * 1024;
/// Largest image file: the body limit minus `enc` and the tag.
pub const MAX_IMAGE_BYTES: usize = MAX_ATTACHMENT_BODY - ENC_LEN - TAG_LEN;

/// Reads and checks an image file: PNG, JPEG or GIF by content, at most [`MAX_IMAGE_BYTES`].
pub async fn load_image(path: &str) -> Result<(ImageType, Vec<u8>, String), String> {
    let path = expand_home(path);
    let meta = tokio::fs::metadata(&path)
        .await
        .map_err(|e| format!("image_path {}: {e}", path.display()))?;
    if !meta.is_file() {
        return Err(format!("image_path {} is not a file", path.display()));
    }
    if meta.len() > MAX_IMAGE_BYTES as u64 {
        return Err(format!(
            "image_path {} is {} bytes; the limit is 1 MiB ({MAX_IMAGE_BYTES} bytes after encryption overhead). \
             Use a smaller screenshot (crop it or save it as JPEG).",
            path.display(),
            meta.len()
        ));
    }
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|e| format!("image_path {}: {e}", path.display()))?;
    if bytes.len() > MAX_IMAGE_BYTES {
        return Err(format!(
            "image_path {} grew past the 1 MiB limit while reading",
            path.display()
        ));
    }
    let kind = ImageType::sniff(&bytes).ok_or_else(|| {
        format!(
            "image_path {} is not a PNG, JPEG or GIF file",
            path.display()
        )
    })?;
    let caption = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "picture".to_owned());
    Ok((kind, bytes, caption))
}

fn expand_home(path: &str) -> std::path::PathBuf {
    if let Some(rest) = path.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        return std::path::PathBuf::from(home).join(rest);
    }
    std::path::PathBuf::from(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn image_checks() {
        let dir = crate::test_dir("img");
        std::fs::create_dir_all(&dir).unwrap();
        let png = dir.join("shot.png");
        std::fs::write(&png, nodkey_proto::vectors::PNG).unwrap();
        let (kind, bytes, caption) = load_image(png.to_str().unwrap()).await.unwrap();
        assert_eq!(kind, ImageType::Png);
        assert_eq!(bytes.len(), 76);
        assert_eq!(caption, "shot.png");

        let svg = dir.join("x.png");
        std::fs::write(&svg, b"<svg/>").unwrap();
        assert!(
            load_image(svg.to_str().unwrap())
                .await
                .unwrap_err()
                .contains("not a PNG")
        );

        let big = dir.join("big.gif");
        let mut data = b"GIF89a".to_vec();
        data.resize(MAX_IMAGE_BYTES + 1, 0);
        std::fs::write(&big, &data).unwrap();
        assert!(
            load_image(big.to_str().unwrap())
                .await
                .unwrap_err()
                .contains("limit is 1 MiB")
        );
        data.truncate(MAX_IMAGE_BYTES);
        std::fs::write(&big, &data).unwrap();
        assert!(load_image(big.to_str().unwrap()).await.is_ok());

        assert!(
            load_image(dir.join("missing.png").to_str().unwrap())
                .await
                .is_err()
        );
        assert!(load_image(dir.to_str().unwrap()).await.is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn limits_add_up() {
        assert_eq!(MAX_IMAGE_BYTES + ENC_LEN + TAG_LEN, 1_048_576);
    }
}
