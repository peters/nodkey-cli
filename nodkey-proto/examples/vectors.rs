//! Writes `vectors/v1.json`, the protocol v1 test vectors shared with the iOS tests.
//!
//! `cargo run -p nodkey-proto --example vectors [-- OUTPUT]`

use std::path::PathBuf;

fn main() {
    let out = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vectors/v1.json"));
    let mut text =
        serde_json::to_string_pretty(&nodkey_proto::vectors::build()).expect("serialize");
    text.push('\n');
    std::fs::write(&out, text).unwrap_or_else(|e| panic!("write {}: {e}", out.display()));
    println!(
        "wrote {}",
        out.canonicalize().unwrap_or(out.clone()).display()
    );
}
