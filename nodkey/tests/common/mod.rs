//! Shared by the tests that run the real binary.

use std::{
    io::Write,
    process::{Command, Output, Stdio},
};

/// Runs `nodkey` like [`Command::output`]. `nodkey pair` asks whether the iPhone shows the same
/// check number; here the person answers yes.
pub fn output(command: &mut Command, args: &[&str]) -> Output {
    let answer: &[u8] = if args.first() == Some(&"pair") {
        b"y\n"
    } else {
        b""
    };
    output_with_input(command, answer)
}

/// Runs `nodkey` with `input` on stdin.
pub fn output_with_input(command: &mut Command, input: &[u8]) -> Output {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run nodkey");
    let mut stdin = child.stdin.take().expect("stdin");
    stdin.write_all(input).expect("write stdin");
    drop(stdin);
    child.wait_with_output().expect("run nodkey")
}
