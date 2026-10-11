//! `nodkey`: ask Nodkey on your iPhone for one-time codes and logins. See the README.

fn main() -> std::process::ExitCode {
    nodkey::cli::main(std::env::args().skip(1).collect())
}
