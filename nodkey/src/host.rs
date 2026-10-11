//! What a request says about this computer (the phone shows it in the history).

use nodkey_proto::ClientInfo;

/// This computer: OS and version, its name, the project folder's name and nodkey's version.
pub fn local_client() -> ClientInfo {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .or_else(|| command("uname", &["-r"]));
    let os = [
        Some(std::env::consts::OS.to_owned()),
        release,
        Some(std::env::consts::ARCH.to_owned()),
    ]
    .into_iter()
    .flatten()
    .map(|p| p.trim().to_owned())
    .collect::<Vec<_>>()
    .join(" ");
    let host = Some(hostname());
    let workdir = std::env::current_dir()
        .ok()
        .and_then(|d| d.file_name().map(|n| n.to_string_lossy().into_owned()));
    ClientInfo {
        os: Some(os),
        host,
        workdir,
        mcp_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
        ..ClientInfo::default()
    }
    .tidy()
}

/// This computer's short name, e.g. "my-laptop".
pub fn hostname() -> String {
    let from_file = |p: &str| std::fs::read_to_string(p).ok().map(|s| s.trim().to_owned());
    from_file("/proc/sys/kernel/hostname")
        .or_else(|| from_file("/etc/hostname"))
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .filter(|h| !h.trim().is_empty())
        .or_else(|| command("hostname", &[]))
        .map(|h| h.trim().to_owned())
        .filter(|h| !h.is_empty())
        .map(|h| h.split('.').next().unwrap_or(&h).to_owned())
        .unwrap_or_else(|| "this computer".to_owned())
}

fn command(program: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(program)
        .args(args)
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}
