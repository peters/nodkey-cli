//! Moving in from the computer (docs/agent-protocol.md, "Moving in"): `nodkey import` and the MCP
//! tool `import_file` send an export file to the import window the user opened on the iPhone.
//!
//! The file is read once into wiped memory, checked and described here (format and counts, never a
//! value), sealed to the phone and uploaded after the request. After `staged` it is deleted from
//! this computer unless the caller keeps it. Nothing of its content reaches stdout, stderr, a log
//! or a tool result.

mod file;

use nodkey_proto::{
    Answer, ClientInfo, Decision, ImportCounts, ImportFormat, ImportRequest, Kind, import,
    import::detect::{self, Summary},
};
use serde::Serialize;
use serde_json::{Map, Value};

use crate::{
    agent::{Agent, Progress, Reported, Text, new_request, text},
    cli::{Args, DENIED, EXPIRED, PAUSED},
    outcome::{NO_PASSCODE, OLD_PROTOCOL, is_paused, paused},
};

pub use file::{Export, display_name, expand_home};

/// Exit codes of `nodkey import` beyond the common ones (docs/agent-protocol.md).
pub const NO_PASSCODE_EXIT: u8 = 10;
pub const IMPORT_CLOSED_EXIT: u8 = 11;
pub const WINDOW_FULL_EXIT: u8 = 12;
pub const UNREADABLE_EXIT: u8 = 13;
pub const TOO_LARGE_EXIT: u8 = 14;

/// What `nodkey import` and `import_file` were asked to do.
#[derive(Debug, Clone, Copy, Default)]
pub struct Options<'a> {
    pub path: &'a str,
    pub source: Option<&'a str>,
    pub reason: Option<&'a str>,
    /// Leave the export on this computer after the phone staged it.
    pub keep: bool,
    /// Read and describe the file, send nothing.
    pub dry_run: bool,
    pub phone: Option<&'a str>,
}

/// What nodkey read from the file before sending: the format and counts, never a value.
#[derive(Serialize)]
struct Detected {
    format: ImportFormat,
    found: u32,
    logins: u32,
    codes: u32,
    skipped: u32,
}

/// The result of an import, for the model and the command line.
#[derive(Serialize, Default)]
struct Outcome<'a> {
    /// The phone's answer: `staged`, `denied` or `expired`; absent when nothing was sent.
    #[serde(skip_serializing_if = "Option::is_none")]
    decision: Option<Decision>,
    sent: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    dry_run: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    phone: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    file: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detected: Option<Detected>,
    /// The phone's counts after `staged`.
    #[serde(skip_serializing_if = "Option::is_none")]
    import: Option<&'a ImportCounts>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
    /// Whether the export was deleted from this computer.
    deleted: bool,
    /// Where the export still is, when it was not deleted.
    #[serde(skip_serializing_if = "Option::is_none")]
    still_at: Option<String>,
    message: String,
}

fn detected(s: &Summary) -> Detected {
    Detected {
        format: s.format,
        found: s.found,
        logins: s.logins,
        codes: s.codes,
        skipped: s.skipped,
    }
}

fn plural(n: u32, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// "2 logins, 1 code; 1 row skipped" for a summary.
fn describe(s: &Summary) -> String {
    let mut out = format!(
        "{} and {}",
        plural(s.logins, "login", "logins"),
        plural(s.codes, "code", "codes")
    );
    if s.skipped > 0 {
        out.push_str(&format!(
            "; {} without a password or code (left out)",
            plural(s.skipped, "row", "rows")
        ));
    }
    out
}

/// Why nodkey does not send a file it read, before anything goes to the phone.
fn refuse_locally(s: &Summary) -> Option<String> {
    if s.archive {
        return Some(
            "This is a zip archive. Ask the user to unpack it and pick the CSV inside (for Dashlane: \
             credentials.csv), then send that file. Delete the archive when done."
                .into(),
        );
    }
    if s.encrypted {
        return Some(format!(
            "This {} export is encrypted, so Nodkey cannot read it. Ask the user to export again without a \
             password (plain CSV, or plain text for a code app), then delete this file.",
            s.format.label()
        ));
    }
    (s.format != ImportFormat::Unknown && s.found == 0).then(|| {
        format!(
            "This {} export holds no login and no code, so there is nothing to send.",
            s.format.label()
        )
    })
}

fn check_source(source: &str) -> Result<(), String> {
    let n = source.trim().chars().count();
    if n == 0 || n > import::MAX_SOURCE || source.chars().any(char::is_control) {
        return Err(format!(
            "source is a short label of 1 to {} characters, e.g. \"Chrome, profile Default\"",
            import::MAX_SOURCE
        ));
    }
    Ok(())
}

/// What the phone's answer means, for the model and the user.
fn message(a: &Answer, phone: &str, name: &str) -> String {
    let error = a.error.as_deref();
    match (a.decision, error) {
        (Decision::Staged, _) => {
            let mut m = format!("Nodkey on {phone} staged {name} for review");
            if let Some(c) = &a.import {
                m.push_str(&format!(": {}", plural(c.found, "entry", "entries")));
                if let (Some(logins), Some(codes)) = (c.logins, c.codes) {
                    m.push_str(&format!(
                        " ({}, {})",
                        plural(logins, "login", "logins"),
                        plural(codes, "code", "codes")
                    ));
                }
                m.push_str(&format!(
                    ": {} new, {} merged, {} duplicates, {} conflicts",
                    c.new, c.merged, c.duplicates, c.conflicts
                ));
                if c.skipped > 0 {
                    m.push_str(&format!("; {} left out", plural(c.skipped, "row", "rows")));
                }
                if let (Some(files), Some(until)) = (c.files, c.until) {
                    let minutes = until.saturating_sub(nodkey_proto::unix_now()).div_ceil(60);
                    m.push_str(&format!(
                        ". The window holds {files} of {} files and stays open {minutes} more minutes",
                        import::WINDOW_FILES
                    ));
                }
            }
            m.push_str(
                ". Nothing is added until the user reviews the list in Nodkey and adds it with one Face \
                 ID; tell them when every file is sent.",
            );
            m
        }
        _ if is_paused(a) => paused(a),
        (_, Some("unsupported_kind" | "unsupported_version")) => format!(
            "{OLD_PROTOCOL} (Moving in from the computer needs a newer Nodkey on the iPhone.)"
        ),
        (_, Some(import::errors::NO_PASSCODE)) => format!(
            "{NO_PASSCODE} Without a passcode Nodkey cannot open an import window either."
        ),
        (_, Some(import::errors::IMPORT_CLOSED)) => format!(
            "No import window is open in Nodkey for this agent. Ask the user to open one on {phone}: Settings \
             \u{2192} Import \u{2192} \"From your computer, with an agent\", pick this agent and confirm. Then \
             send the file again."
        ),
        (_, Some(import::errors::WINDOW_FULL)) => format!(
            "The import window already holds {} files. Ask the user to review and add them in Nodkey, then \
             open a new window for the rest.",
            import::WINDOW_FILES
        ),
        (_, Some(import::errors::TOO_LARGE)) => {
            "The phone says the file is too large (more than 1 MiB). Export fewer items at a time.".into()
        }
        (_, Some(import::errors::IMPORT_UNREADABLE)) => format!(
            "Nodkey could not read {name}. Ask the user to export again as CSV (plain text for a code app), \
             without a password, and send the new file."
        ),
        (_, Some(import::errors::BAD_IMPORT)) => {
            "The file did not reach the phone intact, so nothing was staged. Send it once more; if that fails \
             too, tell the user."
                .into()
        }
        (Decision::Denied, _) => {
            "The phone did not take the file. Ask the user to look at Nodkey on their iPhone.".into()
        }
        (Decision::Expired, _) => {
            "The phone did not answer in time. Ask the user to keep Nodkey open on the iPhone, then send the \
             file again."
                .into()
        }
        _ => crate::outcome::MISFIT.into(),
    }
}

impl Agent {
    /// Sends one export file to the phone's import window (or, with `dry_run`, only describes
    /// it). Never puts any of the file's content into the result.
    pub async fn import_file(
        &self,
        opts: Options<'_>,
        reported: Reported<'_>,
        progress: Progress<'_>,
    ) -> Result<Text, String> {
        if let Some(source) = opts.source {
            check_source(source)?;
        }
        let export = match file::read(opts.path) {
            Ok(e) => e,
            Err((None, e)) => return Err(e),
            Err((Some(code), message)) => {
                return Ok(text(&Outcome {
                    error: Some(code),
                    still_at: Some(expand_home(opts.path.trim()).display().to_string()),
                    message,
                    ..Outcome::default()
                }));
            }
        };
        let summary = detect::detect(&export.bytes);
        let source = opts.source.unwrap_or(summary.format.label()).trim();
        let still_at = || Some(export.path.display().to_string());
        let mut out = Outcome {
            file: Some(&export.name),
            source: Some(source),
            detected: Some(detected(&summary)),
            ..Outcome::default()
        };
        if let Some(why) = refuse_locally(&summary) {
            out.error = Some(import::errors::IMPORT_UNREADABLE);
            out.still_at = still_at();
            out.message = why;
            return Ok(text(&out));
        }
        let what = match summary.format {
            ImportFormat::Unknown => {
                "a file nodkey does not recognise (the phone may still read it)".to_owned()
            }
            f => format!("a {} export with {}", f.label(), describe(&summary)),
        };
        if opts.dry_run {
            out.dry_run = Some(true);
            out.still_at = still_at();
            out.message = format!("{} is {what}. Nothing was sent (dry run).", export.name);
            return Ok(text(&out));
        }

        let client = ClientInfo {
            model: reported.model.map(str::to_owned),
            effort: reported.effort.map(str::to_owned),
            ..self.client.lock().expect("lock").clone()
        };
        let default_reason = format!("Import {} ({source}) into Nodkey", export.name);
        let reason = opts.reason.unwrap_or(&default_reason);
        let mut request = new_request(Kind::Import, "", reason, client);
        request.import = Some(ImportRequest::new(
            &export.name,
            &export.bytes,
            Some(summary.format),
            source,
        ));
        let ex = self
            .exchange_upload(request, None, Some(&export.bytes), opts.phone, progress)
            .await?;
        out.sent = true;
        out.request_id = Some(&ex.request_id);
        out.phone = Some(&ex.phone);
        let Some(answer) = &ex.answer else {
            out.decision = Some(Decision::Expired);
            out.still_at = still_at();
            out.message = message(
                &Answer::decision(&ex.request_id, Decision::Expired),
                &ex.phone,
                &export.name,
            );
            return Ok(text(&out));
        };
        out.decision = Some(answer.decision);
        out.error = answer.error.as_deref();
        out.import = answer.import.as_ref();
        out.message = message(answer, &ex.phone, &export.name);
        if answer.decision != Decision::Staged {
            out.still_at = still_at();
            out.message
                .push_str(" Nothing was staged; the export is still on this computer.");
        } else if opts.keep {
            out.still_at = still_at();
            out.message.push_str(
                " The export is still on this computer (keep); delete it when you no longer need it.",
            );
        } else {
            match export.wipe() {
                Ok(()) => {
                    out.deleted = true;
                    out.message
                        .push_str(" The export was deleted from this computer.");
                }
                Err(e) => {
                    out.still_at = still_at();
                    out.message.push_str(&format!(
                        " The export could not be deleted ({e}); ask the user to delete it."
                    ));
                }
            }
        }
        Ok(text(&out))
    }
}

/// The exit code of an import result (docs/agent-protocol.md, "Moving in").
pub fn exit_code(v: &Value) -> u8 {
    if v["error"] == "paused" {
        return PAUSED;
    }
    match (v["decision"].as_str(), v["error"].as_str()) {
        (_, Some(import::errors::NO_PASSCODE)) => NO_PASSCODE_EXIT,
        (_, Some(import::errors::IMPORT_CLOSED)) => IMPORT_CLOSED_EXIT,
        (_, Some(import::errors::WINDOW_FULL)) => WINDOW_FULL_EXIT,
        (_, Some(import::errors::IMPORT_UNREADABLE)) => UNREADABLE_EXIT,
        (_, Some(import::errors::TOO_LARGE)) => TOO_LARGE_EXIT,
        (_, Some(import::errors::BAD_IMPORT)) => 1,
        (Some("staged"), _) => 0,
        (None, None) if v["dry_run"] == true => 0,
        (Some("denied"), _) => DENIED,
        (Some("expired"), _) => EXPIRED,
        _ => 1,
    }
}

/// Checks the options of `nodkey import` before anything is read.
pub fn check_cli(a: &Args) -> Result<(), String> {
    a.only(
        "import",
        &[
            "source", "reason", "keep", "dry-run", "phone", "model", "effort",
        ],
    )?;
    a.positionals("import", 1, "one FILE: the export to send")?;
    a.value("source").map_or(Ok(()), check_source)
}

/// `nodkey import FILE`: prints the result (`--json`: as JSON) and returns the exit code.
pub async fn run_cli(a: &Args, agent: &Agent, reported: Reported<'_>) -> Result<u8, String> {
    let note = std::sync::atomic::AtomicBool::new(false);
    let progress = |_: u64, _: u64, _: &str| {
        if !note.swap(true, std::sync::atomic::Ordering::Relaxed) {
            eprintln!("Sending the file to Nodkey on your iPhone ...");
        }
    };
    let opts = Options {
        path: &a.positional[0],
        source: a.value("source"),
        reason: a.value("reason"),
        keep: a.flag("keep"),
        dry_run: a.flag("dry-run"),
        phone: a.value("phone"),
    };
    let result = agent.import_file(opts, reported, &progress).await?;
    let v: Value = serde_json::from_str(&result).map_err(|e| format!("unexpected result: {e}"))?;
    let code = exit_code(&v);
    let message = v["message"].as_str().unwrap_or_default();
    if a.flag("json") {
        println!(
            "{}",
            serde_json::to_string_pretty(&v).expect("serializable")
        );
    } else if code == 0 {
        println!("{message}");
    }
    if code != 0 {
        eprintln!("nodkey: {message}");
    }
    Ok(code)
}

/// The MCP tool `import_file`.
pub async fn call(
    agent: &Agent,
    args: &Map<String, Value>,
    reported: Reported<'_>,
    progress: Progress<'_>,
) -> Result<Text, String> {
    use crate::mcp::{opt_str, req_str};
    let flag = |key: &str| match args.get(key) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(format!("{key} must be true or false")),
    };
    let opts = Options {
        path: req_str(args, "path")?,
        source: opt_str(args, "source")?,
        reason: opt_str(args, "reason")?,
        keep: flag("keep")?,
        dry_run: flag("dry_run")?,
        phone: opt_str(args, "phone")?,
    };
    agent.import_file(opts, reported, progress).await
}

#[cfg(test)]
mod tests;
