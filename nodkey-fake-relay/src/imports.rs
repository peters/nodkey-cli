//! The fake phone's import window (docs/agent-protocol.md, "Moving in"). A test opens it for an
//! agent with `PUT /_fake/import`; the phone then answers each `import` request from that agent at
//! once, as the real one does: the refusals in the protocol's order, or `staged` with the counts
//! `nodkey_proto::import::detect` reads. A file staged before in the same window (the same hash)
//! counts as duplicates; the fake does not compare single entries.

use std::time::Duration;

use nodkey_proto::{
    Answer, Decision, ImportCounts, ImportFormat, Kind, Request, import, import::detect,
};
use serde::{Deserialize, Serialize};

use crate::Fake;

/// What a test sends to open a window.
#[derive(Debug, Clone, Deserialize)]
pub struct OpenWindow {
    /// The agent the user picked. Absent: whichever agent sends first.
    #[serde(default)]
    pub agent_id: Option<String>,
    /// How long it takes files (default 1800).
    #[serde(default)]
    pub seconds: Option<u64>,
}

/// An open window and what it staged.
#[derive(Debug, Clone, Serialize)]
pub struct Window {
    pub agent_id: Option<String>,
    pub until: u64,
    pub files: Vec<StagedFile>,
}

/// One staged file, as the phone's list shows it (counts only).
#[derive(Debug, Clone, Serialize)]
pub struct StagedFile {
    pub agent_id: String,
    pub file_name: String,
    pub source: String,
    pub sha256: String,
    pub format: ImportFormat,
    pub counts: ImportCounts,
}

impl Window {
    pub fn open(w: OpenWindow) -> Self {
        Window {
            agent_id: w.agent_id,
            until: nodkey_proto::unix_now() + w.seconds.unwrap_or(import::WINDOW_SECONDS),
            files: Vec::new(),
        }
    }
}

fn denied(rid: &str, error: &str) -> Answer {
    let mut a = Answer::decision(rid, Decision::Denied);
    a.error = Some(error.into());
    a
}

/// The refusals the phone decides without the file, at once: often before the agent uploaded it,
/// so the relay then turns the upload away with `409` (the request is answered).
pub(crate) fn refuse_at_once(
    fake: &Fake,
    agent_id: &str,
    rid: &str,
    request: &Request,
) -> Option<Answer> {
    if !*fake.passcode.lock().unwrap() {
        return Some(denied(rid, import::errors::NO_PASSCODE));
    }
    let now = nodkey_proto::unix_now();
    {
        let mut window = fake.import.lock().unwrap();
        let open = window
            .as_ref()
            .is_some_and(|w| now < w.until && w.agent_id.as_deref().is_none_or(|a| a == agent_id));
        if !open {
            return Some(denied(rid, import::errors::IMPORT_CLOSED));
        }
        let w = window.as_mut().expect("open");
        w.agent_id.get_or_insert_with(|| agent_id.to_owned());
        if w.files.len() >= import::WINDOW_FILES as usize {
            return Some(denied(rid, import::errors::WINDOW_FULL));
        }
    }
    let Some(info) = &request.import else {
        return Some(denied(rid, import::errors::BAD_IMPORT));
    };
    info.check().err().map(|(code, _)| denied(rid, code))
}

/// The phone's answer to an `import` request, `None` for other kinds.
pub(crate) async fn answer(
    fake: &Fake,
    agent_id: &str,
    rid: &str,
    request: &Request,
) -> Option<Answer> {
    if request.kind != Kind::Import {
        return None;
    }
    if let Some(refused) = refuse_at_once(fake, agent_id, rid, request) {
        return Some(refused);
    }
    let info = request.import.as_ref()?;
    // The upload follows the request; wait for it a little, as the phone retries a 404.
    let mut file = None;
    for _ in 0..50 {
        file = fake.inner.lock().unwrap().requests[rid].attachment.clone();
        if file.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let Some(file) = file.filter(|f| info.matches(f)) else {
        return Some(denied(rid, import::errors::BAD_IMPORT));
    };
    let d = detect::detect(&file);
    if d.format == ImportFormat::Unknown || d.encrypted || d.archive || d.found == 0 {
        return Some(denied(rid, import::errors::IMPORT_UNREADABLE));
    }
    let mut window = fake.import.lock().unwrap();
    let w = window.as_mut()?;
    let again = w.files.iter().any(|f| f.sha256 == info.sha256);
    let counts = ImportCounts {
        found: d.found,
        new: if again { 0 } else { d.found },
        merged: 0,
        duplicates: if again { d.found } else { 0 },
        conflicts: 0,
        skipped: d.skipped,
        logins: Some(d.logins),
        codes: Some(d.codes),
        files: Some(w.files.len() as u32 + 1),
        until: Some(w.until),
    };
    w.files.push(StagedFile {
        agent_id: agent_id.to_owned(),
        file_name: info.file_name.clone(),
        source: info.source.clone(),
        sha256: info.sha256.clone(),
        format: d.format,
        counts: counts.clone(),
    });
    let mut a = Answer::decision(rid, Decision::Staged);
    a.import = Some(counts);
    Some(a)
}
