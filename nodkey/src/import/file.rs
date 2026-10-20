//! The export file on this computer: read once into wiped memory, and deleted after the phone
//! staged it: overwritten with zeros, flushed to disk, then removed. Only a regular file is read,
//! never a link, and only the file that was read is deleted. Its content is never printed.

use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::SystemTime,
};

use nodkey_proto::import::{MAX_FILE, MAX_FILE_NAME, errors};
use zeroize::Zeroizing;

/// An export in memory, with what it takes to delete the same file later.
pub struct Export {
    pub path: PathBuf,
    /// The file's name without folders, as the phone shows it.
    pub name: String,
    pub bytes: Zeroizing<Vec<u8>>,
    stamp: Stamp,
}

/// What tells the file that was read from another one put in its place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stamp {
    len: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
}

impl Stamp {
    fn of(m: &fs::Metadata) -> Self {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        Stamp {
            len: m.len(),
            modified: m.modified().ok(),
            #[cfg(unix)]
            dev: m.dev(),
            #[cfg(unix)]
            ino: m.ino(),
        }
    }
}

/// Why a file is not read: the protocol's code when it has one (`too_large`,
/// `import_unreadable`), and a message.
pub type Refused = (Option<&'static str>, String);

/// `~/` at the start means the home folder.
pub fn expand_home(path: &str) -> PathBuf {
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"));
    match (path.strip_prefix("~/"), home) {
        (Some(rest), Some(home)) => PathBuf::from(home).join(rest),
        _ => PathBuf::from(path),
    }
}

/// The name the phone shows: the file name without folders or control characters, at most
/// [`MAX_FILE_NAME`] characters.
pub fn display_name(path: &Path) -> String {
    let raw = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let clean: String = raw
        .chars()
        .map(|c| {
            if c.is_control() || c == '/' || c == '\\' {
                '_'
            } else {
                c
            }
        })
        .take(MAX_FILE_NAME)
        .collect();
    match clean.trim() {
        "" => "export".to_owned(),
        name => name.to_owned(),
    }
}

/// Reads the export at `path`: a regular file of 1 to [`MAX_FILE`] bytes.
pub fn read(path: &str) -> Result<Export, Refused> {
    let path = expand_home(path.trim());
    let shown = path.display();
    let meta = fs::symlink_metadata(&path).map_err(|e| (None, format!("{shown}: {e}")))?;
    if meta.file_type().is_symlink() {
        return Err((
            None,
            format!("{shown} is a link; give the path of the export file itself"),
        ));
    }
    if !meta.is_file() {
        return Err((None, format!("{shown} is not a file")));
    }
    let too_large = |len: u64| {
        (
            Some(errors::TOO_LARGE),
            format!(
                "{shown} is {len} bytes; Nodkey takes at most 1 MiB ({MAX_FILE} bytes) per file. Export fewer \
                 items at a time (for example one folder or vault), or ask the user to import it on the iPhone."
            ),
        )
    };
    if meta.len() > MAX_FILE as u64 {
        return Err(too_large(meta.len()));
    }
    let mut f = fs::File::open(&path).map_err(|e| (None, format!("{shown}: {e}")))?;
    let opened = f.metadata().map_err(|e| (None, format!("{shown}: {e}")))?;
    let stamp = Stamp::of(&opened);
    // One buffer of the largest size, so reading never leaves a copy behind in a freed one.
    let mut bytes = Zeroizing::new(vec![0u8; MAX_FILE + 1]);
    let mut n = 0;
    while n < bytes.len() {
        match f.read(&mut bytes[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err((None, format!("{shown}: {e}"))),
        }
    }
    if n > MAX_FILE {
        return Err(too_large(n as u64));
    }
    if n == 0 {
        return Err((
            Some(errors::IMPORT_UNREADABLE),
            format!("{shown} is empty; export again and wait until the download is done"),
        ));
    }
    bytes.truncate(n);
    let name = display_name(&path);
    Ok(Export {
        path,
        name,
        bytes,
        stamp,
    })
}

/// Opens the file for writing without following a link at its place (Unix: `O_NOFOLLOW`).
fn open_for_wipe(path: &Path) -> std::io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

impl Export {
    /// Deletes the file that was read: overwrites it with zeros, flushes that to disk and removes
    /// it. Leaves it when it is no longer the same file (replaced, grown or turned into a link).
    pub fn wipe(&self) -> Result<(), String> {
        let shown = self.path.display();
        let changed = || format!("{shown} changed after nodkey read it, so it was left as it is");
        let meta = fs::symlink_metadata(&self.path).map_err(|e| format!("{shown}: {e}"))?;
        if meta.file_type().is_symlink() || !meta.is_file() || Stamp::of(&meta) != self.stamp {
            return Err(changed());
        }
        let mut f = open_for_wipe(&self.path).map_err(|e| format!("{shown}: {e}"))?;
        let opened = f.metadata().map_err(|e| format!("{shown}: {e}"))?;
        if Stamp::of(&opened) != self.stamp {
            return Err(changed());
        }
        let zeros = [0u8; 64 * 1024];
        let mut left = self.stamp.len;
        while left > 0 {
            let n = left.min(zeros.len() as u64) as usize;
            f.write_all(&zeros[..n])
                .map_err(|e| format!("{shown}: {e}"))?;
            left -= n as u64;
        }
        f.sync_all().map_err(|e| format!("{shown}: {e}"))?;
        drop(f);
        fs::remove_file(&self.path).map_err(|e| format!("{shown}: {e}"))
    }
}
