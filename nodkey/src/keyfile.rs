//! The `.nodkey` file of a repository: the project its keys belong to and the keys its commands
//! need, by name only. It never holds a value, so it is safe to commit, also in a public
//! repository. `nodkey run -- <command>` reads the nearest one from the current folder up to the
//! repository root or the home folder; a file another user owns, or that everyone may change, is
//! ignored (like git's `safe.directory`), and the one used is named on stderr and to the phone.
//!
//! ```toml
//! project = "sparrow"
//! secrets = ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "global/GITHUB_TOKEN"]
//! ```
//!
//! nodkey reads this small part of TOML: comments, `project` as a string and `secrets` as a list
//! of strings (over several lines if you like). A name may say `global/NAME` (only the global
//! key) or `other-project/NAME`.

use std::path::{Path, PathBuf};

use nodkey_proto::{SecretTarget, apikey};

/// The file's name.
pub const FILE: &str = ".nodkey";

/// What a `.nodkey` file says.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyFile {
    pub path: PathBuf,
    pub project: Option<String>,
    /// Key targets: `NAME`, `global/NAME` or `project/NAME`.
    pub secrets: Vec<String>,
}

/// Why a `.nodkey` file was passed over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Untrusted {
    /// Another user owns it.
    OtherOwner,
    /// Everyone may change it.
    WritableByAll,
}

/// What the search found: the file to use, or the nearest one that was passed over.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Found {
    pub path: Option<PathBuf>,
    pub ignored: Option<(PathBuf, Untrusted)>,
}

/// The nearest `.nodkey` file in `dir` or a folder above it, up to the repository root (a folder
/// with `.git`) or the home folder, whichever comes first. The search stops at the first file
/// it finds; one that is not the user's own is passed over.
pub fn find(dir: &Path) -> Found {
    find_below(dir, crate::store::home_dir().as_deref())
}

pub(crate) fn find_below(dir: &Path, home: Option<&Path>) -> Found {
    for d in dir.ancestors() {
        let path = d.join(FILE);
        if path.is_file() {
            return match untrusted(&path) {
                None => Found {
                    path: Some(path),
                    ignored: None,
                },
                Some(why) => Found {
                    path: None,
                    ignored: Some((path, why)),
                },
            };
        }
        if d.join(".git").exists() || home.is_some_and(|h| d == h) {
            break;
        }
    }
    Found::default()
}

/// Whether a file is not the user's own: another owner, or writable by everyone.
#[cfg(unix)]
fn untrusted(path: &Path) -> Option<Untrusted> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path).ok()?;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let me = unsafe { libc::geteuid() };
    trust(meta.uid(), meta.mode(), me)
}

#[cfg(not(unix))]
fn untrusted(_: &Path) -> Option<Untrusted> {
    None
}

/// The rule of [`untrusted`] on the owner, the mode bits and the user's own id.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) fn trust(owner: u32, mode: u32, me: u32) -> Option<Untrusted> {
    if owner != me {
        Some(Untrusted::OtherOwner)
    } else if mode & 0o002 != 0 {
        Some(Untrusted::WritableByAll)
    } else {
        None
    }
}

/// The nearest `.nodkey` file from `dir` up, read and checked. A file that was passed over is
/// said on stderr, so nobody wonders why its keys are not asked for.
pub fn nearest(dir: &Path) -> Result<Option<KeyFile>, String> {
    let found = find(dir);
    if let Some((path, why)) = &found.ignored {
        eprintln!(
            "nodkey: ignoring {}: {}. Keys named there are not asked for.",
            shown(path),
            match why {
                Untrusted::OtherOwner => "another user owns it",
                Untrusted::WritableByAll => "everyone may change it",
            }
        );
    }
    found.path.map(|p| read(&p)).transpose()
}

/// A path as the user reads it: the home folder as `~`.
pub fn shown(path: &Path) -> String {
    match crate::store::home_dir().and_then(|h| path.strip_prefix(h).ok().map(Path::to_owned)) {
        Some(rest) => format!("~{}{}", std::path::MAIN_SEPARATOR, rest.display()),
        None => path.display().to_string(),
    }
}

/// Reads and checks the `.nodkey` file at `path`.
pub fn read(path: &Path) -> Result<KeyFile, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let mut file = parse(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    file.path = path.to_owned();
    Ok(file)
}

/// Reads the text of a `.nodkey` file.
pub fn parse(text: &str) -> Result<KeyFile, String> {
    let mut p = Parser {
        chars: text.chars().collect(),
        at: 0,
        line: 1,
    };
    let mut file = KeyFile::default();
    let (mut seen_project, mut seen_secrets) = (false, false);
    loop {
        p.skip_blank(true);
        let Some(c) = p.peek() else {
            break;
        };
        if c == '[' {
            return Err(p.error("tables are not part of a .nodkey file"));
        }
        let key = p.key()?;
        p.skip_blank(false);
        p.expect('=')?;
        p.skip_blank(false);
        match key.as_str() {
            "project" if !seen_project => {
                seen_project = true;
                let name = p.string()?;
                let trimmed = name.trim();
                if !trimmed.eq_ignore_ascii_case(apikey::GLOBAL) {
                    if !apikey::valid_project(trimmed) {
                        return Err(p.error(&format!(
                            "{name:?} is not a project name (1 to {} characters, no / or ,)",
                            apikey::MAX_PROJECT
                        )));
                    }
                    file.project = Some(trimmed.to_owned());
                }
            }
            "secrets" if !seen_secrets => {
                seen_secrets = true;
                for name in p.list()? {
                    file.secrets
                        .push(check_name(&name).map_err(|e| p.error(&e))?);
                }
            }
            "project" | "secrets" => return Err(p.error(&format!("{key} is given twice"))),
            other => {
                return Err(p.error(&format!(
                    "unknown key {other:?}; a .nodkey file has project and secrets"
                )));
            }
        }
        p.skip_blank(false);
        match p.peek() {
            None | Some('\n') => {}
            Some(_) => return Err(p.error("one key = value per line")),
        }
    }
    for (i, t) in file.secrets.iter().enumerate() {
        let name = variable(t);
        if file.secrets[..i].iter().any(|u| variable(u) == name) {
            return Err(format!("{name} is in secrets twice"));
        }
    }
    Ok(file)
}

/// The variable name of a key target (`global/NAME` → `NAME`).
pub fn variable(target: &str) -> &str {
    target.rsplit('/').next().unwrap_or(target)
}

/// One entry of `secrets`: `NAME`, `global/NAME` or `project/NAME`, never a value or a service.
fn check_name(name: &str) -> Result<String, String> {
    let name = name.trim();
    if name.contains('=') {
        return Err(format!(
            "{name:?}: secrets holds names only (e.g. \"OPENAI_API_KEY\"), never a value; the file is meant to be committed"
        ));
    }
    let t = SecretTarget::parse(name).map_err(|e| format!("secrets: {e}"))?;
    if t.service.is_some() || t.variable.is_none() {
        return Err(format!(
            "{name:?}: secrets holds variable names (NAME, global/NAME or project/NAME); give a service with \
             nodkey run --secret NAME=SERVICE"
        ));
    }
    Ok(t.to_target())
}

struct Parser {
    chars: Vec<char>,
    at: usize,
    line: usize,
}

impl Parser {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.at).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.at += 1;
        if c == '\n' {
            self.line += 1;
        }
        Some(c)
    }

    fn error(&self, what: &str) -> String {
        format!("line {}: {what}", self.line)
    }

    /// Skips spaces, tabs and comments, and line breaks too when `newlines`.
    fn skip_blank(&mut self, newlines: bool) {
        while let Some(c) = self.peek() {
            match c {
                ' ' | '\t' | '\r' => {}
                '\n' if newlines => {}
                '#' => {
                    while self.peek().is_some_and(|c| c != '\n') {
                        self.bump();
                    }
                    continue;
                }
                _ => return,
            }
            self.bump();
        }
    }

    fn expect(&mut self, want: char) -> Result<(), String> {
        match self.bump() {
            Some(c) if c == want => Ok(()),
            _ => Err(self.error(&format!("expected {want:?}"))),
        }
    }

    /// A bare key (letters, digits, `_` and `-`), or a quoted one.
    fn key(&mut self) -> Result<String, String> {
        if matches!(self.peek(), Some('"' | '\'')) {
            return self.string();
        }
        let start = self.at;
        while self
            .peek()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            self.bump();
        }
        if self.at == start {
            return Err(self.error("expected a key such as project or secrets"));
        }
        Ok(self.chars[start..self.at].iter().collect())
    }

    /// A basic string (`"..."` with escapes) or a literal string (`'...'`), on one line.
    fn string(&mut self) -> Result<String, String> {
        let quote = match self.bump() {
            Some(q @ ('"' | '\'')) => q,
            _ => return Err(self.error("expected a string in quotes")),
        };
        let mut out = String::new();
        loop {
            match self.bump() {
                None | Some('\n') => return Err(self.error("the string has no closing quote")),
                Some(c) if c == quote => return Ok(out),
                Some('\\') if quote == '"' => out.push(self.escape()?),
                Some(c) => out.push(c),
            }
        }
    }

    fn escape(&mut self) -> Result<char, String> {
        let hex = |p: &mut Parser, n: usize| -> Result<char, String> {
            let digits: String = (0..n).filter_map(|_| p.bump()).collect();
            u32::from_str_radix(&digits, 16)
                .ok()
                .and_then(char::from_u32)
                .ok_or_else(|| p.error("bad \\u escape"))
        };
        match self.bump() {
            Some('"') => Ok('"'),
            Some('\\') => Ok('\\'),
            Some('n') => Ok('\n'),
            Some('t') => Ok('\t'),
            Some('r') => Ok('\r'),
            Some('u') => hex(self, 4),
            Some('U') => hex(self, 8),
            _ => Err(self.error("unknown escape in a string")),
        }
    }

    /// `[ "A", "B", ]` over one or more lines, with comments.
    fn list(&mut self) -> Result<Vec<String>, String> {
        self.expect('[')?;
        let mut out = Vec::new();
        loop {
            self.skip_blank(true);
            if self.peek() == Some(']') {
                self.bump();
                return Ok(out);
            }
            out.push(self.string()?);
            self.skip_blank(true);
            match self.bump() {
                Some(',') => {}
                Some(']') => return Ok(out),
                _ => return Err(self.error("expected , or ] in the list")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_file() {
        let f = parse(
            "# Keys for the Sparrow tests\n\
             project = \"sparrow\"\n\
             secrets = [\n  \"OPENAI_API_KEY\", # the test project\n  'ANTHROPIC_API_KEY',\n  \"Global/GITHUB_TOKEN\",\n]\n",
        )
        .unwrap();
        assert_eq!(f.project.as_deref(), Some("sparrow"));
        assert_eq!(
            f.secrets,
            ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "global/GITHUB_TOKEN"]
        );
        let f = parse("secrets = [\"A\"]").unwrap();
        assert_eq!(f.project, None);
        let f = parse("project = \"Global\"\r\nsecrets = []\r\n").unwrap();
        assert_eq!((f.project, f.secrets.len()), (None, 0));
        assert_eq!(
            parse("project = \"B\\u00e5t\"").unwrap().project.as_deref(),
            Some("Båt")
        );
        assert_eq!(parse("").unwrap(), KeyFile::default());
    }

    #[test]
    fn refuses_what_it_does_not_know() {
        for (text, want) in [
            ("project = sparrow", "string in quotes"),
            ("project = \"a/b\"", "not a project name"),
            (
                "project = \"x\"\nproject = \"y\"",
                "line 2: project is given twice",
            ),
            ("secret = [\"A\"]", "unknown key"),
            ("[keys]\nA = 1", "tables"),
            (
                "secrets = [\"OPENAI_API_KEY=sk-test-0000\"]",
                "never a value",
            ),
            (
                "secrets = [\"openai.com/OPENAI_API_KEY\"]",
                "--secret NAME=SERVICE",
            ),
            ("secrets = [\"openai.com\"]", "--secret NAME=SERVICE"),
            ("secrets = [\"A-B\"]", "not a service"),
            ("secrets = [\"A\", \"sparrow/A\"]", "A is in secrets twice"),
            ("secrets = [\"A\" \"B\"]", "expected , or ]"),
            ("secrets = [\"A\"", "expected , or ]"),
            ("project = \"x\" secrets = []", "one key = value per line"),
            ("project = \"x", "closing quote"),
        ] {
            let err = parse(text).unwrap_err();
            assert!(err.contains(want), "{text:?}: {err}");
        }
    }

    #[test]
    fn finds_the_nearest_file() {
        let root = crate::test_dir("keyfile");
        let deep = root.join("repo/src/bin");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(root.join("repo").join(FILE), "project = \"sparrow\"\n").unwrap();
        let used = |dir: &Path| find_below(dir, None).path;
        assert_eq!(used(&deep), Some(root.join("repo").join(FILE)));
        std::fs::write(root.join("repo/src").join(FILE), "secrets = []\n").unwrap();
        assert_eq!(used(&deep), Some(root.join("repo/src").join(FILE)));
        assert_eq!(read(&used(&deep).unwrap()).unwrap().project, None);

        // Not above the repository root, nor above the home folder.
        std::fs::remove_file(root.join("repo/src").join(FILE)).unwrap();
        std::fs::create_dir_all(root.join("repo/src/.git")).unwrap();
        assert_eq!(find_below(&deep, None), Found::default());
        std::fs::remove_dir_all(root.join("repo/src/.git")).unwrap();
        assert_eq!(
            find_below(&deep, Some(&root.join("repo/src"))),
            Found::default()
        );
        assert_eq!(used(&deep), Some(root.join("repo").join(FILE)));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn only_the_users_own_files() {
        assert_eq!(trust(501, 0o100644, 501), None);
        assert_eq!(
            trust(501, 0o100664, 501),
            None,
            "group-writable is the usual umask 002"
        );
        assert_eq!(trust(0, 0o100644, 501), Some(Untrusted::OtherOwner));
        assert_eq!(trust(502, 0o100600, 501), Some(Untrusted::OtherOwner));
        assert_eq!(trust(501, 0o100666, 501), Some(Untrusted::WritableByAll));
    }

    #[cfg(unix)]
    #[test]
    fn a_file_everyone_may_change_is_passed_over() {
        use std::os::unix::fs::PermissionsExt;
        let root = crate::test_dir("keyfile-mode");
        std::fs::create_dir_all(root.join("repo")).unwrap();
        let file = root.join("repo").join(FILE);
        std::fs::write(&file, "secrets = [\"A_TOKEN\"]\n").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).unwrap();
        let found = find_below(&root.join("repo"), None);
        assert_eq!(found.path, None);
        assert_eq!(
            found.ignored,
            Some((file.clone(), Untrusted::WritableByAll))
        );
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(find_below(&root.join("repo"), None).path, Some(file));
        std::fs::remove_dir_all(&root).unwrap();
    }
}
