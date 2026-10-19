//! Keys by project (peters/nodkey#98). A key has a list of projects ("Sparrow", "Otter"); an empty
//! list makes it **global**: every project, and every request that names no project, may use it.
//! The same variable name may be on one key per project and on one global key. The phone looks a
//! key up the same way everywhere ([`lookup`]): a key of the asked project, else the global key,
//! else nothing (the user may pick a key by hand or answer `no_secret`).

use serde::{Deserialize, Serialize};

use super::SecretTarget;
use crate::{Kind, Request};

/// Longest project name, in characters.
pub const MAX_PROJECT: usize = 40;
/// At most this many projects on one key.
pub const MAX_PROJECTS: usize = 10;
/// The word for the global keys in a target (`global/NAME`). No project has this name.
pub const GLOBAL: &str = "global";

/// Whether `name` can be a project name: 1 to [`MAX_PROJECT`] characters without spaces at
/// either end, no `/`, `,` or control character (a line break separates projects in iCloud), and
/// not [`GLOBAL`] in any case.
pub fn valid_project(name: &str) -> bool {
    let n = name.chars().count();
    name.trim() == name
        && (1..=MAX_PROJECT).contains(&n)
        && !name.chars().any(|c| c == '/' || c == ',' || c.is_control())
        && !name.eq_ignore_ascii_case(GLOBAL)
}

/// Whether two names are the same project: compared without regard to case ("sparrow" in a
/// `.nodkey` file is the app's "Sparrow").
pub fn same_project(a: &str, b: &str) -> bool {
    a.trim().to_lowercase() == b.trim().to_lowercase()
}

/// Whether two project lists hold the same projects, in any order and case (empty = global).
pub fn same_projects(a: &[String], b: &[String]) -> bool {
    let has = |list: &[String], p: &String| list.iter().any(|q| same_project(p, q));
    a.iter().all(|p| has(b, p)) && b.iter().all(|p| has(a, p))
}

/// The rules for the projects of a key to save: each a [`valid_project`], at most
/// [`MAX_PROJECTS`], none twice.
pub(crate) fn check_projects(projects: &[String]) -> Result<(), String> {
    if projects.len() > MAX_PROJECTS {
        return Err(format!("a key belongs to at most {MAX_PROJECTS} projects"));
    }
    for (i, p) in projects.iter().enumerate() {
        if !valid_project(p) {
            return Err(project_error(p));
        }
        if projects[..i].iter().any(|q| same_project(p, q)) {
            return Err(format!("the project {p:?} is given twice"));
        }
    }
    Ok(())
}

fn project_error(p: &str) -> String {
    format!(
        "{p:?} is not a project name (1 to {MAX_PROJECT} characters, no / or , and not \"{GLOBAL}\")"
    )
}

/// The request's `project`: a [`valid_project`], only on a `secret` request or a bundle with
/// `secret` items.
pub(crate) fn check_request(r: &Request) -> Result<(), String> {
    let Some(p) = &r.project else {
        return Ok(());
    };
    if !valid_project(p) {
        return Err(project_error(p));
    }
    let keys_in_bundle = r
        .bundle
        .iter()
        .flat_map(|b| &b.items)
        .any(|i| i.kind == Kind::Secret);
    match r.kind {
        Kind::Secret => Ok(()),
        Kind::Bundle if keys_in_bundle => Ok(()),
        _ => Err("only a secret request or a bundle with secret items names a project".into()),
    }
}

/// Where the key in an answer comes from (`secret.from`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyFrom {
    /// A key of the asked project.
    Project,
    /// A global key: the request named no project, asked for `global/NAME`, or the project has no
    /// key that matches.
    Global,
    /// Nothing matched; the user picked this key by hand.
    Chosen,
}

/// A saved key as the lookup sees it: names only.
#[derive(Debug, Clone, Copy)]
pub struct KeyNames<'a> {
    pub service: Option<&'a str>,
    pub variable: Option<&'a str>,
    /// Empty for a global key.
    pub projects: &'a [String],
}

/// What [`lookup`] found: where the keys come from and their indexes (the user picks one when
/// there are several).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub from: KeyFrom,
    pub keys: Vec<usize>,
}

impl SecretTarget {
    /// The project this target asks in: its own (`sparrow/NAME`), none for `global/NAME`, else the
    /// request's `project`.
    pub fn asked_project<'a>(&'a self, request_project: Option<&'a str>) -> Option<&'a str> {
        if self.global {
            return None;
        }
        self.project.as_deref().or(request_project)
    }
}

/// The phone's lookup for a `secret` request or item: the keys of the asked project
/// ([`SecretTarget::asked_project`]) that match the target, else the global keys that match.
/// `None`: no key matches; the phone still asks the user (pick by hand, or `no_secret`).
pub fn lookup(
    target: &SecretTarget,
    request_project: Option<&str>,
    keys: &[KeyNames],
) -> Option<Found> {
    let hits = |keep: &dyn Fn(&KeyNames) -> bool| -> Vec<usize> {
        keys.iter()
            .enumerate()
            .filter(|(_, k)| target.matches(k.service, k.variable) && keep(k))
            .map(|(i, _)| i)
            .collect()
    };
    if let Some(p) = target.asked_project(request_project) {
        let keys = hits(&|k| k.projects.iter().any(|q| same_project(q, p)));
        if !keys.is_empty() {
            return Some(Found {
                from: KeyFrom::Project,
                keys,
            });
        }
    }
    let keys = hits(&|k| k.projects.is_empty());
    (!keys.is_empty()).then_some(Found {
        from: KeyFrom::Global,
        keys,
    })
}

/// The saved key a `save_secret` updates: the same service (none matches none), the same
/// variable name without regard to case, and the same projects ([`same_projects`]; none =
/// global). `None`: the phone adds a key.
pub fn saved_key(
    service: Option<&str>,
    variable: &str,
    projects: &[String],
    keys: &[KeyNames],
) -> Option<usize> {
    keys.iter().position(|k| {
        k.service == service
            && k.variable.is_some_and(|v| v.eq_ignore_ascii_case(variable))
            && same_projects(k.projects, projects)
    })
}

#[cfg(test)]
mod tests;
