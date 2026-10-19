//! `nodkey secret save NAME [--service HOST] [--project NAMES] [--title TEXT] [--notes TEXT]
//! [--expires DATE] --reason TEXT`: reads the value of a new key from stdin (never from the
//! arguments) and asks the phone to keep it. Without `--project`, a key saved in a folder with a
//! `.nodkey` file belongs to its project; `--project global` saves a global key.

use std::{io::IsTerminal, process::ExitCode};

use zeroize::Zeroizing;

use crate::{
    agent::Reported,
    cli::{Args, agent_for, fail, usage_error},
    keyfile,
    run::{runtime, waiting},
    secret::NewKey,
};

/// `nodkey secret save`.
pub fn main(rest: &[String]) -> ExitCode {
    let parsed = (|| -> Result<(NewKey, Args), String> {
        let usage = "nodkey secret save NAME [--service HOST] [--project NAME] --reason TEXT, with the key on stdin";
        let (Some("save"), Some(tail)) = (rest.first().map(String::as_str), rest.get(1..)) else {
            return Err(usage.into());
        };
        let args = Args::parse(tail)?;
        args.only(
            "secret save",
            &[
                "service", "project", "title", "notes", "expires", "reason", "phone", "model",
                "effort",
            ],
        )?;
        args.positionals("secret save", 1, "one NAME, e.g. OPENAI_API_KEY")?;
        args.value("reason")
            .ok_or("nodkey secret save needs --reason: say in one sentence what the key is for")?;
        let expires = args
            .value("expires")
            .map(|v| crate::secret::expires(Some(&serde_json::Value::String(v.to_owned()))))
            .transpose()?
            .flatten();
        let projects = match args.value("project") {
            Some(list) => crate::secret::projects(list.split(','))?,
            None => from_file()?.into_iter().collect(),
        };
        let key = NewKey {
            variable: args.positional[0].clone(),
            service: args.value("service").map(str::to_owned),
            title: args.value("title").map(str::to_owned),
            notes: args.value("notes").map(str::to_owned),
            expires,
            projects,
        };
        crate::secret::target(Some(&key.variable), key.service.as_deref())?;
        Ok((key, args))
    })();
    let (key, args) = match parsed {
        Ok(p) => p,
        Err(e) => return usage_error(&e),
    };
    let value = match read_value() {
        Ok(v) => v,
        Err(e) => return usage_error(&e),
    };
    let agent = match agent_for(&args) {
        Ok(a) => a,
        Err(e) => return usage_error(&e),
    };
    let runtime = match runtime() {
        Ok(rt) => rt,
        Err(e) => return fail(&e),
    };
    let progress = waiting(format!(
        "Waiting for you to save the key in Nodkey on your iPhone (up to {} s) ...",
        agent.timing.request.as_secs()
    ));
    let reported = Reported {
        model: args.value("model"),
        effort: args.value("effort"),
    };
    let result = runtime.block_on(agent.save_secret(
        key,
        value,
        args.value("reason").unwrap_or_default(),
        args.value("phone"),
        reported,
        &progress,
    ));
    match result
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).map_err(|e| e.to_string()))
    {
        Ok(v) => {
            let code = crate::commands::exit_for(&v);
            eprintln!("nodkey: {}", v["message"].as_str().unwrap_or_default());
            println!(
                "{}",
                serde_json::to_string_pretty(&v).expect("serializable")
            );
            ExitCode::from(code)
        }
        Err(e) => fail(&e),
    }
}

/// The project of the nearest `.nodkey` file, said on stderr so the user knows.
fn from_file() -> Result<Option<String>, String> {
    let Some(path) = std::env::current_dir().ok().and_then(|d| keyfile::find(&d)) else {
        return Ok(None);
    };
    let project = keyfile::read(&path)?.project;
    if let Some(p) = &project {
        eprintln!(
            "nodkey: saving the key for the project {p} ({}); --project global saves a global key.",
            path.display()
        );
    }
    Ok(project)
}

/// The key from stdin, without the line break at its end.
fn read_value() -> Result<Zeroizing<String>, String> {
    use std::io::Read;
    // On a terminal the key does not show while it is pasted, so it stays out of the scrollback.
    let quiet = std::io::stdin().is_terminal().then(|| {
        eprintln!(
            "Paste the key (it does not show), then press Enter and Ctrl-D (Ctrl-Z and Enter on Windows):"
        );
        super::noecho::NoEcho::stdin()
    });
    let mut value = Zeroizing::new(String::new());
    let read = std::io::stdin().read_to_string(&mut value);
    drop(quiet);
    read.map_err(|e| format!("cannot read the key from stdin: {e}"))?;
    let end = value.trim_end_matches(['\r', '\n']).len();
    value.truncate(end);
    if value.trim().is_empty() {
        return Err("no key on stdin; pipe it in, e.g. from your clipboard tool".into());
    }
    Ok(value)
}
