//! What each command line command does once its arguments are checked.

use nodkey_proto::Kind;
use serde_json::{Value, json};

use crate::{
    agent::{Agent, Reported},
    card::payment,
    cli::{Args, DENIED, EXPIRED, cleanup_filter, credential_items},
};

/// Prints `note` on stderr the first time a wait reports progress.
fn waiting(note: String) -> impl Fn(u64, u64, &str) + Send + Sync {
    let shown = std::sync::atomic::AtomicBool::new(false);
    move |_, _, _| {
        if !shown.swap(true, std::sync::atomic::Ordering::Relaxed) {
            eprintln!("{note}");
        }
    }
}

fn parse(text: &str) -> Result<Value, String> {
    serde_json::from_str(text).map_err(|e| format!("unexpected result: {e}"))
}

fn print_json(v: &Value) {
    println!("{}", serde_json::to_string_pretty(v).expect("serializable"));
}

/// The exit code for a request's `decision`.
fn exit_for(v: &Value) -> u8 {
    match v["decision"].as_str() {
        Some("approved") => 0,
        Some("denied") => DENIED,
        Some("expired") => EXPIRED,
        _ => 1,
    }
}

pub async fn run(command: &str, a: &Args, agent: &Agent) -> Result<u8, String> {
    let reported = Reported {
        model: a.value("model"),
        effort: a.value("effort"),
    };
    let wait_note = || {
        waiting(format!(
            "Waiting for your answer in Nodkey on your iPhone (up to {} s) ...",
            agent.timing.request.as_secs()
        ))
    };
    match command {
        "pair" => pair(a, agent).await,
        "code" | "login" => {
            let kind = if command == "code" {
                Kind::Code
            } else {
                Kind::Login
            };
            let text = agent
                .request(
                    kind,
                    &a.positional[0],
                    a.value("reason").unwrap_or_default(),
                    a.value("image"),
                    a.value("phone"),
                    reported,
                    &wait_note(),
                )
                .await?;
            let v = parse(&text)?;
            let code = exit_for(&v);
            if code != 0 {
                eprintln!(
                    "nodkey: {}",
                    v["message"].as_str().unwrap_or("not approved")
                );
            }
            match a.value("field") {
                Some(field) if code == 0 => match &v[field] {
                    Value::String(s) => println!("{s}"),
                    Value::Null => return Err(format!("the answer has no {field}")),
                    other => println!("{other}"),
                },
                Some(_) => {}
                None => println!("{}", text.as_str()),
            }
            Ok(code)
        }
        "credentials" => {
            let (wanted, follow_up, session) = credential_items(a)?;
            let text = agent
                .credentials(
                    wanted,
                    a.value("reason").unwrap_or_default(),
                    follow_up,
                    session,
                    a.value("image"),
                    a.value("phone"),
                    reported,
                    &wait_note(),
                )
                .await?;
            let v = parse(&text)?;
            let code = exit_for(&v);
            if code != 0 {
                eprintln!(
                    "nodkey: {}",
                    v["message"].as_str().unwrap_or("not approved")
                );
            }
            println!("{}", text.as_str());
            Ok(code)
        }
        "pay" => {
            let (merchant, amount) = payment(a)?;
            let text = agent
                .pay(
                    &merchant,
                    amount,
                    a.value("reason").unwrap_or_default(),
                    a.value("image"),
                    a.value("phone"),
                    reported,
                    &wait_note(),
                )
                .await?;
            let v = parse(&text)?;
            let code = crate::card::exit_for_error(v["error"].as_str()).unwrap_or(exit_for(&v));
            if code != 0 {
                eprintln!(
                    "nodkey: {}",
                    v["message"].as_str().unwrap_or("not approved")
                );
            }
            match a.value("field") {
                Some(field) if code == 0 => match &v["card"][field] {
                    Value::String(s) => println!("{s}"),
                    Value::Null => return Err(format!("the card has no {field}")),
                    other => println!("{other}"),
                },
                Some(_) => {}
                None => println!("{}", text.as_str()),
            }
            Ok(code)
        }
        "accounts" | "insights" => {
            let (kind, default_reason) = if command == "accounts" {
                (Kind::List, "See which accounts I may ask for")
            } else {
                (
                    Kind::Insights,
                    "Suggest clean-up rules without seeing names",
                )
            };
            let reason = a.value("reason").unwrap_or(default_reason);
            let text = agent
                .request(
                    kind,
                    "",
                    reason,
                    None,
                    a.value("phone"),
                    reported,
                    &wait_note(),
                )
                .await?;
            let v = parse(&text)?;
            let code = exit_for(&v);
            if a.flag("json") || command == "insights" || code != 0 {
                print_json(&v);
            } else {
                print_accounts(&v);
            }
            Ok(code)
        }
        "cleanup" => {
            let filter = cleanup_filter(a)?;
            let text = agent
                .cleanup(
                    filter,
                    a.value("reason").unwrap_or_default(),
                    a.value("phone"),
                    reported,
                    &waiting(format!(
                        "Waiting for you to check the list in Nodkey on your iPhone (up to {} s) ...",
                        agent.timing.request.as_secs()
                    )),
                )
                .await?;
            let v = parse(&text)?;
            if a.flag("json") {
                print_json(&v);
            } else {
                println!("{}", v["message"].as_str().unwrap_or_default());
                for login in v["accounts"].as_array().into_iter().flatten() {
                    let site = login["site"].as_str().unwrap_or("-");
                    println!("  {site}  {}", login["name"].as_str().unwrap_or_default());
                }
            }
            Ok(exit_for(&v))
        }
        "phones" => {
            let v = parse(&agent.list_phones()?)?;
            if a.flag("json") {
                print_json(&v);
            } else if v["phones"].as_array().is_none_or(Vec::is_empty) {
                println!(
                    "{} is not paired yet. Run `nodkey pair`.",
                    agent.default_name()
                );
            } else {
                for p in v["phones"].as_array().into_iter().flatten() {
                    println!(
                        "{}  check {}  scope {}  id {}",
                        p["name"].as_str().unwrap_or_default(),
                        p["check"].as_str().unwrap_or_default(),
                        p["scope"].as_str().unwrap_or_default(),
                        p["phone_id"].as_str().unwrap_or_default()
                    );
                }
            }
            Ok(0)
        }
        "unpair" => {
            let v = parse(&agent.unpair(&a.positional[0]).await?)?;
            if a.flag("json") {
                print_json(&v);
            } else {
                println!("Left {}.", v["phone"].as_str().unwrap_or("the phone"));
                if let Some(w) = v["relay_warning"].as_str() {
                    eprintln!("nodkey: {w}");
                }
            }
            Ok(0)
        }
        "agents" => agents(a, agent),
        "end-session" => {
            let v = parse(
                &agent
                    .end_session(a.value("reason"), reported, &wait_note())
                    .await?,
            )?;
            eprintln!("nodkey: {}", v["message"].as_str().unwrap_or_default());
            Ok(0)
        }
        _ => Err(format!("unknown command {command:?}")),
    }
}

/// `nodkey pair`: shows the code to type on the phone, waits, then shows the check number.
async fn pair(a: &Args, agent: &Agent) -> Result<u8, String> {
    let start = parse(&agent.pair_start(a.value("name")).await?)?;
    let code = start["code"].as_str().unwrap_or_default().to_owned();
    if a.flag("json") {
        print_json(&start);
    } else {
        println!(
            "Pairing \"{}\".\n\nIn Nodkey on your iPhone, open Agents, tap Add agent and type this code:\n\n    {code}\n\nThe code is valid for {} minutes.",
            start["agent_name"].as_str().unwrap_or_default(),
            start["expires_in_seconds"]
                .as_u64()
                .unwrap_or(300)
                .div_ceil(60)
        );
    }
    let done = parse(
        &agent
            .pair_finish(&code, &waiting("Waiting for your iPhone ...".to_owned()))
            .await?,
    )?;
    if a.flag("json") {
        print_json(&done);
    } else {
        println!(
            "\nPaired with {}. Check number: {}\n\nYour iPhone shows a check number too. If it is not the same, run\n`nodkey unpair \"{}\"` and remove the agent in Nodkey: someone may have swapped keys.",
            done["phone"].as_str().unwrap_or("your iPhone"),
            done["check"].as_str().unwrap_or_default(),
            done["phone"].as_str().unwrap_or_default()
        );
    }
    Ok(0)
}

/// `nodkey agents`: every agent identity on this computer with its phones.
fn agents(a: &Args, agent: &Agent) -> Result<u8, String> {
    let home = agent.home.as_ref().map_err(String::clone)?;
    let mut list = Vec::new();
    for slug in home.agents().map_err(|e| e.to_string())? {
        let store = home.agent(&slug).map_err(|e| e.to_string())?;
        let id = store.identity().map_err(|e| e.to_string())?;
        let phones = store.phones().map_err(|e| e.to_string())?;
        list.push(json!({
            "agent": slug,
            "name": id.map(|i| i.name),
            "phones": phones.iter().map(|p| p.name.clone()).collect::<Vec<_>>(),
        }));
    }
    if a.flag("json") {
        print_json(&json!({ "agents": list }));
    } else if list.is_empty() {
        println!("No agent on this computer is paired yet. Run `nodkey pair`.");
    } else {
        for e in &list {
            let phones: Vec<_> = e["phones"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            println!(
                "{:<16} {}  ({})",
                e["agent"].as_str().unwrap_or_default(),
                e["name"].as_str().unwrap_or_default(),
                if phones.is_empty() {
                    "not paired".to_owned()
                } else {
                    format!("paired with {}", phones.join(", "))
                }
            );
        }
    }
    Ok(0)
}

fn print_accounts(v: &Value) {
    let list = v["accounts"].as_array().cloned().unwrap_or_default();
    if list.is_empty() {
        println!("No accounts. The user picks per request, or none are shared with this agent.");
    }
    for e in list {
        let mut has = Vec::new();
        if e["has_code"].as_bool() == Some(true) {
            has.push("code");
        }
        if e["has_password"].as_bool() == Some(true) {
            has.push("password");
        }
        println!(
            "{}  {}  {}  {}",
            e["issuer"].as_str().unwrap_or_default(),
            e["name"].as_str().unwrap_or_default(),
            e["site"].as_str().unwrap_or("-"),
            has.join("+")
        );
    }
    for c in v["cards"].as_array().into_iter().flatten() {
        println!(
            "Card  {}  {} \u{b7}\u{b7}\u{b7}\u{b7}{}",
            c["title"].as_str().unwrap_or_default(),
            c["brand"].as_str().unwrap_or_default(),
            c["last4"].as_str().unwrap_or_default()
        );
    }
}
