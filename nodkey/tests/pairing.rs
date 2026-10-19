//! Pairing with a commitment and signed answers (docs/agent-protocol.md, "Pairing and the check
//! number" and "Signed requests and answers"), with the real binary against the fake phone: an
//! app without the commitment, a nonce that does not fit, a person who says the numbers differ,
//! and answers without a signature.

mod common;

use nodkey_fake_relay::{self as fake_relay, pairing::PairingMode};
use serde_json::Value;
use std::process::{Command, Output};

struct Cli {
    relay: std::net::SocketAddr,
    dir: std::path::PathBuf,
}

impl Cli {
    fn new(relay: std::net::SocketAddr) -> Self {
        let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("nodkey-pairing-{}", nodkey_proto::random_id()));
        Cli { relay, dir }
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nodkey"));
        c.args(args)
            .env("NODKEY_AGENT_DIR", &self.dir)
            .env("NODKEY_KEYSTORE", "file")
            .env("NODKEY_RELAY", format!("http://{}", self.relay))
            .env("NODKEY_REQUEST_TIMEOUT", "3")
            .env_remove("NODKEY_AGENT")
            .env("TMPDIR", env!("CARGO_TARGET_TMPDIR"));
        c
    }

    fn run(&self, args: &[&str]) -> Output {
        common::output(&mut self.command(args), args)
    }

    fn pair_answering(&self, answer: &str) -> Output {
        common::output_with_input(&mut self.command(&["pair"]), answer.as_bytes())
    }

    fn phones(&self) -> Option<Value> {
        let path = self.dir.join("agents/terminal/phones.json");
        std::fs::read(path)
            .ok()
            .map(|b| serde_json::from_slice(&b).unwrap())
    }

    fn agent_id(&self) -> String {
        let path = self.dir.join("agents/terminal/identity.json");
        let id: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        id["agent_id"].as_str().unwrap().to_owned()
    }
}

impl Drop for Cli {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

#[test]
fn an_app_without_the_commitment_gets_a_clear_refusal() {
    let (fake, addr) = fake_relay::start(1);
    fake.set_pairing(PairingMode {
        old_app: true,
        ..Default::default()
    });
    let cli = Cli::new(addr);
    let out = cli.run(&["pair"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(text(&out).contains("too old"), "{}", text(&out));
    assert!(text(&out).contains("not saved"), "{}", text(&out));
    assert!(cli.phones().is_none());
    // The agent left at the relay, so the phone drops it.
    assert_eq!(fake.left(), vec![cli.agent_id()]);
}

#[test]
fn a_nonce_that_does_not_fit_the_commitment_stops_the_pairing() {
    let (fake, addr) = fake_relay::start(1);
    fake.set_pairing(PairingMode {
        bad_nonce: true,
        ..Default::default()
    });
    let cli = Cli::new(addr);
    let out = cli.run(&["pair"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(text(&out).contains("commitment"), "{}", text(&out));
    assert!(cli.phones().is_none());
    assert_eq!(fake.left(), vec![cli.agent_id()]);
}

#[test]
fn nothing_is_saved_unless_the_person_says_the_numbers_are_the_same() {
    for answer in ["n\n", "", "yes please\n"] {
        let (fake, addr) = fake_relay::start(1);
        let cli = Cli::new(addr);
        let out = cli.pair_answering(answer);
        assert_eq!(out.status.code(), Some(2), "{answer:?}: {}", text(&out));
        assert!(text(&out).contains("not saved"), "{}", text(&out));
        assert!(cli.phones().is_none(), "{answer:?}");
        assert_eq!(fake.left(), vec![cli.agent_id()]);
    }
    let (fake, addr) = fake_relay::start(1);
    let cli = Cli::new(addr);
    let out = cli.pair_answering("Y\n");
    assert!(out.status.success(), "{}", text(&out));
    let phones = cli.phones().unwrap();
    assert_eq!(phones["phones"][0]["signs"], true);
    assert_eq!(
        phones["phones"][0]["check"],
        fake.check_for(&cli.agent_id()).replace(' ', "")
    );
    assert!(!cli.dir.join("agents/terminal/pairing.json").exists());
}

#[test]
fn answers_must_be_signed_after_a_pairing_with_the_commitment() {
    let (fake, addr) = fake_relay::start(1);
    let cli = Cli::new(addr);
    assert!(cli.run(&["pair"]).status.success());
    let ask = ["code", "github.com", "--reason", "Merge PR #4"];
    assert!(cli.run(&ask).status.success());
    fake.set_pairing(PairingMode {
        unsigned_answers: true,
        ..Default::default()
    });
    let out = cli.run(&ask);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(text(&out).contains("not signed"), "{}", text(&out));
    assert!(!text(&out).contains(fake_relay::CODE));
}

#[test]
fn an_older_pairing_requires_signatures_after_the_first_signed_answer() {
    let (fake, addr) = fake_relay::start(1);
    let cli = Cli::new(addr);
    assert!(cli.run(&["pair"]).status.success());
    // A pairing made before signatures: no "signs" in phones.json.
    let path = cli.dir.join("agents/terminal/phones.json");
    let mut phones = cli.phones().unwrap();
    phones["phones"][0].as_object_mut().unwrap().remove("signs");
    std::fs::write(&path, serde_json::to_vec(&phones).unwrap()).unwrap();

    let ask = ["code", "github.com", "--reason", "Merge PR #4"];
    fake.set_pairing(PairingMode {
        unsigned_answers: true,
        ..Default::default()
    });
    // An app before signatures: its answers still work.
    assert!(cli.run(&ask).status.success());
    assert!(cli.phones().unwrap()["phones"][0].get("signs").is_none());
    // The app was updated: its first signed answer is remembered.
    fake.set_pairing(PairingMode::default());
    assert!(cli.run(&ask).status.success());
    assert_eq!(cli.phones().unwrap()["phones"][0]["signs"], true);
    // From then on an unsigned answer is refused.
    fake.set_pairing(PairingMode {
        unsigned_answers: true,
        ..Default::default()
    });
    let out = cli.run(&ask);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(text(&out).contains("not signed"), "{}", text(&out));
}
