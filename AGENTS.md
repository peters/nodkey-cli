# nodkey agent rules

`nodkey` is the agent side of Nodkey: one binary with a command line and an MCP server (`nodkey
mcp`). The iOS app and the relay live in the private repository `peters/nodkey`; read
`docs/agent-protocol.md` before you change anything that goes over the wire.

## Layout

- `nodkey-proto/`: the protocol (messages, HPKE, signed relay calls, check number, pairing codes)
  and the generator of `vectors/v1.json`.
- `nodkey/`: the library (`agent.rs` what the tools do, `relay.rs` relay calls, `store.rs` the agent
  folder and profiles, `profile.rs` which agent is asking), the MCP server (`mcp.rs`, `tools.rs`), the
  command line (`cli.rs`, `commands.rs`) and `setup.rs`. Tests: `tests/e2e.rs` (MCP) and
  `tests/cli.rs` run the real binary against `tests/fake_relay`, which also plays the phone.
- `skills/nodkey/SKILL.md`: the skill `nodkey setup` installs (compiled into the binary).

## Rules

- Keep each source file below 600 lines. Split a file before it gets larger.
- Before each commit, run `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and
  `cargo test`.
- Code, comments, commits and docs in English. `README.md` uses plain language. No em dashes.
- No personal data in this repository: no real names, e-mail addresses, phone or computer names,
  account names or paths. Test data uses invented values (`alex@example.com`, `Test iPhone`).
- No secrets of any kind. The APNs key and the relay's secrets stay with the relay.
- Never print or store a code or a password. They pass through wiped buffers on their way into a
  tool result or stdout only.
- Keep the dependencies small. A new dependency needs a reason in the commit message.
- Tests write only under `target/`, never in the system temp folder.

## Protocol changes

The app speaks the same protocol. A change to a message, to sealing or to the relay API needs the
same change in `peters/nodkey` (app and relay) and new vectors:
`cargo run -p nodkey-proto --example vectors` rewrites `vectors/v1.json` (a test fails when it is
stale). The app's tests keep a copy of that file; copy the new one there in the same change.

## Releases

The repository is private. Do not make it public, publish a release or share an install link
without the owner's explicit yes.

1. Raise `version` in `Cargo.toml`, run the checks, commit, tag `vX.Y.Z` and push the tag.
   `release.yml` builds every target and makes a **draft** release with `SHA256SUMS`.
2. Sign and notarize the macOS binaries on the Mac that holds the team's Developer ID certificate:
   `gh release download vX.Y.Z --repo peters/nodkey-cli --dir <dir>`, then
   `scripts/sign-macos.sh <mac-host> <dir>` and
   `gh release upload vX.Y.Z <dir>/* --clobber --repo peters/nodkey-cli`.
3. Publish the draft only after the owner says yes.

CI runs Linux on every push. Run `CI` by hand (workflow_dispatch) for macOS and Windows before a
release; run `Release` by hand to build the archives as workflow artifacts without a release.
