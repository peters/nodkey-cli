# nodkey agent rules

`nodkey` is the agent side of Nodkey: one binary with a command line and an MCP server (`nodkey
mcp`). The iOS app and the relay live in the private repository `peters/nodkey`; read
`docs/agent-protocol.md` before you change anything that goes over the wire.

## Layout

- `nodkey-proto/`: the protocol (messages, HPKE, signed relay calls, check number, pairing codes),
  `import.rs` (moving in: the `import` request, the sealed file and `import/detect.rs`, the format
  and counts of an export without its values),
  `client.rs` (the agent's side of requests and pairing, shared with the browser extension in
  `peters/nodkey-browser`), `passkey.rs` (passkey requests and the client data check), `prf.rs`
  (the WebAuthn PRF extension: inputs, outputs and the derivation), `webauthn.rs`
  (the authenticator data, keys and signatures the phone makes), `signin.rs` (sign-in methods, the
  provider login, the second step order, `suggest` and `sms_code`), `site.rs` (websites: hosts read like a browser, the Public Suffix List snapshot
  in `data/`, registrable domains, the same website, `fill_only_on`; `scripts/update-psl.sh`
  updates the list), `quota.rs` (the agent limit:
  `quota_warning`, `paused` and its numbers), `apikey.rs` (API keys: `secret` targets, the key in
  answers and `save_secret`; `apikey/project.rs` keys by project and the lookup), `generate.rs`
  (a new password: the `generate` request, `generate/rules.rs` the `passwordrules` reading and
  `bad_rules`, `generate/make.rs` a generator that plays the phone in tests), `dh.rs` (HPKE open when X25519 runs in WebCrypto) and the generator of
  `vectors/v1.json`. It builds for `wasm32-unknown-unknown`; keep it free of OS-only dependencies.
- `nodkey-fake-relay/`: a relay that plays the phone, for tests (library and binary with `/_fake/...`
  control routes). The extension's tests use it too.
- `nodkey/`: the library (`agent.rs` what the tools do, `relay.rs` relay calls, `store.rs` the agent
  folder and profiles (`store/identity.rs` the identity), `keystore.rs` where the private keys are
  (the keychain of the system or the file), `profile.rs` which agent is asking, `signin.rs` sign-in methods, `suggest` and
  `sms_code`, `secret.rs` API keys (`secret/save.rs` `nodkey secret save`), `run.rs` `nodkey run`,
  `keyfile.rs` the `.nodkey` file, `import.rs` `nodkey import` and the `import_file` tool with
  `import/file.rs`, which reads the export once and overwrites and deletes it), `generate.rs`
  `nodkey generate` and the `create_login` tool, the
  MCP server (`mcp.rs`, `tools.rs`), the command line (`cli.rs`, `usage.rs`, `commands.rs`) and
  `setup.rs`. Tests: `tests/e2e.rs` (MCP),
  `tests/cli.rs`, `tests/signin.rs`, `tests/quota.rs`, `tests/secrets.rs`, `tests/projects.rs` and
  `tests/import.rs` and `tests/generate.rs` run the real binary against `nodkey-fake-relay`.
- `skills/nodkey/SKILL.md` and `skills/nodkey-move-in/SKILL.md`: the skills `nodkey setup`
  installs (compiled into the binary). The move-in skill must keep its rule that an agent never
  reads an export file.

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
same change in `peters/nodkey` (app and relay), a check of `peters/nodkey-browser` (it depends on
`nodkey-proto` from this repository by git revision) and new vectors:
`cargo run -p nodkey-proto --example vectors` rewrites `vectors/v1.json` (a test fails when it is
stale). The app's tests keep a copy of that file; copy the new one there in the same change.

## Releases

The repository is public. Do not publish a release or announce an install link without the
owner's explicit yes.

1. Raise `version` in `Cargo.toml`, add the release to `CHANGELOG.md` (plain words, for users), run
   the checks and the WebAssembly build
   (`cargo build -p nodkey-proto --target wasm32-unknown-unknown --features getrandom/wasm_js`; the
   browser extension picks the same random source), commit, tag `vX.Y.Z` and push the tag.
   `release.yml` builds every target, attests the build provenance of each archive
   (`actions/attest`) and makes a **draft** release with `SHA256SUMS`. Only the attest and release
   jobs get write permissions; the build jobs read only. Put the release's section of
   `CHANGELOG.md` into the draft: `gh release edit vX.Y.Z --notes-file <file>`.
2. Sign and notarize the macOS binaries on the Mac that holds the team's Developer ID certificate:
   `gh release download vX.Y.Z --repo peters/nodkey-cli --dir <dir>`, then
   `scripts/sign-macos.sh <mac-host> <dir>` (it signs only archives that pass
   `gh attestation verify`) and
   `gh release upload vX.Y.Z <dir>/* --clobber --repo peters/nodkey-cli`.
3. Publish the draft only after the owner says yes.

CI runs Linux, macOS and Windows on every push and pull request, and `cargo audit` (RustSec
advisories for `Cargo.lock`) on every run and once a week. After a change to `Cargo.lock`, run
`cargo audit` too. Workflows pin every action by commit (Dependabot proposes updates). Run
`Release` by hand (workflow_dispatch) to build the archives as workflow artifacts without a release.
