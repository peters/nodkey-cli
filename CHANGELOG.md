# Changelog

What changed in each release of `nodkey`. The protocol is in
[docs/agent-protocol.md](docs/agent-protocol.md).

## 0.3.0 (2026-10-20)

The first public release. It needs [Nodkey](https://apps.apple.com/app/id6820952672) 1.3 or later
on your iPhone.

### What you can do

- Ask your iPhone for one two-step code (`nodkey code`, the MCP tool `request_code`) or one login
  (`nodkey login`, `request_login`), and see which accounts an agent may ask for
  (`nodkey accounts`, `list_accounts`).
- Ask for what a task needs in one request (`nodkey credentials`, `request_credentials`): several
  logins, codes, passkeys and API keys at once. With a task session of 15, 30 or 60 minutes, the
  rest of the task does not ask again. `nodkey end-session` (`end_session`) ends it early.
- See how you sign in to a site. A login can say "Sign in with Google" and bring the Google login,
  which may be filled on Google's own sign-in pages only. `nodkey suggest`
  (`suggest_sign_in_method`) adds a method to your suggestion list in Nodkey, for you to accept.
- Get a code that a site sent by SMS (`nodkey sms-code`, `request_sms_code`). Your own Shortcuts
  automation passes the message to Nodkey, and you approve with Face ID.
- Use API keys without showing them to the agent. `nodkey run -- <command>` asks for the keys that a
  `.nodkey` file names and puts them only into the environment of the command it starts. Keys can
  belong to projects or be global. `nodkey secret save` (`save_secret`) keeps a new key in Nodkey;
  it reads the key from stdin, never from the command line.
- Let a browser host sign in with a passkey that stays on your iPhone (`nodkey webauthn`), also with
  the WebAuthn PRF extension. A browser host can fill a login (`nodkey login-fill`) or a card
  (`nodkey card-fill`) itself, so the model gets only a summary.
- Pay with your card for one purchase at a shop, for an exact amount (`nodkey pay`,
  `request_payment`). Cards are off until you turn them on for an agent, and every payment asks for
  Face ID. A browser host can also add your card to a site for later payments, if you turned that on
  for the host.
- Propose to clean up old saved logins (`nodkey cleanup`, `cleanup_logins`). You confirm on your
  iPhone, and they go to Recently deleted.
- Set up Claude Code, Codex, Cursor and Claude Desktop with one command (`nodkey setup`). Each agent
  pairs with its own name, so you can pause or remove one without touching the others.

### Safety

- Pairing shows a check number on your computer and on your iPhone, and you confirm it on both
  before the pairing is saved. The iPhone commits to its part of the number first, so the relay
  that passes the keys cannot pick keys that give the same number on both screens.
- Every request and every answer is signed by the side that sent it, inside the encryption.
- The agent's private keys go to the keychain of your computer where there is one: the macOS
  Keychain, the Secret Service on Linux (with `secret-tool`), or DPAPI on Windows.
- Websites are matched by their registrable domain, with the Public Suffix List, and every login or
  code says on which sites it may be filled (`fill_only_on`).
- Your iPhone limits how many new logins and codes one agent gets in 24 hours. Above the limit you
  see a notice; well above it the agent is paused until you resume it.
- An iPhone without a passcode gives agents no cards, no API keys, no "always allow" and no passkey
  sign-in that needs a verified user.
- The command line asks as the agent whose shell runs it, so a `nodkey run` that Claude Code
  started shows up on your iPhone as Claude Code.
- `nodkey run` looks for a `.nodkey` file no higher than the repository root or your home folder,
  ignores one that someone else owns, and tells you which file it used.
- The relay address must use `https` (plain `http` only for a relay on this computer), and `nodkey`
  follows no redirects.
- `nodkey setup` keeps the permissions of the config files it changes, and keeps symlinks.
- Every archive has build provenance. The install scripts check it with `gh attestation verify`
  when the GitHub CLI is logged in, and on macOS they check the Developer ID signature.

### Good to know

- A new pairing needs Nodkey 1.3 or later; an older app gets a message to update Nodkey. Pairings
  you already have keep working.
- Exit codes: 0 approved or queued, 1 error, 2 denied or rejected, 3 no answer in time, 4 the agent
  is paused, 64 bad arguments. `pay` and `card-fill` have a few more; the README lists them.
