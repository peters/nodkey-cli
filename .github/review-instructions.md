# Code review instructions

These rules set the scope of the Claude review in this repository
(`.github/workflows/claude-review.yml`). `AGENTS.md` has the full project
rules.

## What to report

- Report a finding only when you can name a concrete input or state and the
  wrong result that it causes.
- A PR that lacks an item that `AGENTS.md` or this file requires is a finding
  without a runtime input.
- Report findings in the lines that this PR changes.
- In unchanged code, report only a problem that this PR causes, makes
  reachable or makes worse.
- In round 2, start with the lines that changed since round 1. In the other
  lines of this PR, report a missed defect only with a concrete trigger. Do not
  look there for new attack surfaces.
- Do not report a design decision that a code comment or a document on the
  base branch states as deliberate. For a PR from the owner, the PR body and
  the documents of this PR count too.
- Do not report a finding again when a reply from the owner or a collaborator
  on its thread gave the reason that it is not a defect. Report it again only
  when the code changes.
- Do not report style, naming or formatting.

## Rules for this repository

Read `SECURITY.md` ("What is in scope") and, for anything that goes over the
wire, `docs/agent-protocol.md`.

- A code, a password or an API key is never logged or stored. It reaches a
  tool result or stdout only through wiped buffers. A change that copies one
  into an unwiped buffer, an error text, a log line or a file is a finding.
- The relay and the web pages that an agent visits are untrusted. Check sealing,
  the signed relay calls, the check number and the website match
  (`site.rs`, `fill_only_on`) against `docs/agent-protocol.md`.
- A protocol change (a message, sealing or the relay API) updates
  `docs/agent-protocol.md`, `nodkey-proto`, the fake relay and
  `vectors/v1.json` in the same pull request.
- `nodkey-proto` builds for `wasm32-unknown-unknown`: no OS-only dependency.
- The move-in skill keeps its rule that an agent never reads an export file.
- No personal data and no secrets. Test data uses invented values. Tests write
  only under `target/`, never in the system temp folder.
- Each source file stays below 600 lines. No em dashes. A new dependency needs
  a reason in the commit message.
- Workflows pin every action by commit. In `release.yml`, only the attest and
  release jobs get write permissions.
