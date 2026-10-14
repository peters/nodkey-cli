# Security

`nodkey` asks your iPhone for passwords and one-time codes, so a security problem in it matters.
Please tell us about one in private before you tell anyone else.

## Report a problem

Use **Report a vulnerability** under the repository's Security tab
(GitHub private vulnerability reporting). Do not open a public issue.

Tell us what you found, how to make it happen and what an attacker could get. A proof of concept
helps. We answer within a week and tell you when a fix is out. We name you in the release notes if
you want.

## What is in scope

- This repository: the `nodkey` command line, the MCP server, `nodkey-proto` (the protocol, sealing
  and pairing) and the install scripts.
- The protocol in `docs/agent-protocol.md` and the relay behavior it describes.
- The Nodkey relay at `relay.nodkey.app` when the problem is in how it handles requests from agents.
  Do not test against other people's pairings, and do not try to break the service.

`nodkey-fake-relay` is a test tool. Problems that only exist in it are not security problems.

## Supported versions

Only the newest release gets fixes.
