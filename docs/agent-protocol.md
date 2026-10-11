# Agent protocol (version 1)

The exact contract between the phone (Nodkey), the agent tool (`nodkey`: the command line and the
MCP server `nodkey mcp`) and the relay. Test vectors: `vectors/v1.json` (made by
`cargo run -p nodkey-proto --example vectors`; the iOS app's tests keep a copy of the same file).

## Principles

- The relay forwards ciphertext and public keys. It never sees a code, a password, an account name or a
  reason. It keeps a request for at most 120 s and stores no IP address.
- An agent never receives a TOTP key, only one code at a time, and a password only for the request it
  asked for. The agent tools store no secrets from the phone.
- Every decision is made on the phone. A lease ("lend for 1 day") is a rule the phone keeps; the agent
  must still ask each time, and the phone answers by itself while the lease lasts.
- An agent may propose a clean-up of saved logins; the phone never deletes anything for good on an
  agent's word. Matches go to Recently deleted after the user saw them and confirmed with Face ID.

## Encoding

- JSON, UTF-8. Binary values are base64url without padding (`b64u`).
- Ids are 16 random bytes in `b64u` (22 characters): `phone_id`, `agent_id`, `request_id`.
- Times are Unix seconds (integers).

## Keys

Each side (phone, agent) has:

| Key | Algorithm | Use |
| --- | --- | --- |
| `kem` | X25519 | HPKE recipient key; public key = 32 bytes |
| `sign` | Ed25519 | signs every relay call; public key = 32 bytes |

HPKE (RFC 9180) base mode, suite DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305
(KEM 0x0020, KDF 0x0001, AEAD 0x0003). Single-shot seal/open. `enc` is 32 bytes.

| Message | HPKE `info` | AEAD `aad` |
| --- | --- | --- |
| request (agent → phone) | `nodkey/v1/request` | `request_id` ‖ `agent_id` (ASCII of the b64u strings) |
| answer (phone → agent) | `nodkey/v1/answer` | `request_id` ‖ `phone_id` |
| pairing grant (phone → agent) | `nodkey/v1/pairing` | pairing `code` (6 canonical upper-case characters, no dash: `K7P2QX`) ‖ `phone_id` |
| attachment (agent → phone) | `nodkey/v1/attachment` | `request_id` ‖ `agent_id` |

## Signing relay calls

Header `Nodkey-Auth: <id>.<ts>.<sig>` where `id` is the caller's `phone_id` or `agent_id`, `ts` the
current Unix time, and `sig` = `b64u(Ed25519(sign_key, M))` with

```text
M = "nodkey/v1\n" + METHOD + "\n" + PATH_WITH_QUERY + "\n" + ts + "\n" + hex(SHA-256(body))
```

The relay rejects a signature older or newer than 120 s, an unknown id, or a key that does not match
the one registered for that id. `POST /v1/pairings` (the agent is not known yet) is signed with the key
in its own body.

## Check number

Both sides show `check = (u32 big-endian of SHA-256("nodkey/v1/check" ‖ agent_sign ‖ agent_kem ‖
phone_sign ‖ phone_kem)[0..4]) mod 1_000_000`, as six digits ("418 902"). The user compares them; a relay
that swapped keys would show a different number.

## Relay API

Base URL: `https://relay.nodkey.app`.

| Call | Signed by | Body → response |
| --- | --- | --- |
| `PUT /v1/phones/{phone_id}` | phone | `{sign, kem, apns_token?, apns_sandbox?}` → `204`. First call registers (trust on first use); later calls must be signed by the registered key. |
| `POST /v1/pairings` | agent (own key) | `{agent_id, name, sign, kem}` → `201 {code, expires}`. `code` is 6 Crockford base32 characters, valid 300 s. |
| `GET /v1/pairings/{code}/agent` | phone | → `200 {agent_id, name, sign, kem}` of the agent waiting on a live, unclaimed code, `404` otherwise. The phone needs these keys to seal the grant (and its check number) before it claims. Counts against the phone's 10 claims per hour, so a pairing (lookup + claim) uses two. |
| `POST /v1/pairings/{code}/claim` | phone | `{enc, ct}` (sealed grant to the agent) → `200 {agent_id, name, sign, kem}`; the phone checks these are the keys the lookup returned |
| `GET /v1/pairings/{code}?wait=60` | agent | → `{phone_id, sign, kem, enc, ct}` once claimed, `204` on timeout, `404` when expired |
| `POST /v1/phones/{phone_id}/requests` | agent (paired) | `{request_id, enc, ct, attachment?: true}` → `202`. Rate limit 20 per hour per agent. Sends a push when the phone has an APNs token; with `attachment: true` the push waits until the attachment is uploaded or 5 s have passed. |
| `PUT /v1/requests/{request_id}/attachment` | agent (the requester) | raw body = `enc` (32 bytes) ‖ ciphertext of the image; the whole body at most 1 MiB (1 048 576 bytes, so the image at most 1 048 528) → `204`, bigger → `413 too_large`; within 120 s of the request. Optional; see Attachments. |
| `GET /v1/requests/{request_id}/attachment` | phone | → the same bytes (`application/octet-stream`), `404` when there is none |
| `GET /v1/phones/{phone_id}/requests?wait=25` | phone | → `[{request_id, agent_id, enc, ct, created, has_attachment, ip?, country?}]` pending requests (the app polls while open and when a push arrives); `ip`/`country` are what Cloudflare saw of the agent; a `Nodkey-Push: none` header means the relay holds no push token (APNs refused it), and the phone registers again |
| `POST /v1/requests/{request_id}/answer` | phone | `{enc, ct}` → `204` |
| `GET /v1/requests/{request_id}?wait=60` | agent (the requester) | → `{enc, ct}` once answered, `204` on timeout, `410` after 120 s |
| `DELETE /v1/phones/{phone_id}/agents/{agent_id}` | phone | → `204`; the relay rejects that agent from then on |
| `DELETE /v1/agents/{agent_id}/phones/{phone_id}` | agent | → `204`; the agent leaves: the relay forgets the pairing and the phone drops the agent the next time it lists pending requests (`GET …/requests` sends the ids of agents that left in a `Nodkey-Revoked: id1,id2` header, once) |
| `DELETE /v1/phones/{phone_id}` | phone | → `204`; forget the phone and all its agents |

Errors: `{error: "<code>", message}` with 400 `bad_request`, 401 `bad_signature`, 403 `not_paired`,
404 `not_found`, 409 `already_claimed`, 410 `expired`, 413 `too_large`, 429 `rate_limited`.

## Messages (plaintext inside HPKE)

Pairing grant (phone → agent):

```json
{"v":1, "phone_name":"Test iPhone", "scope":"selected", "check":"418902"}
```

`scope`: `selected` (the user picks accounts per request), `codes`, `logins`, `all`.

Request (agent → phone):

```json
{"v":1, "request_id":"…", "kind":"code|login|list|insights|cleanup|save", "target":"github.com/alex",
 "reason":"Merge PR #42", "agent":"Claude · Horizon", "ts":1791620000}
```

- `attachment` (optional): `{"type":"image/png|image/jpeg|image/gif", "bytes":12345, "caption":"vg.no login page"}`
  when the agent uploads a picture of what it is about to sign in to (a screenshot of the login page, or
  a short animated GIF). The phone shows it in the notification.
- `kind: code` returns a one-time code; `login` returns user name, password and, when the login has a
  TOTP key (linked, or a code account with the same site and user name), a code. For 120 s after
  the user approves a login or code once, a `code` request from the same agent for that account is
  answered without asking (a follow-up window, not shown as a lease); `list` returns the names of the accounts this agent may ask for (no secrets).
- `target` is free text the phone matches against its accounts: a site or issuer, optionally
  `/account` (`vg.no`, `github.com/alex`, `GitHub`). The phone asks the user when several match. A
  named account that is not there matches nothing (no other account on the site is offered); after a
  scheme (`https://vg.no/login`) the tail is a path, not an account.
  Empty (`""`) for `list` and `cleanup`.
- `kind: insights` asks for clean-up help **without identifying data**. The user approves it like a
  list (no lease). The answer's `insights` holds counts and anonymous groups, never a site, user name
  or title:

  ```json
  {"total":712, "with_code":40,
   "ages":{"never":300, "over_5y":50, "over_2y":80, "over_1y":60, "recent":222},
   "ip_or_local":23, "test_hosts":7, "no_site":4,
   "sites":[{"group":"d_3fa9c21b07e4", "logins":47, "spread":3, "last_used_year":2019, "never_used":40, "added_year":2017}],
   "usernames":[{"group":"u_19c2ab5f0d11", "logins":31, "spread":29, "never_used":31, "added_year":2016, "email":true}]}
  ```

  `sites` are registrable domains with 3 or more logins (`spread` = distinct user names), `usernames`
  are user names on 3 or more sites (`spread` = distinct sites); at most 40 each, largest first. A group
  id is `d_`/`u_` plus the first 6 bytes (hex) of HMAC-SHA256 over `d:<domain>` / `u:<lower-case user
  name>` with a per-agent key, HMAC-SHA256(key = the phone's Ed25519 private key, `nodkey/v1/insight-groups/<agent_id>`).
  The agent cannot reverse it, and two agents get different ids for the same site. A clean-up
  `filter` may carry `group`; the phone resolves it to `domain` or `username` (refusing at once with
  `error: "unknown_group"` when it matches nothing) and shows the user the real filter before anything moves.
- `client` (optional, every field optional) says who is asking, for the phone's history:
  `{"app":"Claude Code", "app_version":"2.4.1", "model":"claude-opus-5-5", "effort":"high",
  "os":"linux 7.0.0 x86_64", "host":"dev-laptop", "workdir":"nodkey", "mcp_version":"0.1.0"}`.
  nodkey-mcp fills `app`/`app_version` from MCP `initialize`, `os`, `host`, `workdir` (the last path
  component only) and `mcp_version` itself, and `model`/`effort` from optional tool arguments. Each
  field is at most 80 characters. It is self-reported: the phone shows it as such in the history
  (tap an event) and never decides anything on it.
- `kind: cleanup` proposes moving the saved logins that match `filter` to Recently deleted:

  ```json
  {"v":1, "request_id":"…", "kind":"cleanup", "target":"", "reason":"Remove logins for old router addresses",
   "agent":"Claude · Horizon", "ts":1791620000,
   "filter":{"ip_only":true, "last_used_before":1760084000}}
  ```

  `filter` fields, all optional, every one that is set must hold:

  | Field | Meaning |
  | --- | --- |
  | `query` | wildcard (`*`, `?`) over site, address, title and user name; without a wildcard "contains" |
  | `username` | the user name exactly (case-insensitive), or a wildcard pattern (`alex.old@*`) |
  | `domain` | a domain including its subdomains (`old-company.no` takes `mail.old-company.no`) |
  | `ip_only` | `true`: the site is an IPv4 or IPv6 literal, with or without port (`192.168.1.1`, `10.0.0.138:8080`, `[fe80::1]`), `localhost` or a `*.local` name |
  | `last_used_before` | Unix time; a login never used counts as before |
  | `added_before` | Unix time |
  | `password_changed_before` | Unix time; without a change date the date added counts |
  | `never_used` | `true`: never used from Nodkey (never copied, never handed to an agent) |
  | `group` | an anonymous group id from `insights` (`d_…` site, `u_…` user name), resolved on the phone |

  At least one criterion is required (blank text and `false` do not count). Both sides refuse an
  empty filter: the agent tools do not send it, and the phone answers `denied` with
  `error: "empty_filter"` without asking the user. Cleanup requests are **never covered by a lease**.
  The phone runs the filter over its saved logins; with no match it answers `approved`, `moved: 0`
  at once (and logs it in the Agents history); otherwise it shows the filter in words, the number of
  matches and the list (site and user name) with "Move N to Recently deleted" (Face ID first) and
  Deny. Approving moves exactly the logins shown (still there) through the normal delete path
  (removed from the iCloud backup, restorable for 30 days). The notification for a clean-up
  (category `AGENT_REQUEST_CLEANUP`) offers only Deny and Open Nodkey, because the decision needs
  the list; the notification extensions cannot read the login list, so the app decides. An older
  phone that does not know `cleanup` cannot read the request and lets it expire. Scopes: allowed for
  `selected`, `logins` and `all`, refused for `codes`.

Answer (phone → agent):

```json
{"v":1, "request_id":"…", "decision":"approved|denied|expired",
 "lease":{"kind":"once|day|week|always", "until":1791706400},
 "account":{"issuer":"GitHub", "name":"alex", "site":"github.com"},
 "code":"190274", "seconds_left":12,
 "username":"alex", "password":"…",
 "accounts":[{"issuer":"GitHub","name":"alex","site":"github.com","has_code":true,"has_password":true}]}
```

Only the fields that apply are present. `until` is absent for `once` and `always`.

A `cleanup` answer carries `moved` (how many logins went to Recently deleted) and `accounts` with
the names of the moved logins (`issuer` = the login's title or host, `name` = user name, `site`;
never a password). A refusal without asking carries `error`: `empty_filter` (a clean-up without a
criterion), `paused` (the user paused this agent, or all agents, under Agents; any kind of request,
answered at once and recorded in the history) or `unsupported_version` (the request's `v` is not a
version the app speaks; planned, see "Versions"):

```json
{"v":1, "request_id":"…", "decision":"approved", "moved":2,
 "accounts":[{"issuer":"Router","name":"admin","site":"192.168.1.1"},{"issuer":"Printer","name":"demo","site":"10.0.0.138"}]}
{"v":1, "request_id":"…", "decision":"denied", "error":"empty_filter"}
{"v":1, "request_id":"…", "decision":"denied", "error":"paused"}
```

## Saving a login

`kind: save` asks the phone to keep a login the user just used, for example when they sign in or
change a password in a browser with the Nodkey extension. `target` is the site (`vg.no`); `save`
holds the login:

```json
{"v":1, "request_id":"…", "kind":"save", "target":"vg.no", "reason":"Save the login you just used on vg.no",
 "agent":"Firefox on Linux", "ts":1791620000,
 "save":{"url":"https://www.vg.no/login", "username":"alex@example.com", "password":"…", "title":"VG"}}
```

The phone shows the site and user name (never the password) and asks the user to save it; Face ID
confirms. A login with the same site and user name gets the new password; otherwise a new login is
added. A save is **never covered by a lease**. The answer carries `saved`: `added`, `updated` or
`unchanged`:

```json
{"v":1, "request_id":"…", "decision":"approved", "saved":"updated"}
```

An agent must not keep the password after the request: if the user does not answer in time, it may
keep the request **sealed to the phone** (only the phone can open it) and offer to send it again.
Vectors: `request_save`, `answer_save`.

## Opening with the X25519 step elsewhere

An agent may keep its X25519 private key where it cannot be read out, for example as a
non-extractable WebCrypto key in a browser. It then computes `dh = X25519(sk, enc)` there and runs
the rest of HPKE base mode itself: `nodkey_proto::dh::open_with_dh(info, dh, pkR, enc, aad, ct)`
gives the same result as an open with the private key. Every HPKE vector checks both ways.

## Attachments

The push payload is limited to 4 KB, so a picture travels separately. The agent seals the image bytes
with HPKE to the phone (`info` = `nodkey/v1/attachment`, `aad` = `request_id` ‖ `agent_id`), posts the
request with `attachment: true` and uploads
`enc ‖ ct` with `PUT /v1/requests/{request_id}/attachment` right after posting the request; the request
plaintext describes it. The notification service extension downloads it (retrying for up to 3 s on `404`), decrypts it and
attaches it
(`UNNotificationAttachment`; animated GIFs play when the notification is expanded on iPhone, a Mac
showing iPhone notifications shows a still image). Limits: 1 MiB, PNG/JPEG/GIF, kept by the relay only as
long as the request (120 s). Without a picture everything works the same.

## Leases

A lease is `(agent_id, account_id, kind: code|login, until)`, kept only on the phone (keychain-backed
store shared with the notification extensions). While a matching lease is valid the phone answers by
itself and shows a quiet notification ("Claude got the password for vg.no"). Durations: once (no lease),
1 day, 7 days, always (until revoked). The user sees and revokes leases under Agents; removing an agent
removes its leases and calls `DELETE …/agents/{agent_id}`.

## Versions

Every plaintext message carries `v` (now `1`). The agent sends the version it speaks in every request;
the phone answers a request whose `v` it does not speak with `decision: denied`, `error:
"unsupported_version"`, without asking the user, and the agent tells the user to update the app or
`nodkey`. (Planned for the app after 1.0; until then the phone ignores a request it cannot read and the
agent sees `expired`.) Requests also carry `client.mcp_version`, the version of `nodkey`.

## Agent side

- Keys and pairings: `~/.config/nodkey-agent/` (directory 0700, files 0600; `NODKEY_AGENT_DIR`
  overrides it). Each agent on the computer has its own identity and pairing under
  `agents/<profile>/`: `identity.json` (`agent_id`, name, both private keys) and `phones.json` (paired
  phones: `phone_id`, public keys, name, check). Profiles: `claude-code`, `codex`, `cursor`,
  `claude-desktop`, `terminal` (the command line), or any name given with `--agent`. The phone shows
  each by its name ("Claude Code @ my-laptop", "Terminal @ my-laptop"), so the user can pause or remove
  one without the others and the history shows who asked. `config.json` in the top folder may set
  `relay`. An identity in the top folder (made before profiles) moves into the profile its name
  belongs to on first use, with its keys, so it stays paired.
- One binary `nodkey`. The MCP server is `nodkey mcp` (stdio); `nodkey setup` registers it as
  `nodkey mcp --agent <profile>` in each agent it finds. Without `--agent`, the profile follows the
  MCP client's `clientInfo.name`.
- A tool result only reaches the model when the call ends, so pairing over MCP takes two calls:
  `pair(name?)` returns the code to type on the phone (`K7P-2QX`) at once; `pair(code)` then waits up
  to 5 minutes for the claim and returns the phone name and the check number, which the model shows
  the user to compare. Other tools: `list_phones()`, `unpair(phone)` (calls the agent-side `DELETE`
  and forgets the phone), `request_code(target, reason, image_path?)`,
  `request_login(target, reason, image_path?)`, `list_accounts()`, `cleanup_insights()`,
  `cleanup_logins(filter, reason)` (dates as Unix seconds or `YYYY-MM-DD`; an unknown filter key is an
  error, so a typo cannot widen the filter). `image_path` is an optional PNG/JPEG/GIF file (for example
  a browser screenshot) sent as the attachment. Results go to the model; the server keeps nothing.
- The command line does the same in one process: `nodkey pair` shows the code and then the check
  number; `nodkey code`, `login`, `accounts`, `insights`, `cleanup`, `phones`, `unpair`. Exit codes:
  0 approved, 1 error, 2 denied, 3 expired, 64 bad arguments.
