# Agent protocol (version 1)

The exact contract between the phone (Nodkey), the agent tool (`nodkey`: the command line and the
MCP server `nodkey mcp`) and the relay. Test vectors: `vectors/v1.json` (made by
`cargo run -p nodkey-proto --example vectors`; the iOS app's tests keep a copy of the same file).

## Principles

- The relay forwards ciphertext and public keys. It never sees a code, a password, an account name or a
  reason. It keeps a request for at most 120 s (an `sms_code` request at most 360 s) and stores no
  IP address.
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
| saved password (agent → phone, inside a `save` request) | `nodkey/v1/password` | `agent_id` |
| saved card number or CVC (agent → phone, inside a `save` request) | `nodkey/v1/card` | `agent_id` |

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
| `POST /v1/phones/{phone_id}/requests` | agent (paired) | `{request_id, enc, ct, attachment?: true, ttl?}` → `202`. Rate limit 20 per hour per agent. Sends a push when the phone has an APNs token; with `attachment: true` the push waits until the attachment is uploaded or 5 s have passed. `ttl` (120 to 360, default 120): how many seconds the relay keeps the request and its answer; the agent sends it only for `sms_code` (see "SMS codes"). A relay that does not know `ttl` keeps the request 120 s, and the agent then sees `expired`. |
| `PUT /v1/requests/{request_id}/attachment` | agent (the requester) | raw body = `enc` (32 bytes) ‖ ciphertext of the image; the whole body at most 1 MiB (1 048 576 bytes, so the image at most 1 048 528) → `204`, bigger → `413 too_large`; within 120 s of the request. Optional; see Attachments. |
| `GET /v1/requests/{request_id}/attachment` | phone | → the same bytes (`application/octet-stream`), `404` when there is none |
| `GET /v1/phones/{phone_id}/requests?wait=25` | phone | → `[{request_id, agent_id, enc, ct, created, has_attachment, ip?, country?}]` pending requests (the app polls while open and when a push arrives); `ip`/`country` are what Cloudflare saw of the agent; a `Nodkey-Push: none` header means the relay holds no push token (APNs refused it), and the phone registers again |
| `POST /v1/requests/{request_id}/answer` | phone | `{enc, ct}` → `204` |
| `GET /v1/requests/{request_id}?wait=60` | agent (the requester) | → `{enc, ct}` once answered, `204` on timeout, `410` after the request's `ttl` (120 s by default) |
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
{"v":1, "request_id":"…", "kind":"code|login|list|insights|cleanup|save|passkey|bundle|card|session_end|suggest|sms_code", "target":"github.com/alex",
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
  An account may have extra websites ("Also used on" in the app, for example chatgpt.com on a login
  saved for openai.com). They match strictly by registrable domain: `chatgpt.com` and
  `auth.chatgpt.com` match the extra website `chatgpt.com`, `chatgpt.ru` and `chatgpt.com.evil.io`
  do not. Own names and sites rank before extra websites. When nothing matches, the user may pick
  another account by hand in the app (and may let the phone remember the requested site as an extra
  website of that account); the answer then says `match: "chosen"`, and a fresh `code` for the same
  site in the follow-up window is answered with that account.
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
 "lease":{"kind":"once|day|week|always|session", "until":1791706400},
 "account":{"issuer":"GitHub", "name":"alex", "site":"github.com"},
 "code":"190274", "seconds_left":12,
 "username":"alex", "password":"…",
 "accounts":[{"issuer":"GitHub","name":"alex","site":"github.com","has_code":true,"has_password":true}]}
```

Only the fields that apply are present. `until` is absent for `once` and `always`. `session`
means the answer came from a task session (see "Task sessions"). `decision` is also `queued` or
`rejected`, only for `suggest`. `login` and `code` answers may carry `method`, `via` and
`second_step` (see "Sign-in methods").

A `code` or `login` answer also carries `match`: `direct` (the account's name or site matched the
target), `alias` (one of its extra websites matched) or `chosen` (nothing matched and the user picked
it by hand). `account.sites` and the `sites` of each `accounts` entry list the account's extra
websites, absent when it has none. Older apps send neither. Vectors: `request_login_chosen`,
`answer_login_chosen`, `answer_list_with_sites`.

```json
{"v":1, "request_id":"…", "decision":"approved", "match":"chosen",
 "account":{"issuer":"OpenAI", "name":"alex@example.com", "site":"openai.com", "sites":["chatgpt.com"]},
 "username":"alex@example.com", "password":"…"}
```

A `cleanup` answer carries `moved` (how many logins went to Recently deleted) and `accounts` with
the names of the moved logins (`issuer` = the login's title or host, `name` = user name, `site`;
never a password). A refusal without asking carries `error`: `empty_filter` (a clean-up without a
criterion), `paused` (the user paused this agent, or all agents, under Agents, or the agent limit
paused it; any kind of request, answered at once and recorded in the history; see "Agent limit"), `unsupported_version` (the request's `v` is not a
version the app speaks) or `unsupported_kind` (the app does not know the request's `kind` yet; see
"Versions"). Passkey refusals are listed under "Passkeys":

```json
{"v":1, "request_id":"…", "decision":"approved", "moved":2,
 "accounts":[{"issuer":"Router","name":"admin","site":"192.168.1.1"},{"issuer":"Printer","name":"demo","site":"10.0.0.138"}]}
{"v":1, "request_id":"…", "decision":"denied", "error":"empty_filter"}
{"v":1, "request_id":"…", "decision":"denied", "error":"paused"}
```

## Bundles

`kind: bundle` asks for several codes and logins in one request, when one task needs a login on
one site and a code on another. `target` is empty; `bundle` holds the items:

```json
{"v":1, "request_id":"…", "kind":"bundle", "target":"", "reason":"Sign in to ChatGPT and GitHub",
 "agent":"Claude Code @ my-laptop", "ts":1791620000,
 "bundle":{"items":[{"id":"1", "kind":"login", "target":"chatgpt.com"},
                    {"id":"2", "kind":"code", "target":"github.com/alex"}],
           "follow_up":300}}
```

- 1 to 10 items, each `code` or `login` with a `target` as in a single request and an `id` (1 to 16
  characters, unique in the bundle; `nodkey` numbers them `"1"`, `"2"`, …). A bundle with a
  `session` may also hold `passkey` items (see "Task sessions").
- `follow_up` (optional, 120 to 600 seconds, default 120): for how long after the approval a fresh
  `code` request from the same agent for an approved item is answered without asking. A bundle with
  a `session` has no `follow_up`: the session covers it.
- Both sides check these rules; the agent tools also refuse a request whose sealed `ct` would be
  longer than the relay's 3400 characters (`REQUEST_CT_MAX`, so the push stays under 4 KB).

The phone matches each item on its own and shows one sheet: every item with its site, the matching
account or a picker (as for a single request with no match), the mismatch and look-alike warnings,
"Remember this site", and a check box per item; "Approve N of M" asks for Face ID once. A bundle is
covered by leases only when every item is (then the phone answers by itself). The notification
(category `AGENT_REQUEST_BUNDLE`) lists the items and offers Open and Deny. The history records one
line per item. Scopes: a `codes` agent gets its login items refused (`error: "not_allowed"` on the
item).

The answer is `approved` when at least one item was approved, else `denied` (or `expired`), with one
answer per item in the request's order, carrying the same fields as a single answer:

```json
{"v":1, "request_id":"…", "decision":"approved",
 "items":[{"id":"1", "decision":"approved", "match":"alias", "lease":{"kind":"once"},
           "account":{"issuer":"OpenAI", "name":"alex@example.com", "site":"openai.com", "sites":["chatgpt.com"]},
           "username":"alex@example.com", "password":"…"},
          {"id":"2", "decision":"denied"}]}
```

An older app answers `unsupported_kind`. The MCP tool is `request_credentials(items, reason,
follow_up_seconds?, image_path?)`; the command line is `nodkey credentials login:chatgpt.com
code:github.com/alex --reason TEXT [--follow-up SECS]`. Vectors: `request_bundle`, `answer_bundle`.

## Task sessions

A task session lets one approval cover a whole task. The agent lists everything the task needs in a
bundle with `session`; the user approves the plan once; until the session ends, a later request from
the same agent for an approved item is answered without asking. It is for tasks that sign in to two
or three places, need fresh codes while they work, or are logged out half-way.

```json
{"v":1, "request_id":"…", "kind":"bundle", "target":"", "reason":"Upload the release to the add-on store",
 "agent":"Claude Code @ my-laptop", "ts":1791620000,
 "bundle":{"items":[{"id":"1", "kind":"login", "target":"accounts.firefox.com"},
                    {"id":"2", "kind":"code", "target":"accounts.firefox.com"},
                    {"id":"3", "kind":"passkey", "target":"github.com"}],
           "session":1800}}
```

- `session`: the length the agent asks for, in seconds: `900`, `1800` or `3600`. The phone shows it
  as 15, 30 or 60 minutes, and the user may pick another of the three before approving.
- A `passkey` item names a relying party (`github.com`, the registrable domain); it is allowed only
  with `session`. Approving it lets later passkey sign-ins (`op: get`) for that relying party go
  through in the session. Its item answer carries `account` (the passkey's user name and site), never
  a signature: the agent signs in later with a normal `passkey` request.
- `login` and `code` items are answered at once, as in any bundle.

The phone shows the plan as one sheet (the items, their accounts, the reason, the session length)
and asks for Face ID once. The notification for such a bundle opens the app; it has no Approve
action. The answer carries `session` when at least one item was approved:

```json
{"v":1, "request_id":"…", "decision":"approved",
 "session":{"id":"Qm9vdHN0cmFwU2Vzc2lvbg", "until":1791621800},
 "items":[{"id":"1", "decision":"approved", "account":{…}, "username":"…", "password":"…",
           "lease":{"kind":"session", "until":1791621800}},
          {"id":"2", "decision":"approved", "account":{…}, "code":"190274", "seconds_left":21,
           "lease":{"kind":"session", "until":1791621800}},
          {"id":"3", "decision":"approved", "account":{"issuer":"github.com", "name":"alex", "site":"github.com"}}]}
```

Every approved `login` and `code` item carries `lease: {"kind":"session", …}`; a `passkey` item
carries none. A plan is never answered by leases, even when every item is lent: a session starts
only from an approval in the app. `session.id` is 22 characters of base64url (16 random bytes);
`until` is when it ends (Unix seconds). While it runs, the agent puts `session_id` on its requests:

```json
{"v":1, "request_id":"…", "kind":"code", "target":"accounts.firefox.com", "reason":"…",
 "agent":"Claude Code @ my-laptop", "ts":1791620300, "session_id":"Qm9vdHN0cmFwU2Vzc2lvbg"}
```

The phone answers without asking when all of these hold: the session exists and has not ended, it
belongs to the same agent, and the request asks for an approved item:

| Request | Covered when |
| --- | --- |
| `code` | it matches the account of an approved `code` or `login` item (also the code account linked to an approved login: same site and user name) |
| `login` | it matches the account of an approved `login` item |
| `passkey` with `op: get` | its `rp_id` is the relying party of an approved `passkey` item, or a site below it, with the same passkey |

An account the user picked by hand for an item (no saved account matched its site) covers later
requests for that site in the session, as in the follow-up window.

Such an answer carries `lease: {"kind":"session", "until":…}`. Anything else is asked as usual,
with or without `session_id`: another site or account, a passkey create, `save`, `save_card`,
`card`, `list`, `insights`, `cleanup` and `bundle`. A request with an unknown or ended `session_id`
is also asked as usual; its answer carries `session_ended: true`, so the agent stops sending the id.

A session ends when its time is up, when the agent ends it, when the user taps Stop on it, pauses
the agent or stops all agents, or when the agent is removed. The agent ends it when the task is done:

```json
{"v":1, "request_id":"…", "kind":"session_end", "target":"", "reason":"Done", "agent":"…", "ts":…,
 "session_id":"Qm9vdHN0cmFwU2Vzc2lvbg"}
{"v":1, "request_id":"…", "decision":"approved"}
```

`session_end` is answered at once, also for an unknown session, and before the pause check; the
relay still pushes it, so the phone shows a quiet notification ("Claude Code finished its task").
It leaves no history line. The phone
keeps sessions with the leases (shared with the notification extensions), so the service extension
answers a covered request while the app is closed, with a quiet notification. Agents shows the
running session ("Active task": time left, what was used, Stop), and the history records every
answer under it. Scopes apply to every item as in any bundle. An older app ignores `session` (the
answer has none, and the agent asks as before), refuses a bundle with a `passkey` item or more than
6 items (`error: "bad_bundle"`; the agent tools then say the app needs an update), and answers
`session_end` with `unsupported_kind`. Vectors: `request_bundle_session`,
`answer_bundle_session`, `request_code_in_session`, `answer_code_in_session`, `request_session_end`.

## A code with little time left

A `code` in any answer (single, bundle item or session) that has fewer than 8 seconds left comes with
the next one: `next_code` and `next_seconds_left` (`seconds_left` + the period, usually 30). The agent
tools wait until the next code is current (at most 8 seconds) and hand that one on, so an agent never
gets a code that runs out while it types.

```json
{"v":1, "request_id":"…", "decision":"approved", "code":"190274", "seconds_left":4,
 "next_code":"582911", "next_seconds_left":34}
```

## Saving a login

`kind: save` asks the phone to keep a login the user just used, for example when they sign in or
change a password in a browser with the Nodkey extension. `target` is the site (`vg.no`); `save`
holds the login:

```json
{"v":1, "request_id":"…", "kind":"save", "target":"vg.no", "reason":"Save the login you just used on vg.no",
 "agent":"Firefox on Linux", "ts":1791620000,
 "save":{"url":"https://www.vg.no/login", "username":"alex@example.com", "title":"VG",
         "password":{"enc":"…", "ct":"…"}}}
```

`password` is sealed to the phone **on its own** with HPKE (`info` = `nodkey/v1/password`, `aad` =
`agent_id`), inside the sealed request. The agent seals it the moment it reads the password, so it
never has to keep the password in clear: a save that waits for the user is sent again later as a new
request (new `request_id`) around the same sealed password. The phone opens the request, then the
password.

The phone shows the site and user name (never the password) and asks the user to save it; Face ID
confirms. A login with the same site and user name gets the new password; otherwise a new login is
added. A save is **never covered by a lease**. The answer carries `saved`: `added`, `updated` or
`unchanged`:

```json
{"v":1, "request_id":"…", "decision":"approved", "saved":"updated"}
```

An agent must not keep the password in clear. When the user does not answer in time, it may keep
the sealed password with the site and user name and offer to send it again. Vectors:
`save_password`, `request_save`, `answer_save`.

## Passkeys

`kind: passkey` lets an agent sign in to a site with a passkey that Nodkey holds, or make a new
passkey there. The phone signs; the private key never leaves it. There is no Bluetooth or hybrid
transport: the request goes through the relay like every other request. `target` is the `rp_id`;
`passkey` holds the WebAuthn data. Sign in (`op: get`):

```json
{"v":1, "request_id":"…", "kind":"passkey", "target":"webauthn.io", "reason":"Sign in to webauthn.io",
 "agent":"Claude Code @ my-laptop", "ts":1791620000,
 "passkey":{"op":"get", "rp_id":"webauthn.io", "client_data_json":"<b64u>",
            "allow_credentials":["<b64u>"], "user_verification":"required"}}
```

A new passkey (`op: create`):

```json
"passkey":{"op":"create", "rp_id":"webauthn.io", "rp_name":"WebAuthn.io", "client_data_json":"<b64u>",
           "user":{"id":"<b64u>", "name":"alex", "display_name":"Alex"},
           "algorithms":[-7, -257], "exclude_credentials":["<b64u>"],
           "resident_key":"required", "user_verification":"required"}
```

| Field | Meaning |
| --- | --- |
| `op` | `get` or `create` |
| `rp_id` | the relying party id, the same as `target` |
| `client_data_json` | the whole `clientDataJSON` (b64u of its bytes), not only its hash, so the phone can check it |
| `allow_credentials` | get, optional: credential ids (b64u) the site accepts; empty or absent means any passkey for `rp_id` |
| `rp_name` | create: the site's name |
| `user` | create: `id` (the user handle, b64u, 1 to 64 bytes), `name`, `display_name` |
| `algorithms` | create: COSE algorithm ids the site accepts, in its order |
| `exclude_credentials` | create, optional: credential ids (b64u) the site already has for this user |
| `resident_key`, `user_verification` | `required`, `preferred` or `discouraged`; absent means `preferred`. The phone always makes a discoverable passkey and always asks for Face ID, so these change nothing it does. |

The host that talks to the page (Horizon, the browser extension) makes `client_data_json` itself
from the origin of the calling frame, never from the page or the model:
`{"type":"webauthn.get","challenge":"<b64u>","origin":"https://webauthn.io","crossOrigin":false}`
(`nodkey_proto::passkey::build_client_data_json` makes exactly these bytes).

### The client data check

Before it asks the user, the phone checks `client_data_json` (the agent tools run the same check,
`nodkey_proto::passkey::check_client_data`, before they send):

- it is a JSON object; `type` is `webauthn.get` for get and `webauthn.create` for create;
- `challenge` is a non-empty b64u string;
- `crossOrigin` is absent or `false`;
- `origin` is `https://<host>` or `https://<host>:<port>`, where `host` is `rp_id` or ends with
  `"." + rp_id` (compared without regard to case); or `http://localhost` or
  `http://localhost:<port>` with `rp_id` `localhost`. No path, user name or other scheme;
- `rp_id` is a domain name with a dot (not an IP address), or `localhost`.

If any rule fails, the phone answers `denied` with `error: "bad_client_data"` at once. The vector
section `webauthn.client_data_checks` lists cases that pass and fail.

The phone shows the user the **origin from `client_data_json`**, the reason, and the user name of
the passkey (get) or of the new passkey (create).

### What the phone makes

Nodkey is a software authenticator: ES256 (ECDSA P-256 with SHA-256), sign count always 0,
`none` attestation, AAGUID `97531e9d-ff39-4e63-aaec-b1d68400c3c9`, a credential id of 16 random
bytes.

- `authenticator_data` = SHA-256(`rp_id`) ‖ flags (1 byte) ‖ sign count (4 bytes, 0). Flags are
  UP, UV, BE and BS (`0x1d`) on every answer, also under a lease: iOS needs BE and BS to stay the
  same, and UV is set because the user approved with Face ID when the lease was made.
- create adds the attested credential data: AAGUID ‖ u16 big-endian length of the credential id ‖
  credential id ‖ COSE key, and the AT flag (`0x5d`). The COSE key is the CBOR map
  `{1: 2, 3: -7, -1: 1, -2: x, -3: y}` in this order; `attestation_object` is the CBOR map
  `{"fmt": "none", "attStmt": {}, "authData": authenticator_data}` in this order.
- `signature` (get) is DER ECDSA over `authenticator_data ‖ SHA-256(client_data_json bytes)`.
- `public_key` (create) is the SubjectPublicKeyInfo DER of the new key (WebAuthn's
  `getPublicKey()`), `public_key_algorithm` is `-7`.

### Answers

```json
{"v":1, "request_id":"…", "decision":"approved",
 "passkey":{"credential_id":"<b64u>", "authenticator_data":"<b64u>", "signature":"<b64u DER>",
            "user_handle":"<b64u>", "user_name":"alex"}}
{"v":1, "request_id":"…", "decision":"approved",
 "passkey":{"credential_id":"<b64u>", "attestation_object":"<b64u>", "authenticator_data":"<b64u>",
            "public_key":"<b64u SPKI DER>", "public_key_algorithm":-7}}
```

A get answer may carry `lease` as a login answer does. Refusals are `decision: denied` with
`error`:

| `error` | When |
| --- | --- |
| `bad_client_data` | `client_data_json` fails the check above; at once |
| `no_passkey` | no passkey for `rp_id`, or none of those in a non-empty `allow_credentials`; at once |
| `unsupported_algorithm` | create without `-7` in `algorithms`; at once |
| `excluded` | create when the phone holds a passkey in `exclude_credentials`; answered **after** the user approved, as WebAuthn asks, so a site cannot probe for passkeys without the user |
| `paused`, `unsupported_kind`, `unsupported_version` | as for every kind; an older app answers `unsupported_kind` |

Leases: a get may be covered by a lease of kind `passkey`, `(agent_id, passkey_id, passkey,
until)`, once, 1 day, 7 days or always, as for logins. **A create is never covered by a lease**:
Face ID every time. A get under a lease is answered by the notification service extension with a
quiet notification ("Claude Code signed in to webauthn.io with a passkey"), and the history marks
it as a lease answer. Scopes: allowed for `selected`, `logins` and `all`, refused for `codes`.

Vectors: `request_passkey_get`, `request_passkey_create`, `answer_passkey_get`,
`answer_passkey_create`, and the `webauthn` section: a fixed P-256 test key (`private_key`,
`public_key_x963`, `public_key_spki`, `cose_key`), the credential id and user handle, and for get
and create the `client_data_json` (text and b64u), its hash, the expected `authenticator_data`,
the `attestation_object` (create), and `signed_data` and a `signature` that verifies with the public
key (get; RFC 6979 nonces, so the file stays the same).

## Payment cards

`kind: card` asks for a payment card to pay **one purchase**. A card request always names the shop
and the amount, so the user sees what money is about to be spent. `target` is the merchant; `card`
holds the purchase:

```json
{"v":1, "request_id":"…", "kind":"card", "target":"shop.example.com",
 "reason":"Buy the 2 m USB-C cable you asked for", "agent":"Claude Code @ my-laptop", "ts":1791620000,
 "card":{"mode":"fill", "merchant":"shop.example.com", "amount":{"value":"499.00", "currency":"NOK"},
         "origin":"https://www.shop.example.com", "page_total":{"value":"499.00", "currency":"NOK"},
         "total_source":"page"}}
```

| Field | Meaning |
| --- | --- |
| `mode` | `fill`: a browser host fills the checkout form and the model never sees the number. `reveal`: the agent gets the full card (number, expiry, CVC). |
| `merchant` | the shop's site; the same as `target` |
| `amount` | **required**: what will be paid, `value` a decimal string with a dot (at most 12 digits before it and 3 after, no thousands separators, more than 0), `currency` an ISO 4217 code (`NOK`) |
| `origin` | `fill`, required: the checkout page's origin as the host saw the frame (`https://<host>[:port]`, `host` the merchant or a subdomain of it; or `http://localhost[:port]` with the merchant `localhost`, as for passkeys), never from the page or the model. Absent for `reveal`. |
| `page_total` | `fill`, optional: the order total the host read on the checkout page (`total_source: page`) or the user typed because none was found (`total_source: user`). Must not be more than `amount` (same currency). Absent for `reveal`. |
| `total_source` | `page` or `user`; present exactly when `page_total` is |

Both sides check these rules (`nodkey_proto::CardRequest::check`; the vector section `cards`
lists amounts, requests, card numbers and what each side must decide for them). The agent tools do
not send a request that fails them; the host refuses `total_mismatch` itself before it sends.

**Rules on the phone.** Cards are off for every agent until the user turns them on for it (Face ID),
also for scope `all`. The user picks which cards an agent may use and sets a limit per purchase and
per 24 hours. Full card numbers (`reveal`) are a separate setting, off by default. A card request is
**never covered by a lease**, is never part of a bundle and never part of a follow-up window: Face
ID every time. The notification (category `AGENT_REQUEST_CARD`) shows the amount and the shop in its
title and offers only Open Nodkey and Deny; the user approves in the app on a sheet that shows the
amount, the shop, the reason, the picture and the card, with a button the user holds ("Hold to pay
499,00 kr"). The history records the amount and the shop of every card request, also of refusals.

Refusals without asking (`decision: denied`, `error`), in this order:

| `error` | When |
| --- | --- |
| `cards_off` | cards are off for this agent |
| `amount_missing` | no `amount`, or not a valid amount |
| `total_mismatch` | `page_total` is more than `amount` |
| `bad_card_request` | the card data breaks another rule above |
| `reveal_off` | `mode: reveal` while full card numbers are off for this agent |
| `over_limit` | `amount` is above the agent's limit per purchase, or would take the last 24 hours above the daily limit |
| `no_card` | no card on the phone may be used by this agent |
| `paused`, `unsupported_kind`, `unsupported_version` | as for every kind |

An approved answer carries the card and the amount the user approved:

```json
{"v":1, "request_id":"…", "decision":"approved",
 "card":{"title":"Test Visa", "brand":"visa", "last4":"4242", "holder":"Alex Example",
         "number":"4242424242424242", "exp_month":12, "exp_year":2030, "cvc":"123",
         "approved_amount":{"value":"499.00", "currency":"NOK"}}}
```

`brand` is `visa`, `mastercard`, `amex`, `discover`, `diners`, `jcb`, `unionpay`, `maestro` or
`other` (`nodkey_proto::card::brand`). `cvc` is absent when the card has none stored. A `fill` host
fills the form only when the page total is still at most `approved_amount`, gives the model only the
brand and the last four digits, and never stores the card.

A `list` answer carries `cards` (`title`, `brand`, `last4`; never the number) when cards are on for
the agent.

### Saving a card

A browser offers to keep a card the user typed: `kind: save` with `save_card` instead of `save`.
`number` and `cvc` are each sealed to the phone on their own (`info` = `nodkey/v1/card`, `aad` =
`agent_id`) the moment they are read, like a saved password:

```json
{"v":1, "request_id":"…", "kind":"save", "target":"shop.example.com",
 "reason":"Save the card you just used on shop.example.com", "agent":"Firefox on Linux", "ts":1791620000,
 "save_card":{"number":{"enc":"…","ct":"…"}, "cvc":{"enc":"…","ct":"…"}, "exp_month":12, "exp_year":2030,
              "holder":"Alex Example", "url":"https://www.shop.example.com/checkout", "last4":"4242"}}
```

The phone shows the holder, `····last4` and the expiry and asks the user to save it (Face ID). The
same number updates the card the phone has. The answer carries `saved`: `added`, `updated` or
`unchanged`. Never covered by a lease.

Vectors: `request_card_fill`, `request_card_reveal`, `request_card_missing_amount`, `answer_card`,
`answer_card_amount_missing`, `answer_card_over_limit`, `answer_card_reveal_off`,
`answer_cards_off`, `answer_card_total_mismatch`, `answer_card_no_card`, `save_card_number`,
`save_card_cvc`, `request_save_card`, `answer_save_card`, `answer_list_with_cards`, and the `cards`
section. Test card numbers only.

## Sign-in methods

Many sites are signed in to with "Sign in with Google" (or Apple, GitHub, Microsoft, Facebook), a
passkey, an e-mail code, the company's single sign-on or an SMS, not with a password. The phone keeps
for each site how the user signs in, and for each login or code account which second step to choose.
A method holds no secret. The names are the app's (`SiteMethod.swift`, `SecondStep.swift`); the app's
`emailCode` is `email_code` on the wire. `nodkey_proto::signin` implements this section.

### The method

```json
"method":{"kind":"federated", "provider":"google", "certainty":"confirmed"}
```

| Field | Meaning |
| --- | --- |
| `kind` | `password`, `federated` ("Sign in with ..."), `passkey`, `email_code`, `sso` (the company's single sign-on) or `sms` |
| `provider` | `federated` only: `google`, `apple`, `github`, `microsoft`, `facebook` or `other` |
| `provider_name` | `provider: other` only: the name of the provider (`Okta`), at most 40 characters |
| `certainty` | `confirmed` (the user said so, or accepted a suggestion), `seen` (an agent or the extension signed in that way and it worked) or `likely` (found in a list, for example Google's connected apps) |
| `mailbox` | `email_code` only: the address that gets the code, so the agent knows which mailbox to read |
| `source` | who added the method: `manual`, `agent`, `extension` or `import` |

Read a method tolerantly, as the app does:

- An unknown `provider` string is `other` with that string as `provider_name` (`"provider":"Okta"`
  reads as `other` and `Okta`). The phone sends `other` with `provider_name`.
- An unknown or absent `certainty` is `likely`. An unknown `source` is absent.
- A method with an unknown `kind` is left out: the answer reads as if it had no `method`.

The `signin.methods` vectors give inputs and how they read.

### Method, provider login and second step in answers

An approved `login` answer carries `method` when the phone knows how the user signs in to the target
site: the first method of the site (the one to try first). An approved `login` or `code` answer
carries `second_step`. The same applies to each `login` and `code` item of a bundle answer. Older
apps send neither field; the agent then uses the default order (see "Second step order").

For a `federated` method, the phone adds `via` when it keeps the provider login (for example the
user's Google login for "Sign in with Google"). The user approves it with the same Face ID as the
answer, and the approval sheet names the provider account. `via` has the fields of a login answer:

```json
{"v":1, "request_id":"…", "decision":"approved", "match":"direct", "lease":{"kind":"once"},
 "method":{"kind":"federated", "provider":"google", "certainty":"confirmed"},
 "via":{"account":{"issuer":"Google", "name":"alex@example.com", "site":"accounts.google.com"},
        "username":"alex@example.com", "password":"…", "code":"190274", "seconds_left":21},
 "second_step":{"prefer":["passkey","totp"], "avoid":["app_prompt","sms"]}}
```

- `account`, `username` and `password` at the top level are the login for the target site itself.
  They are absent when the user has no login for the site and signs in only with the method.
- `via.code` and `via.next_code` follow the rules of "A code with little time left".
- **The agent fills `via` only on the sign-in pages of the provider, never on the target site.** The
  pages of the provider are the hosts at or below its registrable domains: Google `google.com`;
  Apple `apple.com`, `icloud.com`; GitHub `github.com`; Microsoft `microsoft.com`, `live.com`,
  `microsoftonline.com`, `outlook.com`, `office.com`; Facebook `facebook.com`, `meta.com`. For
  `other` it is the site of `via.account`. A host at or below the target site is never a page of the
  provider. `nodkey_proto::signin::may_fill_via` makes this decision; the `signin.via_fill` vectors
  give cases. When the target site itself asks for the password of the provider, the agent stops
  and tells the user.
- Under a lease or a task session, the phone adds `via` only when the provider login is covered too.
  If it is not, the answer has `method` without `via`, and the agent asks for the provider login
  with a normal `login` request (target `accounts.google.com`).

### Second step order

`second_step` is `{"prefer":[...], "avoid":[...]}` with these steps: `passkey` (a passkey that Nodkey
keeps), `totp` (a code from Nodkey), `app_prompt` ("Tap Yes on your phone" in another app), `sms` and
`email`. A step in neither list is allowed after the preferred steps. Unknown steps are left out.
When the user did not change the order, the phone makes it: `passkey` first when it keeps a passkey
for the site, then `totp` when the login or account has a code; `app_prompt` and `sms` are avoided.
An answer without `second_step` means `{"prefer":["passkey","totp"], "avoid":["app_prompt","sms"]}`.

At a second-step prompt the agent picks the first preferred step that the site offers, else the
first step in neither list (in the order above). It moves away from an avoided step ("Try another
way") when the site offers a different one. When the site offers only avoided steps, the agent asks
the user. `SecondStepOrder::pick` makes this choice; the `signin.second_step_picks` vectors give
cases.

### Suggestions

`kind: suggest` proposes a sign-in method for the suggestion list of the user, for example after the
agent signed in with Google to a site where the phone knew no method:

```json
{"v":1, "request_id":"…", "kind":"suggest", "target":"renderfarm.example",
 "reason":"Signed in with Google; Nodkey did not know this method", "agent":"Claude Code @ my-laptop",
 "ts":1791620000,
 "suggest":{"method":{"kind":"federated", "provider":"google", "certainty":"seen", "source":"agent"},
            "outcome":"signed_in"}}
```

- `target`: the host of the site as `nodkey_proto::signin::site` makes it: lower case, without
  scheme, user, port, path or `www.` (`renderfarm.example`).
- `suggest.method`: a method as above. `certainty` is `seen` or absent; `confirmed` is refused,
  because only the user confirms a method. `source`, when present, is `agent` or `extension`.
- `suggest.outcome`: `signed_in` (the agent signed in with this method) or `failed` (the agent tried
  this method and it did not work).
- `reason`: one short sentence for the user, as in every request.

The rules on the phone:

- There is no Face ID and no secret. A suggestion is never covered by a lease and is never part of a
  bundle or a task session (the agent tools refuse it with `session_id`). It gives the agent nothing
  from the vault.
- A `signed_in` suggestion goes into the suggestion list with the name of the agent, the time and the
  reason. One tap accepts it; the method is then saved as `confirmed`. The phone leaves out a method
  that the site already has as `confirmed`, and one that already waits in the list.
- A `failed` suggestion is shown as a note on that method of the site, or dropped. The phone never
  removes or moves a method because an agent says so.
- The answer is the same whether or not the phone knows the site, so a suggestion tells the agent
  nothing about the vault.
- Limit: at most 5 suggestions per agent per hour and 20 per 24 hours (`SUGGEST_PER_HOUR`,
  `SUGGEST_PER_DAY`). The phone rejects more with `rate_limited`. The relay limit of 20 requests per
  hour per agent applies too.
- The phone answers at once, also from the notification service extension, with a quiet
  notification or none. Every scope may send suggestions.

The answer:

```json
{"v":1, "request_id":"…", "decision":"queued"}
{"v":1, "request_id":"…", "decision":"rejected", "error":"rate_limited"}
```

`queued` means the suggestion is in the list; nothing was approved. `rejected` means the phone did not
queue it, without asking the user; `error` is `rate_limited`, `bad_suggestion` (the suggestion breaks a
rule above), `paused` or `unsupported_version`. Only `suggest` answers use `queued` and `rejected`. An
app that does not know `suggest` answers `denied` with `unsupported_kind`.

### SMS codes

`kind: sms_code` asks for a code that the site sends only by SMS. iOS gives apps no access to messages. The user's own Shortcuts
automation ("When I get a message that contains 'code'", run immediately, action "Send code to
Nodkey") gives the message to Nodkey. The phone takes the code (4 to 8 digits) from it, drops the
rest of the text at once and stores nothing.

```json
{"v":1, "request_id":"…", "kind":"sms_code", "target":"account.example.com",
 "reason":"The site sent a sign-in code by SMS", "agent":"Claude Code @ my-laptop", "ts":1791620000,
 "wait_seconds":120}
```

- `wait_seconds` (optional, 30 to 300, default 120): how long the phone waits for the message.
- The phone uses a message only for a pending `sms_code` request within its wait. When no request
  waits, it does nothing. So the agent sends the request right after the site sends the SMS (it
  clicks "Send code", then asks at once).
- When a code arrives, the phone asks "Give the SMS code to <agent>?" with Face ID. An `sms_code`
  request is never covered by a lease and is never part of a bundle, a task session or a follow-up
  window.
- The relay keeps the request for `wait_seconds` + 60 s (the time to approve): the envelope carries
  `ttl` (see "Relay API"), and the agent waits as long.
- Every scope may ask for an SMS code.

The answer is `approved` with `code` (and `seconds_left` when the phone knows it, else absent);
`expired` when no code came within the wait or the user did not answer; `denied` when the user said
no; or a refusal (`paused`, `unsupported_kind`, `unsupported_version`) as for every kind:

```json
{"v":1, "request_id":"…", "decision":"approved", "code":"482913"}
{"v":1, "request_id":"…", "decision":"expired"}
```

An agent asks for an SMS code only when the site offers no passkey and no authenticator code.

Vectors: `request_login_federated`, `answer_login_federated`, `answer_login_with_method`,
`answer_code_second_step`, `request_suggest`, `request_suggest_failed`, `answer_suggest_queued`,
`answer_suggest_rejected`, `request_sms_code`, `answer_sms_code`, `answer_sms_code_expired`, the
signed call `post_request_sms_code` (an envelope with `ttl`), and the `signin` section: how methods
read (`methods`), which suggestions pass (`suggestions`), second step choices
(`second_step_picks`), where `via` may be filled (`via_fill`), site names (`sites`), the sites of
each provider (`provider_sites`) and the limits (`sms_wait`, `suggest_limits`).

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

A lease is `(agent_id, account_id, kind: code|login, until)` (for passkeys see "Passkeys"; cards,
`suggest` and `sms_code` never have one), kept only on the phone (keychain-backed
store shared with the notification extensions). While a matching lease is valid the phone answers by
itself and shows a quiet notification ("Claude got the password for vg.no"). Durations: once (no lease),
1 day, 7 days, always (until revoked). The user sees and revokes leases under Agents; removing an agent
removes its leases and calls `DELETE …/agents/{agent_id}`. While the agent limit warns for an agent, its leases
do not answer (see "Agent limit").

## Agent limit

The phone limits how many different logins and codes one agent gets, so that an agent cannot take
everything out of Nodkey. The phone counts and decides; the agent sees the limit only in answers.
`nodkey_proto::quota` holds the numbers below.

- **What counts:** new items only. An item is one saved login or code account; it is new when this
  agent has not received it in the last 30 days. An agent that uses the same few logins every day
  almost never reaches the limit; an agent that goes through many accounts reaches it fast.
- An item is received when an approved answer gives it: a `code` or `login` answer, an approved
  `login` or `code` item of a bundle, the provider login in `via`, and answers that a lease, a task
  session or the follow-up window gave. Passkey signatures (the key never leaves the phone), cards
  (they have their own limits), `sms_code`, `list`, `insights`, `cleanup`, `save` and `suggest` do
  not count.
- The count is per agent, over a rolling 24 hours.
- The limit is per agent: 5, 10 or 25 (the user picks it under Agents; 10 when they did not).

Before it answers a `code`, `login` or `bundle` request, the phone adds the new items of the request
to the count of the last 24 hours:

| Count with this request | What the phone does |
| --- | --- |
| up to the limit | as usual |
| above the limit, up to 25 | the warning (below) |
| above 25 | it pauses the agent and refuses at once: `denied`, `error: "paused"`, with `quota` |

**Burst rule:** when the new items of the last 10 minutes, with this request, are more than 5, the
phone shows the warning at once, whatever the daily count.

**The warning.** The phone asks the user in the app with a large notice ("Claude Code has received
12 new logins and codes today. Is this expected?"), and the user holds the button and confirms with
Face ID. While the warning applies to an agent:

- leases, the follow-up window and task sessions do not answer for it: each `code`, `login` and
  `bundle` request is asked on its own. A bundle with `session` is asked as a bundle without one and
  starts no session. The phone ends the running session of that agent; a request with its
  `session_id` is asked as usual, and the answer carries `session_ended: true`.
- the notification of its requests offers only Open: the user approves in the app.
- every answer to its `code`, `login` and `bundle` requests carries `error: "quota_warning"` and
  `quota`, with the decision the user made (`approved` too). `quota_warning` is informational: it
  says why the user was asked, not that anything failed.

```json
{"v":1, "request_id":"…", "decision":"approved", "error":"quota_warning",
 "quota":{"new_today":12, "limit":10},
 "account":{"issuer":"GitHub", "name":"alex", "site":"github.com"}, "code":"190274", "seconds_left":12}
{"v":1, "request_id":"…", "decision":"approved", "error":"quota_warning",
 "quota":{"new_today":6, "limit":10, "burst":true}, …}
{"v":1, "request_id":"…", "decision":"denied", "error":"paused", "quota":{"new_today":25, "limit":10}}
```

`quota`: `new_today` is the count after this answer (an approved answer's new items count, a refused
one adds nothing), `limit` is the user's limit for this agent, and `burst: true` says the burst rule
set off the warning (absent otherwise).

**OK for today.** The warning has a second choice, "OK for today" (hold and Face ID). It turns the
warning off for this agent for 24 hours: leases and task sessions work again. It does not turn off
the burst rule, and it does not lift a pause.

**Pause.** A paused agent gets every request refused at once with `paused` (`decision: denied`,
`rejected` for `suggest`; `session_end` is still answered), until the user resumes it under Agents.
A pause by the limit carries `quota`; a pause by the user has none. Resuming starts the count again
from zero and ends "OK for today"; items received before still count as received for "new".

**The agent side.** The tools say why in the result and the command line in its message: on
`quota_warning`, that the user saw a notice about many new logins and codes today; on `paused`, that
the agent is paused and the user can resume it under Agents. An agent tells the user, does not retry
in a loop, asks for fewer items and reuses the logins it already has. Older apps send neither
`quota_warning` nor `quota`.

Vectors: `answer_code_quota_warning`, `answer_login_quota_warning_burst`,
`answer_bundle_quota_warning`, `answer_paused`, `answer_paused_by_limit`, and the `quota` section
(the numbers).

## Versions

Every plaintext message carries `v` (now `1`). The agent sends the version it speaks in every request;
the phone answers a request whose `v` it does not speak with `decision: denied`, `error:
"unsupported_version"`, and a request of a `kind` it does not know with `error: "unsupported_kind"`,
without asking the user. The agent tells the user to update the app or the agent. (Apps before this
change ignore such a request, and the agent sees `expired`.) Requests also carry
`client.mcp_version`, the version of `nodkey`.

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
  `request_login(target, reason, image_path?)`, `request_credentials(items, reason, follow_up_seconds?,
  session_minutes?, image_path?)`, `end_session()`, `request_payment(merchant, amount, currency, reason, image_path?)` (`mode: reveal`;
  its description starts with "Spends the user's money."), `list_accounts()`, `cleanup_insights()`,
  `cleanup_logins(filter, reason)` (dates as Unix seconds or `YYYY-MM-DD`; an unknown filter key is an
  error, so a typo cannot widen the filter), `suggest_sign_in_method(target, kind, provider?, mailbox?,
  outcome, reason)` (`provider` is a known name or the provider's own; a `signed_in` suggestion
  goes as `seen`, a `failed` one without `certainty`) and `request_sms_code(target, reason,
  wait_seconds?)`. A `request_login` result shows `via` with `fill_only_on` (`via_sites`), and its
  message says what to do with `method`, `via` and `second_step`. `image_path` is an optional PNG/JPEG/GIF file (for example
  a browser screenshot) sent as the attachment. Results go to the model; the server keeps no secret.
  A running task session (its id, end, phone and the approved items, never a secret) is kept in
  `agents/<profile>/session.json`, so the MCP server, the command line and `nodkey webauthn` of one
  profile share it; `end_session()` and `nodkey end-session` end it.
- The command line does the same in one process: `nodkey pair` shows the code and then the check
  number; `nodkey code`, `login`, `credentials`, `pay`, `suggest`, `sms-code`, `accounts`, `insights`,
  `cleanup`, `phones`, `unpair`. `nodkey suggest SITE --kind KIND [--provider NAME] [--mailbox ADDR]
  [--outcome failed] --reason TEXT`; `nodkey sms-code TARGET --reason TEXT [--wait SECS]`. Exit codes:
  0 approved (or queued), 1 error, 2 denied (or rejected), 3 expired, 4 paused (`error: paused`),
  64 bad arguments; for `pay` and `card-fill` also 5
  `over_limit`, 6 `reveal_off`, 7 `cards_off` or `no_card`, 8 `total_mismatch`. `nodkey pay MERCHANT
  AMOUNT CURRENCY --reason TEXT --reveal` prints the full card, so it requires `--reveal`; without a
  host nothing can fill a card for it. A missing amount is refused before anything is sent.
- `nodkey webauthn --agent <profile> [--phone PHONE]` is the authenticator a browser host (Horizon)
  calls; `nodkey card-fill --agent <profile> [--phone PHONE]` gives such a host a card to fill. See
  below.

## The authenticator command

`nodkey webauthn --agent <profile>` reads one JSON object on stdin and writes one JSON object on
stdout, also when it fails (waiting notes go to stderr). Sign in:

```json
{"version":1, "op":"get", "rp_id":"webauthn.io", "origin":"https://webauthn.io",
 "client_data_json":"<b64u>", "allow_credentials":["<b64u>"], "user_verification":"preferred",
 "reason":"Sign in to webauthn.io in a browser panel", "requester":{"app":"Horizon", "agent":"Claude Code"}}
```

`op: create` adds `rp_name`, `user`, `algorithms`, `exclude_credentials` and `resident_key`, as in
the request. `reason` is optional ("Sign in to webauthn.io with a passkey" or "Create a passkey for
webauthn.io"); `requester` is optional and self-reported, and goes to the phone's history as
`client.app` ("Horizon (Claude Code)"). Before it sends anything the command checks that `origin` is
the origin inside `client_data_json` and runs the client data check. Results:

```json
{"version":1, "status":"ok", "credential_id":"…", "authenticator_data":"…", "signature":"…", "user_handle":"…"}
{"version":1, "status":"ok", "credential_id":"…", "attestation_object":"…", "authenticator_data":"…",
 "public_key":"…", "public_key_algorithm":-7, "transports":["internal","hybrid"]}
{"version":1, "status":"denied|expired|not_found|excluded|error", "message":"…"}
```

| `status` | Exit | When |
| --- | --- | --- |
| `ok` | 0 | the phone signed (get) or made a passkey (create) |
| `denied` | 2 | the user said no, the agent is paused, or the phone refused the client data or the algorithms |
| `not_found` | 2 | the phone has no matching passkey (`no_passkey`) |
| `excluded` | 2 | the phone already holds a passkey in `exclude_credentials` |
| `expired` | 3 | no answer in time |
| `error` | 1 | not paired, relay trouble, an app that is too old, or an answer that fails the agent's check |
| `error` | 64 | the input is not a valid request, or `origin` does not match `client_data_json` |

A failure from the phone also carries the phone's `error` code. A bridge turns `excluded` into
`InvalidStateError` and every other failure into `NotAllowedError`.

## The card fill command

`nodkey card-fill --agent <profile>` is how a browser host (Horizon) fills a checkout form for an
agent without the card reaching the model. It reads one JSON object on stdin and writes one JSON
object on stdout, also when it fails (waiting notes go to stderr):

```json
{"version":1, "merchant":"shop.example.com", "origin":"https://www.shop.example.com",
 "amount":{"value":"499.00", "currency":"NOK"}, "page_total":{"value":"499,00", "currency":"NOK"},
 "total_source":"page", "reason":"Buy the 2 m USB-C cable you asked for",
 "requester":{"app":"Horizon", "agent":"Claude Code"}}
```

`amount` comes from the agent (or is the page total when the user fills by hand); `origin` and
`page_total` come from the host itself, never from the page's script or the model. Amounts take a dot
or a comma before the decimals. Unknown fields are refused. The command sends `kind: card`, `mode:
fill`. Results:

```json
{"version":1, "status":"ok",
 "card":{"number":"4242424242424242", "exp_month":12, "exp_year":2030, "cvc":"123", "holder":"Alex Example",
         "brand":"visa", "last4":"4242", "title":"Test Visa"},
 "approved_amount":{"value":"499.00", "currency":"NOK"},
 "summary":"filled: Visa ····4242 on shop.example.com, at most 499.00 NOK. One purchase; ask again for the next one."}
{"version":1, "status":"denied|expired|over_limit|cards_off|total_mismatch|error", "message":"…", "error":"…"}
```

| `status` | Exit | When |
| --- | --- | --- |
| `ok` | 0 | the user approved; fill the form, then give the model only `summary` |
| `denied` | 2 | the user said no, or the agent is paused |
| `expired` | 3 | no answer in time |
| `over_limit` | 5 | above the user's limit for this agent |
| `cards_off` | 7 | cards are off for this agent, or no card may be used (`error` says which) |
| `total_mismatch` | 8 | the page total is more than the amount; checked before anything is sent |
| `error` | 1 | not paired, relay trouble, an app that is too old |
| `error` | 64 | the input is not a valid request (`error: amount_missing` when the amount is missing) |

Before it fills, the host reads the page total again and fills nothing when it is now more than
`approved_amount`. It keeps watching the total until the form is sent and clears the card fields if
the total goes up. It never clicks the pay button itself and never stores the card.
