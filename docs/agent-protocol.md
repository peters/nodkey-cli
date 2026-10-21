# Agent protocol (version 1)

The exact contract between the phone (Nodkey), the agent tool (`nodkey`: the command line and the
MCP server `nodkey mcp`) and the relay. Test vectors: `vectors/v1.json` (made by
`cargo run -p nodkey-proto --example vectors`; the iOS app's tests keep a copy of the same file).

## Principles

- The relay forwards ciphertext and public keys. It never sees a code, a password, an account name or a
  reason. It keeps a request for 120 s (an `sms_code` request up to 360 s). With each request it keeps
  the agent's IP address and country as Cloudflare saw them, so the phone can show where the request
  came from, and deletes them with the request. It never stores the phone's IP address and logs no
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
| `sign` | Ed25519 | signs every relay call, and every request and answer inside the HPKE box (see "Signed requests and answers"); public key = 32 bytes |

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
| saved key (agent → phone, inside a `save_secret` request) | `nodkey/v1/secret` | `agent_id` |
| import file (agent → phone, after an `import` request; see "Moving in") | `nodkey/v1/import` | `request_id` ‖ `agent_id` |

## Signing relay calls

Header `Nodkey-Auth: <id>.<ts>.<sig>` where `id` is the caller's `phone_id` or `agent_id`, `ts` the
current Unix time, and `sig` = `b64u(Ed25519(sign_key, M))` with

```text
M = "nodkey/v1\n" + METHOD + "\n" + PATH_WITH_QUERY + "\n" + ts + "\n" + hex(SHA-256(body))
```

The relay rejects a signature older or newer than 120 s, an unknown id, or a key that does not match
the one registered for that id. `POST /v1/pairings` (the agent is not known yet) is signed with the key
in its own body.

## Signed requests and answers

HPKE base mode keeps a message secret but does not show who sealed it, and the signatures on relay
calls are checked by the relay only. So the sender also signs each request (agent → phone) and each
answer (phone → agent) with its Ed25519 `sign` key, inside the plaintext, and the receiver checks
the signature with the key it pinned at pairing. A relay that does not keep to the protocol can
then neither read a message nor make one up.

```text
B   = the message's JSON as the sender serialized it (a UTF-8 object with at least "v"), without "sig"
M   = "nodkey/v1/signed\n" + direction + "\n" + agent_id + "\n" + phone_id + "\n" + B
sig = Ed25519(the sender's sign key, M)
plaintext = B without its last byte "}" + ",\"sig\":\"" + b64u(sig) + "\"}"
```

- `direction` is `request` (agent → phone) or `answer` (phone → agent). `agent_id` and `phone_id`
  are the b64u ids of this pairing, in this order for both directions.
- `sig` is always the last member. b64u of 64 bytes is 86 characters, so the last 96 bytes of a
  signed plaintext are `,"sig":"<86 characters>"}`. The receiver takes them off and adds `}` to get
  `B` back byte for byte; no canonical JSON form is needed. Then it verifies `sig` over `M` and
  reads `B` (or the whole plaintext: no message has a field named `sig`).
- `M` starts with `nodkey/v1/signed\n`, a relay call's message with `nodkey/v1\n`, so one
  signature cannot serve as the other.
- The pairing grant is not signed: no key is pinned yet. The check number protects it (see below).
  The saved password, card values and key of a `save` or `save_secret` request are sealed boxes
  inside the signed request, so the signature covers them.
- An attachment is not JSON. The signed request carries `attachment.sha256` (b64u of SHA-256 of
  the image bytes), and the phone shows the picture only when the opened image has that hash. An
  import file likewise: the signed request carries `import.sha256`, and the phone stages only a
  file with that hash.
- Receivers made before signatures ignore the unknown `sig` member and read the message as before.

When a signature is required:

- On every message of a pairing made with the commitment (next section): both sides then know the
  other side signs.
- For a pairing made before this change: from the first message of that side that has a valid
  signature. The receiver remembers this and requires a signature from then on.
- Otherwise an unsigned message is accepted, from an app or agent made before signatures. A
  signature that is there must always verify.

A receiver drops a message without a valid signature when one is required. The phone does not show
or answer such a request. The agent does not use such an answer and tells the user that the answer
is not signed by the phone. Vectors: the `signed` section (the bytes signed, the signature and the
plaintext of each) and its HPKE vectors `request_pairing_check`, `answer_pairing_check`,
`request_code_signed`, `answer_code_signed` and `request_login_signed_with_attachment` (its
picture is `attachment_png`).

## Pairing and the check number

Each side learns the other's keys from the relay. The person compares a six-digit check number on
both screens to see that both sides have the same keys. The phone commits to a random value before
it sees the agent's random value, and the agent sends its value before it sees the phone's. So a
relay that swaps keys cannot choose keys or values that give the same number on both screens: with
swapped keys the numbers are the same only by chance, one time in a million.

```text
commit = SHA-256("nodkey/v1/pairing-commit" ‖ phone_sign ‖ phone_kem ‖ phone_nonce)
check  = u32be(SHA-256("nodkey/v1/pairing-check" ‖ agent_sign ‖ agent_kem ‖ phone_sign ‖ phone_kem
                       ‖ agent_nonce ‖ phone_nonce)[0..4]) mod 1_000_000
```

Each nonce is 32 random bytes, new for each pairing. The keys are the 32-byte public keys. The
number shows as six digits ("418 902").

1. The agent starts the pairing with `POST /v1/pairings` and shows the code.
2. The phone looks up the agent's keys (`GET /v1/pairings/{code}/agent`), makes `phone_nonce`, and
   seals the grant with `commit` (b64u) to the agent. Then it claims the code
   (`POST /v1/pairings/{code}/claim`).
3. The agent gets the phone's keys and the grant (`GET /v1/pairings/{code}`). It makes
   `agent_nonce` and sends one `pairing_check` request with `nonce` = b64u(`agent_nonce`), signed
   (see "Signed requests and answers").
4. The phone answers it at once, without asking the person: `decision: approved`, `nonce` =
   b64u(`phone_nonce`), signed.
5. The agent checks that `commit` is the hash of the phone's keys from the claim and the received
   `phone_nonce`. Both sides show `check`. The person compares the numbers and confirms on each
   side. A new pairing is active only after the person confirmed it on that side.

```json
{"v":1, "request_id":"…", "kind":"pairing_check", "target":"", "reason":"", "agent":"Claude Code @ dev-laptop",
 "ts":1791620000, "nonce":"<b64u, 32 bytes>", "sig":"…"}
{"v":1, "request_id":"…", "decision":"approved", "nonce":"<b64u, 32 bytes>", "sig":"…"}
```

The phone:

- Makes a new `phone_nonce` for each claim, and sends it only in the answer to that agent's first
  `pairing_check`.
- Checks the request's signature with the agent's `sign` key from the lookup, and that the request
  comes from the agent of this pairing (`agent_id` in the pending request list).
- Answers only the first `pairing_check` of a pairing. Any other `pairing_check` (a second one, or
  one from an agent that is not pairing) gets `decision: denied`, `error: "unexpected_pairing_check"`;
  a second one also ends the pairing (the phone removes the agent). A `pairing_check` is never
  covered by a lease or a task session, does not count for the agent limit and shows no
  notification.
- Then shows the check number and asks the person to compare it with the number on the computer.
  When the person confirms that the numbers are the same, the agent is active. When they say the
  numbers differ, or cancel, the phone removes the agent (`DELETE /v1/phones/{phone_id}/agents/{agent_id}`).
- Gives up when no `pairing_check` came within 120 s of the claim: it tells the person that the
  agent may need an update and removes the agent.
- Until the person confirms, it does not show or answer any other request from that agent; those
  expire.

The agent:

- Refuses a grant without `commit`: it comes from an app made before this change. It does not save
  the pairing, leaves (`DELETE /v1/agents/{agent_id}/phones/{phone_id}`) and tells the person to
  update Nodkey on the iPhone. It never falls back to the number without a commitment: a relay
  could pretend to be such an app.
- Sends exactly one `pairing_check` per pairing. It stops, saves nothing and leaves when the answer
  does not come in time, is not `approved`, has no `nonce`, has a nonce that does not match
  `commit`, or has no valid signature of the phone's key from the claim.
- Shows the check number and saves the phone only after the person confirms on the computer that
  the numbers are the same. When they are not the same, it leaves and saves nothing.

Versions:

| Agent | Phone | What happens |
| --- | --- | --- |
| this version | this version | pairing with the commitment; requests and answers signed |
| this version | made before | the grant has `check` and no `commit`: the agent refuses as above; the phone drops the agent the next time it lists requests |
| made before | this version | the agent cannot read the grant (it has no `check`) and saves nothing; the phone gets no `pairing_check` and gives up after 120 s as above |

Pairings made before this change stay as they are: their keys are pinned. Apps made before this
change showed `check = u32be(SHA-256("nodkey/v1/check" ‖ agent_sign ‖ agent_kem ‖ phone_sign ‖
phone_kem)[0..4]) mod 1_000_000` and put it in the grant; a relay that swaps keys can choose its
keys so that this number is the same on both screens, which is why it is no longer used (vectors:
`check`). Vectors: the `pairing` section (nonces, `commit`, the number) and the HPKE vectors
`pairing_grant_commit`, `request_pairing_check` and `answer_pairing_check`.

## Relay API

Base URL: `https://relay.nodkey.app`. An agent accepts plain `http` only for a relay on the same
computer (`localhost`, `127.0.0.1`, `[::1]`), and does not follow redirects.

| Call | Signed by | Body → response |
| --- | --- | --- |
| `PUT /v1/phones/{phone_id}` | phone | `{sign, kem, apns_token?, apns_sandbox?}` → `204`. First call registers (trust on first use); later calls must be signed by the registered key. |
| `POST /v1/pairings` | agent (own key) | `{agent_id, name, sign, kem}` → `201 {code, expires}`. `code` is 6 Crockford base32 characters, valid 300 s. |
| `GET /v1/pairings/{code}/agent` | phone | → `200 {agent_id, name, sign, kem}` of the agent waiting on a live, unclaimed code, `404` otherwise. The phone needs these keys to seal the grant (with its commitment) before it claims. Counts against the phone's 10 claims per hour, so a pairing (lookup + claim) uses two. |
| `POST /v1/pairings/{code}/claim` | phone | `{enc, ct}` (sealed grant to the agent) → `200 {agent_id, name, sign, kem}`; the phone checks these are the keys the lookup returned |
| `GET /v1/pairings/{code}?wait=60` | agent | → `{phone_id, sign, kem, enc, ct}` once claimed, `204` on timeout, `404` when expired |
| `POST /v1/phones/{phone_id}/requests` | agent (paired) | `{request_id, enc, ct, attachment?: true, ttl?}` → `202`. Rate limit 20 per hour per agent. Sends a push when the phone has an APNs token; with `attachment: true` the push waits until the attachment is uploaded or 5 s have passed. `ttl` (120 to 360, default 120): how many seconds the relay keeps the request and its answer; the agent sends it only for `sms_code` (see "SMS codes"). A relay that does not know `ttl` keeps the request 120 s, and the agent then sees `expired`. |
| `PUT /v1/requests/{request_id}/attachment` | agent (the requester) | raw body = `enc` (32 bytes) ‖ ciphertext of the image (or of the export file of an `import` request); the whole body at most 1 MiB (1 048 576 bytes, so the image at most 1 048 528) → `204`, bigger → `413 too_large`; within 120 s of the request. Optional; see Attachments. |
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

Pairing grant (phone → agent; see "Pairing and the check number"):

```json
{"v":1, "phone_name":"Test iPhone", "scope":"selected", "commit":"<b64u, 32 bytes>"}
```

Apps made before the commitment send `"check":"418902"` and no `commit`; the agent refuses such a
grant.

`scope`: `selected` (the user picks accounts per request), `codes`, `logins`, `all`.

Request (agent → phone):

```json
{"v":1, "request_id":"…", "kind":"code|login|list|insights|cleanup|save|passkey|bundle|card|session_end|suggest|sms_code|secret|save_secret|pairing_check|import|generate", "target":"github.com/alex",
 "reason":"Merge PR #42", "agent":"Claude · Horizon", "ts":1791620000}
```

- `attachment` (optional): `{"type":"image/png|image/jpeg|image/gif", "bytes":12345, "caption":"vg.no login page",
  "sha256":"<b64u>"}` when the agent uploads a picture of what it is about to sign in to (a screenshot of the
  login page, or a short animated GIF). The phone shows it in the notification. `sha256` is b64u of
  SHA-256 of the image bytes; the phone shows only a picture with that hash (agents made before
  signatures send none).
- `nonce` (only `pairing_check`): the agent's nonce, b64u of 32 bytes (see "Pairing and the check
  number"). An answer to `pairing_check` carries the phone's `nonce`.
- `kind: code` returns a one-time code; `login` returns user name, password and, when the login has a
  TOTP key (linked, or a code account with the same site and user name), a code. For 120 s after
  the user approves a login or code once, a `code` request from the same agent for that account is
  answered without asking when it is an exact match for it (a follow-up window, not shown as a
  lease; see "Websites"); `list` returns the names of the accounts this agent may ask for (no secrets).
- `target` is the website the agent is about to sign in to: the host of that page, optionally
  `/account` (`vg.no`, `login.example.com`, `github.com/alex`); a bare name (`GitHub`) is allowed
  but always asks the user. The phone matches it by registrable domain (see "Websites") and asks the
  user when several match. A named account that is not there matches nothing (no other account on
  the site is offered); after a scheme (`https://vg.no/login`) the tail is a path, not an account.
  An account may have extra websites ("Also used on" in the app, for example chatgpt.com on a login
  saved for openai.com). They match the same way: `chatgpt.com` and `auth.chatgpt.com` match the
  extra website `chatgpt.com`, `chatgpt.ru` and `chatgpt.com.evil.io` do not. Own sites rank
  before extra websites. When nothing matches, the user may pick another account by hand in the app
  (and may let the phone remember the requested site as an extra website of that account, so the
  next request matches); the answer then says `match: "chosen"`.
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
- `project` (optional): the project a `secret` request or a bundle's `secret` items ask in (see
  "Keys by project").
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
`rejected`, only for `suggest`, and `staged`, only for `import` (see "Moving in"). `login` and `code` answers may carry `method`, `via` and
`second_step` (see "Sign-in methods").

A `code` or `login` answer also carries `match`: `direct` (the account's own site is the target's
website), `alias` (one of its extra websites is) or `chosen` (the account is not saved for the
target's website: nothing matched, or only its name did, and the user picked it by hand in the app). `account.sites` and the `sites` of each `accounts` entry list the account's extra
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

## Websites

How the phone decides that an account belongs to the website a request names, and where an agent
may fill what it gets. `nodkey_proto::site` implements this section, the app has the same rules
(`LoginSite.swift`, `AgentSiteCheck.swift`), and the `sites` vectors keep them in step.

- **Host.** The host of a target or a page is read the way a browser reads a URL: lower case,
  without scheme, user name, port, path, query or fragment; a backslash ends the host
  (`evil.example\@github.com` is `evil.example`); one trailing dot is removed; labels with letters
  outside ASCII are in their `xn--` form. A value with a dot that is not a valid host (a `%`, a
  space, an empty label, numbers that are not a plain IPv4 address such as `0x7f.0.0.1`) is neither
  a website nor a bare name: it matches nothing.
- **Registrable domain.** The public suffix and one label more, from the Public Suffix List with
  both its sections. The private section makes shared hosting domains endings like `com` and
  `co.uk`: `github.io`, `herokuapp.com`, `pages.dev`, `vercel.app`. So `alice.github.io` and
  `bob.github.io` are two websites, and neither is `github.com`. An IP address and `localhost` have
  no registrable domain; their website is the host itself.
- **Same website.** Two hosts are the same website when their registrable domains (or, without one,
  the hosts) are equal. `login.github.com` is github.com; `github.xyz`, `login.github.xyz`,
  `git-hub.com`, `anyone.github.io` and `github.com.evil.example` are not; `bbc.co.uk` is not
  `other.co.uk`.
- **Matching a `code` or `login` target** (and each bundle item):
  1. A target with a host matches the accounts whose own site (`match: direct`) or one of whose
     extra websites (`alias`) is the same website. Only such an exact match is ever answered
     without the user: by a lease, a task session, a bundle under leases or the follow-up window,
     and only when the host does not look like another saved website (punycode or other letters
     outside ASCII, an IP address, `localhost`, a name close to a saved one, a saved name inside
     another domain or under another ending).
  2. When nothing matches exactly, a code account without any website may match by its name
     (`GitHub` for `github.com`).
  3. A bare name (`GitHub`) matches by name only: the account's name, or the name part of its site.

  Anything that is not an exact match (2, 3, a look-alike, or an account the user picks from the
  list) is decided by the user in the app, with the requested host in view; its notification only
  opens the app. Once approved it is answered with `match: "chosen"`, and no lease, follow-up or
  task session ever answers it. "Remember" in the app (not offered for a look-alike) saves the
  requested host as an extra website of the account, so the next request matches exactly.
- **Passkeys.** An `rp_id` is never a public suffix ("The client data check").
- **Where to fill.** The agent tools add `fill_only_on` to every approved login and code (and each
  bundle item): the registrable domains of the account's site and extra websites, or for
  `match: "chosen"` the website of the target, which the user approved it for
  (`nodkey_proto::site::fill_only_on`). The agent fills only on a page whose host is one of them or
  below one (`nodkey_proto::site::may_fill`; below a public suffix never counts), and stops and tells
  the user when the page is elsewhere. `via` carries its own `fill_only_on`: the provider's exact
  sign-in hosts (see "Sign-in methods"). The browser extension checks the same before it fills.
- **The list.** `nodkey-proto/data/public_suffix_list.dat` is an unchanged copy of
  https://publicsuffix.org/list/public_suffix_list.dat (MPL 2.0, as its first lines say). Its
  `VERSION` and `COMMIT` lines name the snapshot; the `sites.psl` vectors carry them and the file's
  SHA-256, and the app's tests check its own copy against them. To update it, run
  `scripts/update-psl.sh` (it downloads the list from publicsuffix.org, never from elsewhere, and
  rewrites the vectors), read the diff of the list for sites people use with Nodkey, run the
  checks, then copy the file to `ios/Shared/Resources/public_suffix_list.dat` in peters/nodkey with
  `vectors/v1.json`, and move the `nodkey-proto` revision of peters/nodkey-browser. Do it a few
  times a year, and when a shared hosting provider people use is added to the list.

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
covered by leases only when every item is an exact match with a lease (then the phone answers by
itself; see "Websites"). The notification
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
| `passkey` with `op: get` | its `rp_id` is the relying party of an approved `passkey` item, or a site below it, with the same passkey, and it has no PRF inputs (see "PRF") |
| `secret` | it matches the key of an approved `secret` item (see "API keys and secrets") |

A request is covered only when its target is an exact match for the item's account (see
"Websites"): any host of the account's website, never a look-alike or a bare name. An account the
user picked by hand for an item covers nothing later in the session (unless the user let the phone
remember the site, which makes it an exact match).

Such an answer carries `lease: {"kind":"session", "until":…}`. Anything else is asked as usual,
with or without `session_id`: another site or account, a passkey create, a passkey get with PRF
inputs or with `user_verification: required`, `save`, `save_card`, `save_secret`,
`generate`, `card`, `list`, `insights`, `cleanup` and `bundle`. A request with an unknown or ended `session_id`
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

## Making a password

`kind: generate` asks the phone to make a strong new password for a sign-up or a password change,
to save it, and to give it to the agent or the browser, which fills it in (peters/nodkey#131). The
phone makes the password and saves it **before** it answers, so a sign-up that fails half-way never
loses it. `nodkey_proto::generate` implements this section.

It is a kind of its own, not `save` with a flag. A `save` request carries a password to the phone
and its answer carries none; a `generate` answer carries a password. So it follows the rules of a
secret that leaves the phone (Face ID every time, `no_passcode`, scopes), not those of a save, and an
app that does not know it refuses it with `unsupported_kind` instead of reading it as a save without
a password.

```json
{"v":1, "request_id":"…", "kind":"generate", "target":"accounts.example.com",
 "reason":"Sign up for Example Cloud, as you asked", "agent":"Claude Code @ my-laptop", "ts":1791620000,
 "generate":{"url":"https://accounts.example.com/signup", "username":"alex@example.com", "title":"Example Cloud",
             "rules":{"passwordrules":"minlength: 12; required: lower; required: upper; required: digit; allowed: [-_.!];",
                      "min_length":12, "max_length":64}}}
```

| Field | Meaning |
| --- | --- |
| `target` | required: the host of the page, as `nodkey_proto::site::host` reads it (`accounts.example.com`): lower case, no scheme, port, path or `/account` |
| `generate.url` | optional: the page's address, `https://` or `http://`, without query and fragment (they can hold tokens), at most 500 characters (`MAX_URL`); its host is `target` |
| `generate.username` | optional: the user name the agent or the page knows, at most 200 characters (`MAX_USERNAME`). The user can type or correct it on the phone. |
| `generate.title` | optional: a title for a new login (the service's name), at most 100 characters (`MAX_TITLE`) |
| `generate.change` | optional: `true` when the page changes the password of an existing account; absent means `false` |
| `generate.rules` | optional: what the page says about the password; every field optional |
| `rules.passwordrules` | the field's `passwordrules` attribute as the page has it (Apple's syntax, below), at most 300 characters (`MAX_RULES`) |
| `rules.min_length`, `rules.max_length` | the field's `minlength` and `maxlength`, whole numbers from 0 |
| `rules.pattern` | the field's `pattern`, at most 300 characters (`MAX_PATTERN`): a JavaScript regular expression the whole password must match, as a browser checks it (`^(?:pattern)$`, `v` flag) |

No text field holds a control character. Both sides check these rules
(`GenerateRequest::check`); the agent tools send nothing that breaks them, and the phone refuses such
a request at once with `bad_generate`. A `generate` request has no `session_id` and is never part of
a bundle; it may carry a picture (`attachment`) like a login request.

### The rules

`passwordrules` is a list of properties separated by `;`, each `name: value`, with spaces allowed
around every part and names in any case:

| Property | Meaning |
| --- | --- |
| `required: CLASSES` | the password has at least one character of CLASSES; each `required` is a requirement of its own |
| `allowed: CLASSES` | the password may use these characters |
| `max-consecutive: N` | at most N of the same character in a row; the smallest N counts |
| `minlength: N`, `maxlength: N` | the largest `minlength` and the smallest `maxlength` count |

CLASSES is a list separated by commas of `upper` (`A` to `Z`), `lower` (`a` to `z`), `digit` (`0` to
`9`), `special` (the ASCII characters from space to `~` that are not letters or digits, space
included), `ascii-printable` (every ASCII character from space to `~`), `unicode` (any character; it
reads as `ascii-printable`) and custom classes in brackets: the characters between `[` and `]`, of
which only those from space to `~` count. In a custom class `-` counts only as the first character,
and `]]` is a `]` that ends the class (`[-_.]]` is `-`, `_`, `.` and `]`). A part without `:`, an
unknown property, an unknown class name and a value of `max-consecutive`, `minlength` or `maxlength`
that is not a whole number are left out; the rest still counts.

The allowed characters are those of every `required` and `allowed` class; with neither, every ASCII
character from space to `~`. The field's attributes join in: the minimum length is the larger of
`minlength` and `rules.min_length`, the maximum the smaller of `maxlength` and `rules.max_length`.
`Rules::read` gives this reading and `Rules::fits` says whether a password meets it (all but
`pattern`).

**What the phone makes.** 20 characters (`DEFAULT_LENGTH`), raised to the minimum and lowered to the
maximum, and at least one per `required` class. It uses the allowed characters, preferring letters,
digits and the symbols `!#$%*+-.=?@_` (`SYMBOLS`); it never uses a space. Without a `required`
property it puts in a lower case letter, an upper case letter, a digit and a symbol, each when the
allowed characters have one. It keeps to `max-consecutive`. With `pattern` it makes passwords until
one matches, at most 100 (`PATTERN_TRIES`); the phone may first narrow the characters and length from
a simple pattern (one bracket class with a count, such as `[A-Za-z0-9]{8,16}`). A `pattern` that is
not a valid expression is left out, as browsers do.

**Rules no password can meet** (`bad_rules`, `Rules::check`), checked before the user is asked:

- the minimum length is above the maximum, the maximum is 0, or the minimum is above 128
  (`MAX_LENGTH`, the longest password Nodkey makes);
- `max-consecutive` is 0;
- a `required` class, or the allowed characters, have no character but a space;
- the maximum length (128 when it is higher or absent) is below the number of `required` classes;
- only one character may be used, and the length is above `max-consecutive`;
- on the phone: no password of `PATTERN_TRIES` matched `pattern`.

The `generate` vectors list rules with their reading, and passwords that do or do not fit them.

### What the phone does

It checks in this order and refuses at once (`decision: denied`, `error`), without asking:

| Check | `error` |
| --- | --- |
| the request's `v` and `kind` | `unsupported_version`, `unsupported_kind` |
| the agent is paused | `paused` |
| the phone has no passcode, so it cannot verify who approves (#126) | `no_passcode` |
| the agent's scope is `codes` | `not_allowed` |
| the request breaks a rule of `GenerateRequest::check` | `bad_generate` |
| the rules cannot be met (above) | `bad_rules` |

Then it asks: "Make a new password for accounts.example.com?" (with `change`: "Change the password
for accounts.example.com?"), with the agent, the reason, the picture, the title and the user name in
a field the user can type in or correct. When a saved login has the same website (see "Websites") and
user name (compared without regard to case), the sheet shows it and says that the new password
replaces its password; with `change`, or when several logins of the website could be meant, the user
picks the login (or a new one). The user approves with **Face ID or the passcode, every time**. A
`generate` request is never answered by a lease, a task session, a follow-up window or a notification
action without Face ID, and is never part of a bundle. Its notification (category
`AGENT_REQUEST_GENERATE`) offers only Open Nodkey and Deny; the notification service extension
answers only the refusals above.

After the approval, and before it answers, the phone:

1. makes the password by the rules (above);
2. saves it. The login the sheet showed gets the new password (`saved: updated`); otherwise a new
   login is added for `target` with the user name, the title (else the host) and `url`
   (`saved: added`);
3. keeps the replaced password of an updated login on this iPhone for 30 days (`KEEP_OLD_DAYS`),
   never in the iCloud backup or an export, so the user can go back when the change fails on the
   site;
4. records "Made a password for accounts.example.com" ("Changed the password for ..." for an update)
   with the agent and the time in the history, never the password.

When it cannot save, it answers `denied` with `error: "save_failed"` and gives no password.

```json
{"v":1, "request_id":"…", "decision":"approved", "saved":"added",
 "account":{"issuer":"Example Cloud", "name":"alex@example.com", "site":"accounts.example.com"},
 "username":"alex@example.com", "password":"…"}
{"v":1, "request_id":"…", "decision":"denied", "error":"bad_rules"}
```

- `password`: the new password.
- `username`: the user name as the user confirmed it on the phone. It may differ from the request's,
  and it is empty when the user left the field empty.
- `account`: the saved login: `issuer` its title, `name` its user name, `site` its site (for an
  update, the site the login had).
- `saved`: `added` or `updated`, never `unchanged`.
- No `lease`, `match`, `code`, `method` or `via`.

`denied` without `error` means the user said no; `expired`, no answer in time. The agent tools use
an approved answer only when it has `password` and `saved` (`added` or `updated`) and no lease other
than `once`; otherwise they give nothing and say why. They add `fill_only_on`: the website of
`target` (`site::site_key`); the password is filled only on a page of that website, and only into
the new password field and its confirm field.

Other rules: a `generate` request does not count against the agent limit (the password is new, and
the user approves each one with Face ID), and the relay's 120 s and 20 requests per hour apply as
for every request. Scopes: allowed for `selected`, `logins` and `all`. An older app answers
`unsupported_kind`, and the agent tells the user to update Nodkey.

**The browser extension** offers "Make a strong password" in a field for a new password
(`autocomplete="new-password"`, a password field with a confirm field next to it, or a page text such
as "create password" or "new password"). It sends `url`, the user name it knows (also from an
earlier page of the same sign-up in this tab), and the field's rules. It fills the answer's password
into the password field and the confirm field, and does not ask "Save this password?" afterwards:
the phone saved it already.

**The agent side.** `nodkey generate --site <url|host> [--user NAME] [--title TEXT] [--rules
'<passwordrules>'] [--min N] [--max N] [--pattern RE] [--change] [--reason TEXT]` prints the
password alone on stdout, with one line on stderr that names the login and where to fill it
(`--json`: the whole result as JSON on stdout instead). The MCP tool is `create_login(site, username?,
title?, rules?, change?, reason, image_path?)`, `rules` being `{passwordrules?, min_length?,
max_length?, pattern?}`; it returns `decision`, `username`, `password`, `account`, `saved`,
`fill_only_on` and a message. An agent uses it only when the user asked it to sign up or to change a
password, fills the password only on that site, and never stores or repeats it. Exit codes: 0
approved, 1 error (also `bad_generate`, `save_failed`), 2 denied (also `not_allowed`), 3 expired, 4
paused, 10 `no_passcode`, 15 `bad_rules`, 64 bad arguments.

Vectors: `request_generate`, `request_generate_change`, `request_generate_signed` (also in
`signed`), `answer_generate_added`, `answer_generate_updated`, `answer_generate_no_passcode`,
`answer_generate_not_allowed`, `answer_generate_bad_generate`, `answer_generate_bad_rules`,
`answer_generate_save_failed`, and the `generate` section: the limits, the symbols, the classes, the
errors in the phone's order, `checks` (requests and the `error` each gets, `null` when it passes),
`rules` (rules with their reading and `error`) and `fits` (passwords against rules).

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
| `resident_key`, `user_verification` | `required`, `preferred` or `discouraged`; absent means `preferred`. The phone always makes a discoverable passkey and asks for Face ID for every create. A get with `user_verification: required` is never answered by a lease or a task session: the phone asks with Face ID, and that answer carries UV. The agent refuses an answer to such a get without UV. A phone without a passcode refuses a get or create with `user_verification: required` with `no_passcode` (see "Answers"). |
| `prf` | optional: the WebAuthn PRF extension (see "PRF") |

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
- `rp_id` is a domain name with a dot (not an IP address), or `localhost`, and not a public suffix:
  not an ending such as `co.uk` and not a shared hosting domain such as `github.io` (see
  "Websites"; browsers refuse such an `rp_id` too).

If any rule fails, the phone answers `denied` with `error: "bad_client_data"` at once. The vector
section `webauthn.client_data_checks` lists cases that pass and fail.

The phone shows the user the **origin from `client_data_json`**, the reason, and the user name of
the passkey (get) or of the new passkey (create).

### What the phone makes

Nodkey is a software authenticator: ES256 (ECDSA P-256 with SHA-256), sign count always 0,
`none` attestation, AAGUID `97531e9d-ff39-4e63-aaec-b1d68400c3c9`, a credential id of 16 random
bytes.

- `authenticator_data` = SHA-256(`rp_id`) ‖ flags (1 byte) ‖ sign count (4 bytes, 0). A get the
  user approved with Face ID has UP, UV, BE and BS (`0x1d`). A get that a lease (once, 1 day, 7 days
  or always) or a task session answered has UP, BE and BS (`0x19`): nobody was verified for that
  answer, so UV is not set. A phone without a passcode verifies nobody either: each get it answers
  has `0x19`, and each create `0x59`. BE and BS are always set: iOS needs them to stay the same.
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
| `prf_unsupported` | get with PRF inputs when no passkey for `rp_id` (or in a non-empty `allow_credentials`) supports PRF; at once (see "PRF") |
| `no_passcode` | the phone has no passcode, so it cannot verify the user: a get or create with `user_verification: required`, or a get with PRF inputs (`PasskeyRequest::needs_passcode`); at once, right after `bad_client_data`. It answers any other request without UV. |
| `paused`, `unsupported_kind`, `unsupported_version` | as for every kind; an older app answers `unsupported_kind` |

Leases: a get may be covered by a lease of kind `passkey`, `(agent_id, passkey_id, passkey,
until)`, once, 1 day, 7 days or always, as for logins. **A create, a get with PRF inputs and a
get with `user_verification: required` are never covered by a lease**: Face ID every time. A get
under a lease carries no UV (see "What the phone makes"). A get under a lease is answered by the notification service extension with a
quiet notification ("Claude Code signed in to webauthn.io with a passkey"), and the history marks
it as a lease answer. Scopes: allowed for `selected`, `logins` and `all`, refused for `codes`.

Vectors: `request_passkey_get`, `request_passkey_create`, `answer_passkey_get`,
`answer_passkey_create`, and the `webauthn` section: a fixed P-256 test key (`private_key`,
`public_key_x963`, `public_key_spki`, `cose_key`), the credential id and user handle, and for get
and create the `client_data_json` (text and b64u), its hash, the expected `authenticator_data`,
the `attestation_object` (create), and `signed_data` and a `signature` that verifies with the public
key (get; RFC 6979 nonces, so the file stays the same).

A phone without a passcode: `request_passkey_get_preferred` and `request_passkey_create_preferred`
(`user_verification: preferred`) with `answer_passkey_get_without_uv` (`0x19`) and
`answer_passkey_create_without_uv` (`0x59`), `answer_passkey_no_passcode` (to
`request_passkey_get`) and `answer_passkey_get_prf_no_passcode` (to `request_passkey_get_prf`),
and `webauthn.no_passcode`: for each op, `user_verification` and `prf`, whether it is `refused`.

### PRF

The WebAuthn PRF extension (CTAP2 `hmac-secret`) lets a site or a program get a secret key from a
passkey: the same passkey and the same input always give the same 32 bytes. `nodkey_proto::prf`
implements it.

Each passkey that the phone makes holds `credRandom`, 32 random bytes made with the passkey. The
phone keeps it with the private key: in the keychain, in the end-to-end encrypted iCloud backup and
in a vault export, so a restored phone gives the same output. For each input the phone answers

```
salt   = SHA-256("WebAuthn PRF" || 0x00 || input)
output = HMAC-SHA256(credRandom, salt)
```

as WebAuthn Level 3 says. A passkey made before PRF support has no `credRandom`; the phone does not
add one later (an older backup would not have it), so such a passkey answers `prf_unsupported`.

`prf` in the request (the WebAuthn names in snake case; inputs b64u, 0 to 256 bytes each):

```json
"passkey":{"op":"create", …, "prf":{}}
"passkey":{"op":"create", …, "prf":{"eval":{"first":"<b64u>"}}}
"passkey":{"op":"get", …, "allow_credentials":["<id>"],
           "prf":{"eval":{"first":"<b64u>", "second":"<b64u>"},
                  "eval_by_credential":{"<id>":{"first":"<b64u>"}}}}
```

- create: `{}` asks for a passkey with PRF (every new passkey has it). `eval` also asks for the
  outputs at once. `eval_by_credential` is not allowed.
- get: `eval` and/or `eval_by_credential` is required. Each key of `eval_by_credential` is a
  credential id (b64u) in `allow_credentials` (so that list is not empty). For the passkey that
  signs, its entry in `eval_by_credential` is used, else `eval`. `second` is optional.

The agent checks these rules before it sends; the vector section `prf.input_checks` lists cases.
The phone checks them too and answers a `prf` that breaks them (or does not decode) with
`bad_client_data` at once.

`prf` in the answer:

```json
"passkey":{"credential_id":"<b64u>", …, "prf":{"enabled":true, "results":{"first":"<b64u>"}}}
"passkey":{"credential_id":"<b64u>", …, "prf":{"results":{"first":"<b64u>", "second":"<b64u>"}}}
```

`enabled` is only in a create answer. `results` holds the outputs (32 bytes each) when the request
had inputs for the passkey that answered; `second` exactly when it was asked. The authenticator data
does not change (no extension data, no ED flag).

Rules on the phone:

- A get with PRF inputs is shown as unlocking a key: "Unlock a key for <rp_id>", with the origin
  and the passkey's user name. It always needs Face ID. A lease, a task session, a bundle item or a
  notification action without Face ID in the app never answers it, and its answer carries no
  `lease`. The agent refuses a PRF answer with a lease other than `once`.
- When the user can pick between passkeys, only passkeys with PRF are offered. When none has PRF,
  the phone answers `prf_unsupported` at once.
- An older app does not know `prf`: it answers a create without `prf` (so `enabled` is false) and a
  get without `results`. The agent treats that get as `prf_unsupported`.

The outputs are secret keys: an agent passes them on only to the program that asked and never logs
or stores them in clear.

Vectors: `request_passkey_create_prf`, `request_passkey_get_prf`,
`request_passkey_get_prf_by_credential`, `answer_passkey_create_prf`, `answer_passkey_get_prf`,
`answer_passkey_get_prf_by_credential`, `answer_passkey_prf_unsupported`, and the `prf` section: a
fixed `cred_random` for the vectors' passkey, `derivations` (input, salt, output) and
`input_checks`.

## Payment cards

`kind: card` asks for a payment card. `purpose: pay` (the default) pays **one purchase**: the
request always names the shop and the amount, so the user sees what money is about to be spent.
`purpose: setup` lets a browser add the card to a site for later payments, with no amount (see
"Cards for later payments"). `target` is the merchant; `card` holds the request:

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
| `purpose` | `pay` or `setup`. Absent means `pay`, and a `pay` request leaves it out. `setup` is only for `fill`. |
| `merchant` | the site of the top-level page (what the address bar shows), never the host of a payment frame; the same as `target` |
| `via` | `fill`, optional: the host of the payment frame the card goes into, when that frame is from another site than the merchant (a payment provider's frame, `js.pay.example`). It must not be the merchant or a subdomain of it: leave it out when the card form is on the shop's own site. Absent for `reveal`. |
| `amount` | `pay`, **required**: what will be paid, `value` a decimal string with a dot (at most 12 digits before it and 3 after, no thousands separators, more than 0), `currency` an ISO 4217 code (`NOK`). Absent for `setup`. |
| `origin` | `fill`, required: the origin of the frame the card goes into, as the host saw it, never from the page or the model. Without `via`: `https://<host>[:port]`, `host` the merchant or a subdomain of it; or `http://localhost[:port]` with the merchant `localhost`, as for passkeys. With `via`: `https://<via>[:port]`. Absent for `reveal`. |
| `page_total` | `pay` with `fill`, optional: the order total the host read on the checkout page (`total_source: page`) or the user typed because none was found (`total_source: user`). Must not be more than `amount` (same currency). Absent for `reveal` and `setup`. |
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
The shop the phone shows is always `merchant`; with `via` it adds "via js.pay.example".

Refusals without asking (`decision: denied`, `error`), in this order:

| `error` | When |
| --- | --- |
| `cards_off` | cards are off for this agent |
| `no_passcode` | the phone has no passcode, so Nodkey hands out no cards (`pay` or `setup`); checked after `paused` and `cards_off`, before the rest |
| `amount_missing` | `pay` without `amount`, or not a valid amount |
| `total_mismatch` | `page_total` is more than `amount` |
| `bad_card_request` | the card data breaks another rule above |
| `reveal_off` | `mode: reveal` while full card numbers are off for this agent |
| `setup_off` | `purpose: setup` while adding cards for later payments is off for this agent |
| `over_limit` | `pay`: `amount` is above the agent's limit per purchase, or would take the last 24 hours above the daily limit |
| `no_card` | no card on the phone may be used by this agent |
| `paused`, `unsupported_kind`, `unsupported_version` | as for every kind |

An approved answer carries the card and the amount the user approved (`approved_amount`, absent
for `setup`):

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

### Cards for later payments

A billing page or a subscription often asks for a card with no total, so that the site can charge
it later. A browser asks for such a card with `purpose: setup`:

```json
{"v":1, "request_id":"…", "kind":"card", "target":"shop.example.com",
 "reason":"Add your card at shop.example.com for later payments", "agent":"Firefox on Linux", "ts":1791620000,
 "card":{"mode":"fill", "purpose":"setup", "merchant":"shop.example.com", "via":"js.pay.example",
         "origin":"https://js.pay.example"}}
```

- Only `mode: fill`, and no `amount`, `page_total` or `total_source` (else `bad_card_request`). The
  card goes to the browser, which fills it only into the frame of `origin`.
- Only a browser that fills the card itself asks: the Nodkey browser extension acting for the
  user, or a browser host under its own profile (`nodkey card-fill --agent horizon`). An agent
  never does: `request_payment` and `nodkey pay` have no `setup`, and an agent's card requests keep
  the required amount, currency, merchant and limits.
- On the phone, adding cards for later payments is a separate setting per agent, off by default,
  like full card numbers. It is meant for a browser: the user turns it on for the Nodkey browser
  extension or a browser host, never for an agent's own profile. Without it the phone refuses at
  once with `setup_off`. Cards must be on for the agent (`cards_off`), the phone must have a
  passcode (`no_passcode`), and the agent must be allowed a card (`no_card`).
- The phone shows "Add your card at shop.example.com, via js.pay.example" (without `via`: "Add
  your card at shop.example.com"), the reason, the picture and the card, and asks for Face ID every
  time. One approval fills the card once. A setup request is never covered by a lease, and never
  part of a bundle, a task plan, a task session or a follow-up window. The history records it with
  the shop and `via`.
- The limits per purchase and per 24 hours do not apply, because there is no amount, and the
  request adds nothing to the amount of the last 24 hours.
- The approved answer is the card without `approved_amount`. The browser never stores it.
- An app that does not know `setup` reads a request without an amount and refuses it with
  `amount_missing`. The browser then tells the user to update the app.

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
`save_card_cvc`, `request_save_card`, `answer_save_card`, `answer_list_with_cards`,
`request_card_setup`, `request_card_fill_via`, `answer_card_setup`, `answer_card_setup_off`,
`answer_card_no_passcode`, and the `cards` section (its `requests` include `setup`, `fill_via` and the setup and `via` rules).
Test card numbers only.

## API keys and secrets

Nodkey keeps API keys and other secrets ("keys"), so a user does not paste a key into a chat or
keep it in a plain `.env` file. A key has a title, a service (a host, `openai.com`), an environment
variable name (`OPENAI_API_KEY`), the value, notes, an optional expiry date and a list of projects
(empty: a global key; see "Keys by project"). The value stays in the phone's keychain.
`nodkey_proto::apikey` implements this section.

### Asking for a key

`kind: secret` asks for one key. `target` names it:

| `target` | Means |
| --- | --- |
| `openai.com` | a service: the key's service is this host, or one is a subdomain of the other (`api.openai.com`) |
| `OPENAI_API_KEY` | a variable name: letters, digits and `_`, not a digit first, at most 100 characters; compared without regard to case |
| `openai.com/OPENAI_API_KEY` | both must match |
| `sparrow/OPENAI_API_KEY` | the variable name in the project `sparrow` (see "Keys by project") |
| `global/OPENAI_API_KEY` | the variable name among the global keys only |

A target with a dot and no slash is a service. Before a slash, a part with a dot (or `localhost`)
is a service, `global` (in any case) means the global keys, and anything else is a project name. A service is in the form of
`nodkey_proto::signin::site` (lower case, no scheme, port, path or `www.`); the agent tools tidy
it before they send. The phone checks the target too and refuses a bad one at once with
`bad_secret_request`.

```json
{"v":1, "request_id":"…", "kind":"secret", "target":"openai.com/OPENAI_API_KEY",
 "reason":"Run the test suite that calls the OpenAI API", "agent":"Claude Code @ my-laptop", "ts":1791620000}
```

The phone shows the keys that match (the user picks one when several match) with the reason and
asks for Face ID **every time**. When no key matches, the phone still asks: the user can pick a key
by hand, add one, or tell the agent that there is none (`error: "no_secret"`, sent only after the
user answered, so an agent cannot probe for keys). An approved answer carries the key:

```json
{"v":1, "request_id":"…", "decision":"approved", "lease":{"kind":"once"},
 "secret":{"title":"OpenAI", "service":"openai.com", "variable":"OPENAI_API_KEY",
           "value":"sk-test-0000", "expires":1799396000}}
```

`service`, `variable` and `expires` are absent when the key has none. `from` and `project` say
which key the phone gave (see "Keys by project").

Rules on the phone:

- A key is **never covered by a lease** ("Always allow" is not offered) and never by the follow-up
  window. The notification offers Open and Deny; the user approves in the app with Face ID or the
  passcode.
- A key counts against the agent limit like a login (see "Agent limit").
- Scopes: allowed for `selected`, `logins` and `all`; refused at once for `codes` with
  `error: "not_allowed"`.
- The history on the phone records which agent got which key, and when. The key shows "Last used
  by <agent>".
- Refusals at once: `no_passcode` (the phone has no passcode, so Nodkey hands out no keys; checked
  right after `paused`, before the other checks), `bad_secret_request`, `not_allowed`, and
  `paused`, `unsupported_kind`, `unsupported_version` as for every kind. An older app answers
  `unsupported_kind`.

### Keys in bundles and task plans

A bundle may hold `secret` items (`target` as above). In a bundle without `session`, an approved
item carries `secret` with its value, as a single answer does. `nodkey run` asks this way for
several keys at once, with one approval.

In a task plan (a bundle with `session`), a `secret` item carries `secret` **without** `value` and
without `lease`: the plan only lets later `secret` requests for that key go through in the session
(see "Task sessions"), with `lease: {"kind":"session", …}`. So `nodkey run --secret` gets the key
later and the model never sees it. An older app refuses a bundle with a `secret` item with
`error: "bad_bundle"`.

A phone without a passcode leaves out each `secret` item of a bundle or task plan, without asking:
the item answer is `decision: denied` with `error: "no_passcode"`, and the other items go on as
usual. When no other item is left, the phone refuses the whole bundle at once with
`error: "no_passcode"`.

### Saving a key

`kind: save_secret` asks the phone to keep a key that an agent made, for example in a provider's
dashboard. `target` is `service/VARIABLE` from the fields of `save_secret` (or `VARIABLE` when there is no
service):

```json
{"v":1, "request_id":"…", "kind":"save_secret", "target":"openai.com/OPENAI_API_KEY",
 "reason":"Save the API key I just made in the OpenAI dashboard", "agent":"Claude Code @ my-laptop", "ts":1791620000,
 "save_secret":{"variable":"OPENAI_API_KEY", "service":"openai.com", "title":"OpenAI",
                "notes":"Made for the test project", "expires":1799396000, "value":{"enc":"…", "ct":"…"}}}
```

`value` is sealed to the phone **on its own** with HPKE (`info` = `nodkey/v1/secret`, `aad` =
`agent_id`), like the password of a `save` request. `variable` is required; `service`, `title`
(at most 100 characters), `notes` (at most 500), `expires` and `projects` (see "Keys by project")
are optional. The agent tools send a
value of at most 1500 bytes (`MAX_SAVE_VALUE`), so the request fits the relay; a longer key is
added in the app.

The phone shows the title, the service, the variable name and the projects (never the value) and
asks the user to save it with Face ID. A key with the same service, variable name and projects (the
name compared without regard to case; no service matches no service; projects as in "Keys by
project") gets the new value; otherwise the phone adds a key.
A save is **never covered by a lease** and is never part of a bundle or a task session. It does
not count against the agent limit. Every scope may save a key. The answer carries `saved`:
`added`, `updated` or `unchanged`, or a refusal (`bad_secret_request`, `paused`,
`unsupported_kind`, `unsupported_version`).

### Lists

A `list` answer carries `secrets`, the names of the keys the agent may ask for (never a value),
when its scope allows keys:

```json
"secrets":[{"title":"OpenAI", "service":"openai.com", "variable":"OPENAI_API_KEY"},
           {"title":"OpenAI (Sparrow)", "variable":"OPENAI_API_KEY", "projects":["Sparrow"]}]
```

`projects` is absent for a global key.

### Keys by project

A key has a list of projects ("Sparrow", "Otter", "Heron"). An empty list makes it **global**: every
project, and every request that names no project, may use it. One project: only that project. Several:
shared by those projects. The same variable name may be on one key per project and on one global key.
`nodkey_proto::apikey::project` implements this part.

A project name is 1 to 40 characters (`MAX_PROJECT`) without spaces at either end, without `/`,
`,` or a control character, and is not `global` in any case. Two names are the same project when
they are equal without regard to case (Unicode lower case: `sparrow` is the app's "Sparrow"). A key
belongs to at most 10 projects (`MAX_PROJECTS`). In iCloud the app keeps the list as one string,
the names joined by line breaks.

A `secret` request (and a bundle with `secret` items) may name the project it asks in:

```json
{"v":1, "request_id":"…", "kind":"secret", "target":"OPENAI_API_KEY",
 "reason":"Run the tests that call the OpenAI API", "agent":"Claude Code @ my-laptop", "ts":1791620000,
 "project":"sparrow"}
```

`project` is allowed only on a `secret` request and on a bundle with at least one `secret` item (it
applies to all of them); both sides refuse it elsewhere, and the phone refuses a bad name with
`bad_secret_request`. A target's own `project/NAME` wins over the request's `project`, and
`global/NAME` asks for the global key whatever the request's `project` says.

**The lookup** (the phone, the same everywhere, `apikey::lookup`):

1. The keys of the asked project (the target's, else the request's) that match the target.
2. Else the global keys that match the target.
3. Else no key matches: the phone still asks, and the user can pick a key by hand, add one, or
   answer `no_secret`.

When several keys match in one step, the user picks one. The approval names the source:
"OPENAI_API_KEY from Sparrow" or "OPENAI_API_KEY (global)"; a bundle in a project reads "Claude Code
wants 3 keys from Sparrow". Every key still needs Face ID, is never covered by a lease, counts
against the agent limit and may be in a task plan (a plan item in a project covers later requests
in the session that the lookup answers with the same key).

The key in an answer says where it came from:

```json
{"v":1, "request_id":"…", "decision":"approved", "lease":{"kind":"once"},
 "secret":{"title":"OpenAI (Sparrow)", "variable":"OPENAI_API_KEY", "value":"sk-test-sparrow-0000",
           "from":"project", "project":"Sparrow"}}
```

`from` is `project` (a key of the asked project; `project` is its name as the user wrote it),
`global` (a global key) or `chosen` (nothing matched and the user picked this key by hand). Apps
before projects send neither.

A `save_secret` carries `projects` (absent or empty: a global key); a save updates the key with the
same service, variable name and projects (the same names in any order and case), else adds one
(`apikey::saved_key`):

```json
"save_secret":{"variable":"OPENAI_API_KEY", "service":"openai.com", "title":"OpenAI for Sparrow",
               "projects":["Sparrow"], "value":{"enc":"…", "ct":"…"}}
```

**The `.nodkey` file.** A repository says which keys its commands need in a `.nodkey` file at its
root, by name only, so it is safe to commit (also in a public repository):

```toml
project = "sparrow"
secrets = ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "global/GITHUB_TOKEN"]
```

`nodkey` reads a small part of TOML: comments, `project` as a string and `secrets` as a list of
strings (`NAME`, `global/NAME` or `project/NAME`; never a value or a service, and every variable
name once). Other keys and tables are refused. `nodkey run -- <command>` in that folder or below it
reads the nearest file and asks for all its keys in one request (one bundle with `project`, or one
`secret` request for a single key). The search goes up from the current folder to the repository
root (a folder with `.git`) or the home folder, whichever comes first, and stops at the first
`.nodkey` it finds. On Unix a file another user owns, or one everyone may write, is ignored (like
git's `safe.directory`) and nodkey says so on stderr. nodkey names the file it used on stderr and
adds it to the reason the phone shows ("Run npm test (keys named in ~/src/app/.nodkey)").

Vectors: `request_secret_project`, `answer_secret_project`, `answer_secret_project_global`,
`answer_secret_project_chosen`, `request_secret_global`, `answer_secret_global`,
`request_secret_project_target`, `request_bundle_project`, `answer_bundle_project`,
`request_bundle_project_session`, `answer_bundle_project_session`, `save_secret_projects_value`,
`request_save_secret_projects`, `answer_save_secret_projects`, `answer_list_with_key_projects`, and
the `key_projects` section: project names (`names`), the same project (`same`), targets with a
project or `global` (`targets`), a set of `keys`, which keys the lookup finds for a target and a
request's project (`lookups`: `from` and the indexes, `null` and `[]` when nothing matches) and
which key a save updates (`saves`: an index, or `null` for a new key). Test values only.

### The agent side

- `nodkey run [--secret NAME[=SERVICE]]... [--project NAME] [--reason TEXT] -- <command> [args]`
  asks for the keys of the nearest `.nodkey` file (in its project) and the `--secret` ones (which
  add to the file's, or replace one with the same name; `global/NAME` and `project/NAME` work too),
  puts each value only into the environment of the command as `NAME`, and never prints a value.
  `--project NAME` asks in another project; `--project global` asks for global keys only. The reason
  defaults to `Run <command>`. One key is one `secret` request; several keys are one bundle (or,
  while a task session runs, one `secret` request each, which the session may cover). The command
  runs only when the phone gave every key; stderr says where each came from ("OPENAI_API_KEY from
  Sparrow, GITHUB_TOKEN (global)"). **This is the preferred way:** the model never sees the value.
- `nodkey secret save NAME [--service HOST] [--project NAMES] [--title TEXT] [--notes TEXT]
  [--expires DATE] --reason TEXT` reads the value from stdin, never from the arguments. `--project`
  takes names separated by commas (`global`: a global key); without it, the project of the nearest
  `.nodkey` file, if any.
- The MCP tool `request_secret` (with an optional `project`) returns the value, with a message to
  prefer `nodkey run`; `save_secret` (with optional `projects`) saves a key; `list_accounts` shows
  the key names and their projects.
- An agent never pastes a key into a chat, a file, a commit or a log, and saves a key it made at
  once with `save_secret`.

Vectors: `request_secret`, `request_secret_by_variable`, `answer_secret`,
`answer_secret_quota_warning`, `answer_secret_no_secret`, `save_secret_value`,
`request_save_secret`, `answer_save_secret`, `request_bundle_secrets`, `answer_bundle_secrets`,
`request_bundle_secret_session`, `answer_bundle_secret_session`, `request_secret_in_session`,
`answer_secret_in_session`, `answer_list_with_secrets`, `answer_secret_no_passcode`, and the
`secrets` section: how targets
read (`targets`), which keys match which targets (`matches`), the limits and the errors. Test
values only.

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
  pages of the provider are its exact sign-in hosts and the hosts below them, not its whole domain
  (`google.com` also has pages anyone can make): Google `accounts.google.com`; Apple
  `appleid.apple.com`, `idmsa.apple.com`, `account.apple.com`; GitHub `github.com`; Microsoft
  `login.microsoftonline.com`, `login.live.com`, `login.microsoft.com`; Facebook
  `www.facebook.com`, `m.facebook.com` (`Provider::sign_in_hosts`). For `other` it is the exact site
  of `via.account`. A host of the target's website is never a page of the provider.
  `nodkey_proto::signin::may_fill_via` makes this decision; the `signin.via_fill` and
  `sites.via_fill` vectors give cases, `sites.provider_sign_in_hosts` the lists. (`signin.provider_sites`
  lists where the app looks for the provider's own saved login, which is a different question.) When the target site itself asks for the password of the provider, the agent stops
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

## Moving in

A user can bring the passwords and codes from their browsers and password managers into Nodkey
from their computer, with an agent's help: a first move, or a clean-up round. The phone opens an
**import window** for one agent. The agent sends each export file to the phone, end to end
encrypted; the phone stages what it reads for review; the user adds it all with one Face ID. The
window is **inbound only**: the agent never gets a secret back, and nothing is added without the
user's review. `nodkey_proto::import` implements this section (peters/nodkey#130).

### The import window

- The user opens it on the phone: Settings → Import → "From your computer, with an agent". They
  pick one paired agent and confirm with Face ID or the passcode. A phone without a passcode
  cannot open one.
- It takes files for 30 minutes (`WINDOW_SECONDS`), at most 20 (`WINDOW_FILES`). The user can
  close it at any time; adding the reviewed entries closes it too. One window at a time per phone.
- No message opens it: the agent learns that it is open only from the answer to an `import`
  request. Without an open window for this agent the phone refuses at once (`import_closed`), so
  no agent can push logins unasked.

### The request

```json
{"v":1, "request_id":"…", "kind":"import", "target":"", "reason":"Move the passwords saved in Chrome into Nodkey",
 "agent":"Claude Code @ my-laptop", "ts":1791620000,
 "import":{"file_name":"Chrome Passwords.csv", "size":243, "sha256":"fomLLc-QCrPoXSjLGMW5Zhy_S29QHbce4vLRxQfLMtU",
           "format_hint":"chrome_csv", "source":"Chrome, profile Default"}}
```

| Field | Meaning |
| --- | --- |
| `file_name` | the export's name without folders: 1 to 120 characters (`MAX_FILE_NAME`), no `/`, `\` or control characters |
| `size` | the file's size in bytes, 1 to 1 048 576 − 48 = 1 048 528 (`MAX_FILE`), so the sealed body fits the relay's 1 MiB attachment limit |
| `sha256` | b64u of SHA-256 of the file's bytes |
| `format_hint` | optional: what the agent thinks the file is (table below). A hint only: the phone reads the file with its own importers. An unknown value reads as `unknown`. |
| `source` | a short label for the phone's list: 1 to 80 characters (`MAX_SOURCE`) without control characters (`Chrome, profile Default`, `Firefox`, `Bitwarden`) |

`target` is empty and `reason` is required, as for `list`. The request has no `attachment` field
and no `session_id`, and is never part of a bundle. The file follows like a picture: the envelope
carries `attachment: true`, and right after posting, the agent uploads the body `enc ‖ ct` with
`PUT /v1/requests/{request_id}/attachment`: the file sealed to the phone on its own, HPKE `info`
`nodkey/v1/import`, `aad` = `request_id` ‖ `agent_id`. The relay limits are those of a picture
(1 MiB, within 120 s of the request), and the relay forgets the file when the phone answers. Both
sides check these rules (`ImportRequest::check`); the agent tools send nothing that breaks them.

| `format_hint` | File |
| --- | --- |
| `chrome_csv` | Chrome, Chromium, Edge, Brave, Vivaldi or Opera: `name,url,username,password,note` |
| `firefox_csv` | Firefox (`about:logins`, Export Logins) |
| `apple_passwords_csv` | Apple Passwords or Safari on a Mac (with `OTPAuth`) |
| `bitwarden_csv`, `bitwarden_json` | Bitwarden, CSV or JSON (not encrypted) |
| `1password_csv` | 1Password CSV |
| `lastpass_csv` | LastPass |
| `dashlane_csv` | Dashlane `credentials.csv` (from the zip it exports) |
| `proton_pass_csv` | Proton Pass CSV |
| `nordpass_csv` | NordPass |
| `keepassxc_csv` | KeePassXC CSV |
| `generic_csv` | another CSV with a password column |
| `otpauth_list` | one `otpauth://` link per line (the plain text export of Aegis or Ente Auth, other code apps) |
| `2fas_json` | a 2FAS backup (`.2fas`) |
| `aegis_json` | an Aegis JSON export, not encrypted |
| `unknown` | none of these |

`nodkey_proto::import::detect` makes the hint from the content alone, never from the file name,
with the column rules of the app's `PasswordImport.source`.

### What the phone does

The phone answers an `import` request at once, without asking: the open window is the user's
approval. It checks in this order and refuses with `decision: denied` and `error`:

| Check | `error` |
| --- | --- |
| the request's `v` and `kind` | `unsupported_version`, `unsupported_kind` |
| the agent is paused | `paused` |
| the phone has no passcode | `no_passcode` |
| no open window for this agent (none, closed, timed out, or another agent's) | `import_closed` |
| the window already holds 20 files | `window_full` |
| `size` above 1 048 528, or a body above 1 MiB | `too_large` |
| the request breaks another rule above; the file did not arrive within 60 s (`FILE_WAIT`), does not open, or its size or SHA-256 differs from the request | `bad_import` |
| the importers cannot read it: an unknown format, an encrypted export, or not one login or code | `import_unreadable` |

The refusals up to `too_large` need no file, so the phone sends them at once, often before the
upload is done. The relay then turns the upload away with `409 already_claimed` (the request is
answered); the agent does not treat that as a failure, reads the answer as usual and reports the
refusal.

The phone fetches the file with `GET /v1/requests/{request_id}/attachment` and retries a `404`
for up to 60 s, because a large upload can take longer than the relay's 5 s push hold. It opens
the file in memory, reads it with its importers (`PasswordImport`, `AuthenticatorImport`,
`LoginImport`) and drops the raw file at once. The entries go into the window's staging list "To
review", with the agent, the file name, the source and the time. Within the window, each file is
compared with the files staged before it: the same entry is left out, and the same login on
another host of the website is merged, as in any import. Then the phone answers `staged`.

Only the app stages a file: it parses the export in memory, which the notification service
extension does not. While Nodkey is not open, the extension answers only the refusals it can decide
without the app (`paused`, `no_passcode`, `import_closed`, `window_full`, `too_large`) and leaves
any other import for the app, with a notification to open Nodkey. So the user keeps Nodkey open on
the window's screen while the agent sends files (the app keeps the screen on there); a request the
app did not see in time ends as `expired`, and the agent sends the file again once Nodkey is open.


```json
{"v":1, "request_id":"…", "decision":"staged",
 "import":{"found":2, "new":2, "merged":0, "duplicates":0, "conflicts":0, "skipped":1,
           "logins":2, "codes":0, "files":1, "until":1791621800}}
```

| Field | Meaning |
| --- | --- |
| `found` | entries read from this file (a login with a code is one entry) |
| `new` | entries this file added to the staging list |
| `merged` | entries merged into one staged before in this window: the same user name and password on another host of the website, or a code for a staged login |
| `duplicates` | entries the same as one staged before in this window (site, user name and password, or the same code key); left out |
| `conflicts` | of `new`: the same address (host, without `www.`) and user name as an entry staged before in this window, with another password; the user picks one in the review. The same user name with another password on another host of the website (`jira.example.com` and `mail.example.com`) is two new entries, not a conflict. |
| `skipped` | rows the phone could not use (no password and no code key, or not readable) |
| `logins`, `codes` | optional, of `found`: how many have a password, how many a code key |
| `files` | optional: how many files the window holds now, this one included |
| `until` | optional: when the window stops taking files (Unix seconds) |

`found` = `new` + `merged` + `duplicates`, and `conflicts` ≤ `new`. **No count depends on the
vault.** The comparison with what Nodkey already holds (new, already saved, a newer password) is
shown on the phone only: a count against the vault would let an agent test a guessed password by
sending a file with it and reading `duplicates`. An answer never carries a site, a user name, a
password or a code. `staged` is used only for `import`. `denied` without `error` is a refusal for
another reason, and `expired` means no answer came within the request's 120 s; the agent then
tells the user to look at the phone.

### The review

The user opens "To review" on the phone when the agent is done, or when the window's time is up.
It shows every entry with the agent and the file it came from: new, merged, already saved (left
out) and conflicts with the vault or between files (the same address and user name with another
password; the source and date of each, the newest suggested). One Face ID adds it all and closes
the window. Nothing is added before that; what the user does not add is dropped with the staging
list. The Agents history shows which agent sent which file. An `import` is never covered by a lease
and does not count for the agent limit (the relay's 20 requests per hour per agent still apply).
Every scope may import: the user picked this agent for the window.

### The agent side

- `nodkey import FILE [--source LABEL] [--reason TEXT] [--keep] [--dry-run] [--phone PHONE]` and
  the MCP tool `import_file(path, source?, reason?, keep?, dry_run?)` do the same.
- They read the file once into memory (wiped afterwards), refuse an empty file or one above
  1 048 528 bytes before anything is sent (`too_large`), and refuse a zip archive or an encrypted
  export (`import_unreadable`: unpack the archive, or export again without a password). They
  detect the format for `format_hint` and use its name as `source` when none is given.
- `--dry-run` sends nothing. It shows the format and the counts per type (logins, codes, skipped
  rows), never a value.
- After `staged` they delete the export: they overwrite its bytes with zeros, flush them to disk,
  and remove the file, unless `--keep` is given. After a refusal the file stays where it is, and
  the result says so. On SSDs and copy-on-write file systems an overwrite may not reach every old
  block; the disk encryption of the system (FileVault, BitLocker, LUKS) covers what is left.
- They never print, log or keep the content; the result carries only the counts. The model never
  reads the export itself (no `cat`, no file reading tool, no copy); the `nodkey-move-in` skill
  says so.
- Exit codes: 0 `staged`, 1 error (also `bad_import`), 2 denied, 3 expired, 4 `paused`, 10
  `no_passcode`, 11 `import_closed`, 12 `window_full`, 13 `import_unreadable`, 14 `too_large`, 64
  bad arguments. An older app answers `unsupported_kind`; the agent tells the user to update
  Nodkey.

Vectors: `request_import`, `import_file` (the sealed Chrome sample; `body_b64u` is the upload),
`request_import_signed` (also in `signed`), `answer_import_staged`, `answer_import_closed`,
`answer_import_window_full`, `answer_import_too_large`, `answer_import_bad_import`,
`answer_import_unreadable`, `answer_import_no_passcode`, and the `import` section: the limits, the
formats, the errors in the phone's order, `checks` (requests and the `error` each gets, `null` when
it passes) and `detect` (invented export files with the format and counts `detect` reads from
them; the phone's own counts may differ where its importers read a row differently).

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
long as the request (120 s). Without a picture everything works the same. The export file of an
`import` request takes the same path, sealed with `nodkey/v1/import` (see "Moving in"); the relay
does not tell the two apart.

## Leases

A lease is `(agent_id, account_id, kind: code|login, until)` (for passkeys see "Passkeys"; cards,
keys, `suggest`, `sms_code`, `import` and `generate` never have one), kept only on the phone (keychain-backed
store shared with the notification extensions). While a matching lease is valid the phone answers by
itself and shows a quiet notification ("Claude got the password for vg.no"), but only for a target
that is an exact match for the account (see "Websites"). Durations: once (no lease),
1 day, 7 days, always (until revoked). The user sees and revokes leases under Agents; removing an agent
removes its leases and calls `DELETE …/agents/{agent_id}`. While the agent limit warns for an agent, its leases
do not answer (see "Agent limit"). A phone without a passcode has nothing to approve a lease with:
it gives no leases (only once), no task sessions and no follow-up windows, and it refuses cards and
keys with `no_passcode`.

## Agent limit

The phone limits how many different logins, codes and keys one agent gets, so that an agent cannot take
everything out of Nodkey. The phone counts and decides; the agent sees the limit only in answers.
`nodkey_proto::quota` holds the numbers below.

- **What counts:** new items only. An item is one saved login, code account or key; it is new when this
  agent has not received it in the last 30 days. An agent that uses the same few logins every day
  almost never reaches the limit; an agent that goes through many accounts reaches it fast.
- An item is received when an approved answer gives it: a `code` or `login` answer, an approved
  `login` or `code` item of a bundle, the provider login in `via`, a `secret` answer or an approved
  `secret` item of a bundle (also a plan item without a value), and answers that a lease, a task
  session or the follow-up window gave. Passkey signatures (the key never leaves the phone), cards
  (they have their own limits), `sms_code`, `list`, `insights`, `cleanup`, `save`, `save_secret`,
  `suggest`, `import` and `generate` do not count.
- The count is per agent, over a rolling 24 hours.
- The limit is per agent: 5, 10 or 25 (the user picks it under Agents; 10 when they did not).

Before it answers a `code`, `login`, `secret` or `bundle` request, the phone adds the new items of the request
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

- leases, the follow-up window and task sessions do not answer for it: each `code`, `login`,
  `secret` and `bundle` request is asked on its own. A bundle with `session` is asked as a bundle without one and
  starts no session. The phone ends the running session of that agent; a request with its
  `session_id` is asked as usual, and the answer carries `session_ended: true`.
- the notification of its requests offers only Open: the user approves in the app.
- every answer to its `code`, `login`, `secret` and `bundle` requests carries `error: "quota_warning"` and
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
`client.mcp_version`, the version of `nodkey`. Pairing with the commitment and signed messages kept
`v: 1`; how old and new sides meet is in "Pairing and the check number" and "Signed requests and
answers".

## Agent side

- Keys and pairings: `~/.config/nodkey-agent/` (directory 0700, files 0600; `NODKEY_AGENT_DIR`
  overrides it). Each agent on the computer has its own identity and pairing under
  `agents/<profile>/`: `identity.json` (`agent_id`, name, and the private keys or where they are; see
  the next item) and `phones.json` (paired phones: `phone_id`, public keys, name, check, and
  `signs: true` when the phone's answers must be signed). While a pairing waits for the person's
  confirmation, `pairing.json` holds it (the code and the phone, at most 10 minutes). Profiles: `claude-code`, `codex`, `cursor`,
  `claude-desktop`, `terminal` (the command line), or any name given with `--agent`. The phone shows
  each by its name ("Claude Code @ my-laptop", "Terminal @ my-laptop"), so the user can pause or remove
  one without the others and the history shows who asked. The command line uses `--agent`, else
  `NODKEY_AGENT`, else the agent whose shell runs it (Claude Code sets `CLAUDECODE=1` there; Codex
  sets `CODEX_SANDBOX` or `CODEX_SANDBOX_NETWORK_DISABLED` in its sandbox), else `terminal`. So
  `nodkey run` started by Claude Code asks as Claude Code. Profiles name the asker; they do not
  separate programs on one computer. Every program that runs as the user can read the agent folder
  and ask under any profile, so pausing one agent on the phone does not stop a program from asking
  under another profile. Pausing all agents under Agents on the phone stops all of them. `config.json` in the top folder may set
  `relay`. An identity in the top folder (made before profiles) moves into the profile its name
  belongs to on first use, with its keys, so it stays paired.
- The agent's private keys go to the keychain of the system when there is one, so a copy of the
  agent folder alone cannot act as the agent. macOS: the login Keychain (a generic password, service
  `nodkey-agent`, account = `agent_id`). Windows: DPAPI for the current user; the sealed keys stay in
  `identity.json` (`sealed_keys`), and only this user on this computer can open them. Linux and
  other Unix systems: the Secret Service through `secret-tool` (libsecret), when it is installed and
  a session bus is there; the keys go over stdin and stdout, never in arguments. Otherwise, and with
  `NODKEY_KEYSTORE=file` (or `"keystore": "file"` in `config.json`), the keys stay in `identity.json`
  (`kem_sk`, `sign_sk`). With the keys in a keychain, `identity.json` has `keys` (`macos-keychain`,
  `dpapi` or `secret-service`) and the public keys `sign` and `kem`, and nodkey refuses keys from the
  keychain that do not match them. Keys that are still in the file move into the keychain the first
  time the agent uses them (once per process; when that fails, they stay in the file). When the
  keychain that holds the keys does not open, for example a locked login keychain over SSH, nodkey
  stops with a message that says what to do. It never makes a new identity in its place.
  `nodkey agents` shows where the keys of each agent are.
- One binary `nodkey`. The MCP server is `nodkey mcp` (stdio); `nodkey setup` registers it as
  `nodkey mcp --agent <profile>` in each agent it finds. Without `--agent`, the profile follows the
  MCP client's `clientInfo.name`.
- A tool result only reaches the model when the call ends, so pairing over MCP takes three calls:
  `pair(name?)` returns the code to type on the phone (`K7P-2QX`) at once; `pair(code)` then waits up
  to 5 minutes for the claim, runs the pairing check and returns the phone name and the check number,
  which the model shows the user to compare; `pair(code, confirm)` saves the phone when the user says
  the numbers are the same (`confirm: true`), or leaves and saves nothing (`confirm: false`). Other tools: `list_phones()`, `unpair(phone)` (calls the agent-side `DELETE`
  and forgets the phone), `request_code(target, reason, image_path?)`,
  `request_login(target, reason, image_path?)`, `request_credentials(items, reason, follow_up_seconds?,
  session_minutes?, image_path?)`, `end_session()`, `request_payment(merchant, amount, currency, reason, image_path?)` (`mode: reveal`;
  its description starts with "Spends the user's money."), `list_accounts()`, `cleanup_insights()`,
  `cleanup_logins(filter, reason)` (dates as Unix seconds or `YYYY-MM-DD`; an unknown filter key is an
  error, so a typo cannot widen the filter), `suggest_sign_in_method(target, kind, provider?, mailbox?,
  outcome, reason)` (`provider` is a known name or the provider's own; a `signed_in` suggestion
  goes as `seen`, a `failed` one without `certainty`), `request_sms_code(target, reason,
  wait_seconds?)`, `request_secret(variable?, service?, project?, reason, image_path?)` and
  `save_secret(variable, service?, value, title?, notes?, expires?, projects?, reason)` (see "API
  keys and secrets"), `import_file(path, source?, reason?, keep?, dry_run?)` (see "Moving in") and
  `create_login(site, username?, title?, rules?, change?, reason, image_path?)` (see "Making a
  password"). Every approved `request_code` and `request_login` result, and each approved
  login and code item of `request_credentials`, carries `fill_only_on` (see "Websites"). A
  `request_login` result shows `via` with its own `fill_only_on` (`via_sites`), and its
  message says what to do with `method`, `via` and `second_step`. `image_path` is an optional PNG/JPEG/GIF file (for example
  a browser screenshot) sent as the attachment. Results go to the model; the server keeps no secret.
  The agent app keeps tool results in its saved conversation and sends them to the model provider,
  so a code, password, key or revealed card in a result stays there. `nodkey run` (keys) and the
  host fill commands (`login-fill`, `card-fill`) keep the secret out of the conversation.
  A running task session (its id, end, phone and the approved items, never a secret) is kept in
  `agents/<profile>/session.json`, so the MCP server, the command line and `nodkey webauthn` of one
  profile share it; `end_session()` and `nodkey end-session` end it.
- The command line does the same in one process: `nodkey pair` shows the code and then the check
  number, and reads one line on stdin: `y` (or `yes`) when the iPhone shows the same number saves the
  pairing; anything else, or no line, saves nothing (exit code 2); `nodkey code`, `login`, `credentials`, `pay`, `suggest`, `sms-code`, `run`, `secret save`,
  `accounts`, `insights`, `cleanup`, `phones`, `unpair`, `import`, `generate`. `nodkey suggest SITE --kind KIND [--provider NAME] [--mailbox ADDR]
  [--outcome failed] --reason TEXT`; `nodkey sms-code TARGET --reason TEXT [--wait SECS]`. Exit codes:
  0 approved (or queued), 1 error, 2 denied (or rejected), 3 expired, 4 paused (`error: paused`),
  64 bad arguments; for `pay` and `card-fill` also 5
  `over_limit`, 6 `reveal_off`, 7 `cards_off` or `no_card`, 8 `total_mismatch`, 10 `no_passcode`,
  and for `card-fill` 9 `setup_off`; for `import` 0 is `staged`, and 10 `no_passcode`, 11
  `import_closed`, 12 `window_full`, 13 `import_unreadable`, 14 `too_large`; for `generate` also 10
  `no_passcode` and 15 `bad_rules`. `nodkey pay MERCHANT
  AMOUNT CURRENCY --reason TEXT --reveal` prints the full card, so it requires `--reveal`; without a
  host nothing can fill a card for it. A missing amount is refused before anything is sent.
  `nodkey run` passes on the exit code of the command it ran (126 or 127 when the command cannot
  start); when the phone does not give every key, the command does not run and the exit code is 2,
  3, 4 or 1 as above.
- `nodkey webauthn --agent <profile> [--phone PHONE]` is the authenticator a browser host (Horizon)
  calls; `nodkey login-fill --agent <profile> [--phone PHONE]` gives such a host a login to fill;
  `nodkey card-fill --agent <host> [--phone PHONE]` gives it a card to fill, under the host's own
  profile. See below.

## The authenticator command

`nodkey webauthn --agent <profile>` reads one JSON object on stdin and writes one JSON object on
stdout, also when it fails (waiting notes go to stderr). Sign in:

```json
{"version":1, "op":"get", "rp_id":"webauthn.io", "origin":"https://webauthn.io",
 "client_data_json":"<b64u>", "allow_credentials":["<b64u>"], "user_verification":"preferred",
 "reason":"Sign in to webauthn.io in a browser panel", "requester":{"app":"Horizon", "agent":"Claude Code"}}
```

`op: create` adds `rp_name`, `user`, `algorithms`, `exclude_credentials` and `resident_key`, as in
the request. `reason` is optional ("Sign in to webauthn.io with a passkey", "Unlock a key for
webauthn.io" for a get with PRF inputs, or "Create a passkey for webauthn.io"); `requester` is optional and self-reported, and goes to the phone's history as
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
| `prf_unsupported` | 2 | a get with PRF inputs, and the passkey (or the app) has no PRF |
| `denied` | 2 | the user said no, the agent is paused, the phone refused the client data or the algorithms, or it has no passcode (`error: no_passcode`) |
| `not_found` | 2 | the phone has no matching passkey (`no_passkey`) |
| `excluded` | 2 | the phone already holds a passkey in `exclude_credentials` |
| `expired` | 3 | no answer in time |
| `error` | 1 | not paired, relay trouble, an app that is too old, or an answer that fails the agent's check |
| `error` | 64 | the input is not a valid request, or `origin` does not match `client_data_json` |

A failure from the phone also carries the phone's `error` code. A bridge turns `excluded` into
`InvalidStateError` and every other failure into `NotAllowedError`.

PRF: the request may have `extensions.prf` in the WebAuthn JSON form, as a page gives it to
`navigator.credentials` (`eval`, `evalByCredential`; inputs b64u). Other extensions are ignored. The
command sends it as `prf` (see "PRF") and puts the answer in `clientExtensionResults.prf`, as
`PublicKeyCredential.toJSON()` has it, so a host can copy both objects as they are:

```json
{"version":1, "op":"get", "rp_id":"example.com", "origin":"https://example.com",
 "client_data_json":"<b64u>", "allow_credentials":["<b64u>"],
 "extensions":{"prf":{"eval":{"first":"<b64u>", "second":"<b64u>"}}}}
{"version":1, "status":"ok", "credential_id":"…", "authenticator_data":"…", "signature":"…", "user_handle":"…",
 "clientExtensionResults":{"prf":{"results":{"first":"<b64u>", "second":"<b64u>"}}}}
{"version":1, "status":"ok", "credential_id":"…", "attestation_object":"…", …,
 "clientExtensionResults":{"prf":{"enabled":true, "results":{"first":"<b64u>"}}}}
```

`clientExtensionResults` is there only when the request had `extensions.prf`. `nodkey webauthn
--help` prints the whole contract. The RP ID rule is the client data check above: `rp_id` is a
domain name with a dot or `localhost`, and the host of the origin is `rp_id` or ends with `"." +
rp_id`, and `rp_id` is not a public suffix (`github.io` and `co.uk` are refused; `alice.github.io`
and `example.co.uk` are fine).

## The card fill command

`nodkey card-fill --agent <host>` is how a browser host (Horizon) fills a checkout form for an
agent without the card reaching the model. It reads one JSON object on stdin and writes one JSON
object on stdout, also when it fails (waiting notes go to stderr).

The host runs it under its own profile (`--agent horizon`), paired once with
`nodkey pair --agent horizon`, and the user turns cards on for that profile in Nodkey, never for the
model's own profile. `card-fill` refuses to run without `--agent` or under an agent's profile
(`claude-code`, `codex`, `cursor`, `claude-desktop`, `terminal`, `mcp`) with exit code 64. The
`requester` field still names the agent the host acts for. The card stays away from the model only
when the model cannot run `nodkey` and cannot read the agent folder (no shell, or a sandbox
without them): a model with a shell could run `card-fill` under the host's profile, and the phone
cannot tell the two apart. Each payment still needs the person's hold and Face ID, and the amount
is checked.

```json
{"version":1, "merchant":"shop.example.com", "origin":"https://www.shop.example.com",
 "amount":{"value":"499.00", "currency":"NOK"}, "page_total":{"value":"499,00", "currency":"NOK"},
 "total_source":"page", "reason":"Buy the 2 m USB-C cable you asked for",
 "requester":{"app":"Horizon", "agent":"Claude Code"}}
{"version":1, "purpose":"setup", "merchant":"shop.example.com", "via":"js.pay.example",
 "origin":"https://js.pay.example", "requester":{"app":"Horizon", "agent":"Claude Code"}}
```

`purpose` is `pay` (when left out) or `setup`: add the card for later payments, with no `amount`,
`page_total` or `total_source` (see "Cards for later payments"). `merchant` is the top-level page's
site. `via` is the payment frame's host when the card form is in a frame from another site, and
`origin` is then that frame's origin. `amount` comes from the agent (or is the page total when the
user fills by hand); `origin`, `via` and `page_total` come from the host itself, never from the
page's script or the model. Amounts take a dot or a comma before the decimals. `reason` is optional
("Pay 499.00 NOK at shop.example.com", or "Add your card at shop.example.com for later payments").
Unknown fields are refused. The command sends `kind: card`, `mode: fill`. Results:

```json
{"version":1, "status":"ok",
 "card":{"number":"4242424242424242", "exp_month":12, "exp_year":2030, "cvc":"123", "holder":"Alex Example",
         "brand":"visa", "last4":"4242", "title":"Test Visa"},
 "approved_amount":{"value":"499.00", "currency":"NOK"},
 "summary":"filled: Visa ····4242 on shop.example.com, at most 499.00 NOK. One purchase; ask again for the next one."}
{"version":1, "status":"ok", "card":{…},
 "summary":"filled: Visa ····4242 on shop.example.com via js.pay.example, to add the card for later payments. No purchase was approved; ask again for the next card."}
{"version":1, "status":"denied|expired|over_limit|cards_off|total_mismatch|setup_off|no_passcode|error", "message":"…", "error":"…"}
```

A `setup` result has no `approved_amount`. With `via`, the summary names the shop "via" the frame.

| `status` | Exit | When |
| --- | --- | --- |
| `ok` | 0 | the user approved; fill the form, then give the model only `summary` |
| `denied` | 2 | the user said no, or the agent is paused |
| `expired` | 3 | no answer in time |
| `over_limit` | 5 | above the user's limit for this agent |
| `cards_off` | 7 | cards are off for this agent, or no card may be used (`error` says which) |
| `total_mismatch` | 8 | the page total is more than the amount; checked before anything is sent |
| `setup_off` | 9 | `setup`, and adding cards for later payments is off for this host |
| `no_passcode` | 10 | the phone has no passcode, so Nodkey hands out no cards; the user can set one in Settings, Face ID & Passcode |
| `error` | 1 | not paired, relay trouble, an app that is too old (for `setup` also `error: amount_missing`: the app does not know it) |
| `error` | 64 | the input is not a valid request (`error: amount_missing` when a `pay` request has no amount) |

Before it fills, the host reads the page total again and fills nothing when it is now more than
`approved_amount`. It keeps watching the total until the form is sent and clears the card fields if
the total goes up. For `setup` there is no total: the host fills only the frame of `origin`. It
never clicks the pay button itself and never stores the card.

## The login fill command

`nodkey login-fill --agent <profile>` is how a browser host (Horizon) fills a sign-in form for an
agent, so the password goes to the host and not into the model's conversation. It reads one JSON
object on stdin and writes one JSON object on stdout, also when it fails (waiting notes go to
stderr). `--agent` names the agent the host acts for (its leases and history apply); without it
the profile follows the usual rule (see "Agent side").

```json
{"version":1, "origin":"https://www.vg.no", "target":"vg.no", "reason":"Sign in to read the article you asked for",
 "requester":{"app":"Horizon", "agent":"Claude Code"}}
```

`origin` is the sign-in page's origin as the host saw the frame, never from the page's script or
the model (`https://` or `http://`). `target` (optional, the origin's host when absent) is what the
command asks for, as in a `login` request; `reason` is optional ("Sign in to www.vg.no"). Unknown
fields are refused. The command sends `kind: login`. Results:

```json
{"version":1, "status":"ok", "username":"alex@example.com", "password":"…", "code":"190274", "seconds_left":12,
 "account":{"issuer":"VG", "name":"alex@example.com", "site":"vg.no"}, "fill_only_on":["vg.no"],
 "summary":"filled: the login alex@example.com on vg.no. Ask again for the next sign-in."}
{"version":1, "status":"denied|expired|wrong_site|error", "message":"…", "error":"…"}
```

| `status` | Exit | When |
| --- | --- | --- |
| `ok` | 0 | the user approved and `origin` is on the login's `fill_only_on`; fill the form, then give the model only `summary` |
| `denied` | 2 | the user said no (exit 4 when the agent is paused) |
| `expired` | 3 | no answer in time |
| `wrong_site` | 1 | the login is saved for another website than `origin`; nothing is given |
| `error` | 1 | not paired, relay trouble, an app that is too old, an answer without a website |
| `error` | 64 | the input is not a valid request |

`code` and `seconds_left` are there when the login has a code. The host fills only visible fields
on a page of `origin` and never stores the login. The password stays out of the conversation only
when the model cannot run `nodkey` or read the agent folder (no shell, or a sandbox).
