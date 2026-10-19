---
name: nodkey
description: Use the user's logins, one-time codes and saved passwords from Nodkey on their iPhone, each request approved by them with Face ID; sign in to websites, fetch a two-step code, see which accounts exist, tidy up old saved logins, use API keys without seeing them, and pay a purchase the user asked for with their card. Use when a task needs a login, a two-step code or an API key (for example OPENAI_API_KEY), when you made a new API key, when asked to sign in to a site (for example in a Horizon browser panel), when the user asks which accounts they have, or when they ask to clean up, review or remove stale or old saved passwords, or when they ask you to buy something. Uses the nodkey MCP server (request_login, request_code, request_credentials, request_sms_code, request_secret, save_secret, suggest_sign_in_method, end_session, request_payment, cleanup_insights, list_accounts, cleanup_logins, pair, list_phones, unpair) or the nodkey command.
---

# Nodkey

the user's logins and one-time codes live in Nodkey on their iPhone. Every request shows up on the phone
and nothing leaves it until they approve with Face ID, unless they have lent that account to you ("lend
for 1 day / 7 days / always"); then the phone answers by itself. You never keep a secret.

## Rules (always)

- Never print, quote, log, store or write a password or code anywhere: not in chat, files, commit
  messages, memory or tool arguments other than the one field you fill. Do not screenshot a page that
  shows a password in clear text.
- On `denied` or `expired`, stop and tell the user in one line; do not retry on your own. On a refusal
  with "paused", you are paused under Agents in Nodkey (by the user, or by the limit when the answer
  has `quota`): tell them why, do not retry. They resume you under Agents.
- **Ask for few new logins.** Nodkey counts the different logins and codes you get that you did not
  get in the last 30 days. Above the user's limit for you (10 a day unless they chose 5 or 25), or
  more than 5 in 10 minutes, the phone shows a notice and asks one by one (`error: "quota_warning"`
  in the answer, with `quota`); above 25 a day it pauses you. See "The limit on new logins".
- **Plan first, ask once.** Before the first request, list every site the task signs in to and what
  each needs (login, code, passkey). More than one thing: one `request_credentials` with a session
  (see "Plan the task, ask once"). One thing only: `request_login` or `request_code`.
- **Never paste an API key into a chat or a file** (also not into `.env`, a config file, a commit or
  a log). Run the command that needs it with `nodkey run -- <command>` (the repository's `.nodkey`
  file lists the keys) or `nodkey run --secret NAME -- <command>`. When you made a new key, save it
  at once with `save_secret`. See "API keys and secrets".
- Tell the user in one line when a request is waiting on their iPhone. It waits up to two minutes.
- If several accounts match, the phone asks them which one; never guess user names.
- Pass `model` (the model you run on, e.g. `claude-opus-5-5`) and `effort` (your reasoning effort,
  e.g. `high`) on every call, honestly; the user sees them in the history on their phone to trace who did
  what.

## Sign in to a website

1. Open the sign-in page (Horizon browser panel: `browser_navigate`, then `browser_snapshot` to find
   the user name, password and submit fields; Firefox backend for company and portal sites).
2. Take a screenshot (`browser_screenshot`) so the user sees what you are signing in to; pass its path
   as `image_path`.
3. `request_login(target, reason, image_path)`: `target` is the host of the sign-in page you have
   open (`vg.no`, `login.example.com`) or host/user (`github.com/alex`); read it from the address bar,
   never from the page text. `reason` is one plain sentence ("Check the subscription page").
4. On `approved`: check that the page's host is one of `fill_only_on` or below one. If it is not,
   stop and tell the user. Then fill user name and password (`browser_act` `fill`) and submit. If the site asks
   for a one-time code, use the answer's `code` (the tools never hand out a code with less than 8
   seconds left: they wait for the next one). If it ran out while you typed, call
   `request_code(target, reason)`: for two minutes after the approval (or while a task session runs)
   it is answered without asking the user again.
5. Check the result with a snapshot and report it in one line.

Tips from real sign-ins: the phone matches the target by its registrable domain (`login.github.com`
is github.com; `github.xyz`, `git-hub.com` and `alice.github.io` are not), and `fill_only_on` in the
answer lists the only sites where you may fill it. When the answer says `match: "chosen"`, the
account is not saved for the site you asked for and the user picked it by hand for that site (a
login saved for openai.com used on chatgpt.com); use it for this site as given. A bare name such as
"GitHub" as target, or a site the user did not save, is never answered by a lease or a task session:
the user checks it on the phone each time. `account.sites` lists more websites the account is used on. Two-step pages may split the code into one box per digit: fill them one by one. When a site offers an
app prompt instead of a code (Google, Microsoft), choose "another way" and the authenticator code
(see "Second step: passkey, then code").

## How the user signs in: method and via

Many sites are signed in to with "Sign in with Google" (or Apple, GitHub, Microsoft, Facebook), a
passkey, an e-mail code or the company's single sign-on, not a password. A `request_login` answer
then says so:

- `method.kind`: `password`, `federated` ("Sign in with" `method.provider`), `passkey`,
  `email_code`, `sso` or `sms`. Try that method first.
- `via` (with `federated`): the provider login, for example the user's Google login, approved with the
  same Face ID. **Fill `via` only on the provider's own sign-in pages, the hosts in
  `via.fill_only_on` or below them (accounts.google.com for Google, not other google.com pages).
  Never fill it on the target site.**
  If the target site itself shows a form for the provider's password, stop and tell the user.
  Without `via`, ask for the provider login with `request_login` on the provider's own site when its
  page asks for it.
- `email_code`: read only the newest mail from that site (the last 5 minutes) with your own mail
  tool, if you have one (`method.mailbox` is the address). Else ask the user for the code. Nodkey
  never reads mail.
- No `method`: the phone does not know. Sign in the way the page offers.

**Tell the phone what you learned** with `suggest_sign_in_method(target, kind, provider, outcome,
reason)`. It holds no secret and needs no Face ID; the user accepts it with one tap.

- You signed in with a method the phone did not know (no `method`, or a different one): send it
  with `outcome: "signed_in"`.
- The known method failed: try the next one the site offers. When that works, suggest it
  (`signed_in`), and suggest the one that failed with `outcome: "failed"`.
- One suggestion per site and method; at most 5 per hour. On `rejected` do not retry.

## Second step: passkey, then code

At a second-step prompt, follow the answer's `second_step` (`prefer` in order, never `avoid`). Without
it, choose in this order:

1. A passkey from Nodkey.
2. A one-time code from Nodkey (`request_code`, or `via.code` on the provider's page).
3. Avoid app prompts ("tap Yes on your phone") and SMS. Use them only when the user tells you to.

When a site sends its code only by SMS and offers nothing better, click its "Send code" and call
`request_sms_code(target, reason)` at once: the user's Shortcuts automation passes the SMS to
Nodkey, and they approve with Face ID. On `expired`, ask the user to type the code; do not loop.

Use the switch path in the provider's guide ("Try another way", "Other ways to sign in"). The
guides also show where the user sees which sites use "Sign in with" that provider, and how to add
a passkey or an authenticator code that Nodkey can keep:
https://github.com/peters/nodkey-cli/tree/main/skills/nodkey/guides (Google, Apple, Microsoft,
Meta, GitHub, Amazon). Every change to a sign-in method needs the user's explicit yes first. Never
turn off two-step sign-in, remove the last method, delete recovery codes or change a password on
your own.

## Plan the task, ask once

When a task needs more than one thing, ask for all of it in one plan. The user approves the plan
with one Face ID, and a task session covers the rest of the task.

1. **List what the task needs** before you open the first page: every site, and for each a `login`,
   a `code` or a `passkey` sign-in. Take along what will come: a login on a site with two-step
   sign-in also needs its `code`; a portal that sends you on to another sign-in (Microsoft, Google,
   Schibsted) needs both.
2. **Ask once:** `request_credentials(items, reason, session_minutes)`, items like
   `[{"kind": "login", "target": "accounts.example.com"}, {"kind": "code", "target": "accounts.example.com"},
   {"kind": "passkey", "target": "github.com"}]` (at most 10). `session_minutes` by the job: 15 for a
   few sign-ins, 30 for a normal task, 60 only for long work.
3. **Use the answer.** Each item has its own `decision`; use only the approved ones, each for its own
   site, and do not ask again for the denied ones. When `session` is in the answer, the session
   runs: `request_code`, `request_login` and passkey sign-ins for the approved items go through
   without asking (a fresh code, or the same login after the site logged you out). Anything else
   still asks the user.
4. **End it:** call `end_session` when the task is done.

Without `session_minutes` the plan is answered once, and fresh codes follow for two minutes
(`follow_up_seconds` up to 600). An older Nodkey app answers without a session, or refuses passkey
items and plans with more than 6 items (`bad_bundle`): then tell the user to update Nodkey.

## The limit on new logins

Nodkey limits how many different logins and codes one agent gets, so that no agent can take
everything out of it. Using the same login again does not count; asking for many new ones does.

- **`quota_warning`** (with any decision, also `approved`): the user saw a notice that you have
  received many new logins and codes today (`quota.new_today`, their limit `quota.limit`;
  `quota.burst` when it was many in a short time). Use what you got. Then tell the user in one line
  why they were asked. Until the notice is gone, leases and task sessions do not answer for you,
  and a plan starts no session: each request waits for the user.
- **`paused`**: the phone refused at once. With `quota`, you went above 25 new items in 24 hours;
  without it, the user paused you. Stop, tell the user why, and that they can resume you under
  Agents in Nodkey.
- Do not retry in a loop, and do not go through accounts one by one to find the right one. Ask
  for fewer items: reuse the login you already have for a site, ask `list_accounts` once when you
  need to know which accounts exist, and ask the user which account to use when you are not sure.
- The command line exits with 4 when you are paused.

## Pay for something (spends the user's money)

Only when the user asked you to buy this exact thing. Every payment shows the shop and the amount on
their iPhone and needs Face ID; there is no "always allow" for cards.

- In a browser host that fills cards (Horizon, or the Nodkey browser extension), let it fill the
  checkout form: the card number never enters the conversation, and the host checks the total on
  the page. You get only `filled: Visa ····4242 ..., at most 499.00 NOK`.
- Otherwise `request_payment(merchant, amount, currency, reason, image_path)`: `amount` is the exact
  total the checkout page shows (with a screenshot of it as `image_path`). The answer has the full
  `card`; fill it straight into the payment form and never repeat it. It works only when the user
  turned full card numbers on for you; `reveal_off` means it is off: tell them, do not retry.
- `over_limit`: the amount is above the user's limit for you. Stop and tell them. **Never split a
  purchase into smaller ones** to get under a limit, and never pay more than the approved amount.
- One approval pays one purchase. For the next one, ask again.

## API keys and secrets

Nodkey keeps API keys and tokens with a service (`openai.com`), an environment variable name
(`OPENAI_API_KEY`) and the projects they belong to ("Sparrow", "Otter"). A key without projects is
**global**: every project may use it. The phone gives the key of the asked project, else the
global key with that name. The user approves every key with Face ID; there is no "always allow"
for keys.

1. **A repository that needs keys gets a `.nodkey` file** at its root, with names only (never a
   value), so it is safe to commit, also in a public repository:

   ```toml
   project = "sparrow"
   secrets = ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "global/GITHUB_TOKEN"]
   ```

   `project` is the repository's name in Nodkey (ask the user, or take the repository's name);
   `global/NAME` takes only the global key. Make the file when a task needs keys and it is missing,
   and add a name when the code reads a new key. Never put a value, a `.env` line or a comment with
   a key into it.
2. **Use the keys without seeing them** (preferred): run the command with the keys in its
   environment. In the repository (or any folder below it):

   ```sh
   nodkey run --reason "Run the tests that call the OpenAI API" -- npm test
   nodkey run --secret EXAMPLE_TOKEN=api.example.com --reason "Deploy the preview" -- ./deploy.sh
   nodkey run --project otter --secret OPENAI_API_KEY --reason "Try the Otter prompt" -- python try.py
   ```

   It asks for every key of the nearest `.nodkey` file (up to the repository root or the home
   folder; one the user does not own is ignored) in one request (one Face ID; the user sees
   "wants 3 keys from Sparrow", and the reason names the file). `--secret NAME[=SERVICE]` adds a key (`=SERVICE` helps the phone
   find it; `global/NAME` takes only the global key); `--project NAME` asks in another project
   (`global`: only global keys). On stderr nodkey says which key it got ("OPENAI_API_KEY from
   Sparrow, GITHUB_TOKEN (global)"). The command's output and exit code are its own; nodkey never
   prints a key. When the phone refuses, the command does not run (exit 2 denied, 3 expired, 4
   paused).
3. **Only when no command can take it from the environment:** `request_secret(variable, service,
   project, reason)` returns the value. Pass the `project` of the `.nodkey` file. Use it once, for
   that task only; never write it anywhere.
4. **You made a new key** (for example in a provider's dashboard): save it at once with
   `save_secret(variable, service, value, projects, reason)` (`projects`: the `.nodkey` project, or
   none for a global key), then use it with `nodkey run`. On the command line: `printf %s "$KEY" |
   nodkey secret save NAME --service HOST --reason TEXT` (the value comes from stdin, never from
   the arguments; in a folder with a `.nodkey` file the key belongs to its project unless you pass
   `--project NAME` or `--project global`). A key with the same service, variable name and projects
   gets the new value.
5. `no_secret`: the user says Nodkey has no such key. Ask them to add it under Passwords, Keys in
   Nodkey (in the right project); do not ask them to paste it into the chat.
6. In a plan, add a key as `{"kind": "secret", "target": "sparrow/OPENAI_API_KEY"}` (or
   `openai.com/OPENAI_API_KEY`, `global/NAME`). With a session, the plan item carries no value,
   and later `nodkey run` calls for that key go through without asking.
7. `list_accounts` shows the key names (`secrets`) with their projects; never a value.

Keys count toward the limit on new items, like logins.

## A two-step code only

`request_code(target, reason)` when a CLI, portal or API asks for a one-time code. Use it at once;
it is valid for `seconds_left` more seconds.

## Which accounts exist

`list_accounts(reason)` returns issuer, account name, site and whether each has a code or a
password; never a secret. It needs the user's approval too, so use it only when they ask, or as the first
step of a clean-up they asked for.

## Tidy up saved logins

The user can ask you to clean up their saved passwords ("old IP addresses can go", "remove
alex@old-company.example", "go through everything and suggest rules"). Matches go to Recently
deleted on the phone (restorable for 30 days), never away for good, and nothing moves until they see
the list and confirm with Face ID.

1. **Look first, without names** (when they ask you to go through everything):
   `cleanup_insights("Suggest clean-up rules")`. You get totals, age buckets, counts for IP addresses
   and test hosts, and anonymous groups (`d_…` logins sharing a site, `u_…` sharing a user name) with
   counts and years; never a site or user name. Use `list_accounts` only if the user asks for names.
2. **Propose rules in chat**, each with its count, narrowest first, describing groups by their numbers
   ("a site with 47 logins, none used since 2019", "one e-mail address used on 29 sites"). Good
   rules: logins for IP addresses and `localhost` (routers, printers, dev servers: `ip_only`); an old
   employer's or school's domain (`domain`); an old e-mail address as user name (`username`); test and
   staging hosts (`query` like `*staging*`, `*.test`, `*.local`); sites that no longer exist; logins
   never used since a date (`last_used_before`, only when they talk about age). Duplicates of the same
   site and user are already merged by Nodkey; do not propose them.
3. **Wait for the user to pick.** Then call `cleanup_logins(filter, reason)` once per rule they chose; at
   least one criterion per filter; for a group use `{"group": "d_…"}`. The phone shows them the real
   site or user name. Do not bundle unrelated criteria.
4. **Report** in one line per rule: how many were moved (`moved`) and, if few, which sites. `moved: 0`
   means nothing matched.

Never propose a clean-up on your own initiative, and never call `cleanup_logins` for a rule the user
did not choose.

## Pairing

Each agent pairs once, with its own name ("Claude Code @ my-laptop", "Codex @ my-laptop"), so the
user can pause or remove one agent without the others. Do it when a tool says this agent is not
paired, or when the user asks: `pair` gives a code they type under Agents → Add agent in Nodkey; call
`pair` again with the code, then show them the check number and ask whether their iPhone shows the
same number. Call `pair` with the code and `confirm: true` only when they say it is the same; with
`confirm: false` when it is not (nothing is saved then; tell them to cancel on the iPhone too).
Never confirm for the user. `list_phones` shows the paired phones; `unpair` leaves one.

## Without MCP: the nodkey command

When the MCP tools are not available but the `nodkey` command is, use it the same way. It asks as
the agent whose shell runs it (Claude Code or Codex, so the same identity as your MCP tools), else as
"Terminal @ <computer>"; `--agent NAME` or `NODKEY_AGENT` names another. Use your own identity: do
not pass another agent's name. The user pairs it once with `nodkey pair`
(it shows the code, waits, shows the check number and asks the user to type `y` when their iPhone
shows the same number; run it in the user's own terminal).

```sh
nodkey code github.com/alex --reason "Merge PR #42" --field code      # prints only the code
nodkey login vg.no --reason "Check the subscription page"              # JSON with username, password
nodkey credentials login:chatgpt.com code:github.com/alex --session 30 --reason "Compare the notes"   # a plan
nodkey end-session                                                     # the task is done
nodkey accounts --reason "See which accounts I may ask for"
nodkey insights
nodkey cleanup --ip-only --reason "Remove logins for old router addresses"
nodkey cleanup --query '*.old-company.example' --last-used-before 2022-01-01 --reason "Old employer"
nodkey pay shop.example.com 499 NOK --reveal --reason "Buy the cable you asked for"   # full card (JSON)
nodkey suggest example.com --kind federated --provider google --reason "Signed in with Google"
nodkey sms-code account.example.com --reason "The site sent a code by SMS" --field code
nodkey run --secret OPENAI_API_KEY --reason "Run the API tests" -- npm test   # the key only in the command's environment
printf %s "$NEW_KEY" | nodkey secret save NEW_KEY --service example.com --reason "Save the key I made"
nodkey phones; nodkey unpair PHONE
```

Exit codes: 0 approved or queued, 2 denied or rejected, 3 expired, 4 paused, 1 error, 64 bad arguments; for `pay` also 5 over the
user's limit, 6 full card numbers off, 7 cards off or no card. `nodkey run` exits with the command's own code once it ran. Waiting notes go to stderr.
Never put a password on a command line, in a file or in a pipe you log; read it from the JSON and fill
it straight into the field that needs it. `--image FILE`, `--model` and `--effort` work as in the tools.

## Setting up

Install `nodkey` (one binary; see its README), then run `nodkey setup`. It adds the MCP server
`nodkey mcp --agent <name>` to Claude Code, Codex, Cursor and Claude Desktop when they are installed,
and writes this skill to `~/.claude/skills`, `~/.codex/skills` and `~/.agents/skills`.
`nodkey setup --remove` takes both away again. Any other MCP client: run `nodkey mcp --agent NAME` as
a stdio server and give the agent this file as instructions.
