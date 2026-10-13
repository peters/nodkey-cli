---
name: nodkey
description: Use the user's logins, one-time codes and saved passwords from Nodkey on their iPhone, each request approved by them with Face ID; sign in to websites, fetch a two-step code, see which accounts exist, and tidy up old saved logins. Use when a task needs a login or a two-step code, when asked to sign in to a site (for example in a Horizon browser panel), when the user asks which accounts they have, or when they ask to clean up, review or remove stale or old saved passwords. Uses the nodkey MCP server (request_login, request_code, cleanup_insights, list_accounts, cleanup_logins, pair, list_phones, unpair) or the nodkey command.
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
  with "paused", the user has paused you (or all agents) under Agents in Nodkey: tell them, do not retry.
- One request per thing you need. Do not ask again in the same task unless the site logged you out.
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
3. `request_login(target, reason, image_path)`: `target` is the site (`vg.no`) or site/user
   (`github.com/alex`); `reason` is one plain sentence ("Check the subscription page").
4. On `approved`: fill user name and password (`browser_act` `fill`) and submit. If the site asks
   for a one-time code and the answer has `code` with `seconds_left` ≥ 5, use it; otherwise call
   `request_code(target, reason)`. For two minutes after the user approved, a `request_code` for the
   same account is answered without asking them again, so a code that expired while you typed costs
   nothing: just ask for a fresh one.
5. Check the result with a snapshot and report it in one line.

Tips from real sign-ins: when the answer's `account.site` names a different host than the page you
opened (payment.schibsted.no, not login.schibsted.com), sign in there; the saved login belongs to it.
When the answer says `match: "chosen"`, no saved account matched the site and the user picked
one by hand (a login saved for openai.com used on chatgpt.com); use it for this site as given.
`account.sites` lists more websites the account is used on. Two-step pages may split the code into one box per digit: fill them one by one. When a site offers an
app prompt instead of a code (Google, Microsoft), choose "another way" and the authenticator code.

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
`pair` again with the code to finish, then show them the check number and ask them to compare it with
their iPhone. A different number means someone swapped keys: `unpair` and tell them. `list_phones`
shows the paired phones; `unpair` leaves one.

## Without MCP: the nodkey command

When the MCP tools are not available but the `nodkey` command is, use it the same way. It pairs as
"Terminal @ <computer>" unless you pass `--agent NAME`; the user pairs it once with `nodkey pair`
(it shows the code, waits, then shows the check number; run it in the user's own terminal).

```sh
nodkey code github.com/alex --reason "Merge PR #42" --field code      # prints only the code
nodkey login vg.no --reason "Check the subscription page"              # JSON with username, password
nodkey accounts --reason "See which accounts I may ask for"
nodkey insights
nodkey cleanup --ip-only --reason "Remove logins for old router addresses"
nodkey cleanup --query '*.old-company.example' --last-used-before 2022-01-01 --reason "Old employer"
nodkey phones; nodkey unpair PHONE
```

Exit codes: 0 approved, 2 denied, 3 expired, 1 error, 64 bad arguments. Waiting notes go to stderr.
Never put a password on a command line, in a file or in a pipe you log; read it from the JSON and fill
it straight into the field that needs it. `--image FILE`, `--model` and `--effort` work as in the tools.

## Setting up

Install `nodkey` (one binary; see its README), then run `nodkey setup`. It adds the MCP server
`nodkey mcp --agent <name>` to Claude Code, Codex, Cursor and Claude Desktop when they are installed,
and writes this skill to `~/.claude/skills`, `~/.codex/skills` and `~/.agents/skills`.
`nodkey setup --remove` takes both away again. Any other MCP client: run `nodkey mcp --agent NAME` as
a stdio server and give the agent this file as instructions.
