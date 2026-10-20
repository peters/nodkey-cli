//! The MCP tool definitions.

use serde_json::{Value, json};

pub const TOOL_NAMES: [&str; 16] = [
    "pair",
    "list_phones",
    "unpair",
    "request_code",
    "request_login",
    "request_credentials",
    "request_sms_code",
    "request_secret",
    "save_secret",
    "suggest_sign_in_method",
    "end_session",
    "request_payment",
    "list_accounts",
    "cleanup_insights",
    "cleanup_logins",
    "import_file",
];

const APPROVAL: &str = "The user approves or denies every request on their iPhone, so this call can wait up to \
2 minutes for them.";

const MATCH: &str = "account.sites lists more websites the account is used on; match says how the phone found \
it: direct (its site), alias (one of its extra websites) or chosen (it is not saved for the site you asked for, and \
the user picked it by hand for that site). fill_only_on lists where you may fill it: only on a page whose host is \
one of those sites or below one. Check the address bar before you fill; if the page is elsewhere, stop and tell \
the user.";

const METHOD: &str = "When the phone knows how the user signs in to the site, the result has method (kind: \
password, federated = \"Sign in with\" a provider, passkey, email_code, sso or sms; provider; certainty) and, for \
federated, via: the provider login (for example the Google login) with its own fill_only_on: the provider's \
sign-in hosts (accounts.google.com for Google). Fill via ONLY there, never on the target site. second_step says which second step to choose (prefer) and which to \
avoid; the message says how.";

/// The tool definitions.
pub fn tools() -> Value {
    let phone = json!({
        "type": "string",
        "description": "Optional phone_id or name from list_phones; defaults to the most recently paired phone."
    });
    let image = json!({
        "type": "string",
        "description": "Optional absolute path to a PNG, JPEG or GIF (at most 1 MiB), for example a browser \
                        screenshot of the sign-in page you are about to use. It is encrypted to the phone and \
                        shown in the user's notification so they can see what they approve."
    });
    let target = json!({
        "type": "string",
        "description": "The website you are about to sign in to: the host of that page (look at the address \
                        bar), optionally followed by /account, e.g. \"github.com\", \"github.com/alex\" or \
                        \"accounts.example.com\". The phone matches its registrable domain against the sites the \
                        user saved. A bare name such as \"GitHub\" works too, but the user must then check it on \
                        the phone every time (no lease or task session answers it)."
    });
    let model = json!({
        "type": "string",
        "description": "Optional: the model you run on, e.g. \"claude-opus-5-5\". Shown in the user's history so they can \
                        trace who asked."
    });
    let effort = json!({
        "type": "string",
        "description": "Optional: your reasoning effort setting, e.g. \"high\". Shown in the user's history."
    });
    let reason = json!({
        "type": "string",
        "description": "Why you need it, in one short concrete sentence the user reads on their lock screen, e.g. \
                        \"Sign in to GitHub to merge PR #42\". Explain the reason honestly; vague reasons get denied."
    });
    json!([
        {
            "name": "request_code",
            "title": "Ask the user's iPhone for a one-time code",
            "description": format!("Ask Nodkey on the user's iPhone for one current one-time code (TOTP) for an account. \
                {APPROVAL} Always explain the reason. Returns JSON with decision (approved, denied or expired) and, \
                when approved, code and seconds_left. Use the code at once; never store or log it. {MATCH} The result may \
                carry second_step (which second step to choose)."),
            "inputSchema": {
                "type": "object",
                "properties": { "target": target, "reason": reason, "image_path": image, "phone": phone, "model": model, "effort": effort },
                "required": ["target", "reason"],
                "additionalProperties": false
            },
            "annotations": { "readOnlyHint": true, "openWorldHint": true }
        },
        {
            "name": "request_login",
            "title": "Ask the user's iPhone for a login",
            "description": format!("Ask Nodkey on the user's iPhone for the user name and password of an account (and a \
                one-time code when the login has one). {APPROVAL} Always explain the reason. Returns JSON with decision \
                and, when approved, username, password and possibly code. Use them only for this sign-in; never store, \
                log or repeat the password. {MATCH} {METHOD}"),
            "inputSchema": {
                "type": "object",
                "properties": { "target": target, "reason": reason, "image_path": image, "phone": phone, "model": model, "effort": effort },
                "required": ["target", "reason"],
                "additionalProperties": false
            },
            "annotations": { "readOnlyHint": true, "openWorldHint": true }
        },
        {
            "name": "request_credentials",
            "title": "Ask the user's iPhone for everything a task needs, once",
            "description": format!("Ask Nodkey on the user's iPhone for everything one task needs in one request: up to 10 \
                logins, one-time codes and (with session_minutes) passkeys. Plan first: list every site the task signs in \
                to and ask once, instead of one request per thing. The user sees every item, can leave some out or pick \
                another account, and approves once with Face ID. {APPROVAL} Always explain the reason. With \
                session_minutes (15, 30 or 60) the approval starts a task session: until it ends, request_code, \
                request_login and passkey sign-ins for the approved items go through without asking again (for a fresh \
                code, or after the site logged you out); call end_session when the task is done. Returns JSON with \
                decision (approved when at least one item was approved), approved and of (counts), session (id, until) \
                when one started, and items: one per item in your order with id, kind, target, decision and, when \
                approved, username and password (logins), code and seconds_left (codes), account, match and \
                fill_only_on (fill the item only on a page whose host is one of those sites or below one). Use each \
                item only for its own sign-in; never store, log or repeat the secrets. Name each site by the host of \
                its sign-in page: a task session answers only requests for the approved items' own websites."),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "items": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 10,
                        "description": "What the task needs, in order.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "kind": { "type": "string", "enum": ["login", "code", "secret", "passkey"], "description": "login: user name and password (and a code when it has one); code: one one-time code; secret: an API key (target = its service, its variable name, service/VARIABLE, project/VARIABLE or global/VARIABLE, e.g. openai.com/OPENAI_API_KEY or sparrow/OPENAI_API_KEY; with session_minutes it carries no value, and later nodkey run --secret calls for it go through); passkey (only with session_minutes): later passkey sign-ins on that site (target = the site, e.g. github.com) go through in the session." },
                                "target": target
                            },
                            "required": ["kind", "target"],
                            "additionalProperties": false
                        }
                    },
                    "reason": reason,
                    "session_minutes": {
                        "type": "integer",
                        "enum": [15, 30, 60],
                        "description": "Optional: start a task session of this many minutes. Pick by the job: 15 for a few \
                                        sign-ins, 30 for a normal task, 60 only for long work. The user may change it."
                    },
                    "follow_up_seconds": {
                        "type": "integer",
                        "minimum": 120,
                        "maximum": 600,
                        "description": "Optional: for how many seconds after the approval a fresh code for an approved item \
                                        may be fetched with request_code without asking again (default 120). Ask for more only \
                                        when the task really takes longer."
                    },
                    "image_path": image,
                    "phone": phone,
                    "model": model,
                    "effort": effort
                },
                "required": ["items", "reason"],
                "additionalProperties": false
            },
            "annotations": { "readOnlyHint": true, "openWorldHint": true }
        },
        {
            "name": "request_sms_code",
            "title": "Ask the user's iPhone for a code the site sent by SMS",
            "description": format!("Ask Nodkey on the user's iPhone for a sign-in code that the site sends only by SMS. \
                Use it only when the site offers no passkey and no authenticator code (prefer request_code). Click the \
                site's \"Send code\" first, then call this at once: the user's Shortcuts automation passes the SMS to \
                Nodkey. {APPROVAL} The call waits up to wait_seconds plus 60 seconds. Always explain the reason. Returns \
                JSON with decision (approved, denied or expired) and, when approved, code. Type the code at once; \
                never store or log it. On expired, ask the user to type the code; do not loop."),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "The site that sent the SMS, e.g. \"account.example.com\"." },
                    "reason": reason,
                    "wait_seconds": { "type": "integer", "minimum": 30, "maximum": 300, "description": "Optional: how long the phone waits for the SMS (default 120)." },
                    "image_path": image, "phone": phone, "model": model, "effort": effort
                },
                "required": ["target", "reason"],
                "additionalProperties": false
            },
            "annotations": { "readOnlyHint": true, "openWorldHint": true }
        },
        {
            "name": "request_secret",
            "title": "Ask the user's iPhone for an API key",
            "description": format!("Ask Nodkey on the user's iPhone for an API key or other secret, by its variable \
                name (e.g. OPENAI_API_KEY), its service (e.g. openai.com) or both. Prefer the command line instead: \
                `nodkey run --secret OPENAI_API_KEY -- <command>` (or just `nodkey run -- <command>` in a repository \
                with a .nodkey file) puts the key only into that command's environment, so it never enters this \
                conversation. Use this tool only when no command can take the key that way. The user approves with \
                Face ID every time; there is never an \"always allow\". {APPROVAL} Always explain the reason. Returns \
                JSON with decision and, when approved, secret (title, service, variable, value, expires, from: \
                project or global, project). Never put the value in a file, a commit, a chat message or a log, and \
                never repeat it. error no_secret: the user says Nodkey has no such key."),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "variable": { "type": "string", "description": "The environment variable name of the key, e.g. \"OPENAI_API_KEY\"." },
                    "service": { "type": "string", "description": "The service the key is for, as a host, e.g. \"openai.com\"." },
                    "project": { "type": "string", "description": "Optional: the project the key is for, e.g. \"sparrow\" (the project of the repository's .nodkey file). The phone gives that project's key, else the global one. \"global\" or none: only a global key." },
                    "reason": reason, "image_path": image, "phone": phone, "model": model, "effort": effort
                },
                "required": ["reason"],
                "additionalProperties": false
            },
            "annotations": { "readOnlyHint": true, "openWorldHint": true }
        },
        {
            "name": "save_secret",
            "title": "Save a new API key in Nodkey",
            "description": format!("Save an API key or other secret in Nodkey on the user's iPhone. Call it at once \
                after you made a new key (for example in a provider's dashboard), so the key never stays in a file or \
                in this conversation. The value is encrypted to the phone at once; the user sees the title, service \
                and variable name (never the value) and saves it with Face ID. A key with the same service, \
                variable name and projects gets the new value; else a new key is added. {APPROVAL} Returns JSON with \
                decision and saved (added, updated or unchanged). After that, use the key with `nodkey run --secret \
                VARIABLE -- <command>` and do not keep the value anywhere else."),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "variable": { "type": "string", "description": "The environment variable name, e.g. \"OPENAI_API_KEY\"." },
                    "service": { "type": "string", "description": "Optional: the service the key is for, as a host, e.g. \"openai.com\"." },
                    "value": { "type": "string", "description": "The key itself (at most 1500 bytes)." },
                    "title": { "type": "string", "description": "Optional: a name for the key, e.g. \"OpenAI test project\"." },
                    "notes": { "type": "string", "description": "Optional: a short note, e.g. what the key may do." },
                    "expires": { "type": ["integer", "string"], "description": "Optional: when the key stops working (YYYY-MM-DD or Unix seconds)." },
                    "projects": { "type": "array", "items": { "type": "string" }, "description": "Optional: the projects the key is for, e.g. [\"sparrow\"] (the project of the repository's .nodkey file). None: a global key every project may use." },
                    "reason": reason, "phone": phone, "model": model, "effort": effort
                },
                "required": ["variable", "value", "reason"],
                "additionalProperties": false
            },
            "annotations": { "readOnlyHint": false, "destructiveHint": false, "idempotentHint": true, "openWorldHint": true }
        },
        {
            "name": "suggest_sign_in_method",
            "title": "Suggest a sign-in method for a site",
            "description": "Propose how the user signs in to a site, for their suggestion list in Nodkey; they accept it \
                with one tap. No Face ID and nothing secret; the phone answers at once. Send one after you signed in \
                with a method the phone did not know (outcome signed_in), or when the known method failed (outcome \
                failed; then also suggest the one that worked). At most 5 per hour. Returns JSON with decision queued \
                (in the list) or rejected (with error, e.g. rate_limited); do not retry a rejected one.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "The site, e.g. \"example.com\" (a URL is cut down to its host)." },
                    "kind": { "type": "string", "enum": ["password", "federated", "passkey", "email_code", "sso", "sms"], "description": "How you signed in: federated is \"Sign in with\" a provider." },
                    "provider": { "type": "string", "description": "federated only: google, apple, github, microsoft, facebook, or the provider's own name (e.g. Okta)." },
                    "mailbox": { "type": "string", "description": "email_code only, optional: the address the code went to." },
                    "outcome": { "type": "string", "enum": ["signed_in", "failed"], "description": "signed_in: you signed in with it; failed: you tried it and it did not work." },
                    "reason": { "type": "string", "description": "One short sentence for the user, e.g. \"Signed in with Google; Nodkey had no method for this site\"." },
                    "phone": phone, "model": model, "effort": effort
                },
                "required": ["target", "kind", "outcome", "reason"],
                "additionalProperties": false
            },
            "annotations": { "readOnlyHint": false, "destructiveHint": false, "idempotentHint": false, "openWorldHint": true }
        },
        {
            "name": "end_session",
            "title": "End the task session",
            "description": "End the task session that request_credentials with session_minutes started, when the \
                task is done, so later requests ask the user again. Answered at once; the user is not asked. Returns \
                JSON with ended and a message.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "reason": { "type": "string", "description": "Optional: one short sentence, e.g. \"The upload is done\"." },
                    "model": model,
                    "effort": effort
                },
                "additionalProperties": false
            },
            "annotations": { "readOnlyHint": false, "idempotentHint": true, "openWorldHint": true }
        },
        {
            "name": "request_payment",
            "title": "Spend the user's money: ask their iPhone for a payment card",
            "description": format!("Spends the user's money. Asks Nodkey on the user's iPhone for the full payment card \
                (number, expiry, CVC) to pay ONE purchase of an exact amount at one shop. Use it only when the user asked \
                you to buy this exact thing. The user sees the shop and the amount and approves with Face ID every time; \
                there is never an \"always allow\". The phone refuses at once (decision denied, error over_limit) when the \
                amount is above the user's limit for you: never split a purchase to get under it. Full card numbers are \
                off for every agent until the user turns them on (error reveal_off); a browser that fills cards for you \
                (Horizon, or the Nodkey browser extension) is better, because the number then never enters this \
                conversation. Only a purchase with an amount: adding a card to a site for later payments (no amount) is for \
                the user's browser, never for you, so never make up an amount for it. {APPROVAL} Always explain the reason: what you buy and why. Returns JSON with decision and, when approved, card (title, brand, last4, \
                number, exp_month, exp_year, cvc). Use the card only for this purchase and never pay more than amount; \
                never store, log or repeat the card details."),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "merchant": { "type": "string", "description": "The shop's site, e.g. \"shop.example.com\"." },
                    "amount": { "type": ["string", "number"], "description": "The total you will pay, with the decimals the shop shows, e.g. \"499.00\". No thousands separators." },
                    "currency": { "type": "string", "description": "Three-letter currency code, e.g. \"NOK\", \"EUR\" or \"USD\"." },
                    "reason": {
                        "type": "string",
                        "description": "What you are buying and why, in one short sentence the user reads on their iPhone, e.g. \
                                        \"Buy the 2 m USB-C cable you asked for\"."
                    },
                    "image_path": {
                        "type": "string",
                        "description": "Optional absolute path to a PNG, JPEG or GIF (at most 1 MiB): a screenshot of the checkout \
                                        page with the total, shown to the user on their iPhone."
                    },
                    "phone": phone,
                    "model": model,
                    "effort": effort
                },
                "required": ["merchant", "amount", "currency", "reason"],
                "additionalProperties": false
            },
            "annotations": { "readOnlyHint": false, "destructiveHint": true, "idempotentHint": false, "openWorldHint": true }
        },
        {
            "name": "cleanup_insights",
            "title": "Get anonymous clean-up insights from the user's iPhone",
            "description": format!("Ask Nodkey on the user's iPhone for clean-up insights without any identifying data: \
                totals, how long ago logins were used, how many are for IP addresses or test hosts, and anonymous \
                groups of logins that share a site (d_…) or a user name (u_…) with counts and years. You never learn \
                which site or user name a group is. {APPROVAL} Prefer this over list_accounts when the user asks you to \
                tidy up. Propose rules from the numbers; to act on a group, call cleanup_logins with {{\"group\": \"d_…\"}}."),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "reason": { "type": "string", "description": "Optional reason shown to the user." },
                    "phone": phone,
                    "model": model,
                    "effort": effort
                },
                "additionalProperties": false
            },
            "annotations": { "readOnlyHint": true, "openWorldHint": true }
        },
        {
            "name": "list_accounts",
            "title": "List the accounts this agent may ask for",
            "description": format!("Ask Nodkey on the user's iPhone which accounts this agent may ask for (issuer, account \
                name, site, whether it has a code or password; no secrets) and, as secrets, the names of the API keys it \
                may ask for (title, service, variable; never a value). {APPROVAL} Pass a reason if the user's task \
                gives one."),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "reason": { "type": "string", "description": "Optional reason shown to the user." },
                    "phone": phone,
                    "model": model,
                    "effort": effort
                },
                "additionalProperties": false
            },
            "annotations": { "readOnlyHint": true, "openWorldHint": true }
        },
        {
            "name": "cleanup_logins",
            "title": "Propose moving old saved logins to Recently deleted",
            "description": "Propose a clean-up of the user's saved logins (passwords) in Nodkey on their iPhone: the logins \
                that match the filter would move to Recently deleted. Nothing happens until the user has seen the list on their \
                iPhone and confirmed with Face ID; nothing is deleted for good (Recently deleted keeps them 30 days and they can \
                restore them). Every criterion you set must hold, and at least one is required. Examples: {\"ip_only\": true} \
                for logins saved for IP addresses such as 192.168.1.1 or 10.0.0.138:8080 (routers, printers); \
                {\"username\": \"alex@old-company.example\"} for one old user name; {\"domain\": \"old-company.example\"} \
                for a site and its subdomains; {\"ip_only\": true, \"last_used_before\": \"2024-01-01\"} to combine. \
                The call can wait up to 2 minutes. Returns JSON with decision (approved, denied or expired) and, when \
                approved, moved (how many) and accounts (title, user name and site of each moved login; never a password). \
                moved 0 means nothing matched.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "filter": {
                        "type": "object",
                        "description": "Which saved logins: every criterion you set must hold; at least one is required.",
                        "properties": {
                            "query": { "type": "string", "description": "Wildcard search over site, address, title and user name: * is any text, ? one character; without a wildcard it means contains. E.g. \"*.old-company.example\"." },
                            "username": { "type": "string", "description": "The user name exactly (case-insensitive), or a wildcard pattern like \"alex.old@*\"." },
                            "domain": { "type": "string", "description": "A domain; its subdomains match too (\"old-company.example\" also takes \"mail.old-company.example\")." },
                            "ip_only": { "type": "boolean", "description": "true: only logins whose site is an IPv4 or IPv6 address (with or without port), localhost or a .local name." },
                            "last_used_before": { "type": ["integer", "string"], "description": "Last used before this time (Unix seconds or YYYY-MM-DD); never used counts as before." },
                            "added_before": { "type": ["integer", "string"], "description": "Saved before this time (Unix seconds or YYYY-MM-DD)." },
                            "password_changed_before": { "type": ["integer", "string"], "description": "Password last changed before this time (Unix seconds or YYYY-MM-DD)." },
                            "never_used": { "type": "boolean", "description": "true: only logins never used from Nodkey (never copied or handed to an agent)." },
                            "group": { "type": "string", "description": "An anonymous group id from cleanup_insights (d_… a site, u_… a user name); the phone resolves it and the user sees the real name." }
                        },
                        "additionalProperties": false
                    },
                    "reason": {
                        "type": "string",
                        "description": "Why, in one short sentence the user reads on their iPhone, e.g. \"Remove logins for old router addresses\"."
                    },
                    "phone": phone,
                    "model": model,
                    "effort": effort
                },
                "required": ["filter", "reason"],
                "additionalProperties": false
            },
            "annotations": { "readOnlyHint": false, "destructiveHint": true, "idempotentHint": false, "openWorldHint": true }
        },
        {
            "name": "import_file",
            "title": "Send a password or code export to the user's iPhone for review",
            "description": "Send one export file (passwords from Chrome, Firefox, Safari, Bitwarden, 1Password and other \
                password managers, or codes from a code app) to the import window the user opened in Nodkey on their \
                iPhone (Settings \u{2192} Import \u{2192} \"From your computer, with an agent\"). NEVER read, open, print, \
                copy, list or summarise the export yourself, not even to check it: pass only its path; this tool reads \
                it. The file is encrypted to the phone, staged there for the user's review (they add everything with one \
                Face ID at the end), and then deleted from this computer unless keep is true. You never get a password or \
                code back. Returns JSON with decision staged and import (found, new, merged, duplicates, conflicts, \
                skipped: counts against the files sent in this window, never against the vault), or an error: \
                import_closed (ask the user to open the window, then send again), window_full (20 files), too_large \
                (more than 1 MiB), import_unreadable (export again as plain CSV or plain text, without a password), \
                no_passcode or paused; expired means Nodkey was not open (ask the user to keep it open on the \
                import screen, then send again). deleted says whether the export is gone; still_at says where it is when it is not. \
                dry_run: true sends nothing and returns the format and counts per type. Follow the nodkey-move-in skill.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Absolute path of the export file, e.g. the CSV the browser saved in Downloads (a leading ~/ means the home folder)." },
                    "source": { "type": "string", "description": "Optional short label the user sees in the list, at most 80 characters, e.g. \"Chrome, profile Default\" or \"Bitwarden\". Default: the app nodkey recognises from the file." },
                    "reason": { "type": "string", "description": "Optional sentence for the user's history, e.g. \"Move the passwords saved in Firefox into Nodkey\"." },
                    "keep": { "type": "boolean", "description": "Optional: true leaves the export on this computer after the phone staged it. Default false: it is overwritten and deleted." },
                    "dry_run": { "type": "boolean", "description": "Optional: true only reads the file and returns its format and counts (logins, codes, skipped rows); nothing is sent." },
                    "phone": phone,
                    "model": model,
                    "effort": effort
                },
                "required": ["path"],
                "additionalProperties": false
            },
            "annotations": { "readOnlyHint": false, "destructiveHint": true, "idempotentHint": false, "openWorldHint": true }
        },
        {
            "name": "pair",
            "title": "Pair with Nodkey on the user's iPhone",
            "description": "Pair this agent with Nodkey on the user's iPhone; needed once per agent before the other tools work. \
                Step 1: call without code. It returns a 6-character code like K7P-2QX; show it to the user and ask them to \
                type it in Nodkey under Agents (valid 5 minutes). Step 2: call again with that code. It waits up to 5 \
                minutes for their phone and returns the phone name and a check number such as 418 902. Show the number \
                and ask the user whether their iPhone shows the same number. Step 3: call again with the code and \
                confirm: true only when the user says it is the same (the pairing is saved then), or confirm: false \
                when it is not. Never confirm for the user. The user also confirms the number on their iPhone.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Optional name the user sees for this agent (step 1). The default is the agent and the computer, e.g. \"Claude Code @ my-laptop\"; give a name only when the user asks for one."
                    },
                    "code": {
                        "type": "string",
                        "description": "The code from step 1: to wait for the phone and get the check number (step 2), and with confirm (step 3)."
                    },
                    "confirm": {
                        "type": "boolean",
                        "description": "Step 3: true when the user says their iPhone shows the same check number, false when it does not."
                    }
                },
                "additionalProperties": false
            },
            "annotations": { "readOnlyHint": false, "destructiveHint": false, "openWorldHint": true }
        },
        {
            "name": "list_phones",
            "title": "List paired phones",
            "description": "List the phones this agent is paired with (name, phone_id, check number, scope). Local; does not contact the phone.",
            "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false },
            "annotations": { "readOnlyHint": true, "openWorldHint": false }
        },
        {
            "name": "unpair",
            "title": "Leave a paired phone",
            "description": "Leave a paired phone: tells the relay this agent leaves (the phone then drops it) and forgets the phone on this computer.",
            "inputSchema": {
                "type": "object",
                "properties": { "phone": { "type": "string", "description": "phone_id or name from list_phones." } },
                "required": ["phone"],
                "additionalProperties": false
            },
            "annotations": { "readOnlyHint": false, "destructiveHint": true, "openWorldHint": true }
        }
    ])
}
