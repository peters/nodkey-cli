//! The MCP tool definitions.

use serde_json::{Value, json};

pub const TOOL_NAMES: [&str; 10] = [
    "pair",
    "list_phones",
    "unpair",
    "request_code",
    "request_login",
    "request_credentials",
    "request_payment",
    "list_accounts",
    "cleanup_insights",
    "cleanup_logins",
];

const APPROVAL: &str = "The user approves or denies every request on their iPhone, so this call can wait up to \
2 minutes for them.";

const MATCH: &str = "account.sites lists more websites the account is used on; match says how the phone found \
it: direct (its name or site), alias (one of its extra websites) or chosen (nothing matched and the user picked it \
by hand).";

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
        "description": "The account: a site or issuer, optionally followed by /account, e.g. \"github.com/alex\", \
                        \"vg.no\" or \"GitHub\". The phone matches it against the user's accounts."
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
                when approved, code and seconds_left. Use the code at once; never store or log it. {MATCH}"),
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
                log or repeat the password. {MATCH}"),
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
            "title": "Ask the user's iPhone for several logins and codes at once",
            "description": format!("Ask Nodkey on the user's iPhone for up to 6 logins and one-time codes in one request, \
                when one task needs several (a login on one site and a code on another). The user sees every item, can \
                leave some out or pick another account, and approves once with Face ID. {APPROVAL} Always explain the \
                reason. Returns JSON with decision (approved when at least one item was approved), approved and of \
                (counts), and items: one per item in your order with id, kind, target, decision and, when approved, \
                username and password (logins), code and seconds_left (codes), account and match. Use each item only \
                for its own sign-in; never store, log or repeat the secrets. For a single login or code use \
                request_login or request_code."),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "items": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 6,
                        "description": "What you need, in order.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "kind": { "type": "string", "enum": ["login", "code"], "description": "login: user name and password (and a code when it has one); code: one one-time code." },
                                "target": target
                            },
                            "required": ["kind", "target"],
                            "additionalProperties": false
                        }
                    },
                    "reason": reason,
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
            "name": "request_payment",
            "title": "Spend the user's money: ask their iPhone for a payment card",
            "description": format!("Spends the user's money. Asks Nodkey on the user's iPhone for the full payment card \
                (number, expiry, CVC) to pay ONE purchase of an exact amount at one shop. Use it only when the user asked \
                you to buy this exact thing. The user sees the shop and the amount and approves with Face ID every time; \
                there is never an \"always allow\". The phone refuses at once (decision denied, error over_limit) when the \
                amount is above the user's limit for you: never split a purchase to get under it. Full card numbers are \
                off for every agent until the user turns them on (error reveal_off); a browser that fills cards for you \
                (Horizon, or the Nodkey browser extension) is better, because the number then never enters this \
                conversation. {APPROVAL} Always explain the reason: what you buy and why. Returns JSON with decision and, when approved, card (title, brand, last4, \
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
                name, site, whether it has a code or password; no secrets). {APPROVAL} Pass a reason if the user's task \
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
            "name": "pair",
            "title": "Pair with Nodkey on the user's iPhone",
            "description": "Pair this agent with Nodkey on the user's iPhone; needed once per agent before the other tools work. \
                Step 1: call without code. It returns a 6-character code like K7P-2QX; show it to the user and ask them to \
                type it in Nodkey under Agents (valid 5 minutes). Step 2: call again with that code. It waits up to 5 \
                minutes for their phone and returns the phone name and a check number such as 418 902; ask the user to \
                confirm their iPhone shows the same number. The user approves the pairing on their iPhone.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Optional name the user sees for this agent (step 1). The default is the agent and the computer, e.g. \"Claude Code @ my-laptop\"; give a name only when the user asks for one."
                    },
                    "code": {
                        "type": "string",
                        "description": "The code from step 1, to wait for the phone and finish pairing (step 2)."
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
