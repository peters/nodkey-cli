//! The text of `nodkey --help`.

pub const USAGE: &str = "\
nodkey: ask Nodkey on your iPhone for one-time codes and logins

Usage:
  nodkey pair [--name NAME]                pair this agent with your iPhone (once)
  nodkey code TARGET --reason TEXT         one one-time code
  nodkey login TARGET --reason TEXT        user name and password (and a code if it has one)
  nodkey credentials ITEM... --reason TEXT up to 10 logins and codes in one request (JSON);
                                           ITEM is login:TARGET, code:TARGET, secret:TARGET or
                                           passkey:SITE (passkey items need --session)
  nodkey end-session [--reason TEXT]       end this agent's task session (from --session)
  nodkey sms-code TARGET --reason TEXT [--wait SECS] [--image FILE]
                                           a code the site sent by SMS, passed to Nodkey by your
                                           Shortcuts automation (wait 30-300 s, default 120)
  nodkey suggest SITE --kind KIND [--provider NAME] [--mailbox ADDR] [--outcome failed]
                   --reason TEXT           propose a sign-in method for your suggestion list
                                           (KIND: password, federated, passkey, email_code, sso,
                                           sms; no Face ID, nothing secret)
  nodkey pay MERCHANT AMOUNT CURRENCY --reason TEXT --reveal
                                           the full payment card for ONE purchase (spends money;
                                           only when the user turned full card numbers on for
                                           this agent); e.g. nodkey pay shop.example.com 499 NOK
  nodkey run [--secret NAME[=SERVICE]]... [--project NAME] [--reason TEXT] -- COMMAND [ARGS]
                                           run COMMAND with API keys from Nodkey in its
                                           environment (NAME is the variable, e.g.
                                           OPENAI_API_KEY); the keys are never printed
  nodkey secret save NAME [--service HOST] [--project NAMES] [--title TEXT] [--notes TEXT]
                   [--expires DATE] --reason TEXT
                                           save a key you made in Nodkey; the key itself comes
                                           from stdin, never from the arguments
  nodkey accounts [--reason TEXT]          the accounts this agent may ask for (no secrets),
                                           and the names of its keys
  nodkey insights [--reason TEXT]          anonymous clean-up numbers (JSON)
  nodkey cleanup FILTER... --reason TEXT   propose moving old saved logins to Recently deleted
  nodkey phones                            the phones this agent is paired with
  nodkey unpair PHONE                      leave a phone (phone name or id)
  nodkey agents                            the agents on this computer and where their keys are
  nodkey webauthn [--phone PHONE]          sign in with a passkey or make one, also with PRF: one
                                           JSON request on stdin, one JSON result on stdout (for
                                           browser hosts and scripts; nodkey webauthn --help)
  nodkey login-fill [--phone PHONE]        a login for a browser host to fill a sign-in form, so the
                                           password stays out of the agent's conversation: one JSON
                                           request on stdin, one JSON result on stdout
  nodkey card-fill --agent HOST [--phone PHONE]
                                           a card for a browser host to fill a checkout form, under
                                           the host's own profile (never an agent's): one JSON
                                           request on stdin, one JSON result on stdout
  nodkey mcp                               run the MCP server on stdio
  nodkey setup [--remove] [--dry-run]      add (or remove) the MCP server and skill in your agents
  nodkey skill                             print the agent skill

TARGET is a site or issuer, optionally with /account: github.com/alex, vg.no, GitHub.

Options for code and login:
  --reason TEXT    why, in one sentence; shown on your lock screen (required)
  --image FILE     a PNG, JPEG or GIF (at most 1 MiB) shown in the notification
  --field NAME     print only this field (code, username, password, seconds_left, ...)
  --phone PHONE    which phone, when this agent is paired with more than one
  --model NAME     --effort LEVEL   shown in the history on the phone

Options for credentials: --reason, --image, --phone, --model, --effort as above, and
  --session MIN     a task session: for 15, 30 or 60 minutes, codes, logins and passkey
                    sign-ins for the approved items go through without asking again
  --follow-up SECS  without a session: how long a fresh code for an approved item follows
                    without asking (120-600)

Options for pay: --reason, --image, --field (number, cvc, exp_month, ...), --phone, --model,
  --effort as above, and --reveal (required: the card number is printed). Without a browser
  host nothing can fill the card for you; the user decides on the iPhone every time.

Options for run: --reason (default: \"Run COMMAND\"), --phone, --model, --effort as above.
  run asks for the keys the nearest .nodkey file lists (from this folder up to the repository
  root or your home folder; only a file you own that others cannot change), in its project:
      project = \"sparrow\"
      secrets = [\"OPENAI_API_KEY\", \"ANTHROPIC_API_KEY\", \"global/GITHUB_TOKEN\"]
  The file holds names only, so it is safe to commit. --secret adds a key (global/NAME: only
  the global key; PROJECT/NAME: another project's key); --project NAME asks in another project
  (global: only global keys). The phone gives the project's key, else the global one. One key is
  one request; several keys are one request with one approval (or, in a task session, one
  request each). The command's own exit code is passed on; when the phone refuses, nothing runs.

Options for secret save: --project NAMES (comma-separated; default: the .nodkey file's project;
  global: a key every project may use), --service, --title, --notes, --expires, --reason,
  --phone, --model, --effort.

Clean-up filter (every one you give must hold; at least one):
  --ip-only  --never-used  --query PATTERN  --username NAME  --domain DOMAIN  --group ID
  --last-used-before DATE  --added-before DATE  --password-changed-before DATE
  PATTERN and NAME take * and ?; DATE is YYYY-MM-DD or Unix seconds.

Global options:
  --agent NAME     which agent identity to use (also $NODKEY_AGENT; default: the agent whose
                   shell runs nodkey, Claude Code or Codex, else terminal)
  --relay URL      the relay (default: $NODKEY_RELAY, else relay in config.json, else
                   https://relay.nodkey.app)
  --json           print JSON for accounts, cleanup, phones, agents, unpair and pair
  -h, --help       -V, --version

Exit codes: 0 approved, queued or done, 1 error, 2 denied or rejected, 3 expired (no answer),
4 paused (the user or the agent limit paused this agent; resume it under Agents), 64 bad arguments;
pay and card-fill: 5 over the user's limit, 6 full card numbers off, 7 cards off or no card,
8 the page total is higher than the amount. run: the command's exit code once it ran (126 or
127 when it cannot start); 2, 3, 4 or 1 as above when the phone did not give the keys.
Environment: NODKEY_AGENT_DIR (default ~/.config/nodkey-agent), NODKEY_REQUEST_TIMEOUT (120 s),
NODKEY_PAIR_TIMEOUT (300 s), NODKEY_KEYSTORE (auto: the private keys in the keychain of the
system when there is one; file: in identity.json), NODKEY_DEBUG.
";
