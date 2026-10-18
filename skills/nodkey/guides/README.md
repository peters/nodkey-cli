# Provider guides

These guides tell an agent how to manage sign-in methods at the large sign-in providers. Each guide
gives exact page addresses and button names in English. Checked on 2026-10-18 against the
provider's own help pages.

| Provider | Guide |
| --- | --- |
| Google | [google.md](google.md) |
| Apple | [apple.md](apple.md) |
| Microsoft | [microsoft.md](microsoft.md) |
| Meta (Facebook, Instagram, Accounts Center) | [meta.md](meta.md) |
| GitHub | [github.md](github.md) |
| Amazon | [amazon.md](amazon.md) |

Each guide has five sections:

1. Sites and apps that use "Sign in with" the provider.
2. Add a passkey.
3. Add an authenticator app (one-time codes, TOTP).
4. Avoid the phone prompt and SMS at sign-in.
5. What the agent must never do.

A step marked "Not verified on 2026-10-18" did not appear in the provider's help pages. Read the
page before you click, and use the label that the page shows.

## The second-step rule

When a site asks for a second step, choose the method in this order:

1. A passkey from Nodkey.
2. A one-time code from Nodkey (`request_code`).
3. Only if the user tells you to: an app prompt ("tap Yes on your phone") or an SMS code.

Use the switch path in section 4 of the guide ("Try another way", "Other ways to sign in").

## Ask first, every time

- Get the user's explicit yes before each change to an account. Say what you will change, on
  which page, and what it does. Then wait.
- One yes covers one change. Ask again for the next change.
- Never turn off two-step verification. Never remove the last second-step method.
- Never change the password, and never make or delete recovery codes, unless the user asks.
- Never copy a setup key, a recovery code or a one-time code into chat, files, logs or memory.

## Add a passkey to Nodkey

Nodkey is a passkey provider on the iPhone.

- On the iPhone: the user turns on Nodkey under Settings > General > AutoFill & Passwords
  (iOS 18 or later; Not verified on 2026-10-18). When the site creates a passkey, the user
  chooses Nodkey.
- In a desktop browser: the Nodkey browser extension takes the request, and the user approves
  on the iPhone. Without the extension, choose the browser's "use a phone or tablet" option. The
  user scans the QR code with the iPhone and chooses Nodkey.

## Add an authenticator code to Nodkey

The agent never reads the setup key aloud or copies it. The user adds it to Nodkey.

1. Open the provider's authenticator setup page (section 3 of the guide).
2. Show the QR code to the user. Tell the user to scan it with Nodkey on the iPhone.
3. If the user cannot scan it, open the "Can't scan it?" link (the guide gives the label). Tell
   the user to type the key into Nodkey. Do not copy the key yourself.
4. Call `request_code` for the provider's site. Fill the code in the verify field.
5. Submit. Check the result with a snapshot. Report it in one line.
