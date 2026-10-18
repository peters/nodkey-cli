# Amazon

Checked on 2026-10-18. Read [README.md](README.md) first: it has the second-step rule, the consent
rule and the shared steps to add a passkey or a code to Nodkey.

The steps are for amazon.com. Other Amazon stores (amazon.co.uk, amazon.de) have the same menus.
A passkey is made for one store only.

Sources (Amazon Help, `https://www.amazon.com/gp/help/customer/display.html?nodeId=...`):
- Login with Amazon apps: nodeId=GSNRZP4F7NYG36N6
- Passkeys: nodeId=TPphmhSWBgcI9Ak87p
- Two-Step Verification: nodeId=G3PWZPU52FKN7PW4
- Two-Step Verification fails: nodeId=GU3SL3GTHLHPDQ2H

## 1. Sites and apps that use "Login with Amazon"

1. Sign in to Amazon.
2. Go to "Your Account" > "Manage your data" > "Manage apps & services with data access".

How to read the list: each entry is a site or app that the user signed in to with Amazon. Each
entry also got the data that the user shared when they signed in (for example the name and the
e-mail address). So every entry is both a sign-in and a data grant.

To remove one, get the user's yes. Then select "Remove" next to it. The site can still use the
data it already has.

## 2. Add a passkey

1. In "Your Account", select "Login & security".
2. Select "Set up" next to "Passkeys".
3. Select "Set up".
4. The user chooses Nodkey and approves.

Amazon allows one passkey for each passkey provider. A passkey for amazon.com does not work on
amazon.co.uk: make one more there, or sign in with the password. Amazon can ask for the passkey
during a high-risk payment.

## 3. Add an authenticator app (TOTP)

1. In "Your Account", select "Login & security".
2. Find "2-Step Verification" and follow the on-screen steps. (The button is "Turn on" when 2SV
   is off and "Manage" or "Edit" when it is on: Not verified on 2026-10-18.)
3. Choose "Authenticator App" (Not verified on 2026-10-18).
4. Show the QR code to the user. The user scans it with Nodkey.
5. If the user cannot scan it, select "Can't scan the barcode?". The page shows the key. The user
   types it into Nodkey. (Not verified on 2026-10-18.)
6. Call `request_code` for `amazon.com`. Type the code and continue.
7. If Amazon asks to make the app the preferred method, tell the user and ask for a yes.

## 4. Avoid the phone prompt and SMS at sign-in

1. Best: sign in with the passkey. Amazon offers "Passkeys" next to the password. Do not use
   "Sign-in with a code" unless the user tells you to: the code goes to the user's phone or
   e-mail (Not verified on 2026-10-18).
2. When Amazon asks for a 2SV code from a text message, select "Didn't Receive the Code".
3. Choose the authenticator app, if the page shows it (Not verified on 2026-10-18).
4. Do not select "Two-Step Verification Account Recovery". It starts account recovery.
5. Do not choose a text message or an approval in the Amazon app unless the user tells you to.

To make the app the default: in the 2-Step Verification settings, make the authenticator app the
preferred method. The link name is Not verified on 2026-10-18. Get the user's yes first.

## 5. Never do this

- Never select "Disable" next to "Two-Step Verification".
- Never remove the last 2SV method (phone number or authenticator app).
- Never change the password unless the user asks.
- Never remove a passkey or a "Login with Amazon" entry without the user's yes.
- Never take a step in "Two-Step Verification Account Recovery" without the user's yes.
- Get the user's explicit yes before every change on these pages.
