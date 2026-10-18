# Microsoft account

Checked on 2026-10-18. Read [README.md](README.md) first: it has the second-step rule, the consent
rule and the shared steps to add a passkey or a code to Nodkey.

This guide is for a personal Microsoft account (Outlook.com, Xbox, OneDrive). A work or school
account is managed by its organization; the notes at the end of each section cover it.

Sources:
- Passkeys: https://support.microsoft.com/en-us/account-billing/create-and-save-a-passkey-e92cd3e0-11fa-4630-a5ea-3ccc0396b3d9
- Authenticator app: https://support.microsoft.com/en-us/account-billing/set-up-an-authenticator-app-as-a-two-step-verification-method-2db39828-15e1-4614-b825-6e2b524e7c95
- Security info: https://support.microsoft.com/help/12428

## 1. Sites and apps that use "Sign in with Microsoft"

Not verified on 2026-10-18: no Microsoft help page names this list. Community pages use this path.

1. Open https://account.live.com/consent/Manage.
2. Read the list of apps and services that the user gave access.
3. Select "Edit" next to an entry to read its permissions.

How to read an entry: an app that only signs the user in asks for the profile and the e-mail
address. An app that asks for mail, files, contacts or calendar has data access. Many entries are
both.

To remove one, get the user's yes. Then select "Remove these permissions". The app keeps the data
that it already has.

Work or school account: https://myapps.microsoft.com, then "Manage your application" on an app
(Not verified on 2026-10-18).

## 2. Add a passkey

1. Open https://account.live.com/proofs/manage (Advanced security options).
2. Select "Add a new way to sign in or verify".
3. Select "Face, Fingerprint, PIN, or Security Key".
4. When the browser suggests a place to save it, select "Change" or "Save another way".
5. Select "iPhone, iPad or Android device". The user scans the QR code with the iPhone and
   chooses Nodkey. With the Nodkey browser extension, the extension takes the request instead.
6. The user approves on the iPhone.

## 3. Add an authenticator app (TOTP)

1. Open https://account.microsoft.com/security.
2. Select "Manage how I sign in".
3. Select "Add a new way to sign in or verify".
4. Select "Use an app".
5. Select "Set up a different Authenticator app", then "Next". The page shows a QR code.
6. The user scans it with Nodkey. If the user cannot scan it, select "I can't scan the bar code".
   The page shows the key. The user types it into Nodkey.
7. Select "Next". Call `request_code` for `microsoft.com` (or `live.com`). Type the code and
   continue.

Microsoft no longer lets most accounts add a phone number as a method.

## 4. Avoid the phone prompt and SMS at sign-in

Not verified on 2026-10-18: Microsoft's help pages do not show the sign-in labels. Use the label
that the page shows.

1. On the user name page, select "Sign-in options" or "Other ways to sign in" to use a passkey.
   Choose "Face, fingerprint, PIN, or security key" and use the passkey from Nodkey.
2. On an "Approve sign in request" page (Microsoft Authenticator), select "I can't use my
   Microsoft Authenticator app right now" or "Other ways to sign in".
3. Choose "Use a verification code". Call `request_code` and type the code.
4. Do not choose a text message or a call unless the user tells you to.

The help pages show no setting that changes the default method for a personal account.
Work or school account: the user can change "Default sign-in method" at
https://mysignins.microsoft.com/security-info (Not verified on 2026-10-18).

## 5. Never do this

- Never turn off two-step verification.
- Never remove the last sign-in or verification method on the Advanced security options page.
- Never make a new recovery code: it replaces the old one.
- Never change the password unless the user asks.
- Never remove a passkey, an app or a method without the user's yes.
- Get the user's explicit yes before every change on these pages.
