# Google Account

Checked on 2026-10-18. Read [README.md](README.md) first: it has the second-step rule, the consent
rule and the shared steps to add a passkey or a code to Nodkey.

Sources:
- Linked apps: https://support.google.com/accounts/answer/13533235
- Passkeys: https://support.google.com/accounts/answer/13548313
- Authenticator: https://support.google.com/accounts/answer/1066447
- Google prompts: https://support.google.com/accounts/answer/7026266

## 1. Sites and apps that use "Sign in with Google"

1. Open https://myaccount.google.com/linkedapps.
2. Use the filters to read each kind of entry:
   - "Sign in with Google" (https://myaccount.google.com/linkedapps?filters=4): the user signs in
     to these sites with Google. This is the sign-in list.
   - "Access to your Google Account" (filters=3): the app can read or change Google data (mail,
     files, calendar). This is a data-access grant, not a sign-in.
   - "Linked account" (filters=2): Google can use the user's account on that app.
   - "Agent access": AI agents that can use the app.
3. Select an entry, then select "See details" to read what it can do.

To remove an entry, get the user's yes first. Then select "Stop using Sign in with Google" (or
"Remove access", or "Delete link") and "Confirm". The user's data in the app stays.

## 2. Add a passkey

1. Open https://myaccount.google.com/signinoptions/passkeys.
2. Select "Create a passkey".
3. Select "Create a passkey" again.
4. Let the user choose Nodkey and approve (see "Add a passkey to Nodkey" in the README).

The "Use another device" button in step 3 is for a hardware security key. The QR code path to a
phone from that button is Not verified on 2026-10-18.

After the first passkey, Google asks for the passkey first. The setting is "Skip password when
possible" under "How you sign in to Google" at https://myaccount.google.com/security. Do not change
it without the user's yes.

## 3. Add an authenticator app (TOTP)

1. Open https://myaccount.google.com/two-step-verification/authenticator.
2. Select "Set up authenticator" (on some devices: "Get Started").
3. Show the QR code to the user. The user scans it with Nodkey.
4. If the user cannot scan it, select "Can't scan it?". The page shows the setup key. The user
   types it into Nodkey. (This label is Not verified on 2026-10-18 in Google's help pages.)
5. Select "Next". Call `request_code` for `google.com`. Type the code and select "Verify".

Google says the new method can take up to 7 days to show as a sign-in option.

## 4. Avoid the phone prompt and SMS at sign-in

Google picks the second step. The help pages show no setting that makes the code the default.
Switch at each sign-in:

1. On the second-step page ("Check your phone" or a similar prompt), select "Try another way".
2. Choose the passkey option ("Use your passkey"). Use the passkey from Nodkey.
3. If there is no passkey, choose the authenticator app code option. Call `request_code` for
   `google.com` and type the code. (The label of this option is Not verified on 2026-10-18.)
4. Do not choose the text message or the "Yes" prompt on a phone unless the user tells you to.

To stop the prompts on a phone, the user signs out of Google on that phone. Do not do this for
the user.

## 5. Never do this

- Never turn off 2-Step Verification.
- Never remove the last second step (passkey, authenticator, phone, security key).
- Never make new backup codes: new codes stop the old ones.
- Never change the password unless the user asks.
- Never remove a "Sign in with Google" entry or a passkey without the user's yes.
- Get the user's explicit yes before every change on these pages.
