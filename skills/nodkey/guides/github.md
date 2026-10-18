# GitHub

Checked on 2026-10-18. Read [README.md](README.md) first: it has the second-step rule, the consent
rule and the shared steps to add a passkey or a code to Nodkey.

Sources:
- OAuth apps: https://docs.github.com/en/apps/oauth-apps/using-oauth-apps/reviewing-your-authorized-oauth-apps
- GitHub Apps: https://docs.github.com/en/apps/using-github-apps/reviewing-and-revoking-authorization-of-github-apps
- Passkeys: https://docs.github.com/en/authentication/authenticating-with-a-passkey/managing-your-passkeys
- Passkey sign-in: https://docs.github.com/en/authentication/authenticating-with-a-passkey/signing-in-with-a-passkey
- Two-factor setup: https://docs.github.com/en/authentication/securing-your-account-with-two-factor-authentication-2fa/configuring-two-factor-authentication
- Change method: https://docs.github.com/en/authentication/securing-your-account-with-two-factor-authentication-2fa/changing-your-two-factor-authentication-method

## 1. Sites and apps that use "Sign in with GitHub"

1. Select the profile picture at the top right, then "Settings".
2. In the "Integrations" part of the sidebar, select "Applications".
3. Read the tabs:
   - "Authorized OAuth Apps" (https://github.com/settings/applications)
   - "Authorized GitHub Apps" (https://github.com/settings/apps/authorizations)
   - "Installed GitHub Apps": apps installed on the user's repositories.

How to read an entry: an authorization lets the app act for the user. An app that asks only for
the profile or the e-mail address is a sign-in. An app with repository or organization access
has data access too. An installed app is not a sign-in.

To remove one, get the user's yes. Then select the "..." menu next to it and "Revoke". Never
select "Revoke all".

## 2. Add a passkey

GitHub needs two-factor authentication on before the first passkey.

1. Open https://github.com/settings/security ("Password and authentication").
2. Under "Passkeys", select "Add a passkey".
3. If GitHub asks, confirm with the password or a second step (use Nodkey, see section 4).
4. Under "Configure passwordless authentication", select "Add passkey".
5. The user chooses Nodkey and approves.
6. Select "Done".

A security key that GitHub can upgrade shows an upgrade button. The upgrade flow ends with
"Upgrade to passkey".

## 3. Add an authenticator app (TOTP)

If two-factor authentication is off:
1. Open https://github.com/settings/security.
2. Select "Enable two-factor authentication".

If it is on and the user wants to move the authenticator to Nodkey:
1. Open https://github.com/settings/security.
2. Under "Two-factor methods", select "Edit" next to the authenticator app (or the "..." menu,
   then "Edit").

Then:
3. Under "Scan the QR code", show the code to the user. The user scans it with Nodkey.
4. If the user cannot scan it, select "setup key". The user types the key into Nodkey.
5. Call `request_code` for `github.com`. Type it under "Verify the code from the app".
6. Select "Save" (when you edit) or continue (when you enable).

A new method works only after GitHub accepts a code from it. Tell the user to remove the old
GitHub entry from the old app only after this.

When you enable two-factor authentication, GitHub shows recovery codes. The user downloads and
keeps them. Do not read or copy them. Only the user selects "I have saved my recovery codes".

## 4. Avoid the phone prompt and SMS at sign-in

1. Make the code the default: at https://github.com/settings/security, under "Two-factor
   authentication", choose the method in "Preferred 2FA method". Get the user's yes first.
2. Best: sign in with a passkey. Open https://github.com/login?passkey=true and select "Sign in
   with a passkey". A passkey replaces the password and the second step.
3. When GitHub shows a GitHub Mobile prompt, select the link to use another method and choose the
   authenticator app (link labels Not verified on 2026-10-18). Call `request_code`.
4. Do not choose the text message unless the user tells you to.

## 5. Never do this

- Never disable two-factor authentication.
- Never remove the last two-factor method.
- Never make new recovery codes: new codes stop the old ones.
- Never change the password unless the user asks.
- Never revoke an app, remove a passkey or remove a method without the user's yes.
- Get the user's explicit yes before every change on these pages.
