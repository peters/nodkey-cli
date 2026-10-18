# Apple Account

Checked on 2026-10-18. Read [README.md](README.md) first: it has the second-step rule, the consent
rule and the shared steps to add a passkey or a code to Nodkey.

Sources:
- Sign in with Apple: https://support.apple.com/en-us/102571
- Two-factor authentication: https://support.apple.com/en-us/102660
- Verification codes: https://support.apple.com/en-us/102606
- Security keys: https://support.apple.com/en-us/102637

Apple Account works differently from the other providers. Read this guide before you plan a task
with an Apple sign-in.

## 1. Sites and apps that use "Sign in with Apple"

On the web:
1. Sign in at https://account.apple.com.
2. Go to "Sign-In & Security".
3. Select "Sign in with Apple".

On the iPhone: Settings > [the user's name] > "Sign in with Apple".
On a Mac: Apple menu > System Settings > [the user's name] > "Sign in with Apple".

Each entry is an app or a developer that the user signs in to with Apple. Some entries use a
"Hide My Email" address. To stop using one, the iPhone path is: select the app, then "Delete". The
removal step on the web and on the Mac is Not verified on 2026-10-18. Get the user's yes first.

## 2. Add a passkey

Apple's help pages do not describe a passkey for the Apple Account that the user can keep in
another passkey provider (Not verified on 2026-10-18). Nodkey cannot hold the Apple Account sign-in.

Apple offers physical security keys instead:
1. On the iPhone: Settings > [name] > "Sign-in & Security" > "Two-Factor Authentication" >
   "Security Keys" > "Add Security Keys".
2. On a Mac: System Settings > [name] > "Sign-in & Security" > "Two-Factor Authentication", then
   "Set Up" next to "Security Keys".

Apple needs at least two FIDO Certified keys. Only the user can do this (the keys are physical).

Nodkey can still hold passkeys for other sites on the iPhone (see the README).

## 3. Add an authenticator app (TOTP)

Apple Account does not use authenticator apps. Its codes come from the user's trusted Apple
devices or a trusted phone number. Nodkey cannot give a code for the Apple Account.

## 4. Avoid the phone prompt and SMS at sign-in

1. When Apple asks for a verification code, ask the user in one line to read the six-digit code
   on a trusted Apple device. The user selects "Allow" on that device to see it.
2. Type the code the user gives you. Do not keep it.
3. Do not select "Didn't Get a Code?" (text message or phone call) unless the user tells you to.
4. "Can't get to your devices?" starts other paths. Do not select it without the user's yes.

## 5. Never do this

- Never remove a trusted phone number or a trusted device.
- Never remove a security key: Apple needs at least two.
- Never try to lower the account security. Two-factor authentication cannot be turned off for most
  accounts.
- Never change the password or the recovery settings (recovery key, recovery contact) unless the
  user asks.
- Never delete a "Sign in with Apple" entry without the user's yes. The user can lose the link to
  that account.
- Get the user's explicit yes before every change on these pages.
