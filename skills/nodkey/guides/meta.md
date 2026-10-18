# Meta: Facebook, Instagram and Accounts Center

Checked on 2026-10-18. Read [README.md](README.md) first: it has the second-step rule, the consent
rule and the shared steps to add a passkey or a code to Nodkey.

Meta is moving users from Accounts Center to "Meta Account settings". The user can see either
name. The steps are the same.

Sources:
- Apps and websites: https://www.facebook.com/help/100754513412802 and
  https://www.facebook.com/help/211829542181913
- Two-factor authentication: https://www.facebook.com/help/148233965247823
- Authentication app: https://www.facebook.com/help/358336074294704
- Trouble at sign-in: https://www.facebook.com/help/147926301947841
- Passkeys: https://www.facebook.com/help/1181045243159511
- Instagram two-factor: https://help.instagram.com/566810106808145

## 1. Sites and apps that use "Log in with Facebook"

Facebook on a computer:
1. Select the profile picture at the top right.
2. Select "Settings & privacy", then "Settings".
3. Select "Apps and Websites" in the left menu.

How to read the list: it shows apps and games that the user logged in to with Facebook. It also
shows accounts that the user linked to Facebook (for example a loyalty program or a news
subscription). A linked account is not a sign-in.

Do not select "Turn Off" next to "Apps, websites and games" under "Preferences". It stops all
Facebook logins to other sites at once. The button to remove one app is Not verified on
2026-10-18. Get the user's yes first.

Instagram: Settings > "Website permissions" > "Apps and websites" (Not verified on 2026-10-18).

## 2. Add a passkey

1. Open Accounts Center: profile picture > "Settings & privacy" > "Settings" > "Accounts Center".
2. Select "Password and security".
3. Select "Passkey".
4. Follow the steps on the page. The user chooses Nodkey and approves. (The button names in this
   step are Not verified on 2026-10-18.)

Facebook can also offer a passkey at sign-in. The passkey name is the user's e-mail address or
phone number. A computer needs Chrome 109, Safari 16, Edge 109 or Firefox 122 or later.
Instagram passkeys: Not verified on 2026-10-18.

## 3. Add an authenticator app (TOTP)

1. Select the profile picture, then "Settings & privacy", then "Settings".
2. Select "Accounts Center", then "Password and security".
3. Select "Two-factor authentication", then the account (Facebook or Instagram).
4. Select "Authentication app".
5. Show the QR code to the user. The user scans it with Nodkey. If the user cannot scan it, the
   page has a setup key to type in (its label is Not verified on 2026-10-18).
6. Select "Next".
7. Call `request_code` for `facebook.com` (or `instagram.com`). Type the code and select "Next".

The same path in Accounts Center works for Instagram.

## 4. Avoid the phone prompt and SMS at sign-in

Facebook can ask the user to approve the login on another device, or send an SMS code.

1. On the code page on a computer, select "Need another way to authenticate?".
2. Select "Other Options".
3. Choose the authentication app (label Not verified on 2026-10-18). Call `request_code` and type
   the code.
4. Do not select "Get more help": it starts account recovery.
5. Do not choose the text message unless the user tells you to.

On iPhone or iPad the link is "Need help?". On Android it is "Having trouble?".
A setting that picks the default method is Not verified on 2026-10-18.

## 5. Never do this

- Never turn off two-factor authentication.
- Never remove the last security method.
- Never make new recovery codes: new codes stop the old ones.
- Never remove a passkey: removal is permanent.
- Never change the password unless the user asks.
- Never select "Turn Off" for apps, websites and games.
- Get the user's explicit yes before every change on these pages.
