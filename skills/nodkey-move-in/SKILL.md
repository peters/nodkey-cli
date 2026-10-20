---
name: nodkey-move-in
description: Help the user move their passwords and one-time codes from this computer into Nodkey on their iPhone, a first move or a clean-up round. Finds the browsers and password managers installed here (only the apps and profiles, never their password stores), guides the user through each app's own export, sends each export file to the import window on the iPhone with import_file (or `nodkey import`), and deletes it afterwards. Use when the user asks to move, bring over, import or migrate passwords, logins or codes into Nodkey, to switch from Chrome, Firefox, Safari, Bitwarden, 1Password, LastPass or another password manager, or to tidy up where their passwords live.
---

# Move in to Nodkey

The user brings their passwords and codes into Nodkey from this computer. Each browser or password
manager makes its own export file; you send each file to Nodkey on their iPhone, where it waits in
"To review". At the end the user adds everything with one Face ID. You never see a password, and
nothing is added before the user's review.

## Rules (always)

- **Never read the export.** Do not `cat`, open, `head`, `grep`, copy, move, upload, attach,
  summarise or screenshot an export file or the browser's password list. Only `import_file` (or
  `nodkey import`) touches the file. To find it, look at file names and dates only
  (`ls -t ~/Downloads`).
- **Never read a password store.** Find apps and profiles by their folders and settings files
  only. Never open `Login Data`, `logins.json`, `key4.db`, a keychain, a `.kdbx` or any vault file.
- **One file at a time, deleted after.** `import_file` deletes the export after the phone has it.
  If an export cannot be sent, ask the user before you delete it (`rm` the path, never read it).
- Every export is the user's own action in the app: they click Export and confirm with their
  password or Touch ID. You may open the right page; you never type their master password.
- Keep the tone calm and the steps short. Say what happens next in one line.

## 1. Get ready

1. Check that this agent is paired: `list_phones`. If not, pair first (the `pair` tool).
2. Ask the user to open the import window on the iPhone:
   **Nodkey → Settings → Import → "From your computer, with an agent"**, pick this agent and
   confirm with Face ID. The window takes up to 20 files for 30 minutes and can be closed any time.
   Ask them to **keep Nodkey open on that screen** while you send files (it keeps the iPhone
   awake there): Nodkey takes a file in only while it is open.
3. You learn that it is open only when you send the first file. `import_closed` means it is not
   open (yet), or it is open for another agent.

## 2. Find what is on this computer

Look only for installed apps and their profile folders. Show the user a short list and ask which
ones to move, and whether they use a password manager in the browser only (LastPass, Dashlane,
NordPass, Proton Pass) that you cannot see from here.

| | macOS | Linux | Windows |
| --- | --- | --- | --- |
| Chrome | `~/Library/Application Support/Google/Chrome/` | `~/.config/google-chrome/` | `%LOCALAPPDATA%\Google\Chrome\User Data\` |
| Chromium | `~/Library/Application Support/Chromium/` | `~/.config/chromium/`, `~/snap/chromium/` | |
| Edge | `~/Library/Application Support/Microsoft Edge/` | `~/.config/microsoft-edge/` | `%LOCALAPPDATA%\Microsoft\Edge\User Data\` |
| Brave | `~/Library/Application Support/BraveSoftware/Brave-Browser/` | `~/.config/BraveSoftware/Brave-Browser/` | `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\` |
| Vivaldi | `~/Library/Application Support/Vivaldi/` | `~/.config/vivaldi/` | `%LOCALAPPDATA%\Vivaldi\User Data\` |
| Firefox | `~/Library/Application Support/Firefox/profiles.ini` | `~/.mozilla/firefox/profiles.ini`, `~/snap/firefox/common/.mozilla/firefox/`, `~/.var/app/org.mozilla.firefox/` | `%APPDATA%\Mozilla\Firefox\profiles.ini` |
| Safari, Passwords | always on a Mac (`/System/Applications/Passwords.app` on macOS 15 and later) | | |
| Bitwarden | `/Applications/Bitwarden.app` | `~/.config/Bitwarden/`, flatpak `com.bitwarden.desktop` | `%LOCALAPPDATA%\Programs\Bitwarden\` |
| 1Password | `/Applications/1Password.app` | `~/.config/1Password/`, `/opt/1Password/` | `%LOCALAPPDATA%\1Password\` |
| KeePassXC | `/Applications/KeePassXC.app` | `keepassxc` on `PATH`, flatpak `org.keepassxc.KeePassXC` | `%ProgramFiles%\KeePassXC\` |
| Proton Pass | `/Applications/Proton Pass.app` | `proton-pass` on `PATH` | `%LOCALAPPDATA%\Programs\ProtonPass\` |
| Ente Auth (codes) | `/Applications/Ente Auth.app` | `ente_auth` on `PATH` | `%LOCALAPPDATA%\Programs\ente_auth\` |

Chromium browsers keep one folder per profile: `Default`, `Profile 1`, `Profile 2`, ... (list the
folder names only). Firefox lists its profiles in `profiles.ini` (names and paths, no passwords).
A browser that syncs passwords (Chrome with a Google account, Edge with a Microsoft account,
Firefox with a Mozilla account) holds the same passwords in every profile that syncs: one export
per account is enough.

## 3. Export and send, one source at a time

For each source: give the steps (or open the page), wait for the file, send it, report the counts
in one line, then go on to the next.

**Chrome, Chromium, Brave, Vivaldi, Edge.** Open the password settings in the right profile, for
example `google-chrome --profile-directory="Profile 1" chrome://password-manager/settings` (Brave
`brave://password-manager/settings`, Edge `edge://settings/passwords`). If the page does not open
from the command line, ask the user to paste the address. Then: **Export passwords → Download file**,
and confirm with the computer's password. The file is `Chrome Passwords.csv` (Edge and Brave name
it after themselves) in Downloads. Source label: `Chrome, profile Default`.

**Firefox.** Open `about:logins` (a profile: `firefox -P "<name>" about:logins`). Then the **⋯**
menu at the top right → **Export Passwords…** → **Export**, confirm with the computer's password,
and save the CSV (`logins.csv` or `passwords.csv`).

**Safari and Apple Passwords (Mac).** Passwords app: **File → Export All Passwords to File…**
(older macOS: Safari → File → Export → Passwords). Codes saved there come along.

**Bitwarden.** Desktop app or web vault: **File → Export vault** (web: Tools → Export vault),
format **.csv** (or **.json**, not the encrypted one), confirm with the master password.

**1Password.** **File → Export → <account>**, format **CSV**, enter the account password.

**LastPass.** Web: **Advanced options → Export** (or Account settings → Export), confirm, save the
CSV.

**Dashlane.** Web app: **My account → Settings → Export data → Unprotected archive**. Unpack the
zip and send `credentials.csv`.

**Proton Pass, NordPass, KeePassXC.** Settings → Export (KeePassXC: **Database → Export → CSV
File…**), format **CSV**, without a password.

**Codes.** Google Authenticator is moved on the iPhone itself (Nodkey → Settings → Import, with its
QR code or screenshots); do not export it here. A code app's plain text export is a list of
`otpauth://` links that you can send from here: Ente Auth on this computer (Settings → Data →
Export codes → **Plain text**), or a 2FAS backup (`.2fas`, without a password). A code app on the
iPhone is easiest to import on the iPhone.

**Wait for the file.** Ask the user to tell you when the export is saved, or check the newest names
in Downloads every few seconds (`ls -t ~/Downloads | head -5`) for up to five minutes. Use the new
file's full path. Never open it to check it; if you are unsure it is the right file, call
`import_file` with `dry_run: true`: it reports the format and the counts only.

**Send it:** `import_file(path, source)` or `nodkey import "<path>" --source "Chrome, profile Default"`.

| Result | What to do |
| --- | --- |
| `staged` | Tell the user the counts in one line ("Chrome: 212 logins staged, 3 rows left out"). The export is deleted (`deleted: true`). |
| `import_closed` | Ask the user to open the window (step 1), then send the same file again. |
| `window_full` | Ask the user to review and add what is staged, then open a new window. |
| `import_unreadable` | Export again as plain CSV (plain text for codes), without a password. Ask, then delete the old file. |
| `too_large` | Export a smaller part (one vault or folder at a time). |
| `no_passcode` | The iPhone needs a passcode first (Settings → Face ID & Passcode). |
| `expired` | Nodkey was probably not open. Ask the user to open it on the import screen, then send the same file once more. |
| `paused`, `denied` | Tell the user in one line and wait for them; do not loop. |

`duplicates` and `conflicts` compare the file with the files sent before in this window; the iPhone
shows the comparison with what Nodkey already holds.

## 4. Review on the iPhone

When every source is sent, tell the user: "Everything is in Nodkey under To review. Check it there
and add it with one Face ID." Nodkey shows new logins, merged ones, ones already saved, and
conflicts (the same site and user name with another password; it suggests the newest). Nothing is
added before they confirm.

## 5. Clean up (offer, do not push)

1. Offer a tidy-up with `cleanup_insights` (reused, weak or long unused logins, logins for IP
   addresses or test hosts). Propose rules from the counts and act only on what the user picks,
   with `cleanup_logins` (the nodkey skill has the details).
2. Offer to stop the old places from keeping passwords, **only after the user added everything in
   Nodkey** and says yes:
   - Chrome, Edge, Brave: password settings → turn off **Offer to save passwords** (and auto sign-in).
     Removing the saved copies: Settings → Privacy → **Delete browsing data → Passwords and
     passkeys**. This also removes passkeys saved in the browser, which an export does not carry,
     and with sync on it removes them on every device of that account; ask about passkeys first.
   - Firefox: `about:preferences#privacy` → untick **Ask to save passwords**; removing them:
     `about:logins` → **⋯ → Remove All Passwords**.
   - Safari on a Mac: Settings → AutoFill → untick **User names and passwords**. Apple Passwords
     syncs with iCloud Keychain; leave it unless the user wants Nodkey only.
   - Password managers: keep the old vault until the user has used Nodkey for a while; cancelling
     a subscription or deleting a vault is the user's own step.
3. Confirm the exports are gone: list Downloads by name and point out any export file that is still
   there (`.csv` files named after a browser or password manager, `.2fas`, `.txt` code lists). Ask
   before you delete one.
