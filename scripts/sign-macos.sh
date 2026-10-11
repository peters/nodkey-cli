#!/usr/bin/env bash
# Sign and notarize the macOS archives of a release on a Mac reachable over ssh.
#
#   scripts/sign-macos.sh MAC_HOST DIR
#
# DIR holds the release archives (gh release download TAG --dir DIR). Every
# nodkey-*-apple-darwin.tar.gz in it is copied to MAC_HOST, its binary signed with the team's
# "Developer ID Application" identity (hardened runtime, secure timestamp) and notarized, then
# packed again in place. SHA256SUMS in DIR is rewritten. Upload afterwards with
#   gh release upload TAG DIR/* --clobber
#
# On the Mac, the file in $ASC_CONFIG (default ~/.appstoreconnect/config) sets TEAM_ID, KEY_ID,
# ISSUER_ID and KEY_PATH (App Store Connect API key for notarytool), and optionally KEYCHAIN_PATH
# and KEYCHAIN_PASSWORD_FILE to unlock the keychain in the ssh session.
set -euo pipefail

host="${1:?usage: sign-macos.sh MAC_HOST DIR}"
dir="${2:?usage: sign-macos.sh MAC_HOST DIR}"
shopt -s nullglob
archives=("$dir"/nodkey-*-apple-darwin.tar.gz)
[ ${#archives[@]} -gt 0 ] || { echo "no nodkey-*-apple-darwin.tar.gz in $dir" >&2; exit 1; }

remote="$(ssh "$host" 'mkdir -p "$HOME/.cache" && mktemp -d "$HOME/.cache/nodkey-sign.XXXXXX"')"
trap 'ssh "$host" "rm -rf \"$remote\""' EXIT
scp -q "${archives[@]}" "$host:$remote/"

ssh "$host" bash -s -- "$remote" <<'REMOTE'
set -euo pipefail
cd "$1"
set -a
# shellcheck disable=SC1090
. "${ASC_CONFIG:-$HOME/.appstoreconnect/config}"
set +a
: "${TEAM_ID:?}" "${KEY_ID:?}" "${ISSUER_ID:?}" "${KEY_PATH:?}"
KEY_PATH="$(eval echo "$KEY_PATH")"
if [ -n "${KEYCHAIN_PASSWORD_FILE:-}" ]; then
  security unlock-keychain -p "$(cat "$(eval echo "$KEYCHAIN_PASSWORD_FILE")")" \
    "$(eval echo "${KEYCHAIN_PATH:-$HOME/Library/Keychains/login.keychain-db}")"
fi
identity="$(security find-identity -v -p codesigning |
  awk -v team="($TEAM_ID)" '/Developer ID Application/ && index($0, team) { print $2; exit }')"
[ -n "$identity" ] || { echo "no Developer ID Application identity for team $TEAM_ID" >&2; exit 1; }
for archive in nodkey-*-apple-darwin.tar.gz; do
  target="${archive%.tar.gz}"
  mkdir "$target"
  tar -xzf "$archive" -C "$target"
  codesign --force --options runtime --timestamp --sign "$identity" "$target/nodkey"
  codesign --verify --strict --verbose=2 "$target/nodkey"
  ditto -c -k "$target/nodkey" "$target.zip"
  xcrun notarytool submit "$target.zip" --key "$KEY_PATH" --key-id "$KEY_ID" --issuer "$ISSUER_ID" --wait \
    | tee "$target.notary"
  grep -q "status: Accepted" "$target.notary" || { echo "notarization failed for $target" >&2; exit 1; }
  tar -C "$target" -czf "$archive" nodkey
  echo "signed and notarized $archive"
done
REMOTE

for archive in "${archives[@]}"; do
  scp -q "$host:$remote/$(basename "$archive")" "$archive"
done
(cd "$dir" && sha256sum nodkey-* > SHA256SUMS && cat SHA256SUMS)
