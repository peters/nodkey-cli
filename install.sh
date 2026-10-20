#!/bin/sh
# Install nodkey from the latest GitHub release.
#   curl -fsSL https://raw.githubusercontent.com/peters/nodkey-cli/main/install.sh | sh
# NODKEY_INSTALL_DIR picks the folder (default ~/.local/bin). NODKEY_VERSION picks a tag.
# The archive must match SHA256SUMS. With a logged-in GitHub CLI, its build provenance must also
# show that the release workflow of this repository built it (gh attestation verify). A GitHub CLI
# that cannot use the API is left out: curl downloads, and only the checksum is checked. On macOS
# the binary must have a valid Developer ID signature.
set -eu

repo="peters/nodkey-cli"
dir="${NODKEY_INSTALL_DIR:-$HOME/.local/bin}"
version="${NODKEY_VERSION:-latest}"

case "$(uname -s)" in
  Linux) os=unknown-linux-musl ;;
  Darwin) os=apple-darwin ;;
  *) echo "nodkey: unsupported system $(uname -s); on Windows use install.ps1" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=x86_64 ;;
  arm64 | aarch64) arch=aarch64 ;;
  *) echo "nodkey: unsupported CPU $(uname -m)" >&2; exit 1 ;;
esac
target="$arch-$os"
asset="nodkey-$target.tar.gz"

# A logged-in GitHub CLI avoids the API's limit on anonymous calls; plain curl works too. gh can
# hold a token it cannot use (no login for this HOME, an expired token, no way to the API), so a
# call that does not count against the limit decides.
use_gh=no
if command -v gh >/dev/null 2>&1 && gh auth token >/dev/null 2>&1 &&
  gh api rate_limit --jq .rate.limit >/dev/null 2>&1; then
  use_gh=yes
fi

if [ "$version" = latest ]; then
  # The newest stable release; while there is none, the newest pre-release. Drafts never.
  version=""
  if [ "$use_gh" = yes ]; then
    version="$(gh api "repos/$repo/releases?per_page=30" \
      --jq '[.[] | select(.draft | not)] | (map(select(.prerelease | not)) + .)[0].tag_name // empty' \
      2>/dev/null || true)"
    # A failed lookup: go on without gh.
    [ -n "$version" ] || use_gh=no
  fi
  if [ -z "$version" ]; then
    tag() { sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1; }
    version="$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" 2>/dev/null | tag)"
    [ -n "$version" ] ||
      version="$(curl -fsSL "https://api.github.com/repos/$repo/releases?per_page=1" | tag)"
  fi
  [ -n "$version" ] || { echo "nodkey: no release found for $repo" >&2; exit 1; }
fi

scratch="${TMPDIR:-$HOME/.cache}"
mkdir -p "$scratch"
work="$(mktemp -d "$scratch/nodkey-install.XXXXXX")"
trap 'rm -rf "$work"' EXIT
echo "nodkey: downloading $asset ($version)"
if [ "$use_gh" = yes ] &&
  ! gh release download "$version" --repo "$repo" --pattern "$asset" --pattern SHA256SUMS --dir "$work" 2>/dev/null; then
  echo "nodkey: the GitHub CLI could not download it; downloading without it"
  rm -f "$work/$asset" "$work/SHA256SUMS"
  use_gh=no
fi
if [ "$use_gh" = no ]; then
  base="https://github.com/$repo/releases/download/$version"
  curl -fsSL "$base/$asset" -o "$work/$asset"
  curl -fsSL "$base/SHA256SUMS" -o "$work/SHA256SUMS"
fi
expected="$(grep " $asset\$" "$work/SHA256SUMS" | cut -d' ' -f1)"
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$work/$asset" | cut -d' ' -f1)"
else
  actual="$(shasum -a 256 "$work/$asset" | cut -d' ' -f1)"
fi
if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
  echo "nodkey: checksum mismatch for $asset" >&2
  exit 1
fi
# SHA256SUMS comes from the same release, so it finds damage, not a replaced release. Build
# provenance does: the release workflow of this repository signs it at build time. The macOS
# archives are signed and notarized after the build, so they are checked by their signature below.
if [ "$os" = apple-darwin ]; then
  :
elif [ "$use_gh" = yes ] && gh attestation --help >/dev/null 2>&1; then
  if ! gh attestation verify "$work/$asset" --repo "$repo" >/dev/null; then
    echo "nodkey: $asset has no valid build provenance from $repo; nothing was installed" >&2
    exit 1
  fi
  echo "nodkey: checked the checksum and the build provenance (gh attestation verify)"
else
  echo "nodkey: checked the checksum; with a logged-in GitHub CLI (gh) the build provenance is checked too"
fi
tar -xzf "$work/$asset" -C "$work"
if [ "$os" = apple-darwin ]; then
  if ! codesign --verify --strict -R="anchor apple generic" "$work/nodkey" 2>/dev/null; then
    echo "nodkey: the macOS binary has no valid Developer ID signature; nothing was installed" >&2
    exit 1
  fi
  echo "nodkey: checked the checksum and the Developer ID signature"
fi
mkdir -p "$dir"
mv "$work/nodkey" "$dir/nodkey"
chmod +x "$dir/nodkey"
echo "nodkey: installed $("$dir/nodkey" --version) to $dir/nodkey"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) echo "nodkey: add $dir to your PATH, for example: export PATH=\"$dir:\$PATH\"" ;;
esac
echo "nodkey: next, run 'nodkey setup' to add Nodkey to your coding agents, and 'nodkey pair' for the terminal"
