#!/bin/sh
# Install nodkey from the latest GitHub release.
#   curl -fsSL https://raw.githubusercontent.com/peters/nodkey-cli/main/install.sh | sh
# NODKEY_INSTALL_DIR picks the folder (default ~/.local/bin). NODKEY_VERSION picks a tag.
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

# A logged-in GitHub CLI avoids the API's limit on anonymous calls; plain curl works too.
use_gh=no
if command -v gh >/dev/null 2>&1 && gh auth token >/dev/null 2>&1; then
  use_gh=yes
fi

if [ "$version" = latest ]; then
  # The newest release, pre-releases included; GitHub's "latest" link skips those.
  if [ "$use_gh" = yes ]; then
    version="$(gh api "repos/$repo/releases?per_page=1" --jq '.[0].tag_name' 2>/dev/null || true)"
  else
    version="$(curl -fsSL "https://api.github.com/repos/$repo/releases?per_page=1" |
      sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)"
  fi
  [ -n "$version" ] || { echo "nodkey: no release found for $repo" >&2; exit 1; }
fi

scratch="${TMPDIR:-$HOME/.cache}"
mkdir -p "$scratch"
work="$(mktemp -d "$scratch/nodkey-install.XXXXXX")"
trap 'rm -rf "$work"' EXIT
echo "nodkey: downloading $asset ($version)"
if [ "$use_gh" = yes ]; then
  gh release download "$version" --repo "$repo" --pattern "$asset" --pattern SHA256SUMS --dir "$work"
else
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
tar -xzf "$work/$asset" -C "$work"
mkdir -p "$dir"
mv "$work/nodkey" "$dir/nodkey"
chmod +x "$dir/nodkey"
echo "nodkey: installed $("$dir/nodkey" --version) to $dir/nodkey"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) echo "nodkey: add $dir to your PATH, for example: export PATH=\"$dir:\$PATH\"" ;;
esac
echo "nodkey: next, run 'nodkey setup' to add Nodkey to your coding agents, and 'nodkey pair' for the terminal"
