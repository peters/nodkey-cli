#!/bin/sh
# Updates the bundled Public Suffix List snapshot (docs/agent-protocol.md, "Websites"): downloads
# the list from publicsuffix.org (its only supported source), checks that it names its version,
# and rewrites the test vectors. Read the diff, run the checks, then copy the file and
# vectors/v1.json to the app as the document says.
set -eu
cd "$(dirname "$0")/.."
list=nodkey-proto/data/public_suffix_list.dat
curl -fsSL --proto '=https' --tlsv1.2 -o "$list.new" https://publicsuffix.org/list/public_suffix_list.dat
if ! grep -q '^// VERSION: ' "$list.new" || ! grep -q '^// COMMIT: ' "$list.new"; then
  rm -f "$list.new"
  echo "update-psl: the download has no VERSION or COMMIT line; nothing changed" >&2
  exit 1
fi
mv "$list.new" "$list"
cargo run -q -p nodkey-proto --example vectors
grep -E '^// (VERSION|COMMIT): ' "$list"
git --no-pager diff --stat -- "$list" vectors/v1.json
