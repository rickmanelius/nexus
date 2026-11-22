#!/bin/sh
# Maintainer: build one unit from this repo, run its selftest, and push it to ghcr.io/rickmanelius.
#
#   ./publish.sh redact-docs 1.0.0
#
# Needs nexus v0.1.0 on PATH (or NEXUS=/path/to/nexus) and a GitHub token that can write
# packages: run `gh auth refresh -h github.com -s write:packages` once, or set GITHUB_TOKEN.
# Stops at the first failure. A newly pushed package is private until you make it public on
# GitHub; the last line prints the settings page for that.
set -eu
[ $# -eq 2 ] || { echo "usage: ./publish.sh <unit-folder> <version>" >&2; exit 2; }
UNIT=$1 VERSION=$2
HERE=$(cd "$(dirname "$0")" && pwd)
NEXUS=${NEXUS:-nexus}
REF="$UNIT:$VERSION"
TARGET="ghcr.io/rickmanelius/$UNIT:$VERSION"

"$NEXUS" --version 2>/dev/null | grep -q 'v0\.1\.0' \
  || { echo "publish: needs nexus v0.1.0 (see README.md, Quickstart step 1), or set NEXUS" >&2; exit 1; }
MANIFEST="$HERE/$UNIT/unit/nexus.yaml"
[ -f "$MANIFEST" ] || { echo "publish: no unit at $UNIT/unit/" >&2; exit 1; }
grep -q "^name: $UNIT$" "$MANIFEST" && grep -q "^version: $VERSION$" "$MANIFEST" \
  || { echo "publish: $UNIT/unit/nexus.yaml does not say name $UNIT, version $VERSION" >&2; exit 1; }

echo "== build $REF"
NEXUS="$NEXUS" "$HERE/$UNIT/build.sh"
echo "== install its models"
"$NEXUS" install --yes "$REF"
echo "== selftest"
OUT=$("$NEXUS" run --no-daemon --no-sandbox "$REF" -p "[selftest]" 2>&1) || { printf '%s\n' "$OUT" | tail -n 5 >&2; exit 1; }
printf '%s\n' "$OUT" | tail -n 1
echo "== push to $TARGET"
GITHUB_TOKEN=${GITHUB_TOKEN:-$(gh auth token)} "$NEXUS" push "$REF" "$TARGET"

echo
echo "Pushed $TARGET. If this is the first push of $UNIT, make it public:"
echo "  https://github.com/users/rickmanelius/packages/container/$UNIT/settings  (Change visibility: Public)"
