#!/bin/sh
# Build the redact-docs unit from this folder into your local nexus store.
#
#   redact-docs/build.sh
#
# The classifier's weights come from `nexus install`, but its tokenizer and config must sit
# inside the unit. This script downloads those three files at the pinned model revision,
# checks each against its sha256, then runs `nexus build` on unit/. It stops on the first
# failure. NEXUS=/path/to/nexus picks a nexus binary other than the one on your PATH.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
NEXUS=${NEXUS:-nexus}

REV=61726e0ad791dcab3e29339bbec3ad42ded65641
URL=https://huggingface.co/knowledgator/gliner-pii-base-v1.0/resolve/$REV
DIR="$HERE/unit/models/gliner"

sha256() {
  if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1
  else sha256sum "$1" | cut -d' ' -f1; fi
}

fetch() {
  _file=$1 _want=$2
  if [ -f "$DIR/$_file" ] && [ "$(sha256 "$DIR/$_file")" = "$_want" ]; then return 0; fi
  echo "build: downloading $_file" >&2
  curl -fsSL --retry 3 --connect-timeout 20 --max-time 600 -o "$DIR/$_file.part" "$URL/$_file"
  if [ "$(sha256 "$DIR/$_file.part")" != "$_want" ]; then
    rm -f "$DIR/$_file.part"
    echo "build: sha256 mismatch for $_file; stopping" >&2
    exit 1
  fi
  mv "$DIR/$_file.part" "$DIR/$_file"
}

command -v "$NEXUS" >/dev/null 2>&1 || [ -x "$NEXUS" ] || { echo "build: nexus not found (install nexus v0.1.0, or set NEXUS)" >&2; exit 1; }
mkdir -p "$DIR"
fetch tokenizer.json ee028763434d18611c1c36356ea1d050e90a9fa94ede57fac48b39f85f818ad1
fetch tokenizer_config.json 3ec8a90d8758fbc56d50831990c3a3a65660f020c5b06534adf43b04091ffa9e
fetch gliner_config.json e33d3da38e0d369fa7574668d3798ca6c7d2b23cba7d628507112eeb426aaccb

# nexus build packs the folder as it is, so build from inside it.
cd "$HERE/unit"
"$NEXUS" build .
