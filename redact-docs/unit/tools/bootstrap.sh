#!/bin/sh
# Prints a Python that has exactly the unit's hash-locked dependencies.
#
# The venv lives in the real user's ~/.cache/nexus-redact (nexus points HOME at
# the run directory), keyed by the lock's hash and the Python version, and is
# built once with pip --require-hashes --only-binary=:all: from requirements.lock.
# A sealed unit carries its wheels in vendor/wheels and installs with no index.
# The lock has wheels for Python 3.12 to 3.14 only (onnxruntime 1.31.1 and PyYAML 6.0.3
# publish none for 3.15), so a newer python3 is skipped rather than left to fail in pip.
DIR=$(cd "$(dirname "$0")/.." && pwd)
LOCK="$DIR/requirements.lock"
SYS=""
for c in python3.14 python3.13 python3.12 python3; do
  p=$(command -v "$c" 2>/dev/null) || continue
  if "$p" -c 'import sys; sys.exit(0 if (3, 12) <= sys.version_info[:2] <= (3, 14) else 1)' 2>/dev/null; then SYS=$p; break; fi
done
[ -n "$SYS" ] || { echo "redact: error: setup: Python 3.12, 3.13 or 3.14 is required (macOS: brew install python@3.14)" >&2; exit 1; }
REAL_HOME=$("$SYS" -c 'import os, pwd; print(pwd.getpwuid(os.getuid()).pw_dir)')
KEY=$("$SYS" -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest()[:12])' "$LOCK")
VER=$("$SYS" -c 'import sys; print("%d.%d" % sys.version_info[:2])')
VENV="${REDACT_CACHE_DIR:-$REAL_HOME/.cache/nexus-redact}/venv-$KEY-py$VER"
if [ ! -f "$VENV/.complete" ]; then
  echo "redact: first run: installing hash-locked Python packages into $VENV (one time)" >&2
  rm -rf "$VENV"
  mkdir -p "$(dirname "$VENV")"
  if [ -d "$DIR/vendor/wheels" ]; then SRC="--no-index --find-links $DIR/vendor/wheels"; else SRC="--index-url https://pypi.org/simple"; fi
  # shellcheck disable=SC2086
  "$SYS" -m venv "$VENV" >&2 \
    && "$VENV/bin/python" -m pip install -q --isolated --disable-pip-version-check --no-deps \
         --require-hashes --only-binary=:all: $SRC -r "$LOCK" >&2 \
    && "$VENV/bin/python" -E -s -c 'import onnxruntime, tokenizers, numpy, anydoc' >&2 \
    && : > "$VENV/.complete" \
    || { echo "redact: error: setup: dependency install failed" >&2; rm -rf "$VENV"; exit 1; }
fi
echo "$VENV/bin/python"
