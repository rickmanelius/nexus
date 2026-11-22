#!/bin/sh
# redact 0.5 entrypoint: a Python with the hash-locked dependencies, then the pipeline.
# The prompt arrives in NEXUS_PROMPT; see tools/pipeline.py for the forms it takes.
DIR=$(cd "$(dirname "$0")/.." && pwd)
PY=$(sh "$DIR/tools/bootstrap.sh") || exit 3
exec "$PY" -E -s "$DIR/tools/pipeline.py"
