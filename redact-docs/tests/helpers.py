"""Paths and loaders for the redact-docs tests (standard library only; no models needed)."""
import json
import os
import random
import string
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RELEASE = os.path.dirname(HERE)
UNIT = os.path.join(RELEASE, "unit")
TOOLS = os.path.join(UNIT, "tools")
DOCS = os.path.join(RELEASE, "docs")
if TOOLS not in sys.path:
    sys.path.insert(0, TOOLS)

import profiles  # noqa: E402


def taxonomy():
    with open(os.path.join(UNIT, "pii", "taxonomy.json"), encoding="utf-8") as f:
        return json.load(f)


def config(profile=None, name="strict"):
    """A Config from the unit's taxonomy and either strict or the given profile dict."""
    tax = profiles.load_taxonomy(os.path.join(UNIT, "pii", "taxonomy.json"))
    if profile is None:
        with open(os.path.join(UNIT, "pii", "profiles", "strict.json"), encoding="utf-8") as f:
            profile = json.load(f)
    return profiles.Config(tax, profile, name)


def fake(seed, n, alphabet=string.ascii_letters + string.digits):
    """A fixed filler for a fake token, built at run time so no token-shaped string sits in the repo."""
    r = random.Random(seed)
    return "".join(r.choice(alphabet) for _ in range(n))
