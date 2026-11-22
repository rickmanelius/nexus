"""Find the unit's two models, and the unit's own name and version.

nexus v0.1.0 hands a script unit only models[0] (the LLM) as NEXUS_MODEL_PATH.
The classifier is found by its pinned digest in the same content-addressed
store: first the directory holding NEXUS_MODEL_PATH, then the real user's
~/.nexusrun. NEXUS_MODEL_PATH_CLASSIFIER, if a later nexus sets it, wins.
"""
import json
import os
import pwd
import re


class ModelError(Exception):
    """A missing or unusable model. needs_install: the fix is `nexus install <unit>`."""

    def __init__(self, message, needs_install=True):
        super().__init__(message)
        self.needs_install = needs_install


def unit_identity(unit_dir):
    """(name, version) from the unit's own nexus.yaml, so a renamed or re-versioned build reports itself."""
    try:
        with open(os.path.join(unit_dir, "nexus.yaml"), encoding="utf-8") as f:
            manifest = f.read()
    except OSError:
        return "redact", "dev"
    name = re.search(r"^name:\s*(\S+)", manifest, re.M)
    version = re.search(r"^version:\s*(\S+)", manifest, re.M)
    return (name.group(1) if name else "redact", version.group(1) if version else "dev")


def real_home():
    """nexus points HOME at the run directory; the password database knows the real one."""
    return pwd.getpwuid(os.getuid()).pw_dir


def load_pins(unit_dir):
    with open(os.path.join(unit_dir, "models.json"), encoding="utf-8") as f:
        return json.load(f)


def _check(path, pin, what):
    try:
        size = os.stat(path).st_size
    except OSError:
        return None
    if size != pin["size_bytes"]:
        raise ModelError(f"{what} model in the store is incomplete or wrong")
    try:
        with open(path, "rb") as f:
            f.read(1)
    except OSError:
        raise ModelError(f"{what} model exists but cannot be read; on Linux the nexus store must sit "
                         "under your home directory for the sandbox to allow it", needs_install=False) from None
    return path


def llm_path(pins, env=os.environ):
    path = env.get("NEXUS_MODEL_PATH", "")
    found = _check(path, pins["llm"], "LLM") if path else None
    if not found:
        raise ModelError("LLM model not available")
    return found


def classifier_path(pins, env=os.environ, home=None):
    pin = pins["classifier"]
    explicit = env.get("NEXUS_MODEL_PATH_CLASSIFIER", "")
    if explicit:
        found = _check(explicit, pin, "classifier")
        if found:
            return found
        raise ModelError("classifier model not available")
    candidates = []
    if env.get("NEXUS_MODEL_PATH"):
        candidates.append(os.path.join(os.path.dirname(env["NEXUS_MODEL_PATH"]), pin["sha256"]))
    candidates.append(os.path.join(home or real_home(), ".nexusrun", "blobs", "sha256", pin["sha256"]))
    for path in candidates:
        found = _check(path, pin, "classifier")
        if found:
            return found
    raise ModelError("classifier model not available")
