"""Load the PII taxonomy and a profile overlay, and validate both.

A profile is JSON data, never code. It may turn Tier B classes off, turn
Tier H classes on, add client classes, add patterns, and list terms that must
always (deny) or never (allow) be redacted. Errors name the profile and the
offending field, never a pattern or a term, since those can be client data.
"""
import json
import os
import re

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
TAG_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
TIERS = ("A", "B", "C", "H")


class ProfileError(Exception):
    pass


def load_taxonomy(path):
    with open(path, encoding="utf-8") as f:
        tax = json.load(f)
    ids, tags = set(), set()
    for c in tax["classes"]:
        if c["id"] in ids or c["tag"] in tags:
            raise ProfileError(f"taxonomy: duplicate class {c['id']}")
        if not TAG_RE.match(c["id"]) or not TAG_RE.match(c["tag"]) or c["tier"] not in TIERS:
            raise ProfileError(f"taxonomy: bad class {c['id']}")
        ids.add(c["id"])
        tags.add(c["tag"])
    return tax


class Config:
    """The active classes and tuning data for one run."""

    def __init__(self, taxonomy, profile, name):
        self.name = name
        self.threshold = float(taxonomy["classifier"]["threshold"])
        self.window_words = int(taxonomy["classifier"]["window_words"])
        self.overlap_words = int(taxonomy["classifier"]["overlap_words"])
        self.form_words = {w.lower() for w in taxonomy.get("form_words", [])}
        self.classes = {c["id"]: dict(c) for c in taxonomy["classes"]}
        self._apply(profile)

    def _fail(self, field, why):
        raise ProfileError(f"profile {self.name}: {field}: {why}")

    def _apply(self, p):
        if not isinstance(p, dict):
            self._fail("file", "not a JSON object")
        known = {"name", "about", "base", "disable", "enable", "classes", "patterns", "deny", "allow",
                 "classifier_threshold"}
        for key in p:
            if key not in known:
                self._fail(key, "unknown field")
        if p.get("name") != self.name:
            self._fail("name", "must match the file name")
        if self.name != "strict" and p.get("base", "strict") != "strict":
            self._fail("base", "only strict is supported")

        for i, c in enumerate(p.get("classes", [])):
            f = f"classes[{i}]"
            if not isinstance(c, dict) or not TAG_RE.match(str(c.get("id", ""))) or not TAG_RE.match(str(c.get("tag", ""))):
                self._fail(f, "needs an upper-case id and tag")
            if c["id"] in self.classes or any(k["tag"] == c["tag"] for k in self.classes.values()):
                self._fail(f, "id or tag already exists")
            if c.get("tier", "A") not in ("A", "B"):
                self._fail(f, "tier must be A or B")
            self.classes[c["id"]] = {
                "id": c["id"], "tag": c["tag"], "tier": c.get("tier", "A"), "name": c.get("name", c["id"]),
                "definition": c.get("definition", ""), "match": c.get("match", "text"),
                "components": c.get("components", "whole"), "propagate": bool(c.get("propagate", True)),
                "labels": [], "classifier_labels": [], "layers": ["rules"], "client": True,
            }

        self.active = {cid for cid, c in self.classes.items() if c["tier"] in ("A", "B")}
        for i, cid in enumerate(p.get("disable", [])):
            c = self.classes.get(cid)
            if c is None:
                self._fail(f"disable[{i}]", "unknown class")
            if c["tier"] == "A":
                self._fail(f"disable[{i}]", "Tier A classes cannot be turned off")
            self.active.discard(cid)
        for i, cid in enumerate(p.get("enable", [])):
            if cid not in self.classes or self.classes[cid]["tier"] == "C":
                self._fail(f"enable[{i}]", "unknown class")
            self.active.add(cid)

        self.patterns = []
        for i, pat in enumerate(p.get("patterns", [])):
            f = f"patterns[{i}]"
            if not isinstance(pat, dict) or pat.get("class") not in self.classes:
                self._fail(f, "class is missing or unknown")
            try:
                rx = re.compile(pat["regex"])
                label = re.compile(pat["label"], re.I) if pat.get("label") else None
            except (KeyError, TypeError, re.error):
                self._fail(f, "regex or label does not compile")
            self.patterns.append((pat["class"], rx, label))

        self.deny = []
        for i, d in enumerate(p.get("deny", [])):
            f = f"deny[{i}]"
            ok = isinstance(d, dict) and d.get("class") in self.classes and \
                isinstance(d.get("term"), str) and d["term"].strip()
            if not ok:
                self._fail(f, "needs a known class and a term")
            self.deny.append((d["class"], d["term"]))

        self.allow = []
        for i, a in enumerate(p.get("allow", [])):
            if not isinstance(a, str) or not a.strip():
                self._fail(f"allow[{i}]", "must be a non-empty string")
            self.allow.append(a)

        if "classifier_threshold" in p:
            t = p["classifier_threshold"]
            if not isinstance(t, (int, float)) or not 0.05 <= t <= 0.95:
                self._fail("classifier_threshold", "must be between 0.05 and 0.95")
            self.threshold = float(t)

    def tag(self, cid):
        return self.classes[cid]["tag"]

    def classifier_labels(self):
        """[(label, class_id)] for every active class, each label once (the first class wins)."""
        pairs = {}
        for cid in sorted(self.active):
            for label in self.classes[cid].get("classifier_labels", []):
                pairs.setdefault(label, cid)
        return list(pairs.items())


def profile_path(name, unit_dir, user_dir):
    """strict always comes from the unit; any other name from the user's directory, then the unit."""
    if not NAME_RE.match(name):
        raise ProfileError("profile name must be lower-case letters, digits, - or _")
    candidates = [os.path.join(unit_dir, "pii", "profiles", name + ".json")]
    if name != "strict":
        candidates.insert(0, os.path.join(user_dir, name + ".json"))
    for path in candidates:
        if os.path.isfile(path):
            return path
    raise ProfileError(f"profile {name} not found")


def load(name, unit_dir, user_dir):
    tax = load_taxonomy(os.path.join(unit_dir, "pii", "taxonomy.json"))
    path = profile_path(name, unit_dir, user_dir)
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        raise ProfileError(f"profile {name}: file is not readable JSON") from None
    return Config(tax, data, name)
