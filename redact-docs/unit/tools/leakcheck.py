"""Check a redacted output against a value-level answer key.

A value leaks fully when it is still in the output, and partly when any
identifying component survives: a name token, a house number with its street
name, or a digit run of four or more. Results carry row numbers and class IDs
only, never values.

The matching here is its own, and looser than the pipeline's, on purpose: a
blind spot the two shared would read as a clean result. The output is
normalized (NFKC, no invisible format characters), a name token also counts in
capitals and, when it has five or more letters, in any case, and digit runs
count even when glued to letters ("MRN00482913").
"""
import re
import unicodedata

from spans import is_digit_value, name_tokens

REPORTED_TIERS = ("A", "B", "H")
ROW = re.compile(r"^\|\s*(\d+)\s*\|\s*([^|]*)\|\s*([^|]*)\|\s*([A-Z][A-Z0-9_]*)\s*\|\s*`([^`]+)`\s*\|\s*$")
NOT_LETTER_BEFORE, NOT_LETTER_AFTER = r"(?<![^\W\d_])", r"(?![^\W\d_])"
NOT_ALNUM_BEFORE, NOT_ALNUM_AFTER = r"(?<![^\W_])", r"(?![^\W_])"


def load_key(path):
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            m = ROW.match(line.strip())
            if m:
                rows.append({"n": int(m.group(1)), "type": m.group(3).strip(), "cls": m.group(4),
                             "value": m.group(5)})
    return rows


def normalize(text):
    text = unicodedata.normalize("NFKC", text)
    return "".join(ch for ch in text if unicodedata.category(ch) != "Cf")


def components(value, cdef):
    kind = cdef.get("components", "whole")
    if kind == "name_tokens":
        return name_tokens(value.replace("/s/", " "))
    if kind == "digits":
        return re.findall(r"\d{4,}", value)
    if kind == "address":
        m = re.match(r"\s*(\d+\w*\s+[A-Za-z][\w.]*)", value)
        return [m.group(1)] if m else []
    return []


def digits_found(output, value):
    """Five or more digits: across separators and glued to letters. Fewer (a CVV, a last four):
    contiguous and standing alone, or every diagnosis code and dosage would count."""
    digits = re.sub(r"\D", "", value)
    if len(digits) < 5:
        body = r"[\s/.-]{1,3}".join(re.findall(r"\d+", value))  # keep the value's own grouping, e.g. 09/28
        return bool(re.search(r"(?<![\w.])" + body + r"(?![\w]|\.\d)", output))
    body = r"[\s().+/-]{0,3}".join(re.escape(d) for d in digits)
    return bool(re.search(r"(?<!\d)" + body + r"(?!\d)", output))


def token_found(output, token):
    """A name token as written, in capitals, or (five letters or more) in any case."""
    variants = [(token, 0), (token.upper(), 0)]
    if len(token) >= 5:
        variants.append((token, re.IGNORECASE))
    return any(re.search(NOT_LETTER_BEFORE + re.escape(v) + NOT_LETTER_AFTER, output, flags)
               for v, flags in variants)


def text_found(output, value):
    """Case-insensitive, whitespace-tolerant search for a multi-character value."""
    chars = [re.escape(c) for c in value if not c.isspace()]
    if not chars:
        return False
    body = r"\s*".join(chars)
    start = NOT_ALNUM_BEFORE if value[:1].isalnum() else ""
    end = NOT_ALNUM_AFTER if value[-1:].isalnum() else ""
    return bool(re.search(start + body + end, output, re.IGNORECASE))


def value_found(output, value):
    value = normalize(value).strip()
    if is_digit_value(value):
        return digits_found(output, value)
    if " " not in value and value.isalpha():
        return token_found(output, value)
    return text_found(output, value)


def component_found(output, comp, cdef):
    if cdef.get("components") == "name_tokens":
        return token_found(output, comp)
    if comp.isdigit():
        return digits_found(output, comp)
    return text_found(output, comp)


def check(output, key, cfg):
    """One result per distinct in-scope (class, value) pair."""
    output = normalize(output)
    results, seen = [], set()
    for row in key:
        cdef = cfg.classes.get(row["cls"])
        if cdef is None or row["cls"] not in cfg.active or (row["cls"], row["value"]) in seen:
            continue
        seen.add((row["cls"], row["value"]))
        full = value_found(output, row["value"])
        partial = full or any(component_found(output, c, cdef) for c in components(row["value"], cdef))
        results.append({"n": row["n"], "cls": row["cls"], "tier": cdef["tier"], "full": full, "partial": partial})
    return results


def summary(results):
    out = {}
    for tier in REPORTED_TIERS:
        rs = [r for r in results if r["tier"] == tier]
        out[tier] = {"values": len(rs), "full": sum(r["full"] for r in rs), "partial": sum(r["partial"] for r in rs),
                     "classes": sorted({r["cls"] for r in rs if r["partial"]})}
    return out
