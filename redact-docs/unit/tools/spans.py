"""Spans, the value matcher, merging, masking, placeholders and the report.

Every layer returns Span(start, end, cls, layer) over the original text. The
merge is a union: overlapping spans become one covering both, named after the
longest member, so no layer can un-redact another. Placeholders are keyed
by class and normalized value, so a value gets one [TAG_N] everywhere.
"""
import re
import unicodedata
from collections import namedtuple

Span = namedtuple("Span", "start end cls layer prio")
Span.__new__.__defaults__ = (0,)
Merged = namedtuple("Merged", "start end cls layers")
Segment = namedtuple("Segment", "masked_start masked_end orig_start orig_end is_mask")

LAYERS = ("rules", "classifier", "llm")
PLACEHOLDER_RE = re.compile(r"\[[A-Z][A-Z0-9_]*(?:_\d+)?\]")
TITLES = {"dr", "mr", "mrs", "ms", "mx", "md", "do", "rn", "np", "pa", "phd", "dds", "jr", "sr", "ii", "iii", "iv", "s"}
# State codes that are also labels, credentials or words ("Patient ID", "Dr. Rao, MD", "OR").
# Each is still redacted where it sits next to a ZIP; it is just not chased through the text.
AMBIGUOUS_STATE_CODES = {"AL", "AS", "CO", "DE", "HI", "ID", "IN", "LA", "MA", "MD", "ME", "MI", "MS", "OH",
                         "OK", "OR", "PA"}
TITLE_THEN_NAME = re.compile(r"\b(?:Dr|Mr|Mrs|Ms|Mx|Prof)\.?\s+[A-Z]")
NEVER_PROPAGATED = {"the", "and", "patient", "name", "family", "history", "example", "clinic", "form", "page",
          "spouse", "child", "mother", "father", "date", "phone", "email", "home", "work", "mobile"}


def nfkc(s):
    return unicodedata.normalize("NFKC", s)


def is_digit_value(value):
    v = nfkc(value)
    return bool(re.search(r"\d", v)) and not re.search(r"[A-Za-z]", re.sub(r"\b(?:x|ext)\.?\s*(?=\d)", "", v))


def value_regex(value, mode):
    """Regex that finds value in text.

    mode "digits": digit values match with any separators between digits.
    mode "casefold": case-insensitive. mode "name": case-sensitive for one word,
    case-insensitive for several. Anything else: case-sensitive. Every mode
    tolerates whitespace (line breaks included) between characters and needs
    word boundaries at both ends.
    """
    v = nfkc(value).strip()
    if mode == "digits" and is_digit_value(v):
        digits = re.sub(r"\D", "", v)
        body = r"[\s().+/-]{0,3}".join(re.escape(d) for d in digits)
        return re.compile(r"(?<![\w.])" + body + r"(?![\w])")
    out, prev_space = [], False
    for ch in v:
        if ch.isspace():
            prev_space = True
            continue
        if out:
            out.append(r"\s+" if prev_space else r"\s*")
        out.append(re.escape(ch))
        prev_space = False
    body = "".join(out)
    flags = 0
    if mode == "casefold" or (mode == "name" and len(v.split()) > 1):
        flags = re.IGNORECASE
    start = r"(?<!\w)" if re.match(r"\w", v) else ""
    end = r"(?!\w)" if re.search(r"\w$", v) else ""
    return re.compile(start + body + end, flags)


def find_all(text, value, mode):
    return [(m.start(), m.end()) for m in value_regex(value, mode).finditer(text)]


def normalize_key(value, mode):
    v = nfkc(value)
    if mode == "digits" and is_digit_value(v):
        return re.sub(r"\D", "", v)
    if mode == "casefold":
        return re.sub(r"\s+", "", v).casefold()
    v = re.sub(r"\s+", " ", v).strip()
    return v.casefold() if mode == "name" and " " in v else v


def merge(spans):
    """Union of overlapping spans; the longest member names the class."""
    out = []
    for s in sorted(spans, key=lambda s: (s.start, -s.end)):
        if s.end <= s.start:
            continue
        if out and s.start < out[-1][1]:
            group = out[-1]
            group[1] = max(group[1], s.end)
            group[2].append(s)
        else:
            out.append([s.start, s.end, [s]])
    merged = []
    for start, end, members in out:
        best = max(members, key=lambda s: (s.end - s.start, s.prio, -LAYERS.index(s.layer) if s.layer in LAYERS else 0))
        merged.append(Merged(start, end, best.cls, frozenset(m.layer for m in members)))
    return merged


def as_spans(merged):
    return [Span(m.start, m.end, m.cls, layer, 0) for m in merged for layer in sorted(m.layers)]


MARKER = "[REDACTED]"
STOPWORDS = {"a", "an", "and", "as", "at", "by", "for", "from", "in", "is", "it", "my", "of", "on", "or", "our",
             "she", "he", "the", "their", "to", "was", "we", "with", "her", "his", "that", "this", "be", "been",
             "same", "made", "asked", "said", "told", "statements", "emailed", "mailed", "rather", "than"}


def is_label_only(value, form_words):
    """True when value is made only of label words, common words and titles: a label, not a value.

    A title followed by a capitalized word ("Dr. Page", "Ms. Child") is a name, whatever the word.
    """
    if re.search(r"[\d@]", value) or MARKER in value or TITLE_THEN_NAME.search(value):
        return False
    words = re.findall(r"[^\W\d_]+(?:['.][^\W\d_]+)*", value)
    return bool(words) and all(w.lower().strip(".") in form_words or w.lower() in STOPWORDS or
                               w.lower().strip(".") in TITLES for w in words)


class Masked:
    """Text with merged spans replaced by one neutral marker, and the way back."""

    def __init__(self, text, merged):
        self.segments = []
        parts, pos, mpos = [], 0, 0
        for m in sorted(merged):
            if m.start > pos:
                chunk = text[pos:m.start]
                parts.append(chunk)
                self.segments.append(Segment(mpos, mpos + len(chunk), pos, m.start, False))
                mpos += len(chunk)
            parts.append(MARKER)
            self.segments.append(Segment(mpos, mpos + len(MARKER), m.start, m.end, True))
            mpos += len(MARKER)
            pos = m.end
        if pos < len(text):
            parts.append(text[pos:])
            self.segments.append(Segment(mpos, mpos + len(text) - pos, pos, len(text), False))
        self.text = "".join(parts)

    def to_orig(self, ms, me):
        """Map a masked range back to the original text, or None if it covers only markers."""
        start = end = None
        plain = False
        for a, b, oa, ob, is_mask in self.segments:
            if b <= ms or a >= me:
                continue
            if is_mask:
                s, e = oa, ob
            else:
                s, e = oa + max(ms, a) - a, oa + min(me, b) - a
                if re.search(r"\w", self.text[max(ms, a):min(me, b)]):
                    plain = True
            start = s if start is None else min(start, s)
            end = e if end is None else max(end, e)
        return (start, end) if plain and start is not None else None


def name_tokens(value):
    """Identifying tokens of a name: no titles, no initials, no punctuation."""
    out = []
    for tok in re.findall(r"[^\W\d_][\w'-]*", nfkc(value)):
        t = tok.strip("'-")
        if len(t) >= 2 and t.lower() not in TITLES:
            out.append(t)
    return out


def propagate(text, merged, cfg, allow_keys):
    """Every other occurrence of a detected value, and of each name token, joins its class."""
    covered = [(m.start, m.end) for m in merged]
    extra = []
    seen = set()
    for m in merged:
        c = cfg.classes[m.cls]
        if not c.get("propagate", True):
            continue
        value = text[m.start:m.end]
        if m.cls == "STATE" and value.strip() in AMBIGUOUS_STATE_CODES:
            continue
        mode = c.get("match", "text")
        values = [value]
        if m.cls == "PERSON":
            values += [t for t in name_tokens(value)
                       if t[0].isupper() and t.lower() not in NEVER_PROPAGATED and len(t) >= 3]
        for v in values:
            key = (m.cls, normalize_key(v, mode))
            if key in seen or normalize_key(v, "casefold") in allow_keys:
                continue
            seen.add(key)
            if mode == "digits" and len(re.sub(r"\D", "", v)) < 4:
                continue
            if mode != "digits" and len(v.strip()) < 2:
                continue
            for s, e in find_all(text, v, "name" if m.cls == "PERSON" else mode):
                if not any(s < b and a < e for a, b in covered):
                    extra.append(Span(s, e, m.cls, sorted(m.layers)[0], -1))
    return extra


def bridge_names(text, merged):
    """Join name spans that touch or are split by one middle name or initial: 'Eleanor [Marguerite] Whitfield'."""
    out = []
    for m in merged:
        if out and out[-1].cls == "PERSON" and m.cls == "PERSON":
            gap = text[out[-1].end:m.start]
            if re.fullmatch(r"[ \t]+(?:(?:[A-Z][a-z'-]+\.?|[A-Z]\.)[ \t]+)?", gap):
                p = out.pop()
                out.append(Merged(p.start, m.end, "PERSON", p.layers | m.layers))
                continue
        out.append(m)
    return out


def assign(text, merged, cfg):
    """[(Merged, placeholder)] in text order, one placeholder per (class, normalized value)."""
    numbers, keys, out = {}, {}, []
    for m in sorted(merged):
        c = cfg.classes[m.cls]
        key = (m.cls, normalize_key(text[m.start:m.end], c.get("match", "text")))
        if key not in keys:
            numbers[m.cls] = numbers.get(m.cls, 0) + 1
            keys[key] = f"[{c['tag']}_{numbers[m.cls]}]"
        out.append((m, keys[key], key))
    return out


def render(text, assigned):
    parts, pos = [], 0
    for m, ph, _ in assigned:
        parts.append(text[pos:m.start])
        parts.append(ph)
        pos = m.end
    parts.append(text[pos:])
    return "".join(parts)


def summary_rows(assigned, cfg):
    rows = {}
    for m, _, key in assigned:
        r = rows.setdefault(m.cls, {"keys": set(), "count": 0, "layers": set()})
        r["keys"].add(key)
        r["count"] += 1
        r["layers"] |= m.layers
    order = list(cfg.classes)
    out = []
    for cid in sorted(rows, key=order.index):
        c, r = cfg.classes[cid], rows[cid]
        layers = ", ".join(l for l in LAYERS if l in r["layers"])
        out.append((c["tag"], c["name"], c["tier"], len(r["keys"]), r["count"], layers))
    return out


def table(rows):
    lines = ["| Placeholder | PII class | Tier | Distinct values | Occurrences | Caught by |",
             "|---|---|---|---|---|---|"]
    for tag, name, tier, distinct, count, layers in rows:
        lines.append(f"| `[{tag}_n]` | {name} | {tier} | {distinct} | {count} | {layers} |")
    if not rows:
        lines.append("| none | no PII found | | 0 | 0 | |")
    return "\n".join(lines)
