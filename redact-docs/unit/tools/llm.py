"""Layer 3: a local LLM that judges what the first two layers left. It never writes output.

The code collects the candidate strings still visible in each chunk of the
masked text: runs of capitalized words, and tokens that carry digits. The
LLM sees the chunk and the numbered candidates, and answers with one type per
candidate (a PII class ID, or NONE), in JSON whose shape a schema fixes. So it
can only nominate strings that occur in the text; it cannot invent,
repeat or reword one. A candidate it types as PII is replaced everywhere it
occurs. Each chunk reaches llama.cpp on stdin, never as an argument or a file.
Output that is not the expected JSON fails the run closed.
"""
import json
import os
import re
import shutil
import subprocess

from spans import MARKER, STOPWORDS, TITLES, Span, is_label_only, value_regex

CHUNK_CHARS = 1400
OVERLAP_CHARS = 200
MAX_CANDIDATES = 48
N_PREDICT = 1024
BINARY = "llama-completion"
FALLBACK_DIRS = ("/opt/homebrew/bin", "/usr/local/bin")
INSTALL_HINT = ("llama.cpp not found: install it (macOS: brew install llama.cpp) or put llama-completion "
                "on PATH, e.g. PATH=/dir/with/llama:$PATH nexus run ...")

CONNECTOR = r"(?:of|and|&|de|del|da|la|le|van|von|der|di|du|bin|ibn|al)"
WORD = r"(?:[A-Z][\w'’]*(?:-[A-Za-z][\w'’]*)*\.?|[A-Z]\.)"
CAPS_RUN = re.compile(r"(?<![\w\[])" + WORD + r"(?:[ \t]+(?:" + CONNECTOR + r"[ \t]+)?(?:" + WORD + r"|#?\d[\w-]*))*")

EXAMPLE_TEXT = ("Name: [REDACTED] Phone: [REDACTED]\n"
                "Seen today by Dr. Okafor at Lakeview Example Clinic. Her brother Luis drove her in from "
                "Springfield.\nDiagnosis: Asthma (J45.909)\n- Albuterol 90 mcg inhaler as needed\n"
                "- Tonsillectomy, [REDACTED]\nWorks as a Paralegal.")
EXAMPLE_CANDIDATES = ["Okafor", "Lakeview Example Clinic", "Luis", "Springfield", "Asthma", "Albuterol",
                      "Tonsillectomy", "Paralegal"]
EXAMPLE_TYPES = ["PERSON", "ORGANIZATION", "PERSON", "CITY", "NONE", "NONE", "NONE", "OCCUPATION"]
EXAMPLE_HEALTH = {"Asthma", "Albuterol", "Tonsillectomy"}  # typed HEALTH_INFO when a profile turns it on
HEALTH_RULE_OFF = ("- Drug names, diagnoses, procedures, allergies, body measurements, products and vehicle makes "
                   "are NONE: they describe a person's health or things, not who the person is.")
HEALTH_RULE_ON = ("- Drug names, diagnoses, diagnosis codes, procedures, allergies, test results and blood type "
                  "are HEALTH_INFO. Body measurements, products and vehicle makes are NONE.")


class LLMError(Exception):
    pass


def find_binary(unit_dir):
    """The unit's own bin/ (sealed builds), then PATH, then the usual install locations."""
    search = [os.path.join(unit_dir, "bin"), os.environ.get("PATH", os.defpath), *FALLBACK_DIRS]
    found = shutil.which(BINARY, path=os.pathsep.join(search))
    if not found:
        raise LLMError(INSTALL_HINT)
    return found


def chunks(text):
    """Deterministic (start, end) windows that prefer to end at a line or sentence break."""
    out, start, n = [], 0, len(text)
    while start < n:
        end = min(n, start + CHUNK_CHARS)
        if end < n:
            cut = max(text.rfind("\n", start + CHUNK_CHARS // 2, end), text.rfind(". ", start + CHUNK_CHARS // 2, end))
            if cut > start:
                end = cut + 1
        out.append((start, end))
        if end >= n:
            break
        start = max(end - OVERLAP_CHARS, start + 1)
        while start < end and text[start - 1].isalnum():
            start += 1
    return out


def candidates(text, form_words):
    """Distinct runs of capitalized words still visible in text, label words trimmed off both ends.

    Numbers are left to the rules and the classifier: a 4B model cannot tell a
    diagnosis code from an account number reliably, and a wrong guess there
    removes clinical content.
    """
    def plain(w):
        w = w.lower().strip(".,")
        return w in STOPWORDS or w in form_words or w.isdigit()

    found = []
    for m in CAPS_RUN.finditer(text):
        words = m.group().rstrip(".").split()
        while words and plain(words[0]):
            words.pop(0)
        while len(words) > 1 and plain(words[-1]) and words[-2].lower().strip(".") not in TITLES:
            words.pop()
        if words and plain(words[-1]) and len(words) == 1:
            words.pop()
        value = " ".join(words)
        if len(value) < 2 or MARKER.strip("[]") in value or is_label_only(value, form_words):
            continue
        if value not in found:
            found.append(value)
    return found


class Detector:
    def __init__(self, unit_dir, model_path, cfg, gpu=True, threads=4):
        self.binary = find_binary(unit_dir)
        self.model_path = model_path
        self.cfg = cfg
        self.gpu = gpu
        self.threads = threads
        with open(os.path.join(unit_dir, "prompts", "detector.txt"), encoding="utf-8") as f:
            template = f.read()
        self.classes = [cid for cid, c in cfg.classes.items() if cid in cfg.active and "llm" in c.get("layers", [])]
        health_on = "HEALTH_INFO" in self.classes
        lines = [f"- {cid}: {cfg.classes[cid]['name']}" for cid in self.classes]
        health = "" if health_on else "diagnoses, medications, "
        lines.append(f"- NONE: not personal information (labels, headings, {health}measurements, ordinary words)")
        self.system = (template.replace("{CLASSES}", "\n".join(lines))
                       .replace("{HEALTH_RULE}", HEALTH_RULE_ON if health_on else HEALTH_RULE_OFF))
        self.types = self.classes + ["NONE"]
        self.example_types = [("HEALTH_INFO" if health_on and c in EXAMPLE_HEALTH else t)
                              for c, t in zip(EXAMPLE_CANDIDATES, EXAMPLE_TYPES)]

    def schema(self, n):
        props = {str(i + 1): {"type": "string", "enum": self.types} for i in range(n)}
        return json.dumps({"type": "object", "properties": props, "required": list(props),
                           "additionalProperties": False}, separators=(",", ":"))

    def command(self, n):
        return [self.binary, "-m", self.model_path, "-f", "/dev/stdin", "-no-cnv", "--no-display-prompt",
                "--temp", "0", "--seed", "42", "-n", str(N_PREDICT), "-c", "4096", "-t", str(self.threads),
                "-b", "512", "--no-warmup", "-ngl", "99" if self.gpu else "0", "-j", self.schema(n)]

    @staticmethod
    def user_turn(text, cands):
        listing = "\n".join(f"{i + 1}. {c}" for i, c in enumerate(cands))
        return f"Document:\n{text}\n\nStrings:\n{listing}"

    def ask(self, chunk_text, cands):
        """[type] for each candidate, from one llama.cpp call."""
        example = json.dumps({str(i + 1): t for i, t in enumerate(self.example_types)})
        prompt = (f"<|im_start|>system\n{self.system}<|im_end|>\n"
                  f"<|im_start|>user\n{self.user_turn(EXAMPLE_TEXT, EXAMPLE_CANDIDATES)}<|im_end|>\n"
                  f"<|im_start|>assistant\n{example}<|im_end|>\n"
                  f"<|im_start|>user\n{self.user_turn(chunk_text, cands)}<|im_end|>\n<|im_start|>assistant\n")
        try:
            r = subprocess.run(self.command(len(cands)), input=prompt, capture_output=True, text=True, timeout=600)
        except subprocess.TimeoutExpired:
            raise LLMError("llama.cpp timed out") from None
        except OSError:
            raise LLMError("llama.cpp could not start") from None
        if r.returncode != 0:
            raise LLMError(f"llama.cpp exited with status {r.returncode}")
        try:
            data = json.loads(r.stdout.replace("[end of text]", "").strip())
            types = [data[str(i + 1)] for i in range(len(cands))]
        except (ValueError, KeyError, TypeError):
            raise LLMError("llama.cpp output was not the expected JSON") from None
        if any(t not in self.types for t in types):
            raise LLMError("llama.cpp answered with an unknown type")
        return types

    def detect(self, masked):
        """Spans, in original-text offsets, for every candidate the LLM typed as PII."""
        text = masked.text
        typed = {}
        for start, end in chunks(text):
            chunk = text[start:end]
            cands = candidates(chunk, self.cfg.form_words)
            for i in range(0, len(cands), MAX_CANDIDATES):
                batch = cands[i:i + MAX_CANDIDATES]
                for value, t in zip(batch, self.ask(chunk, batch)):
                    if t != "NONE":
                        typed.setdefault(value, t)
        out = []
        for value, cid in typed.items():
            out += spans_for(text, value, cid, self.cfg, masked)
        return out


def spans_for(text, value, cid, cfg, masked):
    """Every occurrence of a typed candidate, mapped back to the original text."""
    if cid not in cfg.active:
        return []
    out = []
    for m in value_regex(value, cfg.classes[cid].get("match", "text")).finditer(text):
        orig = masked.to_orig(m.start(), m.end())
        if orig:
            out.append(Span(orig[0], orig[1], cid, "llm", 0))
    return out
