#!/usr/bin/env python3
"""redact 0.5: local conversion, then rules, classifier and LLM, then one report.

Run by nexus with the prompt in NEXUS_PROMPT:
  @/abs/path/doc.pdf      a document (anydoc converts it locally; .txt and .md are read as text)
  any other text          the text itself
  [profile=<name>] ...    pick a profile (default strict, or REDACT_PROFILE)
  [selftest]              clean the bundled fictitious intake form and check it against its key
  [verbose] ...           progress counts on stderr (never text)

stdout carries only the report: a header line, the cleaned Markdown and a
table of what was replaced. Any failure prints one line naming the stage,
never document text or the input's name, and exits non-zero (fail closed).
"""
import os
import re
import shutil
import signal
import socket
import sys
import tempfile
import unicodedata

TOOLS = os.path.dirname(os.path.abspath(__file__))
UNIT_DIR = os.path.dirname(TOOLS)
sys.path.insert(0, TOOLS)

import credentials  # noqa: E402
import leakcheck  # noqa: E402
import models  # noqa: E402
import profiles  # noqa: E402
import classifier as clf_mod  # noqa: E402
import llm as llm_mod  # noqa: E402
from spans import (LAYERS, Masked, Span, as_spans, assign, bridge_names, is_label_only, merge,  # noqa: E402
                   normalize_key, propagate, render, summary_rows, table)

NAME, VERSION = models.unit_identity(UNIT_DIR)
TEXT_EXT = (".txt", ".text", ".md", ".markdown")
PREFIX = re.compile(r"^\s*\[(profile=[a-z0-9][a-z0-9_-]*|selftest|verbose)\]", re.I)
TRIM = " \t\r\n_*,;:"
# Where the unit's own messages go. main() points fd 2 at /dev/null for the run, so a
# native library (anydoc, tokenizers, onnxruntime) that panics or logs can never write
# document text into the stream nexus prints; ERR keeps a handle on the real stderr.
ERR = sys.stderr


class Stop(Exception):
    def __init__(self, code, stage, message):
        super().__init__(message)
        self.code, self.stage, self.message = code, stage, message


def block_network():
    """This process never needs the network; make sure nothing in it can use it."""
    def refuse(*_a, **_k):
        raise OSError("network disabled in redact")
    socket.socket.connect = refuse
    socket.socket.connect_ex = refuse
    socket.create_connection = refuse
    socket.getaddrinfo = refuse


def parse_prompt(prompt):
    flags = {}
    while True:
        m = PREFIX.match(prompt)
        if not m:
            break
        token = m.group(1).lower()
        if token.startswith("profile="):
            flags["profile"] = token.split("=", 1)[1]
        else:
            flags[token] = True
        prompt = prompt[m.end():]
    return flags, prompt.strip()


def normalize_text(text):
    """NFKC, without invisible format characters, so every layer and the matcher see one form.

    A ligature or soft hyphen inside a name would otherwise stop the value from
    matching its own other occurrences. The cleaned output shows this form.
    """
    text = unicodedata.normalize("NFKC", text)
    return "".join(ch for ch in text if unicodedata.category(ch) != "Cf")


def read_input(body):
    return normalize_text(_read_raw(body))


def _read_raw(body):
    if not body.startswith("@"):
        if not body:
            raise Stop(2, "input", 'nothing to redact; pass a document: -p "@/abs/path/doc.pdf"')
        return body
    path = body[1:].strip()
    if path.startswith("~/"):
        path = os.path.join(models.real_home(), path[2:])
    if not os.path.isabs(path) or not os.path.isfile(path):
        raise Stop(2, "input", 'input file not found; pass an absolute path, e.g. -p "@$PWD/doc.pdf"')
    if path.lower().endswith(TEXT_EXT):
        try:
            with open(path, encoding="utf-8") as f:
                text = f.read()
        except (OSError, UnicodeDecodeError):
            raise Stop(1, "input", "text file is not readable UTF-8") from None
    else:
        text = convert(path)
    if not text.strip():
        raise Stop(1, "conversion", "conversion produced no text")
    return text


def convert(path):
    try:
        from anydoc._anydoc import NeedsOcrError, to_markdown  # native converter only, never hosted OCR
    except ImportError:
        raise Stop(3, "conversion", "anydoc is not installed; run the unit once with -p \"[selftest]\"") from None
    try:
        return to_markdown(path)
    except NeedsOcrError:
        raise Stop(1, "conversion", "document needs OCR, which this unit does not do (hosted OCR is disabled)") \
            from None
    except Stop:
        raise
    except Exception as e:  # anydoc messages can carry the path; report the type only
        raise Stop(1, "conversion", f"conversion failed ({type(e).__name__})") from None


def trim(text, s, e):
    while s < e and text[s] in TRIM:
        s += 1
    while e > s and text[e - 1] in TRIM:
        e -= 1
    while e > s and text[e - 1] == ")" and text.count("(", s, e) < text.count(")", s, e):
        e -= 1
    while s < e and text[s] == "(" and text.count("(", s, e) > text.count(")", s, e):
        s += 1
    return s, e


class Pipeline:
    def __init__(self, cfg, verbose=False, layers=LAYERS, classifier=None, detector=None):
        self.cfg = cfg
        self.verbose = verbose
        self.layers = layers
        self.classifier = classifier
        self.detector = detector
        self.allow = {normalize_key(a, "casefold") for a in cfg.allow}

    def note(self, msg):
        if self.verbose:
            print(f"[redact] {msg}", file=ERR, flush=True)

    def _drop_allowed(self, text, merged):
        return [m for m in merged if normalize_key(text[m.start:m.end], "casefold") not in self.allow]

    def finish(self, text, spans):
        merged = self._drop_allowed(text, bridge_names(text, merge(spans)))
        extra = propagate(text, merged, self.cfg, self.allow)
        return self._drop_allowed(text, bridge_names(text, merge(as_spans(merged) + extra)))

    def run(self, text):
        import rules
        spans = []
        if "rules" in self.layers:
            spans += self._layer("rules", lambda: rules.Rules(self.cfg).detect(text))
        merged = self.finish(text, spans)
        if "classifier" in self.layers:
            masked = Masked(text, merged)
            spans = as_spans(merged) + self._layer("classifier", lambda: self._classify(text, masked))
            merged = self.finish(text, spans)
        if "llm" in self.layers:
            masked = Masked(text, merged)
            found = self._layer("llm", lambda: self._values(text, self.detector.detect(masked)))
            merged = self.finish(text, as_spans(merged) + found)
        return assign(text, merged, self.cfg)

    def _layer(self, name, fn):
        try:
            out = fn()
        except Stop:
            raise
        except Exception as e:
            raise Stop(1, name, f"{name} layer failed ({type(e).__name__}: {safe_reason(e)})") from None
        self.note(f"{name}: {len(out)} spans")
        return out

    def _classify(self, text, masked):
        pairs = self.cfg.classifier_labels()
        labels = [label for label, _ in pairs]
        out = []
        for s, e, c, _score in self.classifier.predict(masked.text, labels, self.cfg.threshold,
                                                       self.cfg.window_words, self.cfg.overlap_words):
            orig = masked.to_orig(s, e)
            if orig:
                out.append(Span(*orig, pairs[c][1], "classifier", 0))
        return self._values(text, out)

    def _values(self, text, spans):
        """Trim model spans and drop the ones that are labels, not values (labels stay)."""
        out = []
        for sp in spans:
            s, e = trim(text, sp.start, sp.end)
            if e > s and not is_label_only(text[s:e], self.cfg.form_words):
                out.append(Span(s, e, sp.cls, sp.layer, sp.prio))
        return out


def safe_reason(e):
    """Exception text only when it cannot carry document text: our own short messages."""
    own = (llm_mod.LLMError, clf_mod.ClassifierError, models.ModelError, credentials.SecretsError)
    return str(e) if isinstance(e, own) else "see the layer's setup"


def report(cfg, text, assigned, layers):
    header = f"{NAME} {VERSION} | profile {cfg.name} | layers {', '.join(layers)} | local only"
    body = render(text, assigned).rstrip("\n")
    return f"{header}\n\n{body}\n\n## PII replaced\n\n{table(summary_rows(assigned, cfg))}\n"


def build(cfg, verbose):
    """Preflight: every model, runtime and data file exists before any document is read."""
    try:
        credentials.seed_words()
    except credentials.SecretsError as e:
        raise Stop(3, "setup", str(e)) from None
    pins = models.load_pins(UNIT_DIR)
    try:
        llm_path = models.llm_path(pins)
        clf_path = models.classifier_path(pins)
    except models.ModelError as e:
        hint = f"; run: nexus install {NAME}:{VERSION}" if e.needs_install else ""
        raise Stop(3, "setup", f"{e}{hint}") from None
    try:
        detector = llm_mod.Detector(UNIT_DIR, llm_path, cfg, gpu=os.environ.get("REDACT_LLM_GPU", "on") != "off")
    except llm_mod.LLMError as e:
        raise Stop(3, "setup", str(e)) from None
    try:
        classifier = clf_mod.Gliner(clf_path, os.path.join(UNIT_DIR, "models", "gliner"))
    except clf_mod.ClassifierError as e:
        raise Stop(3, "setup", str(e)) from None
    except Stop:
        raise
    except Exception as e:
        raise Stop(3, "setup", f"classifier failed to load ({type(e).__name__})") from None
    return Pipeline(cfg, verbose=verbose, classifier=classifier, detector=detector)


def selftest(cfg, text, assigned):
    out = render(text, assigned)
    key = leakcheck.load_key(os.path.join(UNIT_DIR, "selftest", "pii-answer-key.md"))
    s = leakcheck.summary(leakcheck.check(out, key, cfg))
    a, b = s["A"], s["B"]
    line = (f"selftest: Tier A {a['partial']} of {a['values']} values leaked, "
            f"Tier B {b['partial']} of {b['values']} leaked")
    if a["partial"]:
        raise Stop(1, "selftest", f"{line} (classes: {', '.join(a['classes'])}); FAILED")
    return f"{line}; passed" + (f" (Tier B classes left: {', '.join(b['classes'])})" if b["partial"] else "")


def silence_native_stderr():
    """Point fd 2 at /dev/null and return (stream on the real stderr, saved fd)."""
    saved = os.dup(2)
    devnull = os.open(os.devnull, os.O_WRONLY)
    os.dup2(devnull, 2)
    os.close(devnull)
    return os.fdopen(os.dup(saved), "w", buffering=1), saved


def main():
    global ERR
    ERR, saved_stderr = silence_native_stderr()
    block_network()
    scratch = tempfile.mkdtemp(prefix="redact-", dir=os.environ.get("HOME") or None)
    os.chmod(scratch, 0o700)
    # Anything a library or llama.cpp writes (onnxruntime keeps a device-id file under
    # HOME) lands here and is deleted with it.
    for var in ("TMPDIR", "HOME"):
        os.environ[var] = scratch
    tempfile.tempdir = scratch

    def on_signal(signum, _frame):
        raise Stop(128 + signum, "interrupted", "interrupted; nothing was written")

    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, on_signal)
    try:
        flags, body = parse_prompt(os.environ.get("NEXUS_PROMPT", ""))
        name = flags.get("profile") or os.environ.get("REDACT_PROFILE") or "strict"
        try:
            cfg = profiles.load(name, UNIT_DIR, os.path.join(models.real_home(), ".config", "nexus-redact", "profiles"))
        except profiles.ProfileError as e:
            raise Stop(3, "profile", str(e)) from None
        pipeline = build(cfg, flags.get("verbose", False))
        if flags.get("selftest"):
            body = "@" + os.path.join(UNIT_DIR, "selftest", "intake-form.pdf")
        pipeline.note("converting")
        text = read_input(body)
        assigned = pipeline.run(text)
        out = report(cfg, text, assigned, pipeline.layers)
        if flags.get("selftest"):
            out += "\n" + selftest(cfg, text, assigned) + "\n"
        sys.stdout.write(out)
        sys.stdout.flush()
        return 0
    except Stop as e:
        print(f"{NAME}: error: {e.stage}: {e.message}", file=ERR, flush=True)
        return e.code
    except BaseException as e:  # a native panic arrives as a BaseException; its text is never shown
        print(f"{NAME}: error: internal: unexpected failure ({type(e).__name__})", file=ERR, flush=True)
        return 1
    finally:
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, signal.SIG_IGN)  # a second Ctrl-C must not cut the cleanup short
        shutil.rmtree(scratch, ignore_errors=True)
        ERR.close()
        ERR = sys.stderr
        os.dup2(saved_stderr, 2)
        os.close(saved_stderr)


if __name__ == "__main__":
    sys.exit(main())
