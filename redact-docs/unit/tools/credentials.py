"""Layer 1, secrets: API keys, tokens, private keys, seed phrases and password fields.

Called by rules.Rules.detect. Formats with a published prefix or a fixed shape
are redacted with no label: provider API keys and tokens, JWTs, AWS key IDs,
private key blocks (PEM, OpenSSH, PGP, PuTTY), crypto private keys (WIF with a
valid base58check checksum, BIP-32 extended keys), BitLocker recovery keys,
the user:password part of a connection string, and 12 or more words in a row
from the BIP-39 list. The rest needs context: the value of a setting whose
name says it holds a secret (OPENAI_API_KEY=..., "password": "..."), an
Authorization header, the whole field after a password-type label, a table
column headed by a secret label, or 3 or more BIP-39 words after a
seed-phrase label. Label words come from the taxonomy.
"""
import hashlib
import os
import re

WORDLIST = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), "pii", "bip39-english.txt")
WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
SEED_MIN = 12          # BIP-39 words in a row that are a seed phrase with no label
SEED_MIN_LABELED = 3   # BIP-39 words in a row after a seed-phrase label
FIELD_MAX = 80         # a password field this long or shorter is taken whole

TOKEN = re.compile(r"(?<![\w-])(?:" + "|".join([
    r"gh[pousr]_[A-Za-z0-9]{36,251}",                  # GitHub
    r"github_pat_[A-Za-z0-9_]{50,251}",
    r"glpat-[A-Za-z0-9_-]{20,}",                       # GitLab
    r"xox[abeoprs]-[A-Za-z0-9-]{10,}",                 # Slack
    r"xapp-\d-[A-Za-z0-9-]{10,}",
    r"(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}",    # Stripe
    r"whsec_[A-Za-z0-9+/=]{24,}",
    r"sk-ant-[A-Za-z0-9_-]{32,}",                      # Anthropic
    r"sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}",   # OpenAI
    r"sk-[A-Za-z0-9]{32,}",
    r"AIza[A-Za-z0-9_-]{35}",                          # Google
    r"GOCSPX-[A-Za-z0-9_-]{20,}",
    r"ya29\.[A-Za-z0-9_-]{20,}",
    r"(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}",            # AWS access key ID
    r"hf_[A-Za-z0-9]{30,}",                            # Hugging Face
    r"npm_[A-Za-z0-9]{36}",                            # npm
    r"pypi-[A-Za-z0-9_-]{50,}",                        # PyPI
    r"SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}",     # SendGrid
    r"SK[0-9a-f]{32}",                                 # Twilio
    r"shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}",             # Shopify
    r"do[opr]_v1_[a-f0-9]{64}",                        # DigitalOcean
    r"dckr_pat_[A-Za-z0-9_-]{20,}",                    # Docker Hub
    r"glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}",            # Grafana
    r"lin_api_[A-Za-z0-9]{40}",                        # Linear
    r"xai-[A-Za-z0-9]{40,}",                           # xAI
    r"gsk_[A-Za-z0-9]{40,}",                           # Groq
    r"ntn_[A-Za-z0-9]{40,}",                           # Notion
    r"key-[A-Za-z0-9]{32}",                            # Mailgun
    r"sq0(?:atp|csp)-[A-Za-z0-9_-]{22,}",              # Square
    r"\d{8,10}:[A-Za-z0-9_-]{35}",                     # Telegram bot
    r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*",  # JWT
    r"\d{6}(?:-\d{6}){7}",                             # BitLocker recovery key
    r"[xyztuv]prv[1-9A-HJ-NP-Za-km-z]{100,112}",       # BIP-32 extended private key
]) + r")(?![\w-])")
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
WIF = re.compile(r"(?<![\w-])[5KL9c][1-9A-HJ-NP-Za-km-z]{50,51}(?![\w-])")
DASHES = r"(?:\\?-){3,}"
KEY_KIND = r"(?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?"
PEM = re.compile(DASHES + r"[ \t]*BEGIN " + KEY_KIND + r"[ \t]*" + DASHES +
                 r"(?:[\s\S]{0,20000}?" + DASHES + r"[ \t]*END " + KEY_KIND + r"[ \t]*" + DASHES +
                 r"|(?:\s+(?:[A-Za-z0-9+/=]{16,}|(?:Proc-Type|DEK-Info|Comment|Version):[^\n]*))*)")
PUTTY = re.compile(r"PuTTY-User-Key-File-\d+:[\s\S]{0,20000}?Private-MAC:[ \t]*[0-9a-fA-F]+")
CONN = re.compile(r"(?<![\w+.-])[A-Za-z][A-Za-z0-9+.-]{1,30}://([^\s:/@?#\[\]]+):([^\s/?#\[\]]+?)@"
                  r"(?=[^\s@/?#\[\]]+(?:[/?#:\s\]]|$))")
HEADER = re.compile(r"(?i)(?<![\w-])(?:proxy-)?authorization[\"']?[ \t]*[:=][ \t]*[\"']?"
                    r"(?:bearer|basic|token|digest|api-?key)[ \t]+([A-Za-z0-9+/=._~-]{8,})")
ASSIGN = re.compile(r"(?<![\w.-])([A-Za-z_][A-Za-z0-9_.-]{0,63})[\"']?[ \t]*(?::=|=>|=|:)[ \t]*"
                    r"(?:\"([^\"\n]{1,200})\"|'([^'\n]{1,200})'|([^\s\"'`,;]{1,200}))")
# Parts of a setting name. A password part makes its value a CREDENTIAL; a secret part, or
# "key" with one of the qualifiers, makes it a SECRET; a non-secret part rules the name out.
PASSWORD_PARTS = {"password", "passwd", "pwd", "passphrase", "passcode"}
PASSWORD_PARTS_ENV = {"pass", "pw"}  # only in DB_PASS style names: getPass, PassWarning are not passwords
SECRET_PARTS = {"secret", "token", "apikey", "credential", "credentials", "bearer", "jwt", "privkey"}
KEY_QUALIFIERS = {"api", "access", "secret", "private", "signing", "client", "master", "encryption", "app",
                  "service", "account", "subscription", "webhook", "session", "license", "auth", "deploy",
                  "admin", "root", "consumer", "integration", "personal", "shared", "storage"}
NOT_SECRET_PARTS = {"url", "uri", "endpoint", "path", "file", "filename", "dir", "type", "name", "id", "length",
                    "len", "count", "ttl", "expiry", "expires", "expiration", "timeout", "lifetime", "limit",
                    "size", "format", "prefix", "header", "field", "param", "public", "pub", "hint", "policy",
                    "min", "max", "enabled", "enable", "disabled", "required", "algorithm", "alg", "version",
                    "host", "port", "region", "mode", "label", "env", "var", "rotation", "provider", "method",
                    "scope", "scopes", "location", "help", "description", "placeholder", "regex", "pattern",
                    "state", "status", "flag", "flags", "ldflags", "cflags", "module", "lib", "libs", "cmd",
                    "command", "prompt", "input", "widget", "button", "dialog", "error", "errors", "message", "msg",
                    "text", "check", "validator", "validation", "strength", "rule", "rules", "mask", "masked",
                    "hidden", "visible", "show", "display", "color", "icon", "style", "class", "schema", "spec",
                    "doc", "docs", "stream", "tokenizer", "cache"}
PLACEHOLDER = re.compile(r"(?i)^(?:\$|\{\{|<|%|os\.|process\.env|env\(|getenv|vault:|(?:null|none|nil|true|false|"
                         r"undefined|n/?a|tbd|todo|unknown|not set|redacted|see below|see above|''|\"\")$|"
                         r"[*xX_.?-]+$|(?:your|optional|example|sample|dummy|placeholder)[\s_-]|.*[\s_-]here$)")
CODE_LIKE = re.compile(r"[()\[\]{}]")
DOTTED_NAME = re.compile(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+")
SYMBOL = re.compile(r"[\d@#$%^&*!+/=~]")
FORM_LINE = re.compile(r"^[\s>*#|_-]*(?:\d+[.)]\s*)?[A-Z]")
QUOTES = {"\"": "\"", "'": "'", "\u201c": "\u201d", "\u2018": "\u2019"}
AMBIGUOUS_COLUMN_LABELS = {"token", "bearer"}
ENV_NAME = re.compile(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+")
LATER_LABEL = re.compile(r"\s[A-Za-z][\w'/ -]{0,30}:(?:\s|$)")
TABLE_SEPARATOR = re.compile(r"^\s*\|?\s*:?-{3,}:?\s*(?:\|\s*:?-{3,}:?\s*)*\|?\s*$")
SECURITY_QUESTION = re.compile(r"(?i)(?:security|secret|challenge) question")
ANSWER = re.compile(r"(?i)(?<![\w-])answer[ \t]*[:=][ \t]*")
# "Password (case sensitive):" may carry a note; "pwd(self):" is code, so the note needs a space before it.
FIELD_SEP = re.compile(r"(?:[ \t]+\([^()\n]{0,24}\)[ \t]*|[ \t]*)([:=|])[ \t]*")
SEED_WORD = re.compile(r"[A-Za-z]+")
# Between two words of one phrase: spaces, line breaks, numbering, commas, pipes, bullets, emphasis.
SEED_GAP = re.compile(r"[\s,|.:\\\-\u2013\u2022\u00b7*#()\d]{1,24}")
# BIP-39 words that are also among the most common English words. A seed phrase is random, so about
# one word in nine is one of these; a run that is more than half these is speech or prose
# ("you know what they say just make this one more time when you want"), not a seed.
COMMON_WORDS = frozenset("""
able about across add again age air all allow almost already also always another any appear area around art
ask because before begin behind believe best better between body book boy bring build business call can car
case certain change child city come consider day decide door during early easy either else end enough expect
eye face fall father few find first follow foot force friend game girl give good great group grow hand hard
have head health help high history hold home hour idea include into issue job just keep kid kind know large
later law learn level life like little live local long love major make mean member minute moment month more
morning mother move much must name neither never next nothing now number offer office often okay old once one
only open other over own party pass people person place play point power pretty problem provide public pull put
raise rather real reason remain remember report require result right room run same say sell service side small
someone soon sort speak special spend stand start stay still story such suggest sure talk team that then there
they thing this time today together tomorrow tonight toward true turn two under use very wait walk want water
way what when where will win woman word work world write year you young
""".split())
BLANK_GAP = re.compile(r"\n[ \t]*\n")
HEADING_GAP = re.compile(r"\n[ \t]*#|-{3,}")  # a heading, a rule or a table's |---| row
LONE_WORD = re.compile(r"[^A-Za-z]*[A-Za-z]+[^A-Za-z]*")


class SecretsError(Exception):
    pass


_words = None


def seed_words():
    """The BIP-39 English list, checked against its pinned sha256 (a damaged list fails closed)."""
    global _words
    if _words is None:
        try:
            with open(WORDLIST, "rb") as f:
                data = f.read()
        except OSError:
            raise SecretsError("seed word list is missing; reinstall the unit") from None
        if hashlib.sha256(data).hexdigest() != WORDLIST_SHA256:
            raise SecretsError("seed word list does not match its pinned sha256; reinstall the unit")
        _words = frozenset(data.decode("ascii").split())
    return _words


def base58check(s):
    n = 0
    for ch in s:
        i = B58.find(ch)
        if i < 0:
            return False
        n = n * 58 + i
    raw = b"\0" * (len(s) - len(s.lstrip("1"))) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    if len(raw) < 5:
        return False
    return hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] == raw[-4:]


def name_parts(name):
    """'OPENAI_API_KEY' -> ['openai', 'api', 'key']; 'clientSecret' -> ['client', 'secret']."""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    return [p for p in re.split(r"[\s_.-]+", spaced.lower()) if p]


def setting_class(name):
    parts = name_parts(name)
    if not parts or any(p in NOT_SECRET_PARTS for p in parts):
        return None
    env_style = not re.search(r"[a-z]", name) and len(parts) > 1  # DB_PASS, but not a test's "PASS:"
    if any(p in PASSWORD_PARTS or (env_style and p in PASSWORD_PARTS_ENV) for p in parts):
        return "CREDENTIAL"
    if any(p in SECRET_PARTS for p in parts):
        return "SECRET"
    if "key" in parts and any(p in KEY_QUALIFIERS for p in parts):
        return "SECRET"
    return None


def mentions(word, text):
    """True when text uses word on its own ('pwd#module-pwd'), not inside a value ('password123')."""
    return bool(re.search(r"(?<![\w])" + re.escape(word) + r"(?![\w])", text, re.I))


def is_placeholder(value):
    return not value.strip() or bool(PLACEHOLDER.match(value.strip()))


def trim_value(text, s, e):
    """Drop surrounding spaces, trailing sentence punctuation and unbalanced closing brackets."""
    while s < e and text[s].isspace():
        s += 1
    while e > s and (text[e - 1].isspace() or text[e - 1] in ".,;:"):
        e -= 1
    for close, open_ in ((")", "("), ("]", "["), ("}", "{")):
        while e > s and text[e - 1] == close and text.count(open_, s, e) < text.count(close, s, e):
            e -= 1
    return s, e


def _label_rx(labels):
    return re.compile(r"(?<![\w-])(?:" + "|".join(labels) + r")(?![\w-])", re.I) if labels else None


class Detector:
    def __init__(self, cfg):
        self.words = seed_words()
        classes = cfg.classes
        self.field_rx = _label_rx(classes["CREDENTIAL"].get("field_labels", []))
        self.seed_rx = _label_rx(classes["SEED_PHRASE"].get("labels", []))
        # A bare "Token" heading is as often a design token, a word token or a coin as a secret, so it
        # does not make a column secret; "API key", "Access token" or "Password" do.
        secret_columns = [l for l in classes["SECRET"].get("labels", []) if l not in AMBIGUOUS_COLUMN_LABELS]
        self.columns = [(cid, re.compile(r"(?:" + "|".join(labels) + r")", re.I)) for cid, labels in (
            ("SEED_PHRASE", classes["SEED_PHRASE"].get("labels", [])),
            ("SECRET", secret_columns),
            ("CREDENTIAL", classes["CREDENTIAL"].get("field_labels", []))) if labels]

    def connection_userinfo(self, text):
        """(start, end) of each user:password in a connection string, so EMAIL leaves it alone."""
        return [(m.start(1), m.end(2)) for m in CONN.finditer(text)]

    def detect(self, text):
        """[(start, end, class, prio)] for every secret found."""
        out = []
        for m in TOKEN.finditer(text):
            out.append((m.start(), m.end(), "SECRET", 5))
        for m in WIF.finditer(text):
            if base58check(m.group()):
                out.append((m.start(), m.end(), "SECRET", 5))
        for rx in (PEM, PUTTY):
            for m in rx.finditer(text):
                out.append((m.start(), m.end(), "SECRET", 5))
        for s, e in self.connection_userinfo(text):
            out.append((s, e, "CREDENTIAL", 5))
        for m in HEADER.finditer(text):
            out.append((m.start(1), m.end(1), "SECRET", 5))
        out += self._settings(text)
        out += self._fields(text)
        out += self._columns(text)
        out += self._seeds(text)
        return out

    def _settings(self, text):
        out = []
        for m in ASSIGN.finditer(text):
            cid = setting_class(m.group(1))
            if cid is None:
                continue
            g = next(i for i in (2, 3, 4) if m.group(i) is not None)
            s, e = m.start(g), m.end(g)
            if g == 4:
                s, e = trim_value(text, s, e)
            value = text[s:e]
            if is_placeholder(value) or len(value) < 3:
                continue
            if g == 4 and not self._literal(m.group(1), text[m.end(1):m.start(g)], value):
                continue
            line_end = text.find("\n", e)
            if re.search(r"[a-z]", m.group(1)) and mentions(m.group(1), text[s:len(text) if line_end < 0 else line_end]):
                continue  # password: The password for the account (a description, not a value)
            if cid == "SECRET" and (len(value) < 8 or re.search(r"\s", value)):
                continue
            # "Secret: Tuesday" and 'token': 'token#module-token' are not keys. An env name
            # (JWT_SECRET=...) is trusted with any value; any other name needs a key-like one.
            if cid == "SECRET" and re.search(r"[a-z]", m.group(1)) and not re.search(r"\d", value) and len(value) < 20:
                continue
            out.append((s, e, cid, 4))
        return out

    @staticmethod
    def _literal(name, sep, value):
        """Is an unquoted value a literal, rather than code (token = next_token())?

        Env files and YAML write literals bare; code quotes them, so a bare value after a
        lower-case name and '=' is usually an expression.
        """
        if CODE_LIKE.search(value) or value.lower() in PASSWORD_PARTS | SECRET_PARTS or value == name:
            return False
        if not re.search(r"[a-z]", name):  # OPENAI_API_KEY=...
            return not re.fullmatch(r"[A-Z_]+", value)  # TOKEN_ENDS = TSPECIALS names another constant
        if DOTTED_NAME.fullmatch(value):  # clientSecret: keys.web.client_secret
            return False
        return bool(SYMBOL.search(value)) if "=" in sep else True

    def _fields(self, text):
        """The value after a password-type label and ':', '=' or a table pipe, taken as written."""
        out = []
        if self.field_rx is None:
            return out
        hits = []
        for m in self.field_rx.finditer(text):
            sep = FIELD_SEP.match(text, m.end())
            if sep:
                hits.append((m.start(), sep.end(), sep.group(1)))
        # A bare "Answer:" counts only near a security question.
        hits += [(m.start(), m.end(), ":") for m in ANSWER.finditer(text)
                 if SECURITY_QUESTION.search(text, max(0, m.start() - 200), m.start())]
        for label_start, pos, kind in hits:
            span = self._field_value(text, label_start, pos, kind)
            if span:
                out.append((*span, "CREDENTIAL", 4))
        return out

    def _field_value(self, text, label_start, pos, kind):
        line_end = text.find("\n", pos)
        line_end = len(text) if line_end < 0 else line_end
        if kind == "|":
            next_end = text.find("\n", line_end + 1)
            if TABLE_SEPARATOR.match(text[line_end + 1:next_end if next_end >= 0 else len(text)]):
                return None  # a header row: the next cell is another heading, not a value
        bar = text.find("|", pos, line_end)
        end = bar if bar >= 0 else line_end
        if not text[pos:end].strip():
            # "Password:" alone on a form line, the value on the next. A label line that starts in
            # lower case ("if passwd:") is code, and its next line is not a value.
            label_line = text[text.rfind("\n", 0, label_start) + 1:label_start]
            if kind != ":" or bar >= 0 or line_end >= len(text) or not FORM_LINE.match(label_line + text[label_start]):
                return None
            pos = line_end + 1
            line_end = text.find("\n", pos)
            end = len(text) if line_end < 0 else line_end
            if end - pos > FIELD_MAX or LATER_LABEL.match(" " + text[pos:end]):
                return None
        s, e = trim_value(text, pos, end)
        value = text[s:e]
        if value[:1] in QUOTES:
            q = text.find(QUOTES[value[0]], s + 1, e)
            # An empty or unclosed quote means the label sat inside a string: prompt='Password: '.
            return (s + 1, q) if q > s + 1 and not is_placeholder(text[s + 1:q]) else None
        cut = re.search(r"\s\(|\s-\s", value)
        if cut:
            e = s + cut.start()
            value = text[s:e]
        if kind == "=" or LATER_LABEL.search(value) or len(value) > FIELD_MAX:
            first = re.match(r"\S+", value)  # code and config after '=': one token
            s, e = trim_value(text, s, s + first.end())
            value = text[s:e]
        if is_placeholder(value) or (value.startswith("(") and value.endswith(")")) or self.field_rx.search(value):
            return None  # a value that names its own label describes the field: "The password for the account"
        if kind == "=" and (CODE_LIKE.search(value) or DOTTED_NAME.fullmatch(value) or not SYMBOL.search(value) or
                            value.lower() in PASSWORD_PARTS):
            return None  # password = lexer.get_token() is code; forms use ':'
        return (s, e)

    def _columns(self, text):
        """Cells under a table heading that names a secret: | Service | Password |."""
        out = []
        lines, pos = [], 0
        for line in text.split("\n"):
            lines.append((pos, line))
            pos += len(line) + 1
        i = 0
        while i + 1 < len(lines):
            head_pos, head = lines[i]
            if "|" not in head or not TABLE_SEPARATOR.match(lines[i + 1][1]):
                i += 1
                continue
            cols = {}
            for n, cell in enumerate(_cells(head)):
                label = re.sub(r"[*_`]", "", cell[2]).strip()
                for cid, rx in self.columns:
                    if rx.fullmatch(label):
                        cols[n] = cid
                        break
            i += 2
            while i < len(lines) and "|" in lines[i][1]:
                row_pos, row = lines[i]
                for n, (cs, ce, cell) in enumerate(_cells(row)):
                    cid = cols.get(n)
                    if cid is None:
                        continue
                    s, e = trim_value(text, row_pos + cs, row_pos + ce)
                    value = text[s:e]
                    if is_placeholder(value):
                        continue
                    if cid == "SECRET":
                        bare = value.strip("`")
                        # A key is one random string; "STRIPE_API_KEY" names one, and a phrase describes one.
                        if len(bare) < 8 or re.search(r"\s", bare) or ENV_NAME.fullmatch(bare):
                            continue
                    out.append((s, e, cid, 4))
                i += 1
        return out

    def _seeds(self, text):
        runs, run = [], []
        for m in SEED_WORD.finditer(text):
            # A word with a colon right after it is a label ("Copy:"), never part of a phrase.
            if m.group().lower() in self.words and not text.startswith(":", m.end()):
                if run and not _joins(text, run[-1], m):
                    runs.append(run)
                    run = []
                run.append(m)
            elif run:
                runs.append(run)
                run = []
        if run:
            runs.append(run)
        # Where a phrase may start after each label: past a ':' or '=' on the label's line, else on the
        # next line. "a physical mnemonic -- one finger" has neither, so its words are not a seed.
        starts = []
        for lm in self.seed_rx.finditer(text) if self.seed_rx else ():
            q = lm.end()
            line_end = text.find("\n", q)
            line_end = len(text) if line_end < 0 else line_end
            colon = re.search(r"[:=]", text[q:min(line_end, q + 60)])
            starts.append((q + colon.end(), True) if colon else (q, False))
        out = []
        for r in runs:
            # "seed", "phrase" and "word" are BIP-39 words: a run never swallows its own label.
            inside = [q for q, _ in starts if r[0].start() <= q <= r[-1].end()]
            words = [w for w in r if w.start() >= max(inside)] if inside else r
            if len(words) >= SEED_MIN and _random_enough(words):
                out.append((words[0].start(), words[-1].end(), "SEED_PHRASE", 5))
        for q, after_colon in starts:
            for r in runs:
                words = [w for w in r if w.start() >= q]
                if not words:
                    continue
                gap = text[q:words[0].start()]
                if len(words) >= SEED_MIN_LABELED and len(gap) <= 80 and not re.search(r"[A-Za-z]", gap) and \
                        (after_colon or "\n" in gap) and _random_enough(words):
                    out.append((words[0].start(), words[-1].end(), "SEED_PHRASE", 4))
                break
        return out


def _joins(text, prev, m):
    """True when two BIP-39 words belong to one phrase: only numbering or separators between them.

    A run stops at code punctuation ('_', '=', quotes, brackets), at a word ending a sentence,
    a label or a call ('below.', 'card:', 'check('), at a heading, and at
    a blank line, unless both lines hold one (numbered) word, as on a seed card converted one
    word per paragraph.
    """
    gap = text[prev.end():m.start()]
    if not SEED_GAP.fullmatch(gap) or gap[0] in ".:()" or HEADING_GAP.search(gap):
        return False
    if BLANK_GAP.search(gap):
        return _lone_word(text, prev) and _lone_word(text, m)
    return True


def _random_enough(words):
    """At most half the words are common English: a random phrase, not a sentence."""
    return sum(w.group().lower() in COMMON_WORDS for w in words) * 2 <= len(words)


def _lone_word(text, m):
    start = text.rfind("\n", 0, m.start()) + 1
    end = text.find("\n", m.end())
    return bool(LONE_WORD.fullmatch(text[start:len(text) if end < 0 else end]))


def _cells(row):
    """[(start, end, text)] of each cell in a Markdown table row, offsets within the row."""
    out, start = [], 0
    s = row.find("|")
    if s < 0:
        return out
    if row[:s].strip():  # a row with no leading pipe
        s = -1
    start = s + 1
    while True:
        bar = row.find("|", start)
        if bar < 0:
            if row[start:].strip():
                out.append((start, len(row), row[start:]))
            break
        out.append((start, bar, row[start:bar]))
        start = bar + 1
    return out
