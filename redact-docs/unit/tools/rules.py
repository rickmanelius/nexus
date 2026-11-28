"""Layer 1: patterns, checksums and label context.

Formats distinctive enough to stand alone are redacted with no label: emails,
URLs, IPs, phone numbers with separators, dashed SSNs that pass the SSA rules,
Luhn-valid card numbers with a card-network prefix, Medicare MBIs, VINs with
a valid check digit, and dates more specific than a year. Everything else
(routing, NPI, member IDs, bare digit runs) needs a matching label just
before it, and is then redacted even when its checksum fails. Keys, tokens,
private keys, seed phrases and password fields are found by credentials.py.
"""
import ipaddress
import re

import credentials
from spans import Span, find_all

LABEL_WINDOW = 64  # characters searched before a value for its label

MONTHS = (r"(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|June?|July?|Aug(?:ust)?|"
          r"Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\.?")
DAY = r"(?:[12]\d|3[01]|0?[1-9])(?:st|nd|rd|th)?"
YEAR = r"(?:1[89]\d\d|20\d\d)"

DATE_PATTERNS = [
    re.compile(r"(?<![\w./-])(\d{1,2})[/.-](\d{1,2})[/.-](\d{4}|\d{2})(?![\w/-]|\.\d)"),
    re.compile(r"(?<![\w./-])" + YEAR + r"-(?:0?[1-9]|1[0-2])-(?:[12]\d|3[01]|0?[1-9])(?![\w-])"),
    re.compile(r"(?<![\w/])(?:0?[1-9]|1[0-2])/" + YEAR + r"(?![\w/])"),
    re.compile(r"\b" + MONTHS + r"\s+" + DAY + r"(?:,?\s+" + YEAR + r")?\b"),
    re.compile(r"\b(?:the\s+)?" + DAY + r"(?:\s+of)?\s+" + MONTHS + r"(?:,?\s+" + YEAR + r")?\b"),
    re.compile(r"\b" + DAY + r"-" + MONTHS.replace(r"\.?", "") + r"-(?:" + YEAR + r"|\d\d)\b"),
    re.compile(r"\b" + MONTHS + r",?\s+" + YEAR + r"\b"),
]

EMAIL = re.compile(r"(?<![\w.%+-])[A-Za-z0-9][\w.%+-]*@\s?[A-Za-z0-9]+(?:-\s?[A-Za-z0-9]+)*"
                   r"(?:\.[A-Za-z0-9]+(?:-\s?[A-Za-z0-9]+)*)*\.[A-Za-z]{2,}\b")
URL = re.compile(r"\b(?:https?://|www\.)[^\s\[\]()<>\"']+", re.I)
IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.]*\d)")
IPV6 = re.compile(r"(?<![\w:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![\w:])")
MAC = re.compile(r"(?<![\w:-])[0-9A-Fa-f]{2}(?:([:-])[0-9A-Fa-f]{2})(?:\1[0-9A-Fa-f]{2}){4}(?![\w:-])")
SEP = r"[\s.-]{1,2}"
PHONE = re.compile(
    r"(?<![\w+])(?:\+?1[\s.-]?)?(?:\(\d{3}\)\s?|\d{3}" + SEP + r")\d{3}" + SEP + r"\d{4}"
    r"(?:\s?(?:x|ext\.?)\s?\d{1,5})?(?!\d)"
    r"|(?<![\w+])\+\d{1,3}(?:[\s.-]\d{2,4}){2,4}(?!\d)")
SSN_DASHED = re.compile(r"(?<![\w-])(\d{3})-\s?(\d{2})-\s?(\d{4})(?![\w-])")
CARD = re.compile(r"(?<![\w-])\d(?:[ -]?\d){12,18}(?![\w-])")
MBI = re.compile(r"(?<![\w-])[1-9][AC-HJKMNP-RT-Y][AC-HJKMNP-RT-Y0-9]\d-?[AC-HJKMNP-RT-Y][AC-HJKMNP-RT-Y0-9]\d"
                 r"-?[AC-HJKMNP-RT-Y]{2}\d\d(?![\w-])")
VIN = re.compile(r"(?<![\w-])[A-HJ-NPR-Z0-9]{17}(?![\w-])")
STATE_ZIP = re.compile(r"\b([A-Z]{2})\s+(\d{5}(?:-\d{4})?)(?![\w-])")
SPELLED_DIGIT = (r"(?:zero|oh|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|"
                 r"fifteen|sixteen|seventeen|eighteen|nineteen|(?:twenty|thirty|forty|fifty|sixty|seventy|eighty|"
                 r"ninety)(?:-(?:one|two|three|four|five|six|seven|eight|nine))?)")
SPELLED_RUN = re.compile(r"\b" + SPELLED_DIGIT + r"(?:[\s,-]+" + SPELLED_DIGIT + r"){4,}\b", re.I)
CALL = re.compile(r"[A-Za-z_][\w.]*\(.*\)[;,]?")
SIGNATURE = re.compile(r"/s/\s*([A-Z][A-Za-z'-]*(?:\s+(?:[A-Z]\.|[A-Z][A-Za-z'-]*)){0,3})")

US_STATES = ("AL AK AZ AR CA CO CT DE DC FL GA HI ID IL IN IA KS KY LA ME MD MA MI MN MS MO MT NE NV NH NJ NM NY "
             "NC ND OH OK OR PA PR RI SC SD TN TX UT VT VA VI WA WV WI WY GU AS MP").split()
STATE_NAMES = re.compile(
    r"\b(?:Alabama|Alaska|Arizona|Arkansas|California|Colorado|Connecticut|Delaware|Florida|Georgia|Hawaii|"
    r"Idaho|Illinois|Indiana|Iowa|Kansas|Kentucky|Louisiana|Maine|Maryland|Massachusetts|Michigan|Minnesota|"
    r"Mississippi|Missouri|Montana|Nebraska|Nevada|New Hampshire|New Jersey|New Mexico|New York|"
    r"North Carolina|North Dakota|Ohio|Oklahoma|Oregon|Pennsylvania|Rhode Island|South Carolina|"
    r"South Dakota|Tennessee|Texas|Utah|Vermont|Virginia|Washington|West Virginia|Wisconsin|Wyoming|"
    r"Puerto Rico)\b")

# Values that follow a label: (class, value pattern). Label words come from the taxonomy.
LABELED = [
    ("SSN", r"\d{3}-?\s?\d{2}-?\s?\d{4}|\d{4}"),
    ("ITIN", r"\d{3}-?\d{2}-?\d{4}|\d{2}-\d{7}"),
    ("MRN", r"[A-Z]{0,4}-?\d[\dA-Z-]{3,}"),
    ("MEDICARE_ID", r"[0-9A-Z]{4}-?[0-9A-Z]{3}-?[0-9A-Z]{4}|\d{9}[A-Z]\d?"),
    ("HEALTH_PLAN_ID", r"[A-Z0-9][A-Z0-9-]{3,}\d[A-Z0-9-]*|[A-Z0-9-]*\d[A-Z0-9-]{3,}"),
    ("ACCOUNT_NUMBER", r"[\dX*]{4,17}"),
    ("ROUTING_NUMBER", r"\d{9}"),
    ("CARD_NUMBER", r"\d{4}(?:[ -]?\d{4}){2,3}(?:[ -]?\d{1,3})?|\d{4}"),
    ("CARD_EXPIRY", r"(?:0?[1-9]|1[0-2])\s?/\s?(?:\d{4}|\d{2})"),
    ("CARD_CVV", r"\d{3,4}"),
    ("DRIVERS_LICENSE", r"(?:[A-Z]{2}\s)?[A-Z0-9]{1,3}[\d-]{4,}[A-Z0-9]*|[A-Z]\d{6,14}"),
    ("PASSPORT", r"[A-Z0-9]{6,9}"),
    ("VIN", r"[A-HJ-NPR-Z0-9]{17}"),
    ("LICENSE_PLATE", r"[A-Z0-9]{1,4}[ -]?[A-Z0-9]{1,5}"),
    ("NPI", r"\d{10}|[A-Z]{2}\d{7}"),
    ("OTHER_ID", r"[A-Z0-9][A-Z0-9-]*\d[A-Z0-9-]*"),
    ("AGE", r"\d{1,3}"),
    ("ZIP", r"\d{5}(?:-\d{4})?"),
    ("SEX", r"(?:Female|Male|Woman|Man|Non-?binary|Intersex|Transgender|F|M)"),
    ("MARITAL_STATUS", r"(?:Married|Single|Divorced|Widowed|Separated|Partnered|Domestic partner(?:ship)?|Engaged)"),
    ("PHONE", r"\d{10}|\d{3}-?\d{4}"),
    # Before CREDENTIAL, so a long value after "API key:" or "token" is named a SECRET.
    ("SECRET", r"0x[0-9a-fA-F]{64}|(?=[\w+/=.~-]*\d)[\w+/=~-][\w+/=.~-]{14,}[\w+/=~-]|[\w+/=~-][\w+/=.~-]{22,}[\w+/=~-]"),
    ("CREDENTIAL", r"(?=\S*[\d@#$%^&*!_])\S{4,}"),
]
LABEL_GAP = (r"(?:\s+(?:to|at|is|was|of|on|in|as|given|verbally|written|ending|number|no\.?|#))*"
             r"[\s:#.(),=-]{0,4}(?:\([A-Za-z ]{1,12}\)[\s:#.]{0,3})?")


def luhn(digits):
    total, alt = 0, False
    for d in reversed(digits):
        n = int(d)
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return total % 10 == 0


def ssn_valid(area, group, serial):
    a = int(area)
    return a not in (0, 666) and a < 900 and group != "00" and serial != "0000"


def aba_valid(d):
    if len(d) != 9 or not d.isdigit():
        return False
    w = (3, 7, 1) * 3
    return sum(int(x) * y for x, y in zip(d, w)) % 10 == 0


def npi_valid(d):
    return len(d) == 10 and d.isdigit() and luhn("80840" + d)


def card_network(digits):
    return bool(re.match(r"4|5[1-5]|2[2-7]|3[47]|6(?:011|5)|35|30[0-5]|36|38", digits)) and 13 <= len(digits) <= 19


VIN_VALUES = {**{str(i): i for i in range(10)}, **dict(zip("ABCDEFGH", range(1, 9))),
              **dict(zip("JKLMN", range(1, 6))), "P": 7, "R": 9, **dict(zip("STUVWXYZ", range(2, 10)))}
VIN_WEIGHTS = (8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2)


def vin_valid(v):
    if not re.search(r"\d", v) or not re.search(r"[A-Z]", v):
        return False
    total = sum(VIN_VALUES[c] * w for c, w in zip(v, VIN_WEIGHTS))
    check = total % 11
    return v[8] == ("X" if check == 10 else str(check))


def date_ok(m):
    if m.re is DATE_PATTERNS[0]:
        a, b, y = int(m.group(1)), int(m.group(2)), m.group(3)
        if not ((1 <= a <= 12 and 1 <= b <= 31) or (1 <= b <= 12 and 1 <= a <= 31)):
            return False
        return len(y) == 4 and 1800 <= int(y) <= 2099 or len(y) == 2
    return True


class Rules:
    def __init__(self, cfg):
        self.cfg = cfg
        self.labels = {}
        for cid, c in cfg.classes.items():
            if c.get("labels"):
                self.labels[cid] = re.compile(r"(?:^|(?<=[^\w]))(?:" + "|".join(c["labels"]) + r")" + LABEL_GAP + r"$",
                                              re.I)
        self.labeled = [(cid, re.compile(r"(?<![\w-])(?:" + pat + r")(?![\w-])")) for cid, pat in LABELED]
        self.secrets = credentials.Detector(cfg)

    def has_label(self, text, start, cid):
        rx = self.labels.get(cid)
        if rx is None:
            return False
        window = text[max(0, start - LABEL_WINDOW):start]
        if rx.search(window):
            return True
        # A label on the line above a value that starts its own line.
        line_start = text.rfind("\n", 0, start) + 1
        if text[line_start:start].strip() == "" and line_start > 0:
            prev = text[text.rfind("\n", 0, line_start - 1) + 1:line_start - 1]
            return bool(rx.search(prev.rstrip() + " "))
        return False

    def detect(self, text):
        out = []
        active = self.cfg.active

        def add(s, e, cid, prio=0):
            if cid in active and e > s:
                out.append(Span(s, e, cid, "rules", prio))

        conn = self.secrets.connection_userinfo(text)
        for m in EMAIL.finditer(text):
            if not any(s <= m.start() < e for s, e in conn):  # "pass@db.example.com" in postgres://user:pass@...
                add(m.start(), m.end(), "EMAIL", 5)
        for s, e, cid, prio in self.secrets.detect(text):
            add(s, e, cid, prio)
        for m in URL.finditer(text):
            e = m.end()
            while e > m.start() and text[e - 1] in ".,;:!?'\"":
                e -= 1
            add(m.start(), e, "URL", 5)
        for m in IPV4.finditer(text):
            if self._ip(m.group()) and not re.search(r"(?:version|ver\.?|v)\s*$", text[max(0, m.start() - 12):m.start()], re.I):
                add(m.start(), m.end(), "IP_ADDRESS", 5)
        for m in IPV6.finditer(text):
            g = m.group()
            if g.count(":") >= 2 and len(g) >= 6 and re.search(r"[0-9A-Fa-f]", g) and self._ip(g):
                add(m.start(), m.end(), "IP_ADDRESS", 5)
        for m in MAC.finditer(text):
            add(m.start(), m.end(), "MAC_ADDRESS", 5)
        for m in SSN_DASHED.finditer(text):
            if ssn_valid(*m.groups()) or self.has_label(text, m.start(), "SSN"):
                add(m.start(), m.end(), "SSN", 5)
        for m in MBI.finditer(text):
            add(m.start(), m.end(), "MEDICARE_ID", 5)
        for m in VIN.finditer(text):
            if vin_valid(m.group()) or self.has_label(text, m.start(), "VIN"):
                add(m.start(), m.end(), "VIN", 5)
        for m in CARD.finditer(text):
            d = re.sub(r"\D", "", m.group())
            if (card_network(d) and luhn(d)) or self.has_label(text, m.start(), "CARD_NUMBER"):
                add(m.start(), m.end(), "CARD_NUMBER", 5)
        for m in PHONE.finditer(text):
            cid = "FAX" if self.has_label(text, m.start(), "FAX") else "PHONE"
            add(m.start(), m.end(), cid, 1)
        for rx in DATE_PATTERNS:
            for m in rx.finditer(text):
                if date_ok(m):
                    cid = "CARD_EXPIRY" if self.has_label(text, m.start(), "CARD_EXPIRY") and \
                        re.fullmatch(r"\d{1,2}\s?/\s?\d{2,4}", m.group()) else "DATE"
                    add(m.start(), m.end(), cid, 1)
        for m in STATE_ZIP.finditer(text):
            before = re.search(r"(\w+)\W*$", text[max(0, m.start() - 24):m.start()])
            if before and before.group(1).lower() in self.cfg.form_words:
                continue  # "Patient ID 48213" is a label and a number, not Idaho
            if m.group(1) in US_STATES:
                add(m.start(1), m.end(1), "STATE", 1)
                add(m.start(2), m.end(2), "ZIP", 1)
        for m in STATE_NAMES.finditer(text):
            add(m.start(), m.end(), "STATE", 0)
        for m in SPELLED_RUN.finditer(text):
            cid = "SSN" if self.has_label(text, m.start(), "SSN") else "OTHER_ID"
            add(m.start(), m.end(), cid, 2)
        for m in SIGNATURE.finditer(text):
            add(m.start(1), m.end(1), "PERSON", 1)
        for rank, (cid, rx) in enumerate(self.labeled):
            if cid not in active:
                continue
            prio = 4 - rank / 100  # earlier, more specific classes win ties
            for m in rx.finditer(text):
                if self.has_label(text, m.start(), cid) and self._labeled_ok(cid, m.group()):
                    add(m.start(), m.end(), cid, prio)
        for cid, rx, label in self.cfg.patterns:
            for m in rx.finditer(text):
                if label is None or label.search(text[max(0, m.start() - LABEL_WINDOW):m.start()]):
                    add(m.start(), m.end(), cid, 6)
        for cid, term in self.cfg.deny:
            mode = self.cfg.classes[cid].get("match", "text")
            for s, e in find_all(text, term, "casefold" if mode == "name" else mode):
                add(s, e, cid, 6)
        return out

    @staticmethod
    def _ip(s):
        try:
            ipaddress.ip_address(s)
            return True
        except ValueError:
            return False

    @staticmethod
    def _labeled_ok(cid, value):
        if cid == "AGE":
            return 0 < int(value) < 130
        if cid == "LICENSE_PLATE":
            return bool(re.search(r"\d", value))
        if cid in ("CREDENTIAL", "SECRET"):
            # Not a label, a blank form field ("________") or a call in code ("next_token()").
            return not (value.endswith(":") or credentials.is_placeholder(value) or CALL.fullmatch(value))
        return True
