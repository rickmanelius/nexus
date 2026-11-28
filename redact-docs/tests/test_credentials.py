"""Secrets: API keys, tokens, private keys, seed phrases and password fields (issue #1).

Every token here is built at run time from a fixed filler, so the repo holds no token-shaped
string for a secret scanner to flag. Seed phrases are published BIP-39 test vectors, which
hold no funds. All other values are fictitious.
"""
import hashlib
import os
import shutil
import tempfile
import unittest

from helpers import RELEASE, config, fake

import credentials  # noqa: E402
import pipeline  # noqa: E402
import rules  # noqa: E402
from spans import render  # noqa: E402

SEED_12 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
SEED_12B = "legal winner thank year wave sausage worth useful legal winner thank yellow"
SEED_24 = ("letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor "
           "acoustic avoid letter advice cage absurd amount doctor acoustic bless")
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
HEX = "0123456789abcdef"
DASH5 = "-" * 5


def armor(kind, body, end=True):
    """A private key block, assembled here so the file never holds a literal one."""
    head = f"{DASH5}BEGIN {kind}{DASH5}\n{body}"
    return head + (f"\n{DASH5}END {kind}{DASH5}" if end else "")


def found(text, cfg=None):
    """{(value, class)} the rules layer redacts in text."""
    return {(text[s.start:s.end], s.cls) for s in rules.Rules(cfg or config()).detect(text)}


def values_of(text, cls, cfg=None):
    return {v for v, c in found(text, cfg) if c == cls}


def b58encode(raw):
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + out


def wif(seed):
    """A wallet import format key with a valid checksum, from a fictitious 32-byte key."""
    body = b"\x80" + hashlib.sha256(seed.encode()).digest() + b"\x01"
    return b58encode(body + hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4])


def tokens():
    """(name, token) for each provider format the rules know by prefix."""
    return [
        ("github", "gh" + "p_" + fake("gh", 36)),
        ("github fine-grained", "github" + "_pat_" + fake("ghf1", 22) + "_" + fake("ghf2", 59)),
        ("gitlab", "gl" + "pat-" + fake("gl", 20)),
        ("slack", "xo" + "xb-" + "1234567890123-1234567890123-" + fake("sl", 24)),
        ("stripe", "sk" + "_live_" + fake("st", 24)),
        ("anthropic", "sk-" + "ant-api03-" + fake("an", 93) + "AA"),
        ("openai project", "sk-" + "proj-" + fake("op", 48)),
        ("openai legacy", "sk-" + fake("ol", 48)),
        ("google", "AI" + "za" + fake("go", 35)),
        ("aws key id", "AK" + "IA" + fake("aw", 16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")),
        ("hugging face", "hf" + "_" + fake("hf", 34)),
        ("npm", "npm" + "_" + fake("np", 36)),
        ("sendgrid", "SG" + "." + fake("sg1", 22) + "." + fake("sg2", 43)),
        ("twilio", "SK" + fake("tw", 32, HEX)),
        ("digitalocean", "dop" + "_v1_" + fake("do", 64, HEX)),
        ("telegram bot", "1234567890" + ":" + "AA" + fake("tg", 33)),
        ("jwt", "eyJ" + fake("j1", 20) + "." + "eyJ" + fake("j2", 30) + "." + fake("j3", 43)),
        ("bitlocker", "-".join(fake("bl" + str(i), 6, "0123456789") for i in range(8))),
        ("extended private key", "xp" + "rv" + fake("xp", 107, B58)),
        ("wif", wif("fictitious")),
    ]


class FormatTest(unittest.TestCase):
    def test_every_known_token_format_alone(self):
        for name, tok in tokens():
            with self.subTest(name):
                self.assertEqual(values_of(f"found in the notes: {tok}. Thanks", "SECRET"), {tok})

    def test_a_token_inside_a_longer_word_is_not_cut_out(self):
        tok = "gh" + "p_" + fake("gh", 36)
        self.assertEqual(values_of("x" + tok, "SECRET"), set())

    def test_wif_needs_its_checksum(self):
        good = wif("fictitious")
        bad = good[:-1] + ("2" if good[-1] != "2" else "3")
        self.assertEqual(values_of(f"key {bad} here", "SECRET"), set())

    def test_private_key_block_whole(self):
        body = "\n".join(fake("pem" + str(i), 64) for i in range(3))
        for kind in ("RSA PRIVATE KEY", "OPENSSH PRIVATE KEY", "PRIVATE KEY", "ENCRYPTED PRIVATE KEY",
                     "PGP PRIVATE KEY BLOCK"):
            with self.subTest(kind):
                block = armor(kind, body)
                self.assertEqual(values_of(f"Key:\n{block}\nThat is all.", "SECRET"), {block})

    def test_private_key_block_without_its_end_line(self):
        block = armor("RSA PRIVATE KEY", "\n".join(fake("pem" + str(i), 64) for i in range(2)), end=False)
        self.assertEqual(values_of(f"{block}\nThe rest was cut off.", "SECRET"), {block})

    def test_private_key_block_with_escaped_dashes(self):
        # A Markdown converter may escape the dashes.
        block = armor("PRIVATE KEY", fake("e", 64)).replace("-", "\\-")
        self.assertEqual(values_of(block, "SECRET"), {block})

    def test_public_key_block_is_left(self):
        self.assertEqual(values_of(armor("PUBLIC KEY", fake("pub", 64)), "SECRET"), set())

    def test_connection_string_hides_user_and_password_only(self):
        text = "Database: postgres://bakery_admin:Tr0ub4dor&3@db.example.com:5432/orders"
        got = found(text)
        self.assertIn(("bakery_admin:Tr0ub4dor&3", "CREDENTIAL"), got)
        self.assertFalse(any(c == "EMAIL" for _, c in got))  # "Tr0ub4dor&3@db.example.com" is not an email

    def test_password_with_an_at_sign_in_a_connection_string(self):
        self.assertIn("admin:p@ss", values_of("mysql://admin:p@ss@db.example.com/app", "CREDENTIAL"))

    def test_authorization_header(self):
        tok = fake("bearer", 40)
        self.assertEqual(values_of(f'curl -H "Authorization: Bearer {tok}" https://api.example.com', "SECRET"),
                         {tok})

    def test_long_value_after_a_key_label(self):
        tok = fake("label", 32)
        self.assertEqual(values_of(f"API key: {tok}", "SECRET"), {tok})
        self.assertEqual(values_of(f"Private key: 0x{fake('eth', 64, HEX)}", "SECRET"), {"0x" + fake("eth", 64, HEX)})


class SettingTest(unittest.TestCase):
    def test_env_json_and_yaml_settings(self):
        tok = fake("set", 40)
        for text in (f"OPENAI_API_KEY={tok}", f'ANTHROPIC_API_KEY="{tok}"', f'{{"client_secret": "{tok}"}}',
                     f"aws_secret_access_key: {tok}", f"export GITHUB_TOKEN={tok}", f"apiKey: '{tok}'"):
            with self.subTest(text[:12]):
                self.assertEqual(values_of(text, "SECRET"), {tok})

    def test_the_setting_name_stays(self):
        tok = fake("set", 40)
        out = pipeline.Pipeline(config(), layers=("rules",)).run(f"OPENAI_API_KEY={tok}\n")
        self.assertEqual(render(f"OPENAI_API_KEY={tok}\n", out), "OPENAI_API_KEY=[SECRET_1]\n")

    def test_env_password_takes_any_value(self):
        self.assertEqual(values_of("DB_PASSWORD=sunshine", "CREDENTIAL"), {"sunshine"})
        self.assertEqual(values_of("SMTP_PASS=sunshine", "CREDENTIAL"), {"sunshine"})
        self.assertEqual(values_of('JWT_SECRET="supersecretvalue"', "SECRET"), {"supersecretvalue"})

    def test_code_and_references_are_not_secrets(self):
        for text in ("token = next_token()", "password = lexer.get_token()", "TOKEN_ENDS = TSPECIALS",
                     'api_key = os.environ["API_KEY"]', '"api_key": "${API_KEY}"', "token = nextchar",
                     "clientSecret: keys.web.client_secret", "public_key=" + fake("pk", 40),
                     "client_id: " + fake("cid", 24), "token_url: https://auth.example.com/token",
                     'GOOGLE_API_KEY="your-api-key"', "secret: Tuesday", "PASS: turn 1: no dashes",
                     "if passwd:\n    passwd = ''", "def pwd(self):\n    '''Return the working directory.'''",
                     "prompt='Password: '"):
            with self.subTest(text[:24]):
                got = found(text)
                self.assertFalse({c for _, c in got} & {"SECRET", "CREDENTIAL"}, got)


class PasswordFieldTest(unittest.TestCase):
    def test_letters_only_and_multi_word_values(self):
        self.assertEqual(values_of("Guest Wi-Fi password: sunshine", "CREDENTIAL"), {"sunshine"})
        self.assertIn("correct horse battery staple",
                      values_of("Backup vault passphrase: correct horse battery staple", "CREDENTIAL"))
        self.assertIn("Hunter Two", values_of("Password (case sensitive): Hunter Two", "CREDENTIAL"))
        self.assertIn("a b c", values_of('Password: "a b c" (quoted)', "CREDENTIAL"))

    def test_a_later_field_on_the_same_line_stays(self):
        got = found("Password: hunter2 Email: e.whitfield@example.com")
        self.assertIn(("hunter2", "CREDENTIAL"), got)
        self.assertIn(("e.whitfield@example.com", "EMAIL"), got)

    def test_value_on_the_next_line(self):
        self.assertEqual(values_of("Password:\nsunshine\n", "CREDENTIAL"), {"sunshine"})

    def test_pin_and_security_answers(self):
        self.assertEqual(values_of("Alarm PIN: 4821", "CREDENTIAL"), {"4821"})
        self.assertEqual(values_of("Bank security answer: Biscuit", "CREDENTIAL"), {"Biscuit"})
        self.assertIn("Biscuit",
                      values_of("Security question: First pet's name?\nAnswer: Biscuit", "CREDENTIAL"))

    def test_words_that_are_not_values(self):
        for text in ("Reset your password at the front desk.", "Password: ________", "Password: N/A",
                     "Password: (on file)", "Pin: blue", "- password: The password for the account",
                     "Answer: Yes"):
            with self.subTest(text):
                self.assertEqual(values_of(text, "CREDENTIAL"), set())

    def test_labels_stay_in_the_cleaned_text(self):
        text = "Admin portal password: Tr0ub4dor&3\nReset your password at the front desk.\n"
        out = render(text, pipeline.Pipeline(config(), layers=("rules",)).run(text))
        self.assertEqual(out, "Admin portal password: [CREDENTIAL_1]\nReset your password at the front desk.\n")


class TableTest(unittest.TestCase):
    def test_password_and_key_columns(self):
        tok = fake("tbl", 32)
        text = ("| Service | Username | Password | API key |\n|---|---|---|---|\n"
                f"| Mail | ellie | sunshine | {tok} |\n| Bank | ewhitfield | ******** | |\n")
        got = found(text)
        self.assertIn(("sunshine", "CREDENTIAL"), got)
        self.assertIn((tok, "SECRET"), got)
        self.assertFalse(any(v in ("Password", "API key", "********") for v, _ in got))

    def test_label_and_value_cells_in_one_row(self):
        text = "| Field | Value |\n|---|---|\n| Password | sunshine |\n"
        self.assertEqual(values_of(text, "CREDENTIAL"), {"sunshine"})

    def test_columns_that_name_tokens_but_hold_none(self):
        for text in ("| Token | Value |\n|---|---|\n| `--theme-blue-70` | #1e407c |\n",
                     "| Secret | Where it lives |\n|---|---|\n| `OPENAI_API_KEY` | the shell |\n",
                     "| Item | Pin |\n|---|---|\n| Image | v1.2.3 |\n"):
            with self.subTest(text[:12]):
                self.assertFalse({c for _, c in found(text)} & {"SECRET", "CREDENTIAL"})


class SeedPhraseTest(unittest.TestCase):
    def test_twelve_words_alone(self):
        for seed in (SEED_12, SEED_12B, SEED_12.upper()):
            with self.subTest(seed[:12]):
                self.assertEqual(values_of(f"Written below.\n\n{seed}\n", "SEED_PHRASE"), {seed})

    def test_numbered_over_several_lines(self):
        words = SEED_24.split()
        lines = "\n".join(" ".join(f"{i + 1}. {w}" for i, w in list(enumerate(words))[k:k + 8])
                          for k in range(0, 24, 8))
        got = values_of(f"In the order on the card:\n{lines}\n\nFirst steps next.", "SEED_PHRASE")
        self.assertEqual(len(got), 1)
        phrase = got.pop()
        self.assertTrue(phrase.startswith("letter") and phrase.endswith("bless"), phrase)

    def test_markdown_escaped_numbering(self):
        lines = "\n".join(f"{i + 1}\\. {w}" for i, w in enumerate(SEED_12B.split()))
        self.assertEqual(len(values_of(lines, "SEED_PHRASE")), 1)

    def test_a_table_and_one_word_per_paragraph(self):
        words = SEED_12B.split()
        table = "| # | Word |\n|---|---|\n" + "\n".join(f"| {i + 1} | {w} |" for i, w in enumerate(words))
        paragraphs = "\n\n".join(f"{i + 1}. {w}" for i, w in enumerate(words))
        for text in (table, paragraphs):
            with self.subTest(text[:8]):
                got = values_of(text, "SEED_PHRASE")
                self.assertEqual(len(got), 1)
                self.assertTrue(got.pop().endswith("yellow"))

    def test_after_a_label_three_words_are_enough(self):
        self.assertEqual(values_of("First four seed words of the spare: legal winner thank year", "SEED_PHRASE"),
                         {"legal winner thank year"})
        self.assertEqual(values_of("Recovery phrase:\nlegal winner thank\n", "SEED_PHRASE"),
                         {"legal winner thank"})

    def test_the_label_is_never_swallowed(self):
        # "seed" and "phrase" are themselves BIP-39 words.
        self.assertEqual(values_of(f"Seed phrase: {SEED_12}", "SEED_PHRASE"), {SEED_12})

    def test_a_run_stops_at_sentences_labels_and_headings(self):
        text = f"It is written below.\n\n{SEED_12}\n\n## Ordinary text that must stay\n"
        self.assertEqual(values_of(text, "SEED_PHRASE"), {SEED_12})

    def test_prose_speech_and_code_are_not_seeds(self):
        for text in ("well, you know what they say just make this one more time when you want to",
                     "\n".join(["you"] * 13),
                     "def check(year, month, day):\n    year = index(year)\n    month = index(month)\n"
                     "    day = index(day)\n    check(year, month, day)",
                     "Counting on your hand is a physical mnemonic -- one finger, one minute.",
                     "frame_target = Frame(frame_custom)\ntarget_title = Label(frame_target, text='Action')"):
            with self.subTest(text[:20]):
                self.assertEqual(values_of(text, "SEED_PHRASE"), set())

    def test_one_placeholder_for_a_repeated_phrase(self):
        text = f"Card: {SEED_12B}\nCopy: {SEED_12B}\n"
        out = render(text, pipeline.Pipeline(config(), layers=("rules",)).run(text))
        self.assertEqual(out, "Card: [SEED_PHRASE_1]\nCopy: [SEED_PHRASE_1]\n")


class WordListTest(unittest.TestCase):
    def setUp(self):
        self.saved = credentials.WORDLIST
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        credentials.WORDLIST, credentials._words = self.saved, None
        shutil.rmtree(self.tmp)

    def test_the_pinned_list(self):
        words = credentials.seed_words()
        self.assertEqual(len(words), 2048)
        self.assertIn("abandon", words)
        self.assertIn("zoo", words)

    def test_a_damaged_or_missing_list_stops_the_run_before_any_document(self):
        bad = os.path.join(self.tmp, "bip39-english.txt")
        shutil.copy(self.saved, bad)
        with open(bad, "a", encoding="ascii") as f:
            f.write("extra\n")
        for path, why in ((bad, "sha256"), (os.path.join(self.tmp, "missing.txt"), "missing")):
            with self.subTest(why):
                credentials.WORDLIST, credentials._words = path, None
                with self.assertRaises(pipeline.Stop) as e:
                    pipeline.build(config(), False)  # the first preflight check, before any model
                self.assertEqual((e.exception.code, e.exception.stage), (3, "setup"))
                self.assertIn(why, e.exception.message)


class HandoverNoteTest(unittest.TestCase):
    """A fictitious IT handover note with 23 planted secrets. 1.0.0's rules left 19 of them."""

    def note(self):
        s = {
            "github": "gh" + "p_" + fake("n-gh", 36),
            "github_fine": "github" + "_pat_" + fake("n-ghf", 22) + "_" + fake("n-ghf2", 59),
            "aws_id": "AK" + "IA" + fake("n-aws", 16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"),
            "aws_secret": fake("n-awss", 40),
            "openai": "sk-" + "proj-" + fake("n-oa", 48),
            "anthropic": "sk-" + "ant-api03-" + fake("n-an", 93) + "AA",
            "stripe": "sk" + "_live_" + fake("n-st", 24),
            "slack": "xo" + "xb-" + "1234567890123-1234567890123-" + fake("n-sl", 24),
            "google": "AI" + "za" + fake("n-go", 35),
            "telegram": "1234567890" + ":" + "AA" + fake("n-tg", 33),
            "jwt": "eyJ" + fake("n-j1", 30) + ".eyJ" + fake("n-j2", 50) + "." + fake("n-j3", 43),
            "bearer": fake("n-be", 44),
            "hf": "hf" + "_" + fake("n-hf", 34),
            "npm": "npm" + "_" + fake("n-np", 36),
            "db_password": "Tr0ub4dor&3",
            "wifi": "sunshine",
            "passphrase": "correct horse battery staple",
            "answer": "Biscuit",
            "pin": "4821",
            "seed12": SEED_12,
            "seed24": SEED_24,
            "seed_partial": "legal winner thank year",
            "pem_line": fake("n-pem2", 64),
        }
        pem = armor("OPENSSH PRIVATE KEY", fake("n-pem1", 64) + "\n" + s["pem_line"])
        numbered = "\n".join(" ".join(f"{i + 1}. {w}" for i, w in list(enumerate(SEED_24.split()))[k:k + 8])
                             for k in range(0, 24, 8))
        text = f"""FICTITIOUS TEST DATA, NOT REAL CREDENTIALS

# IT handover note for the Example Bakery office

Admin portal password: {s['db_password']}
Guest Wi-Fi password: {s['wifi']}
Backup vault passphrase: {s['passphrase']}
Bank security answer: {s['answer']}
Alarm PIN: {s['pin']}

## Developer keys

Our CI token is {s['github']} and the deploy bot uses {s['github_fine']}.

    AWS_ACCESS_KEY_ID={s['aws_id']}
    AWS_SECRET_ACCESS_KEY={s['aws_secret']}
    OPENAI_API_KEY={s['openai']}
    ANTHROPIC_API_KEY="{s['anthropic']}"

Billing runs on Stripe ({s['stripe']}), alerts go to Slack with {s['slack']},
maps use {s['google']} and the shop bot token is {s['telegram']}.
Model downloads use {s['hf']}; publishing uses {s['npm']}.

config.json has {{"api_key": "{s['openai']}", "region": "us-east-1"}}.

    curl -H "Authorization: Bearer {s['bearer']}" https://api.example.com/v1/orders

A saved session cookie was {s['jwt']}

Database: postgres://bakery_admin:{s['db_password']}@db.example.com:5432/orders

{pem}

## Crypto wallet

The owner's hardware wallet recovery phrase is written below.

{s['seed12']}

The old wallet's seed, in the order on the card:
{numbered}

First four seed words of the spare: {s['seed_partial']}

## Ordinary text that must stay

The token ring meeting is on the first floor. Reset your password at the front desk.
The user guide covers the key steps. Our public key fingerprint is on the website.
"""
        return text, s

    def test_rules_alone_leave_none_of_the_23(self):
        text, planted = self.note()
        out = render(text, pipeline.Pipeline(config(), layers=("rules",)).run(text))
        for name, value in planted.items():
            with self.subTest(name):
                if name.startswith("seed"):
                    words = value.split()
                    for a, b in zip(words, words[1:]):  # no two words of a phrase survive in order
                        self.assertNotRegex(out, rf"(?i)\b{a}\W+(?:\d+\W+)?{b}\b")
                else:
                    self.assertNotIn(value, out)

    def test_ordinary_text_and_structure_stay(self):
        text, _ = self.note()
        out = render(text, pipeline.Pipeline(config(), layers=("rules",)).run(text))
        for line in ("The token ring meeting is on the first floor. Reset your password at the front desk.",
                     "The user guide covers the key steps. Our public key fingerprint is on the website.",
                     "The owner's hardware wallet recovery phrase is written below.",
                     "The old wallet's seed, in the order on the card:", "## Ordinary text that must stay",
                     "Admin portal password: [CREDENTIAL_", "    AWS_SECRET_ACCESS_KEY=[SECRET_",
                     "First four seed words of the spare: [SEED_PHRASE_", "postgres://[CREDENTIAL_"):
            with self.subTest(line[:30]):
                self.assertIn(line, out)


class RepoHygieneTest(unittest.TestCase):
    def test_no_token_shaped_strings_in_the_release_folder(self):
        """Secret scanners would flag them, and a real one must never be committed here."""
        hits = []
        for root, dirs, files in os.walk(RELEASE):
            dirs[:] = [d for d in dirs if d not in ("models", "__pycache__")]
            for name in files:
                if name.endswith((".pdf", ".pyc")):
                    continue
                path = os.path.join(root, name)
                with open(path, encoding="utf-8", errors="replace") as f:
                    text = f.read()
                for rx in (credentials.TOKEN, credentials.PEM):
                    hits += [os.path.relpath(path, RELEASE) for _ in rx.finditer(text)]
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
