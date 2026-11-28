# redact-docs

A [NexusRun](https://nexusrun.dev) unit that removes personal information from a document on your own machine. You give it a PDF, Word file, spreadsheet, slide deck or text file; it gives back the document as Markdown with every name, date, ID number, address, phone number, account number, password, API key, private key, seed phrase and similar value replaced by a placeholder, plus a table of what it replaced. The document never leaves your computer.

```text
Patient Name: Eleanor Marguerite Whitfield   ->   Patient Name: [PERSON_1]
SSN: 987-65-4320                             ->   SSN: [SSN_1]
Mobile: 312-555-0187                         ->   Mobile: [PHONE_2]
Guest Wi-Fi password: sunshine               ->   Guest Wi-Fi password: [CREDENTIAL_1]
OPENAI_API_KEY=<the key>                     ->   OPENAI_API_KEY=[SECRET_1]
```

Labels stay and values go, and a value gets the same placeholder everywhere it appears, so the cleaned document still reads correctly. (All data in these examples is fictitious.)

Version 1.1.0. Published as `ghcr.io/rickmanelius/redact-docs:1.1.0`.

## Quickstart

You need nexus v0.1.0 ([install steps](../README.md#quickstart)), llama.cpp, and Python 3.12, 3.13 or 3.14. Python 3.15 does not work yet: the pinned onnxruntime and PyYAML have no 3.15 wheels, and plain `brew install python` now gives 3.15. On a Mac with Apple silicon and [Homebrew](https://brew.sh):

```sh
brew install llama.cpp python@3.14
nexus pull ghcr.io/rickmanelius/redact-docs:1.1.0
nexus install --yes redact-docs:1.1.0
nexus run --no-daemon --no-sandbox redact-docs:1.1.0 -p "[selftest]"
```

`nexus install` downloads the two models the unit names (2.7 GB) and checks each against its pinned sha256. The selftest run installs the unit's Python packages the first time (about 175 MB, into `~/.cache/nexus-redact/`), then cleans the fictitious intake form bundled in `unit/selftest/` and checks the result against its answer key. It should end with:

```text
selftest: Tier A 0 of 80 values leaked, Tier B 0 of 14 leaked; passed
```

Then clean your own file. Give an absolute path after `@`:

```sh
nexus run --no-daemon --no-sandbox redact-docs:1.1.0 -p "@$PWD/my-document.pdf" > cleaned.md
```

About the flags:

- `--no-daemon`: if `nexus serve` is running, nexus v0.1.0 would hand the prompt to the daemon as a chat and never run the redaction. Every real report starts with the line `redact-docs 1.1.0 | profile strict | layers rules, classifier, llm | local only`.
- `--no-sandbox`: macOS has no nexus script sandbox. On Linux, leave the flag out and the unit runs sandboxed.

## What you get

The report is the cleaned document, then a summary table. From the bundled intake form:

```text
redact-docs 1.1.0 | profile strict | layers rules, classifier, llm | local only

## FICTITIOUS TEST DATA-NOT A REAL PATIENT

# [ORG_1]-New Patient Intake Form

Patient Name: [PERSON_1] Preferred Name: [PERSON_2] Date of Birth: [DATE_1] Age: [AGE_1] Sex: [SEX_1] ...

## PII replaced

| Placeholder | PII class | Tier | Distinct values | Occurrences | Caught by |
|---|---|---|---|---|---|
| `[PERSON_n]` | Person name | A | 20 | 30 | rules, classifier |
| `[SSN_n]` | Social Security number | A | 3 | 3 | rules |
| `[DATE_n]` | Date linked to a person | A | 17 | 17 | rules |
...
```

No original value is printed anywhere: not in the table, not in error messages. If anything fails, the run prints one line naming the stage (for example `redact-docs: error: conversion: document needs OCR ...`) and exits non-zero, without the document's text or its file name.

## How it works

One run goes through these steps in order:

1. **Checks first.** The profile, both models, llama.cpp and the seed word list (checked against its sha256) must be present before the document is read.
2. **Local conversion.** [anydoc](https://github.com/firecrawl/anydoc) turns the file into Markdown with its native converter only. Hosted OCR is never called, so scanned PDFs that need OCR are refused.
3. **Rules.** Emails, URLs, IP addresses, phone numbers, dates, valid SSNs, card numbers (Luhn), Medicare numbers and VINs are caught by their format. Routing numbers, member IDs, account numbers and other digit runs are caught when a label sits just before them, even when their checksum fails. Secrets are caught here too, so they never depend on the models: API keys and tokens by their published prefix, private key blocks, seed phrases from the BIP-39 word list, the value of a setting such as `OPENAI_API_KEY=` or `"password":`, the field after a password label, and table columns headed by one.
4. **Classifier.** [GLiNER-PII](https://huggingface.co/knowledgator/gliner-pii-base-v1.0) runs on what the rules left, on onnxruntime, and finds names, addresses, cities and organizations.
5. **LLM.** Qwen3-4B, through llama.cpp, looks at the capitalized words still visible and marks the ones that name a person, place or organization. It only labels strings taken from the document, so it cannot invent or rewrite text, and the document reaches it on stdin.
6. **Replace and report.** Every span any layer found is replaced, along with every other occurrence of the same value.

The same document, profile and version give byte-identical output on the same machine.

## What it redacts

The full definition is [docs/pii-definition.md](docs/pii-definition.md), and its machine copy is [unit/pii/taxonomy.json](unit/pii/taxonomy.json). The default profile, `strict`, redacts:

- **Tier A, always:** names (nicknames included), SSNs and tax IDs, every date more specific than a year, phone and fax numbers, emails, street addresses, medical record numbers, health plan and Medicare IDs, account, card and routing numbers, card expiry and security codes, driver's license and passport numbers, VINs and plates, IP and device addresses, URLs, provider IDs, any other identifying number, and secrets: user names, passwords, passphrases, PINs and security answers (`[CREDENTIAL_n]`), API keys, tokens and private keys (`[SECRET_n]`), and wallet seed phrases (`[SEED_PHRASE_n]`).
- **Tier B, on by default:** city, state, ZIP, age, sex, marital status, occupation, and organizations tied to the person (employer, clinic, pharmacy, bank).

It keeps health content (diagnoses, codes, medications, allergies), because a cleaned medical form is not useful without it. When in doubt it redacts: over-redaction is preferred to a leak.

Secrets are redacted in any document, config files and code snippets included, because a leaked key does harm on its own. Removing one from a copy does nothing for the original: **a key, password or seed phrase that was in it should still be rotated** (for a seed phrase, the funds moved) if the original was ever stored or sent somewhere you do not control.

## Tuning for your documents

A profile is a JSON file in `~/.config/nexus-redact/profiles/<name>.json`, picked per run with a prefix:

```sh
nexus run --no-daemon --no-sandbox redact-docs:1.1.0 -p "[profile=client-a] @$PWD/claim.pdf"
```

```json
{
  "name": "client-a",
  "base": "strict",
  "disable": ["OCCUPATION"],
  "classes": [{"id": "CLAIM_NUMBER", "tag": "CLAIM", "tier": "A", "name": "Claim number"}],
  "patterns": [{"class": "CLAIM_NUMBER", "regex": "CLM-\\d{4}-\\d{6}"}],
  "deny": [{"class": "PERSON", "term": "Jordan Example"}],
  "allow": ["Example Mutual Health"]
}
```

A profile can turn Tier B classes off, turn health content on (`"enable": ["HEALTH_INFO"]`), add your own ID formats, and list terms that must always (`deny`) or never (`allow`) be redacted. Tier A classes cannot be turned off. A profile with an unknown class or a pattern that does not compile stops the run before the document is read. The profile's name is printed in the report's first line, so give profiles neutral names.

Other prompt prefixes: `[selftest]` runs the bundled check, and `[verbose]` adds progress counts (never text). Text without `@` is redacted as given, but prefer a file: text on the command line lands in your shell history.

## Results and limits

On the bundled fictitious intake form (five pages, 133 planted values), 0 of 80 distinct direct identifiers and 0 of 14 context identifiers are left in the output, counting partial leaks such as a surname left beside a placeholder. A run takes about 15 seconds on an Apple M4 Pro. That is one hand-made form, not a benchmark. Check the output on your own documents before you rely on it.

For secrets, the tests include a fictitious IT handover note with 23 planted secrets: keys and tokens from 10 providers in prose, env lines, JSON and a curl header, a bearer token, a JWT, a private key block, a connection string, letters-only and multi-word passwords, a PIN, a security answer, and three seed phrases. The rules alone leave none of them. Version 1.0.0 left 10 of them with all three layers running, and which ones it caught changed with the characters in each key. On about 150 MB of ordinary text (Python's standard library, npm package READMEs, and a private set of notes and podcast transcripts), the seed-phrase rule now fires 0 times; that text was also used to tune it.

Known limits:

- **macOS has no sandbox.** There, "nothing leaves the machine" rests on the unit's own code: the pipeline switches off Python's network calls, conversion never calls hosted OCR, and llama.cpp gets the text on stdin. After setup the unit also runs with all network denied. On Linux the nexus sandbox limits file access, but the unit declares `network` for its first-run package install, so it does not block egress.
- **English, born-digital documents.** No OCR for scanned pages.
- **Combinations.** Each value is judged on its own. A rare mix of harmless details (a small town, an age and a job) can still point to one person.
- **Secrets it does not know.** A random-looking string with no label, no known prefix and no setting name that gives it away is kept: guessing by randomness alone would also take hashes and IDs. Seed phrases are caught in English BIP-39 only, not Monero's 25 words, SLIP-39 shares or other languages, and a phrase made mostly of common English words is taken for prose. Wallet addresses are not redacted.
- **Tested on macOS with Apple silicon.** Linux on x86_64 is expected to work and is not yet tested.

## Build it yourself

```sh
redact-docs/build.sh
nexus install --yes redact-docs:1.1.0
```

Run these from the repo root. `build.sh` fetches the classifier's tokenizer files, checks their sha256, then runs `nexus build`. `unit/` is exactly what the published artifact contains, apart from those three tokenizer files.

| Path | What it is |
|---|---|
| `unit/nexus.yaml` | The unit's manifest: its entrypoint, its two models by pinned source and sha256, its settings |
| `unit/tools/` | The pipeline: `redact.sh` (entrypoint), `pipeline.py`, `rules.py`, `classifier.py`, `llm.py` and helpers |
| `unit/pii/` | The PII taxonomy, the `strict` profile and the BIP-39 seed word list |
| `unit/prompts/detector.txt` | The LLM's instructions |
| `unit/requirements.lock` | Every Python package, pinned with its sha256 |
| `unit/selftest/` | The fictitious intake form and its answer key |
| `docs/pii-definition.md` | What counts as PII, class by class |
| `tests/` | Unit tests for the rules and the taxonomy (not packed into the unit) |

The tests use the Python standard library alone (checked on 3.11 and 3.14), with no models and no network:

```sh
python3 -m unittest discover -s redact-docs/tests
```

Third-party models and packages, with their licenses: [THIRD_PARTY.md](THIRD_PARTY.md). Changes: [CHANGELOG.md](CHANGELOG.md).
