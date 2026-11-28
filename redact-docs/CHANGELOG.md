# redact-docs changelog

## 1.1.0 (unreleased)

Secrets: API keys, tokens, private keys, seed phrases and passwords ([#1](https://github.com/rickmanelius/nexus/issues/1)).

- New Tier A class `SECRET` (`[SECRET_n]`): API keys and tokens by their published prefix (GitHub, GitLab, Slack, Stripe, Anthropic, OpenAI, Google, AWS, Hugging Face, npm, PyPI, SendGrid and others), JWTs, whole private key blocks (PEM, OpenSSH, PGP, PuTTY), WIF and extended crypto private keys, BitLocker recovery keys, long values after a key or token label, settings such as `OPENAI_API_KEY=` or `"client_secret":`, and `Authorization` headers.
- New Tier A class `SEED_PHRASE` (`[SEED_PHRASE_n]`): 12 or more BIP-39 words in a row, numbered, comma-separated, in a table or one per line, or 3 or more after a seed-phrase label. Runs that are mostly common English are taken for prose. The BIP-39 English word list ships in `unit/pii/` and is checked against its sha256 before any document is read.
- `CREDENTIAL` now takes the whole value after a password, passphrase, PIN or security-answer label, so letters-only and multi-word passwords are caught, plus password columns in tables and the user:password part of connection strings.
- Secrets are found by the rules layer alone, so they no longer depend on what the classifier happens to tag.
- Label words such as password, token and seed are kept when a model marks one on its own: `Reset your password` used to become `Reset your [CREDENTIAL_1]`.
- Blank fields (`Password: ________`) and code (`token = next_token()`) are no longer redacted as credentials.
- New `tests/` folder (standard library only, no models): 44 tests for the new rules and the taxonomy. They build every fake token at run time, so the repo holds no token-shaped string.
- The bundled selftest result and output are unchanged.

## 1.0.0 (2026-11-22)

First public release.

- Three detection layers run in order on a document converted on your machine: rules (formats, checksums and labels), the GLiNER-PII classifier on onnxruntime, and Qwen3-4B through llama.cpp, which can only label strings taken from the document.
- One written PII definition (`docs/pii-definition.md`) drives every layer. The default profile, `strict`, redacts direct identifiers and context identifiers such as city, age and employer, and keeps health content.
- Client profiles in `~/.config/nexus-redact/profiles` tune it as data: Tier B classes on or off, extra ID formats, and terms to always or never redact.
- Fail-closed: any failure prints one line naming the stage, never document text or the file's name.
- Measured on the bundled fictitious intake form: 0 of 80 direct identifiers and 0 of 14 context identifiers left in the output, the same output on every run, about 15 seconds on an Apple M4 Pro.
