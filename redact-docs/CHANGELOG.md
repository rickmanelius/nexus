# redact-docs changelog

## 1.0.0 (2026-11-22)

First public release.

- Three detection layers run in order on a document converted on your machine: rules (formats, checksums and labels), the GLiNER-PII classifier on onnxruntime, and Qwen3-4B through llama.cpp, which can only label strings taken from the document.
- One written PII definition (`docs/pii-definition.md`) drives every layer. The default profile, `strict`, redacts direct identifiers and context identifiers such as city, age and employer, and keeps health content.
- Client profiles in `~/.config/nexus-redact/profiles` tune it as data: Tier B classes on or off, extra ID formats, and terms to always or never redact.
- Fail-closed: any failure prints one line naming the stage, never document text or the file's name.
- Measured on the bundled fictitious intake form: 0 of 80 direct identifiers and 0 of 14 context identifiers left in the output, the same output on every run, about 15 seconds on an Apple M4 Pro.
