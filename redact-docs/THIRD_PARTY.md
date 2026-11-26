# Third-party components in redact-docs

The unit's own code is Apache-2.0 (see [LICENSE](../LICENSE)). It downloads or runs the components below, each under its own license, and changes none of them.

## Models

`nexus install` downloads both, and checks each against the sha256 pinned in [unit/nexus.yaml](unit/nexus.yaml).

| Model | Author | License | Source |
|---|---|---|---|
| GLiNER-PII base v1.0, `onnx/model_quint8.onnx` (plus `tokenizer.json`, `tokenizer_config.json` and `gliner_config.json`, which `build.sh` downloads) | Knowledgator; DeBERTa-v3-small backbone by Microsoft (MIT) | [Apache-2.0](https://huggingface.co/knowledgator/gliner-pii-base-v1.0) | https://huggingface.co/knowledgator/gliner-pii-base-v1.0, revision `61726e0ad791dcab3e29339bbec3ad42ded65641` |
| Qwen3-4B-Instruct-2507, GGUF `Qwen3-4B-Instruct-2507-Q4_K_M.gguf` | Qwen team, Alibaba Cloud; GGUF conversion by Unsloth | [Apache-2.0](https://huggingface.co/unsloth/Qwen3-4B-Instruct-2507-GGUF) | https://huggingface.co/unsloth/Qwen3-4B-Instruct-2507-GGUF, revision `a06e946bb6b655725eafa393f4a9745d460374c9` |

The GLiNER inference code in `unit/tools/classifier.py` reimplements the parts of the [`gliner`](https://github.com/urchade/GLiNER) package (Apache-2.0) that span inference needs. No code was copied.

## Programs you install

| Program | License | Role |
|---|---|---|
| [NexusRun](https://github.com/VerdictLayer/nexusrun) (`nexus`) | Apache-2.0 | Builds, installs and runs the unit |
| [llama.cpp](https://github.com/ggml-org/llama.cpp) (`llama-completion`) | [MIT](https://github.com/ggml-org/llama.cpp/blob/master/LICENSE) | Runs the LLM layer |
| Python 3.12, 3.13 or 3.14 | PSF-2.0 | Runs the pipeline |

## Python packages

On its first run the unit installs exactly the packages in [unit/requirements.lock](unit/requirements.lock) into `~/.cache/nexus-redact/`, every file checked against its sha256. Licenses are as each package's own metadata states them. `colorama` (Windows only) and `httpx2-jsfetch` (WebAssembly only) are in the lock for completeness and are never installed on macOS or Linux.

| Package | Version | License |
|---|---|---|
| anyio | 4.15.1 | MIT |
| click | 8.5.0 | BSD-3-Clause |
| colorama | 0.4.6 | BSD-3-Clause |
| filelock | 4.2.4 | MIT |
| firecrawl-anydoc | 0.2.4 | MIT |
| flatbuffers | 25.12.19 | Apache-2.0 |
| fsspec | 2026.9.0 | BSD-3-Clause |
| h11 | 0.16.0 | MIT |
| hf-xet | 1.8.0 | Apache-2.0 |
| httpcore2 | 2.16.0 | BSD-3-Clause |
| httpx2 | 2.16.0 | BSD-3-Clause |
| httpx2-jsfetch | 1.0 | BSD-3-Clause |
| huggingface_hub | 2.4.0 | Apache-2.0 |
| idna | 3.20 | BSD-3-Clause |
| numpy | 2.5.4 | BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0 |
| onnxruntime | 1.31.1 | MIT |
| packaging | 26.3 | Apache-2.0 OR BSD-2-Clause |
| protobuf | 7.36.2 | BSD-3-Clause |
| PyYAML | 6.0.3 | MIT |
| tokenizers | 0.23.3 | Apache-2.0 |
| tqdm | 4.70.1 | MPL-2.0 AND MIT |
| truststore | 0.10.5 | MIT |
| typing_extensions | 4.16.0 | PSF-2.0 |

## Test data

Everything in `unit/selftest/` is fictitious and was written for this unit; see [unit/selftest/README.md](unit/selftest/README.md).
