# NexusRun units by Rick Manelius

This repo holds the [NexusRun](https://nexusrun.dev) units I build and publish. A NexusRun unit is an AI tool packaged as one artifact: its code, a manifest naming the models it uses, and the instructions to run it on your own machine. You pull it from a container registry, install its models once, and run it with one command. No cloud service sees your data. NexusRun itself is open source: [VerdictLayer/nexusrun](https://github.com/VerdictLayer/nexusrun).

Each unit lives in its own folder here, with its full source, so you can read exactly what runs before you run it. The built units are published as public packages on the GitHub container registry.

## Units

| Unit | Version | What it does | Pull |
|---|---|---|---|
| [**redact-docs**](redact-docs/) | 1.0.0 | Removes personal information (names, dates, IDs, addresses, account numbers and more) from a document on your own machine, and returns the cleaned text plus a table of what it replaced | `ghcr.io/rickmanelius/redact-docs:1.0.0` |

`redact-docs` is the first public unit. More will follow in the same layout.

## Quickstart

These steps are for a Mac with Apple silicon, where every unit here is tested. Linux on x86_64 should work the same way with the Linux build of nexus, but it has not been tested yet.

**1. Install nexus v0.1.0.** Download the release, check its sha256, and put the binary on your PATH:

```sh
curl -fsSLO https://github.com/VerdictLayer/nexusrun/releases/download/v0.1.0/nexus-darwin-arm64.tar.gz
echo "3fc1643b8ec433458fe92bbfb7863fcc2eb744e9eeadb747c4f6022bd95ab8f9  nexus-darwin-arm64.tar.gz" | shasum -a 256 -c
tar -xzf nexus-darwin-arm64.tar.gz && mkdir -p ~/.local/bin && mv nexus-darwin-arm64/nexus ~/.local/bin/
export PATH="$HOME/.local/bin:$PATH"
nexus --version
```

The last line should print `nexus version v0.1.0 (28f8e25)`. A new Mac does not have `~/.local/bin` on its PATH, so the `export` line adds it for this terminal; add the same line to `~/.zprofile` to keep it in new terminals. Other platforms are on the [v0.1.0 release page](https://github.com/VerdictLayer/nexusrun/releases/tag/v0.1.0), with their checksums.

**2. Pull a unit, install its models, and run it.** You need [Homebrew](https://brew.sh). For `redact-docs`:

```sh
brew install llama.cpp python@3.14
nexus pull ghcr.io/rickmanelius/redact-docs:1.0.0
nexus install --yes redact-docs:1.0.0
nexus run --no-daemon --no-sandbox redact-docs:1.0.0 -p "[selftest]"
```

`brew install` gets llama.cpp, the LLM runtime, and Python 3.14. The unit runs on Python 3.12, 3.13 or 3.14. Plain `brew install python` now gives Python 3.15, which the unit's pinned packages do not support yet. `nexus install` downloads the two models the unit names (2.7 GB, once) and checks each against its sha256.

The last command installs the unit's Python packages the first time (about 175 MB), cleans a fictitious intake form bundled with the unit, checks the result against its answer key, and ends with `selftest: ... passed`. Then clean your own file:

```sh
nexus run --no-daemon --no-sandbox redact-docs:1.0.0 -p "@$PWD/my-document.pdf" > cleaned.md
```

See [redact-docs/README.md](redact-docs/README.md) for what it redacts, how to tune it, and its limits.

## Build a unit from source

Every folder here builds the same unit you can pull. For example:

```sh
git clone https://github.com/rickmanelius/nexus && cd nexus
redact-docs/build.sh
nexus install --yes redact-docs:1.0.0
```

`build.sh` fetches the classifier's pinned tokenizer files, checks their sha256, then runs `nexus build`. `publish.sh` is how I build, self-test and push a unit to the registry.

## About

Built by Rick Manelius. Questions and ideas are welcome as [issues](https://github.com/rickmanelius/nexus/issues).

## License

Apache-2.0 (see [LICENSE](LICENSE)). The models and libraries each unit downloads keep their own licenses, listed in that unit's `THIRD_PARTY.md`.
