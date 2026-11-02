# Changelog

All notable changes are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## 0.3.0 — 2026-11-02

### Added

- providers for DeepSeek, Mistral, Groq, Together, Anthropic, and local Ollama
- provider selection from its own environment variable (`DEEPSEEK_API_KEY`, `MISTRAL_API_KEY`, ...)
- keyless providers (Ollama) work without any key, including in `doctor`

### Changed

- `doctor` reports the provider and where the key came from

## 0.2.0 — 2026-11-02

### Added

- `--offline` mode: a full report built from local rules, no model and no key

### Fixed

- the ports collector was registered as a sync helper, so `--ports` and the registry entry broke

## 0.1.2 — 2026-11-02

### Fixed

- releases now dispatch the PyPI job explicitly, since `GITHUB_TOKEN` releases do not fire
  `release` events

## 0.1.1 — 2026-11-02

### Added

- `--provider` presets (`venice`, `openrouter`, `openai`) chosen from a key prefix
- `collectors --json` metadata for scripting
- weekly smoke workflow and a social preview card
- opt-in PyPI publishing through Trusted Publishing

### Changed

- default Venice model is the plain `deepseek-v4-1-flash` alias
- the README demo image no longer names the model
- CI enforces formatting and 85% coverage

### Added

- `diff` command comparing two archived runs: risk direction, breach and subdomain deltas,
  collector health
- `--ports` to scope the TCP probe list
- provider detection from a `sk-or-` key prefix
- `doctor --deep` verifying the key with a one-token completion
- retention window and `prune` for cache, logs, and reports
- `schema` command publishing the model contract
- `batch --only`, `--skip`, `--raw`, and `--concurrency`

### Changed

- breach records merge across sources; risk gets a deterministic floor
- report schema carries `schema_version`
- unknown collector names fail with a suggestion

### Fixed

- repeat runs missed the model cache because of a prompt timestamp
- cached replays double-decoded compressed bodies
- crt.sh organisation search falls back to certificate identity
- batch progress no longer pollutes piped JSON
- rate-limit and empty-completion handling

## 0.1.0 — 2026-11-02

Initial release: lookup, batch, and history commands; twenty public-source collectors;
LLM synthesis with schema validation; Rich, JSON, and Markdown output; local cache and logs.
