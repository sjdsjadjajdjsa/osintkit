# Contributing

Bug reports and pull requests are welcome. By participating you agree to the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Setup

```bash
git clone https://github.com/sjdsjadjajdjsa/osintkit
cd osintkit
uv sync --extra dev
pre-commit install
pytest
```

Tests must not touch the network. HTTP is mocked with `respx`; DNS, WHOIS, and model calls are
monkeypatched. `tests/fixtures/model_reply.json` covers the full-stack path.

## What fits

- new login-free, publicly documented sources
- parser fixes when a source changes shape
- better failure messages, caching, or rate-limit handling
- accessibility and output quality in the Rich renderer
- documentation, examples, and tests

Out of scope: sources that need scraping behind a login, paid brokers, and broad rewrites of the
CLI surface.

## Adding a collector

Collectors are small async functions in `src/osintkit/collectors/`.

1. Register with `@collector(name, target_types, description, order=..., ttl=..., timeout=...)`.
2. Accept `Context`; read only `ctx.target`, `ctx.target_type`, `ctx.http`, and settings.
3. Return plain JSON-able data. Raise nothing for a normal empty result.
4. Pass a `namespace` to every `ctx.http` call so caching is isolated. Use `empty_on` for
   "not found" statuses.
5. Add a `ttl` for volatile data and a `timeout` for slow sources.
6. Test the happy path, the empty path, and one failure path with `respx`.
7. Add the row to `docs/REFERENCE.md#collectors`.

`run_collector` catches exceptions, times the call, and records the outcome, so a collector must
only raise for genuinely broken upstream state.

Never invent data: if a source returns nothing, return an empty value. The synthesis prompt
distinguishes "no findings" from "not collected", and both are visible in the report.

## Style

- `ruff format` and `ruff check` must pass; line length 112.
- Type hints on public functions; `from __future__ import annotations` at the top.
- Comments explain *why*, not *what*. Docstrings for modules and non-obvious functions.
- No new runtime dependency without a reason in the PR.
- Keep the security posture: public data only, no credentials in logs, no shelling out.

## Commits

Present tense, imperative, under 72 characters on the first line. Say what the change enables,
not which files moved. Body only when the reason is not obvious.

## Pull requests

- One logical change per PR; split unrelated cleanups out.
- Describe the problem before the fix, and say how it was tested.
- Include the report or coverage panel for collector changes.
- CI must be green; `--no-verify` is fine locally but not for merging.

Maintainers may squash. A reviewer will ask for a test if a change is behavioural and untested.
