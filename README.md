# osintkit

[![ci](https://github.com/sjdsjadjajdjsa/osintkit/actions/workflows/ci.yml/badge.svg)](https://github.com/sjdsjadjajdjsa/osintkit/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.12%20%7C%203.13-blue)](pyproject.toml)
[![pypi](https://img.shields.io/pypi/v/osintkit)](https://pypi.org/project/osintkit/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

Public-data OSINT for one email, username, domain, company, phone number, or Bitcoin address: gathered from free sources,
briefed by an LLM acting as a defensive analyst, rendered as a colour-coded report.

`osintkit` uses only public sources: certificate transparency, public DNS, WHOIS, public GitHub
search, free breach indexes, paste archives, and public profile pages. It never logs in on your
behalf and never touches a paid data broker.

<img src="docs/demo.svg" alt="osintkit report showing risk, breaches, and recommendations" width="820">

A full trimmed report, including breach and account sections, is in
[docs/sample-output.md](docs/sample-output.md).

## Why

Checking what the public record says about you is tedious: a dozen sites, a dozen formats, no
synthesis. `osintkit` runs those checks concurrently, keeps the raw evidence, and turns it into
a briefing with a risk level and concrete hardening advice. Everything is local, every source
is named, and every gap is reported instead of hidden.

Intended for personal privacy checks, authorised pre-engagement recon, and quick due diligence
on a domain or company. Findings are leads to verify, not facts.

## Install

```bash
pipx install osintkit
# or
uv tool install osintkit
```

Every [release](https://github.com/sjdsjadjajdjsa/osintkit/releases) also carries a wheel with
checksums, and `pip install -e .` works from a clone. Python 3.12+ only.

## Quick start

```bash
osintkit init                      # pick a provider, paste a key once
osintkit lookup alice@example.com
```

`init` stores the provider and key in `~/.config/osintkit/config.toml` (mode 600), checks them
with a one-token request, and afterwards needs no flags and no exports. `osintkit config` shows
what is stored, masked; `osintkit lookup` just works.

Environment variables still win over the file, so `DEEPSEEK_API_KEY=... osintkit lookup ...`
overrides the stored provider for one run.

No key? `osintkit lookup example.com --offline` builds the whole report locally from rule checks,
no model involved. `--raw` gives the collected JSON and `--dry-run` prints the prompt a model
would receive.

Any OpenAI-compatible endpoint works. `init --provider ollama` needs no key for a local server;
`--provider`, `--base-url`, and `--model` cover everything else. The preset table, key variables,
and precedence order are in [docs/REFERENCE.md](docs/REFERENCE.md#providers).

Optional keys: a Have I Been Pwned subscription (`--hibp-key` on init, or `HIBP_API_KEY`) adds
per-account breach and paste membership; `GITHUB_TOKEN` lifts GitHub from 60 to 5000
requests/hour. Both stay local — the key is yours, and every user of the tool brings their own.
Everything else needs no credentials.

## Commands

| Command | Purpose |
| --- | --- |
| `lookup` | One target, one report (`--email`, `--username`, `--domain`, `--company`, `--phone`, `--crypto`) |
| `batch` | A CSV of targets, run concurrently, reported in order |
| `diff` | What changed between two archived runs |
| `password` | Is a password in Pwned Passwords (`--offline` uses a bundled list, no network) |
| `watch` | Re-check on an interval, print only changes, optionally notify |
| `history` | Past runs, replayable by id |
| `doctor` | Key, endpoint, and directory checks (`--deep` verifies auth) |
| `collectors` | Every collector and what it touches |
| `cache` / `prune` | Inspect, clear, or age out local state |
| `schema` | The JSON contract the model must satisfy |

Output: default colour report, `--json`, `--markdown` (they combine), `--raw` for collected
data, `--offline` for a local report with no model, `--dry-run` for the prompt. Exit codes: `0` ok, `1` synthesis or partial failure, `2` bad
input.

## How it works

```
target -> type detection -> collectors (parallel, cached, retried)
                                 |
                                 v
                     merge + risk signals (deterministic)
                                 |
                                 v
           LLM briefing -> pydantic validation -> one repair retry
                                 |            (--offline replaces this with local rules)
                                 |
                                 v
              colour report . JSON . Markdown . archive
```

Collectors degrade to a logged gap, never a dead run; a report is produced even when sources or
the model fail.

- **Merged, enriched breaches.** Records collapse into one row per incident, keeping every
  source and the earliest date, then pick up dates and exposed-field lists from the public HIBP
  and XposedOrNot catalogues. Those catalogues are free; only HIBP *account* checks need a key.
- **Email domains follow the address.** An email lookup also checks the domain's DNS, mail
  posture, and WHOIS, marked as derived.
- **Info-stealer logs.** Hudson Rock reports machines infected by stealers that saved
  credentials, with dates and hostnames; one infection forces a high risk floor.
- **Risk floor.** Breach count and credential types set a floor the model may exceed but never
  undercut.
- **Cached everything.** 24h default, shorter for volatile sources; repeat prompts cost nothing.
- **Validated output.** Strict JSON schema, one repair round-trip, then a clean failure.
- **Confidence per section.** Each section states `low`, `medium`, or `high`, capped by how many
  sources actually back it, so a single weak source never reads as certain.
- **Self-checked claims.** Every breach, date, host, and account URL is compared back to the
  collected data; anything unsupported is called out.

## Collectors

Two dozen sources across four target types, all free and login-free: HIBP (key), XposedOrNot,
LeakCheck, Gravatar, crt.sh (subdomains, certificates, organisation search), public DNS
(A/AAAA/MX/TXT/NS/CNAME plus SPF, DMARC, DKIM, wildcard), passive subdomains, WHOIS, TCP
connect probes, GitHub (profile, commits, user search, org repos), psbdmp with a Gist fallback,
grep.app, Hacker News, Stack Exchange, and username presence. The full table is in
[docs/REFERENCE.md](docs/REFERENCE.md#collectors) or via `osintkit collectors`.

## Breach depth

Breach name lists are free; breach *metadata* is what makes them useful. Every row is joined
against the public HIBP and XposedOrNot catalogues for date, exposed fields, and record count, so
the report can say "LinkedIn, 2021-06, emails and password hashes" instead of a bare name. Add a
`HIBP_API_KEY` (about $4/month) to get per-account membership with the same metadata, plus pastes.

Stealer logs matter more than most breaches: the credentials were live on an infected machine,
not just leaked years ago. They are queried for every target type, keyless.

Passwords are checked separately with `osintkit password`: Pwned Passwords covers hundreds of
millions of leaked passwords, needs no key, and only the first five SHA-1 characters leave the
machine.

## Monitoring

```bash
osintkit watch --domain example.com --every 1d
osintkit watch --email you@example.com --every 6h --no-notify
```

The first run prints a baseline. Later runs print nothing unless `diff` sees movement — a new
breach, a new host, a source failing, or a risk change — and optionally raise a desktop
notification through `notify-send`. `--cycles` bounds the loop, `ctrl-c` stops it, and every run
is archived so you can inspect it afterwards. Pair with cron or a systemd timer for unattended use.

## Safety and legality

- Public data only. No logins, no scraping behind auth, no paid brokers.
- Targets are typed and normalised before any request.
- Requests retry on `429`/`5xx` with backoff and honour GitHub quota headers.
- Results are evidence, not ground truth; the report says which sources were unavailable.
- Cache, logs, and reports stay under `~/.osintkit` (override with `OSINTKIT_HOME`). Retention
  is 30 days by default.

## Limitations

WHOIS is often redacted. GitHub search is shallow. Free breach indexes lag. Port probing only
sees what your network can reach. Model summaries can overstate weak signals. Read the coverage
panel: an empty section may mean "nothing found" or "source skipped".

## Development

```bash
git clone https://github.com/sjdsjadjajdjsa/osintkit
cd osintkit
uv sync --extra dev
pytest
uvx ruff check src tests
```

Tests never touch the network: HTTP is mocked with `respx`, DNS and WHOIS are monkeypatched, and
a recorded model reply covers the full-stack path. CI runs on 3.12 and 3.13. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the collector contract and
[docs/architecture.md](docs/architecture.md) for the module map.

## Licence

MIT. Security reports: [SECURITY.md](SECURITY.md).

`osintkit` is independent tooling. It is not affiliated with any source it queries.
