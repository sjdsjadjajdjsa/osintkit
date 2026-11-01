# osintkit

A command-line OSINT aggregator for **email addresses, usernames, domains, and companies**.

osintkit only queries **publicly available data**: certificate transparency logs, public DNS
resolvers, WHOIS, public GitHub search, public breach indexes, paste archives, and public
profile pages. It never logs in anywhere on your behalf and never touches paid data brokers.

It gathers what it can, hands the raw material to an LLM acting as a defensive analyst, and
renders a colour-coded briefing with a risk level and hardening advice.

> **Intended use:** personal privacy checks, pre-engagement reconnaissance for authorised
> research, and quick due diligence on a domain or company. Results are only as good as the
> public sources behind them. Treat every finding as a lead to verify, not a fact.

## Install

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e .
osintkit --help
```

Requires Python 3.12+.

## API key

Synthesis uses any OpenAI-compatible endpoint. The default is Venice:

```bash
export API_KEY=...   # required for synthesis
```

| Variable | Purpose |
| --- | --- |
| `API_KEY` | model API key (or pass `--api-key`) |
| `HIBP_API_KEY` | enables the Have I Been Pwned collectors; without it they are skipped with a note |
| `GITHUB_TOKEN` | raises GitHub rate limits from 60/h to 5000/h |

Every other source works with no credentials. `--dry-run` needs no key at all.

## Usage

```bash
osintkit lookup alice@example.com
osintkit lookup --username alice
osintkit lookup --domain example.com --markdown
osintkit lookup --company "Example Ltd" --json
osintkit lookup alice@example.com --dry-run          # print the prompt, no model call
osintkit lookup example.com --raw                    # dump collected JSON, no model call
osintkit lookup example.com --only dns_records --skip tcp_ports
osintkit batch --file examples/targets.csv --out ./reports --concurrency 4
osintkit batch --file examples/targets.csv --only dns_records,crt_sh_subdomains
osintkit doctor                                  # check key, endpoint, directories
osintkit schema                                  # JSON schema the model must satisfy
osintkit prune --days 30                         # delete old cache, logs, reports
osintkit history --limit 10
osintkit history --show ~/.osintkit/reports/20260101T120000-example.com-123.json
osintkit collectors
```

Global flags: `--base-url`, `--model`, `--temperature` (default 0.3), `--max-tokens` (default
2400), `--timeout`,
`--max-attempts` (default 3), `--no-cache`, `--cache-ttl`, `--resolver` (repeatable, for
`dns_records`/`passive_subdomains`), `-v` (show raw collector payloads).

Output flags: `--json` (final report as JSON), `--markdown` (export, default filename
`<target>-osint.md`, override with `-o`), `--dry-run` (prompt only), `--raw` (collected data
only). `--dry-run` and `--raw` skip the model and need no key.

Exit codes: `0` success, `1` synthesis or partial failure, `2` bad input.

## What gets collected

| Collector | Targets | Source |
| --- | --- | --- |
| `hibp_breaches`, `hibp_pastes` | email | Have I Been Pwned (key required) |
| `xposed_or_not`, `leakcheck_public` | email | free public breach indexes |
| `gravatar` | email | Gravatar |
| `crt_sh_subdomains`, `crt_sh_certificates` | domain | crt.sh |
| `crt_sh_organization` | company | crt.sh org search |
| `dns_records`, `dns_mail_posture`, `dns_wildcard` | domain | public resolvers (SPF/DMARC/DKIM) |
| `passive_subdomains` | domain | cert logs + passive DNS + resolution |
| `whois_registration` | domain | WHOIS |
| `tcp_ports` | domain | local TCP connect probes |
| `github_profile`, `github_commit_search`, `github_user_search`, `github_org_repos` | username/email/company | GitHub public API |
| `psbdmp_search`, `code_mentions` | email/username/domain | psbdmp (GitHub Gist fallback), grep.app |
| `username_presence` | username | public profile URLs |

Collectors run concurrently and independently. A dead source produces a `failed` entry in the
report instead of aborting the run.

## Output contract

The schema is printed by `osintkit schema` and enforced with pydantic.

Synthesis returns strict JSON: `summary`, `breaches[]`, `associated_accounts[]`,
`infrastructure_notes[]`, `subdomains[]`, `risk_level`, `recommendations[]`. It is validated
with pydantic. A malformed reply gets exactly one repair round-trip, then the run fails
cleanly and the raw collection is still archived.

## Troubleshooting

`osintkit doctor` reports the API key state, endpoint reachability, writable directories, and
which optional source keys are missing. It never echoes the key itself. Exit code is `1` when
a check fails.

## Storage

```
~/.osintkit/cache/     cached responses
~/.osintkit/logs/      JSONL, one file per day, every request and collector result
~/.osintkit/reports/   archived reports (dry runs included, so they can be replayed)
```

Cache lifetime is 24 hours by default. DNS, mail-posture, wildcard, port, and subdomain
results expire after 1 hour and profile-presence checks after 6, because those move fastest.
`--cache-ttl` and `--no-cache` override both.

Old files are pruned automatically at run start when `OSINTKIT_RETENTION_DAYS` is set
(default 30). `osintkit prune --days N` does it on demand, `--dry-run` only counts.

Override the root with `OSINTKIT_HOME`. Nothing leaves your machine except the collector
requests and the synthesis call.

## Notable behaviour

- All HTTP is retried with exponential backoff on `429`/`5xx`, up to three attempts.
- Partial results still produce a report; unavailable sources are listed as gaps.
- `--dry-run` writes the ready-to-send prompt; `--raw` writes the collected data.
- `batch --raw` prints a JSON array of bundles, one per target.
- `batch` runs targets concurrently (`--concurrency`, default 3) but reports in CSV order.
- Port probing is a single connect attempt and can miss filtered ports.

## Development

```bash
pip install -e '.[dev]'
pytest
uvx ruff check src tests
```

CI runs both on Python 3.12 and 3.13.

Tests mock every HTTP call and the model client; nothing touches the network.

## Limitations

WHOIS servers vary wildly and often redact registrant data. GitHub search is shallow by
design. Free breach indexes lag real breaches. `tcp_ports` sees only what is reachable from
your network. Model summaries can overstate weak signals.

## Licence

MIT.
