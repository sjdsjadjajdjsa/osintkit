# Reference

Everything the README leaves out: every flag, every collector, storage, and failure behaviour.

## Collectors

| Collector | Targets | Source | Needs key |
| --- | --- | --- | --- |
| `hibp_breaches`, `hibp_pastes` | email | Have I Been Pwned | yes |
| `xposed_or_not`, `leakcheck_public` | email | free public breach indexes | no |
| `gravatar` | email | Gravatar | no |
| `crt_sh_subdomains`, `crt_sh_certificates` | domain | crt.sh | no |
| `crt_sh_organization` | company | crt.sh organisation search, with apex-domain identity fallback | no |
| `dns_records`, `dns_mail_posture`, `dns_wildcard` | domain | public resolvers (A/AAAA/MX/TXT/NS/CNAME, SPF, DMARC, DKIM) | no |
| `passive_subdomains` | domain | cert logs + passive DNS + resolution | no |
| `whois_registration` | domain | WHOIS | no |
| `tcp_ports` | domain | local TCP connect probes on common ports | no |
| `github_profile`, `github_commit_search`, `github_user_search`, `github_org_repos` | username / email / company | GitHub public API | token optional |
| `psbdmp_search`, `code_mentions` | email / username / domain | psbdmp (GitHub Gist fallback), grep.app | no |
| `hn_mentions`, `stackoverflow_mentions` | all | public search APIs | no |
| `username_presence` | username | public profile URLs that 404 for unknown handles | no |

Collectors run concurrently and independently. A dead source becomes a `failed` row, not a
crash. `--only` and `--skip` accept comma lists and validate names.

## Providers

Any OpenAI-compatible endpoint works:

```bash
export API_KEY=...                                  # or --api-key
osintkit --base-url https://openrouter.ai/api/v1 --model deepseek/deepseek-v4.1-flash-1017 ...
```

A `sk-or-` key selects OpenRouter and its default model automatically. Defaults are Venice and
`deepseek-v4-1-flash-1017-uncensored`. Temperature is 0.3, `--max-tokens` defaults to 2400.

## Global flags

`--base-url`, `--model`, `--api-key`, `--temperature`, `--max-tokens`, `--timeout`,
`--max-connections`, `--max-attempts`, `--no-cache`, `--cache-ttl`, `--resolver` (repeatable),
`-v/--verbose`, `--version`.

Per-command: `--json`, `--markdown`, `-o/--out`, `--raw`, `--dry-run`, `--only`, `--skip`,
`--ports`, `--fail-fast`, `-c/--concurrency`, `--limit`, `--show`, `--days`, `--clear`, `--deep`.

## Output contract

`osintkit schema` prints the JSON Schema. Synthesis must return `summary`, `breaches[]`,
`associated_accounts[]`, `infrastructure_notes[]`, `subdomains[]`, `risk_level`,
`recommendations[]`. It is validated with pydantic; one repair round-trip follows malformed
output, after which the run fails cleanly and the raw collection is still archived.

`breach_index` is a synthetic source: breach records from every index are merged on
case-insensitive names, keeping all sources and the earliest date. `signals.risk_floor` is
computed from breach count and credential types, and the model cannot rank below it.

## Storage

```
~/.osintkit/cache/     cached responses
~/.osintkit/logs/      JSONL per day: every request and collector result
~/.osintkit/reports/   archived reports, replayable with `history --show`
```

24h default TTL. DNS, mail posture, wildcard, port, and subdomain results expire in 1h; CT and
presence checks in 6h. `--cache-ttl` and `--no-cache` override both. `OSINTKIT_RETENTION_DAYS`
(default 30) prunes at run start; `osintkit prune` does it on demand. `OSINTKIT_HOME` moves the
root.

## Failure behaviour

- HTTP retries `429`, `5xx`, and exhausted-quota `403`s with exponential backoff, three
  attempts, `Retry-After` honoured up to 30s.
- TLS/transport failures mark the source failed and continue.
- Identical in-flight requests are coalesced.
- A rejected model key becomes "run `osintkit doctor --deep`".
- Empty or unparseable model output gets one repair attempt.
- Missing optional keys are `skipped` rows with a reason.

## Exit codes

`0` success, `1` synthesis or partial failure, `2` bad input (unknown target, collector, port,
or argument).
