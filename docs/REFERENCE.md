# Reference

Everything the README leaves out: every flag, every collector, storage, and failure behaviour.

## Collectors

| Collector | Targets | Source | Needs key |
| --- | --- | --- | --- |
| `infostealer` | email / username / domain | Hudson Rock stealer logs | no |
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
| `hackertarget_hostsearch` | domain | HackerTarget passive DNS | no |
| `hn_mentions`, `stackoverflow_mentions` | all | public search APIs | no |
| `username_presence` | username | public profile URLs that 404 for unknown handles | no |

Collectors run concurrently and independently. A dead source becomes a `failed` row, not a
crash. `--only` and `--skip` accept comma lists and validate names.

## Providers

Any OpenAI-compatible endpoint works:

```bash
export API_KEY=...                                  # or --api-key
osintkit --provider openrouter ...
osintkit --base-url https://gateway.internal/v1 --model house-model ...
```

| `--provider` | Endpoint | Default model | Key variable |
| --- | --- | --- | --- |
| `venice` (default) | `api.venice.ai/api/v1` | `deepseek-v4-1-flash` | `API_KEY`, `VENICE_API_KEY` |
| `openrouter` | `openrouter.ai/api/v1` | `deepseek/deepseek-v4.1-flash-1017` | `OPENROUTER_API_KEY`, `sk-or-` keys |
| `openai` | `api.openai.com/v1` | `gpt-4.1-mini` | `OPENAI_API_KEY`, `sk-proj-` keys |
| `deepseek` | `api.deepseek.com/v1` | `deepseek-chat` | `DEEPSEEK_API_KEY` |
| `mistral` | `api.mistral.ai/v1` | `mistral-small-latest` | `MISTRAL_API_KEY` |
| `groq` | `api.groq.com/openai/v1` | `llama-3.3-70b-versatile` | `GROQ_API_KEY`, `gsk_` keys |
| `together` | `api.together.xyz/v1` | Llama 3.3 70B | `TOGETHER_API_KEY` |
| `anthropic` | `api.anthropic.com/v1` | `claude-sonnet-4-5` | `ANTHROPIC_API_KEY`, `sk-ant-` keys |
| `ollama` | `localhost:11434/v1` | `llama3.2` | none |

Set a provider-specific variable and that provider is chosen; `API_KEY` alone falls back to the
default. Recognisable key prefixes override that inference. `--provider` beats both.

Explicit `--base-url` and `--model` beat both the provider and the prefix. Temperature is 0.3,
`--max-tokens` defaults to 2400.

## Global flags

`--base-url`, `--model`, `--api-key`, `--temperature`, `--max-tokens`, `--timeout`,
`--max-connections`, `--max-attempts`, `--no-cache`, `--cache-ttl`, `--resolver` (repeatable),
`-v/--verbose`, `--version`.

Per-command: `--json`, `--markdown`, `-o/--out`, `--raw`, `--offline`, `--dry-run`, `--only`, `--skip`,
`--ports`, `--fail-fast`, `-c/--concurrency`, `--limit`, `--show`, `--days`, `--clear`, `--deep`.

## Info-stealer logs

`infostealer` queries Hudson Rock's keyless endpoint for infections that saved credentials on a
compromised machine. It returns the infection count, dates, hostnames, IPs, antivirus state, and
masked logins and passwords. Any infection forces a `high` risk floor; masked values are shown as
the source provides them and are not usable as credentials.

The address goes to Hudson Rock; nothing else does.

## Breach catalogue enrichment

Breach names from free indexes are joined against `haveibeenpwned.com/api/v3/breaches` (keyless
catalogue) with an XposedOrNot catalogue fallback, cached a week, to add dates, exposed fields,
domains, and record counts. At most 15 enriched rows go into the prompt; the true count stays in
`signals`.

## Password checks

`osintkit password [VALUE]` hashes locally, sends only the five-character SHA-1 prefix to
`api.pwnedpasswords.com`, and reports the count and a commonness rating. Exit code `1` means
pwned. `--json` for machines. Nothing about the password beyond the prefix leaves the machine.

## Configuration file

`osintkit init` writes `~/.config/osintkit/config.toml` (or `$XDG_CONFIG_HOME`) with mode 600 in
a 700 directory, after checking the key with a one-token request. Keys recognised:
`provider`, `model`, `base_url`, `api_key`, `resolvers`.

`osintkit config` prints them masked, `--reveal` shows the key, `--unset KEY` removes one, and
`--path` prints the location. Deleting the file is the same as `--unset` everything.

Precedence for each value: command-line flag, then the provider-specific environment variable,
then a key prefix, then the config file, then the built-in default. Stored values apply only when
the stored provider matches the one in use, so a one-off key export never gets the stored key.

## Offline mode

`--offline` skips the model: breaches, accounts, hosts, and policy gaps are rendered from the
collected data, risk comes from the same deterministic floor (plus open risky ports and a
wildcard with no DMARC), and recommendations come from rule checks. Summary text says what was
and was not collected. Useful without a key, in CI, and when a provider is down.

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

## Social preview

`docs/social-preview.png` is a 1280x640 card for the repository. GitHub has no API for it: upload
it under Settings, General, Social preview.

## Scheduled smoke test

`.github/workflows/smoke.yml` runs weekly (and on demand) against two stable domains and fails
if every collector breaks, so upstream parser rot surfaces without a nightly full run.

## Publishing

Releases publish to PyPI through Trusted Publishing (OIDC, `pypi` environment, no token).

The chain: `release.yml` builds, attaches assets, then dispatches `publish.yml` when the
repository variable `PUBLISH_TO_PYPI` is `true`. The dispatch is needed because releases created
by `GITHUB_TOKEN` do not fire `release` events.

To fail safely, `publish.yml` is skipped unless that variable is set and the PyPI pending
publisher matches owner `sjdsjadjajdjsa`, repository `osintkit`, workflow `publish.yml`, and
environment `pypi`.
