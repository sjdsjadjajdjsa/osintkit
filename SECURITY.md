# Security policy

## Supported versions

Only the latest release on `main` is supported.

## Reporting

Use GitHub's private vulnerability reporting: **Security → Report a vulnerability**. If that is
unavailable, open an issue titled `security: <summary>` with no exploit details and the
maintainer will move it.

Please include the version (`osintkit --version`), the command, and the observed versus expected
behaviour. Never paste a live API key.

Expect an acknowledgement within a few days. This is a personal project, so fixes are best
effort; a coordinated disclosure date will be agreed before publication.

## What counts

- API keys or tokens written to logs, archives, cache, or error output
- cache poisoning that survives into a report (key collisions, wrong TTLs, namespace bleed)
- command or path injection through a target, CSV cell, or source response
- SSRF beyond the intended sources, including `tcp_ports` scanning something unexpected
- prompt injection from collected data that changes the risk verdict or invents findings
- dependency vulnerabilities reachable through normal use

## Out of scope

- accuracy of a third-party source
- rate limits or outages
- findings about a target rather than about the tool
- running with a source you do not trust at the network level

## Existing posture

- Public sources only; no credential storage beyond the model key in the environment.
- Keys are never logged; `doctor` reports key length only.
- All HTTP is timeout-bounded, retried, and cached under `~/.osintkit`.
- Model output is schema-validated before rendering; failures keep the raw collection.
- No `eval`, no shell invocation, no dynamic import of remote code.
