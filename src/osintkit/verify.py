"""Post-synthesis check that claims exist in the collected data."""

from __future__ import annotations

from .models import Analysis, CollectorResult

MAX_ISSUES = 5


def _breach_rows(results: list[CollectorResult]) -> list[dict]:
    rows: list[dict] = []
    for result in results:
        if result.collector == "breach_index" and isinstance(result.data, list):
            rows.extend(row for row in result.data if isinstance(row, dict))
    return rows


def _names(results: list[CollectorResult]) -> set[str]:
    return {str(row.get("name") or "").strip().lower() for row in _breach_rows(results)}


def _dates(results: list[CollectorResult]) -> set[str]:
    return {str(row.get("date") or "")[:10] for row in _breach_rows(results) if row.get("date")}


def _subdomains(results: list[CollectorResult]) -> set[str]:
    names: set[str] = set()
    for result in results:
        data = result.data
        if result.collector in {"crt_sh_subdomains"} and isinstance(data, list):
            names.update(str(item).lower() for item in data)
        if result.collector == "passive_subdomains" and isinstance(data, dict):
            for key in ("live_hosts", "common_prefix_hits"):
                names.update(str(row.get("host")).lower() for row in data.get(key) or [] if row.get("host"))
    return names


def _urls(results: list[CollectorResult]) -> set[str]:
    urls: set[str] = set()
    for result in results:
        data = result.data
        if result.collector == "username_presence" and isinstance(data, dict):
            urls.update(str(row.get("url")) for row in data.get("found") or [] if row.get("url"))
        if result.collector == "github_profile" and isinstance(data, dict):
            url = (data.get("profile") or {}).get("url")
            if url:
                urls.add(str(url))
    return urls


def claims(analysis: Analysis, results: list[CollectorResult]) -> list[str]:
    """Return short descriptions of claims that the source data does not support."""
    issues: list[str] = []
    names = _names(results)
    dates = _dates(results)
    hosts = _subdomains(results)
    urls = _urls(results)
    checked = {result.collector for result in results}
    has_breaches = "breach_index" in checked
    has_hosts = bool(checked & {"crt_sh_subdomains", "passive_subdomains"})
    has_accounts = bool(checked & {"username_presence", "github_profile"})

    for breach in analysis.breaches:
        if has_breaches and breach.name.strip().lower() not in names:
            issues.append(f"breach {breach.name!r} not in the supplied data")
        if has_breaches and breach.date and breach.date[:10] not in dates:
            issues.append(f"date {breach.date} for {breach.name!r} not in the supplied data")

    for host in analysis.subdomains:
        if has_hosts and host.strip().lower() not in hosts:
            issues.append(f"subdomain {host!r} not in the supplied data")

    for account in analysis.associated_accounts:
        if has_accounts and account.url and account.url.rstrip("/") not in {url.rstrip("/") for url in urls}:
            issues.append(f"account URL {account.url!r} not in the supplied data")

    return issues[:MAX_ISSUES]
