"""Build a report from collected data alone, with no model call."""

from __future__ import annotations

from typing import Any

from .models import Analysis, AssociatedAccount, Breach, CollectorResult
from .normalise import apply_floor, signals_for

RISKY_PORTS = {
    21: "FTP is plaintext",
    23: "Telnet is plaintext",
    445: "SMB should not face the internet",
    3306: "MySQL is exposed",
    5432: "PostgreSQL is exposed",
    6379: "Redis is often unauthenticated",
    9200: "Elasticsearch is often unauthenticated",
    27017: "MongoDB is often unauthenticated",
}
MAX_SUBDOMAINS = 25


def _data(results: list[CollectorResult], name: str) -> Any:
    for result in results:
        if result.collector == name and result.has_data:
            return result.data
    return None


def _found_accounts(results: list[CollectorResult]) -> list[AssociatedAccount]:
    accounts: list[AssociatedAccount] = []
    presence = _data(results, "username_presence")
    if isinstance(presence, dict):
        for hit in presence.get("found") or []:
            accounts.append(
                AssociatedAccount(
                    platform=str(hit.get("site")),
                    url=hit.get("url"),
                    handle=str(presence.get("handle") or ""),
                    note="profile URL answers 200; ownership unconfirmed",
                )
            )
    profile = _data(results, "github_profile")
    if isinstance(profile, dict):
        user = profile.get("profile") or {}
        if user.get("login"):
            accounts.append(
                AssociatedAccount(
                    platform="GitHub",
                    url=user.get("url"),
                    handle=user.get("login"),
                    note="returned by the GitHub API",
                )
            )
    return accounts


def _subdomains(results: list[CollectorResult]) -> list[str]:
    names: list[str] = []
    passive = _data(results, "passive_subdomains")
    if isinstance(passive, dict):
        names.extend(str(row.get("host")) for row in passive.get("live_hosts") or [])
        names.extend(str(row.get("host")) for row in passive.get("common_prefix_hits") or [])
    certs = _data(results, "crt_sh_subdomains")
    if isinstance(certs, list):
        names.extend(str(name) for name in certs)
    seen: list[str] = []
    for name in names:
        if name not in seen:
            seen.append(name)
    return seen[:MAX_SUBDOMAINS]


def _infrastructure(results: list[CollectorResult], report_notes: list[str]) -> list[str]:
    notes: list[str] = []
    mail = _data(results, "dns_mail_posture")
    if isinstance(mail, dict):
        if mail.get("spf_present"):
            notes.append(f"SPF present, all-qualifier {mail.get('spf_all') or 'unknown'}")
        else:
            notes.append("No SPF record: sender enforcement is missing")
        if mail.get("dmarc_present"):
            notes.append(f"DMARC present with policy {mail.get('dmarc_policy') or 'unknown'}")
        else:
            notes.append("No DMARC record: spoofing is not instructed")
        selectors = mail.get("dkim_selectors_found") or []
        if selectors:
            notes.append(f"{len(selectors)} DKIM selectors answer")

    wildcard = _data(results, "dns_wildcard")
    if isinstance(wildcard, dict) and wildcard.get("wildcard"):
        notes.append("Wildcard DNS is enabled, so unknown labels resolve")

    stealer = _data(results, "infostealer")
    if isinstance(stealer, dict) and stealer.get("infections"):
        first = (stealer.get("stealers") or [{}])[0]
        notes.append(
            f"{stealer['infections']} info-stealer infection(s)"
            + (f", latest {first.get('date')}" if first.get("date") else "")
            + (f" on {first.get('computer')}" if first.get("computer") else "")
        )

    whois = _data(results, "whois_registration")
    if isinstance(whois, dict) and whois.get("registrar"):
        parts = [f"registrar {whois['registrar']}"]
        if whois.get("creation_date"):
            parts.append(f"registered {whois['creation_date']}")
        if whois.get("expiration_date"):
            parts.append(f"expires {whois['expiration_date']}")
        notes.append(", ".join(parts))

    ports = _data(results, "tcp_ports")
    if isinstance(ports, dict):
        for entry in ports.get("open") or []:
            port = entry.get("port")
            if port in RISKY_PORTS:
                notes.append(f"port {port} open: {RISKY_PORTS[port]}")
        if not ports.get("open"):
            notes.append("No probed port accepted a connection")

    dns = _data(results, "dns_records")
    if isinstance(dns, dict) and dns.get("MX") == ["0 ."]:
        notes.append("Null MX: the domain accepts no mail")
    notes.extend(report_notes)
    return notes


def _recommendations(
    creds: int,
    mail: dict | None,
    wildcard: bool,
    ports: list[int],
    breach_count: int,
    infections: int = 0,
) -> list[str]:
    recs: list[str] = []
    if infections:
        recs.append("Change every password saved on the infected machine, then sign out all sessions")
    if creds:
        recs.append("Rotate passwords for the affected services and enable MFA where offered")
    elif breach_count:
        recs.append("Confirm whether the breach set carries credentials before rotating")
    if mail is not None:
        if not mail.get("dmarc_present"):
            recs.append("Publish a DMARC record, starting at p=none with reporting")
        elif mail.get("dmarc_policy") in {"none", "quarantine"}:
            recs.append(f"Move DMARC from p={mail.get('dmarc_policy')} to p=reject once reporting is clean")
        if not mail.get("spf_present"):
            recs.append("Publish an SPF record ending in -all")
        elif mail.get("spf_all") != "-all":
            recs.append("Tighten the SPF all-qualifier to -all")
    if wildcard:
        recs.append("Inventory wildcard-backed hostnames and remove ones no longer served")
    if ports:
        recs.append(f"Close or firewall public ports {', '.join(str(p) for p in ports)}")
    if not recs:
        recs.append("Re-run with a model key for a narrated briefing, or widen the collector set")
    return recs


def build(
    results: list[CollectorResult], report_notes: list[str], target: str, *, narrated: bool = False
) -> Analysis:
    breaches_raw = next((r.data for r in results if r.collector == "breach_index" and r.has_data), [])
    signals = signals_for(breaches_raw)
    accounts = _found_accounts(results)
    subdomains = _subdomains(results)
    mail = _data(results, "dns_mail_posture")
    wildcard = bool((_data(results, "dns_wildcard") or {}).get("wildcard"))
    ports_data = _data(results, "tcp_ports") or {}
    risky = [entry.get("port") for entry in ports_data.get("open") or [] if entry.get("port") in RISKY_PORTS]
    infrastructure = _infrastructure(results, report_notes)

    collected = [r.collector for r in results if r.has_data]
    skipped = [r.collector for r in results if r.skipped]
    failed = [r.collector for r in results if not r.ok and not r.skipped]

    summary_parts = [
        f"Collected public data for {target} from {len(collected)} of {len(results)} sources"
        + (", with no model call." if not narrated else "; the model returned no summary.")
    ]
    if signals["breach_count"]:
        summary_parts.append(
            f"{signals['breach_count']} breach records mention the target, "
            f"{signals['credential_bearing']} of them credential-bearing."
        )
    if accounts:
        summary_parts.append(f"{len(accounts)} public profiles answered.")
    if subdomains:
        summary_parts.append(f"{len(subdomains)} hostnames were discovered.")
    if failed:
        summary_parts.append(f"Failed sources: {', '.join(failed)}.")
    if skipped:
        summary_parts.append(f"Skipped sources: {', '.join(skipped)}.")
    if not narrated:
        summary_parts.append("Risk is computed from counts and policy checks, not narrated.")

    risk = apply_floor("low", signals["risk_floor"])
    if risky or (wildcard and isinstance(mail, dict) and not mail.get("dmarc_present")):
        risk = apply_floor(risk, "medium")

    return Analysis(
        summary=" ".join(summary_parts),
        breaches=[
            Breach(
                name=str(row.get("name")),
                date=row.get("date"),
                data_types=list(row.get("data_types") or []),
                source=row.get("source"),
            )
            for row in breaches_raw[:15]
        ],
        associated_accounts=accounts,
        infrastructure_notes=infrastructure,
        subdomains=subdomains,
        risk_level=risk,
        recommendations=_recommendations(
            signals["credential_bearing"],
            mail if isinstance(mail, dict) else None,
            wildcard,
            risky,
            signals["breach_count"],
            int((_data(results, "infostealer") or {}).get("infections") or 0),
        ),
    )
