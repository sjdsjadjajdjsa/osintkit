"""Per-section confidence, capped by how many sources actually back a section."""

from __future__ import annotations

from typing import Any

from .models import CollectorResult

SECTIONS = ("breaches", "accounts", "infrastructure", "subdomains")
ORDER = ("low", "medium", "high")

CONTRIBUTORS: dict[str, frozenset[str]] = {
    "breaches": frozenset({"breach_index"}),
    "accounts": frozenset({"username_presence", "github_profile", "github_commit_search"}),
    "infrastructure": frozenset(
        {
            "dns_records",
            "dns_mail_posture",
            "dns_wildcard",
            "whois_registration",
            "crt_sh_certificates",
            "tcp_ports",
            "infostealer",
            "phone_info",
            "btc_address",
        }
    ),
    "subdomains": frozenset({"crt_sh_subdomains", "passive_subdomains"}),
}


def _rank(value: str) -> int:
    return ORDER.index(value) if value in ORDER else 0


def derive(results: list[CollectorResult]) -> dict[str, str]:
    """Confidence implied by the data: 2+ contributing sources is high, 1 medium, 0 low."""
    out: dict[str, str] = {}
    for section, names in CONTRIBUTORS.items():
        count = sum(1 for result in results if result.collector in names and result.has_data)
        if section == "breaches":
            rows = next((r.data for r in results if r.collector == "breach_index" and r.has_data), [])
            count = min(len(rows), 2) if rows else 0
        out[section] = "high" if count >= 2 else "medium" if count else "low"
    return out


def apply(chosen: dict[str, Any] | None, derived: dict[str, str]) -> dict[str, str]:
    """Keep the model's honest pessimism, but never let it outrank the evidence."""
    final: dict[str, str] = {}
    for section in SECTIONS:
        claimed = str((chosen or {}).get(section) or "").strip().lower()
        floor = derived.get(section, "low")
        final[section] = claimed if claimed in ORDER and _rank(claimed) <= _rank(floor) else floor
    return final
