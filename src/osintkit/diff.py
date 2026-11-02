"""Compare two archived reports."""

from __future__ import annotations

from typing import Any

from .models import Report

SEVERITY = ("low", "medium", "high")


def _names(rows: list[dict[str, Any]], field: str = "name") -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        key = str(row.get(field) or "").strip().lower()
        if key:
            out[key] = row
    return out


def _set_diff(old: list[str], new: list[str]) -> dict[str, list[str]]:
    before = {item.strip().lower(): item.strip() for item in old if item.strip()}
    after = {item.strip().lower(): item.strip() for item in new if item.strip()}
    return {
        "added": sorted(after[key] for key in after.keys() - before.keys()),
        "removed": sorted(before[key] for key in before.keys() - after.keys()),
    }


def compare(old: Report, new: Report) -> dict[str, Any]:
    old_analysis = old.analysis
    new_analysis = new.analysis
    old_breaches = _names([b.model_dump() for b in old_analysis.breaches]) if old_analysis else {}
    new_breaches = _names([b.model_dump() for b in new_analysis.breaches]) if new_analysis else {}

    delta = _risk_delta(old, new)
    old_status = {c.collector: (c.skipped, c.ok) for c in old.collectors}
    new_status = {c.collector: (c.skipped, c.ok) for c in new.collectors}

    return {
        "old_target": old.target,
        "new_target": new.target,
        "target_changed": old.target != new.target,
        "old_generated": old.generated_at,
        "new_generated": new.generated_at,
        "risk": {
            "old": old_analysis.risk_level if old_analysis else None,
            "new": new_analysis.risk_level if new_analysis else None,
        },
        "breaches": {
            "added": sorted(new_breaches[k]["name"] for k in new_breaches.keys() - old_breaches.keys()),
            "removed": sorted(old_breaches[k]["name"] for k in old_breaches.keys() - new_breaches.keys()),
            "unchanged": len(old_breaches.keys() & new_breaches.keys()),
        },
        "subdomains": _set_diff(
            old_analysis.subdomains if old_analysis else [],
            new_analysis.subdomains if new_analysis else [],
        ),
        "collectors": {
            "started_working": sorted(
                name
                for name, state in new_status.items()
                if state[1] and not state[0] and old_status.get(name, (False, False))[1] is False
            ),
            "started_failing": sorted(
                name
                for name, state in new_status.items()
                if not state[1] and not state[0] and old_status.get(name, (False, True))[1] is True
            ),
        },
        "risk_rose": delta > 0,
        "risk_fell": delta < 0,
    }


def _risk_delta(old: Report, new: Report) -> int:
    if not old.analysis or not new.analysis:
        return 0
    before = SEVERITY.index(old.analysis.risk_level) if old.analysis.risk_level in SEVERITY else 0
    after = SEVERITY.index(new.analysis.risk_level) if new.analysis.risk_level in SEVERITY else 0
    return after - before


def is_empty(diff: dict[str, Any]) -> bool:
    return not any(
        (
            diff["breaches"]["added"],
            diff["breaches"]["removed"],
            diff["subdomains"]["added"],
            diff["subdomains"]["removed"],
            diff["collectors"]["started_working"],
            diff["collectors"]["started_failing"],
            diff["risk_rose"],
            diff["risk_fell"],
        )
    )
