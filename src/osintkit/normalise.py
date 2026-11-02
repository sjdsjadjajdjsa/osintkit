"""Collapse duplicate breach records across sources before prompting."""

from __future__ import annotations

import re
from typing import Any

from .models import CollectorResult

BREACH_SOURCES = frozenset({"hibp_breaches", "xposed_or_not", "leakcheck_public"})
KEY_RE = re.compile(r"[^a-z0-9]+")


def _key(name: str) -> str:
    return KEY_RE.sub("", name.lower())


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [part.strip() for part in re.split(r"[;,]", value) if part.strip()]
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def merge_breaches(results: list[CollectorResult]) -> tuple[list[CollectorResult], int]:
    """Merge duplicate breach names across sources.

    Returns the results to prompt with (breach sources replaced by one index)
    and the number of duplicate records folded away.
    """
    breach_results = [r for r in results if r.collector in BREACH_SOURCES and r.has_data]
    if not breach_results:
        return results, 0

    merged: dict[str, dict[str, Any]] = {}
    duplicates = 0
    for result in breach_results:
        if not isinstance(result.data, list):
            continue
        source = str(result.data[0].get("source") if result.data else result.collector)
        for entry in result.data:
            if not isinstance(entry, dict):
                continue
            name = str(entry.get("name") or "").strip()
            if not name:
                continue
            key = _key(name)
            existing = merged.get(key)
            if existing is None:
                merged[key] = {
                    "name": name,
                    "date": entry.get("date"),
                    "data_types": set(_strings(entry.get("data_types"))),
                    "sources": {source},
                }
                continue
            duplicates += 1
            if not existing["date"] and entry.get("date"):
                existing["date"] = entry["date"]
            existing["data_types"].update(_strings(entry.get("data_types")))
            existing["sources"].add(source)

    if not merged:
        return results, duplicates

    rendered = [
        {
            "name": item["name"],
            "date": item["date"],
            "data_types": sorted(item["data_types"]),
            "sources": sorted(item["sources"]),
            "source": ", ".join(sorted(item["sources"])),
        }
        for item in merged.values()
    ]
    rendered.sort(key=lambda item: (-len(item["data_types"]), item["name"].lower()))

    index = CollectorResult(
        collector="breach_index",
        target=breach_results[0].target,
        target_type=breach_results[0].target_type,
        data=rendered,
    )
    kept = [r for r in results if r.collector not in BREACH_SOURCES]
    kept.extend(r for r in results if r.collector in BREACH_SOURCES and r.skipped)
    position = next((i for i, r in enumerate(results) if r.collector in BREACH_SOURCES), len(kept))
    kept.insert(min(position, len(kept)), index)
    return kept, duplicates
