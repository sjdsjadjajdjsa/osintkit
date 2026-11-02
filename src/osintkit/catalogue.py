"""Public breach catalogues used to enrich bare breach names."""

from __future__ import annotations

import re
from typing import Any

from .errors import OsintKitError
from .http import HttpClient, cache_hit, cache_put

NAMESPACE = "catalogue"
TTL = 7 * 24 * 3600
KEY_RE = re.compile(r"[^a-z0-9]+")

HIBP = "https://haveibeenpwned.com/api/v3/breaches"
XPOSED = "https://api.xposedornot.com/v1/breaches"


def _key(name: str) -> str:
    return KEY_RE.sub("", name.lower())


def _from_hibp(rows: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(rows, list):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = str(row.get("Name") or row.get("Title") or "").strip()
        if not name:
            continue
        out[_key(name)] = {
            "name": name,
            "date": row.get("BreachDate"),
            "data_types": [str(kind) for kind in row.get("DataClasses") or []],
            "domain": row.get("Domain"),
            "pwn_count": row.get("PwnCount"),
        }
    return out


def _from_xposed(body: Any) -> dict[str, dict[str, Any]]:
    rows = body.get("exposedBreaches") if isinstance(body, dict) else None
    if not isinstance(rows, list):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = str(row.get("breachID") or "").strip()
        if not name:
            continue
        out[_key(name)] = {
            "name": name,
            "date": (row.get("breachedDate") or "")[:10] or None,
            "data_types": [str(kind) for kind in row.get("exposedData") or []],
            "domain": row.get("domain"),
            "pwn_count": row.get("exposedRecords"),
        }
    return out


async def _download(http: HttpClient) -> dict[str, dict[str, Any]]:
    try:
        response = await http.get(HIBP, namespace=NAMESPACE, accept="application/json")
        if response.status_code == 200:
            data = _from_hibp(response.json())
            if data:
                return data
    except (OsintKitError, ValueError):
        pass

    try:
        response = await http.get(XPOSED, namespace=NAMESPACE, accept="application/json")
    except OsintKitError:
        return {}
    if response.status_code != 200:
        return {}
    try:
        return _from_xposed(response.json())
    except ValueError:
        return {}


async def fetch(http: HttpClient) -> dict[str, dict[str, Any]]:
    """Return breach metadata keyed by normalised name, cached for a week."""
    cached = cache_hit(http.settings, NAMESPACE, "index", TTL)
    if cached is not None:
        return cached
    data = await _download(http)
    if data:
        cache_put(http.settings, NAMESPACE, "index", data)
    return data
