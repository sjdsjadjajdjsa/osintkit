"""WHOIS registration data."""

from __future__ import annotations

import asyncio
from typing import Any

import whois

from ..http import cache_hit, cache_put
from .base import Context, collector

NAMESPACE = "whois"
FIELD_LIMIT = 1500


def _clean(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, list):
        return [_clean(v) for v in value[:20]]
    if hasattr(value, "isoformat"):
        return value.isoformat()
    if isinstance(value, str):
        return value.strip()[:FIELD_LIMIT]
    return str(value)[:FIELD_LIMIT]


def _blocking_lookup(domain: str) -> dict:
    record = whois.whois(domain)
    if record is None:
        return {}
    data = dict(record)
    keys = (
        "domain_name",
        "registrar",
        "whois_server",
        "referral_url",
        "updated_date",
        "creation_date",
        "expiration_date",
        "name_servers",
        "status",
        "emails",
        "dnssec",
        "org",
        "country",
        "state",
        "city",
    )
    out: dict[str, Any] = {}
    for key in keys:
        if key in data and data[key]:
            out[key] = _clean(data[key])
    return out


@collector("whois_registration", ("domain",), "WHOIS registration record", order=40)
async def whois_registration(ctx: Context) -> dict:
    domain = ctx.target.lower()
    cached = cache_hit(ctx.settings, NAMESPACE, domain)
    if cached is not None:
        return cached
    try:
        result = await asyncio.wait_for(asyncio.to_thread(_blocking_lookup, domain), timeout=25)
    except asyncio.TimeoutError:
        return {"note": "whois lookup timed out"}
    except Exception as exc:
        return {"note": f"whois unavailable: {type(exc).__name__}"}
    cache_put(ctx.settings, NAMESPACE, domain, result)
    return result
