"""DNS record collection through public resolvers."""

from __future__ import annotations

import asyncio

import dns.asyncresolver
import dns.exception
import dns.resolver

from ..http import cache_hit, cache_put
from .base import Context, collector

RECORD_TYPES = ("A", "AAAA", "MX", "TXT", "NS", "CNAME")
NAMESPACE = "dns"


def _key(ctx: Context, host: str) -> str:
    return f"{host}|{','.join(ctx.settings.resolvers)}"


def _resolver(ctx: Context) -> dns.asyncresolver.Resolver:
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = list(ctx.settings.resolvers)
    resolver.timeout = 4.0
    resolver.lifetime = 6.0
    return resolver


def _format(rtype: str, record: object) -> str:
    if rtype == "MX":
        return f"{getattr(record, 'preference', 0)} {getattr(record, 'exchange', record)}".strip()
    if rtype == "TXT":
        strings = getattr(record, "strings", None)
        if strings:
            return b"".join(strings).decode("utf-8", "replace")
        return str(record).strip('"')
    return str(record).rstrip(".")


def _spf_all(records: list[str]) -> str | None:
    """Classify the SPF `all` qualifier: -all is strict, +all is permissive."""
    for record in records:
        for token in record.split():
            lowered = token.lower()
            if lowered.endswith("all") and lowered.lstrip("~-+?").startswith("all"):
                qualifier = lowered[:-3]
                return f"{qualifier}all" if qualifier else "all"
    return None


def _dmarc_policy(record: str) -> str | None:
    for part in record.split(";"):
        key, _, value = part.partition("=")
        if key.strip().lower() == "p":
            return value.strip().lower() or None
    return None


async def _lookup(ctx: Context, host: str, rtype: str) -> list[str]:
    resolver = _resolver(ctx)
    try:
        answer = await resolver.resolve(host, rtype, raise_on_no_answer=False, lifetime=6.0)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        return []
    except dns.resolver.NoNameservers:
        return []
    if answer.rrset is None:
        return []
    return [_format(rtype, rd) for rd in answer]


async def _all_records(ctx: Context, host: str) -> dict[str, list[str]]:
    results = await asyncio.gather(*(_lookup(ctx, host, rt) for rt in RECORD_TYPES))
    return {
        rtype: value
        for rtype, value in zip(RECORD_TYPES, results, strict=True)
        if value
    }


@collector(
    "dns_records", ("domain",), "A/AAAA/MX/TXT/NS/CNAME records", order=30, ttl=3600
)
async def dns_records(ctx: Context) -> dict:
    host = ctx.target.lower()
    key = _key(ctx, host)
    cached = cache_hit(ctx.settings, NAMESPACE, key, ctx.cache_ttl)
    if cached is not None:
        return cached
    records = await _all_records(ctx, host)
    cache_put(ctx.settings, NAMESPACE, key, records)
    return records


@collector(
    "dns_mail_posture", ("domain",), "SPF, DMARC, and DKIM hints", order=31, ttl=3600
)
async def dns_mail_posture(ctx: Context) -> dict:
    host = ctx.target.lower()
    key = f"mail:{_key(ctx, host)}"
    cached = cache_hit(ctx.settings, NAMESPACE, key, ctx.cache_ttl)
    if cached is not None:
        return cached

    txt = await _lookup(ctx, host, "TXT")
    spf = [t for t in txt if t.lower().startswith("v=spf1")]

    dmarc = await _lookup(ctx, f"_dmarc.{host}", "TXT") if not host.startswith("_dmarc.") else []
    dmarc = [t for t in dmarc if t.lower().startswith("v=dmarc1")]

    dkim_selectors = ("default", "google", "selector1", "selector2", "k1", "mail")
    dkim_hits = []
    for selector in dkim_selectors:
        found = await _lookup(ctx, f"{selector}._domainkey.{host}", "TXT")
        if found:
            dkim_hits.append({"selector": selector, "present": True})

    spf_all = _spf_all(spf)
    result = {
        "spf": spf,
        "spf_present": bool(spf),
        "spf_all": spf_all,
        "spf_strict": spf_all == "-all",
        "dmarc": dmarc,
        "dmarc_present": bool(dmarc),
        "dmarc_policy": _dmarc_policy(dmarc[0]) if dmarc else None,
        "dkim_selectors_found": dkim_hits,
    }
    cache_put(ctx.settings, NAMESPACE, key, result)
    return result


@collector("dns_wildcard", ("domain",), "Wildcard DNS detection", order=32, ttl=3600)
async def dns_wildcard(ctx: Context) -> dict:
    probe = f"osintkit-wildcard-probe.{ctx.target.lower()}"
    answers = await _lookup(ctx, probe, "A")
    return {"probe": probe, "wildcard": bool(answers), "answers": answers}
