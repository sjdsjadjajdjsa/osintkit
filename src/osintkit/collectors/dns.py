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


def _resolver() -> dns.asyncresolver.Resolver:
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
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


async def _lookup(host: str, rtype: str) -> list[str]:
    resolver = _resolver()
    try:
        answer = await resolver.resolve(host, rtype, raise_on_no_answer=False, lifetime=6.0)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        return []
    except dns.resolver.NoNameservers:
        return []
    if answer.rrset is None:
        return []
    return [_format(rtype, rd) for rd in answer]


async def _all_records(host: str) -> dict[str, list[str]]:
    results = await asyncio.gather(*(_lookup(host, rt) for rt in RECORD_TYPES))
    return {
        rtype: value
        for rtype, value in zip(RECORD_TYPES, results, strict=True)
        if value
    }


@collector("dns_records", ("domain",), "A/AAAA/MX/TXT/NS/CNAME records", order=30)
async def dns_records(ctx: Context) -> dict:
    host = ctx.target.lower()
    cached = cache_hit(ctx.settings, NAMESPACE, host)
    if cached is not None:
        return cached
    records = await _all_records(host)
    cache_put(ctx.settings, NAMESPACE, host, records)
    return records


@collector("dns_mail_posture", ("domain",), "SPF, DMARC, and DKIM hints", order=31)
async def dns_mail_posture(ctx: Context) -> dict:
    host = ctx.target.lower()
    cached = cache_hit(ctx.settings, NAMESPACE, f"mail:{host}")
    if cached is not None:
        return cached

    txt = await _lookup(host, "TXT")
    spf = [t for t in txt if t.lower().startswith("v=spf1")]

    dmarc = await _lookup(f"_dmarc.{host}", "TXT") if not host.startswith("_dmarc.") else []
    dmarc = [t for t in dmarc if t.lower().startswith("v=dmarc1")]

    dkim_selectors = ("default", "google", "selector1", "selector2", "k1", "mail")
    dkim_hits = []
    for selector in dkim_selectors:
        found = await _lookup(f"{selector}._domainkey.{host}", "TXT")
        if found:
            dkim_hits.append({"selector": selector, "present": True})

    result = {
        "spf": spf,
        "spf_present": bool(spf),
        "dmarc": dmarc,
        "dmarc_present": bool(dmarc),
        "dkim_selectors_found": dkim_hits,
        "spf_strict": any("all" in t.lower() and "-all" in t.lower() for t in spf),
        "dmarc_policy": dmarc[0].lower() if dmarc else None,
    }
    cache_put(ctx.settings, NAMESPACE, f"mail:{host}", result)
    return result


@collector("dns_wildcard", ("domain",), "Wildcard DNS detection", order=32)
async def dns_wildcard(ctx: Context) -> dict:
    probe = f"osintkit-wildcard-probe.{ctx.target.lower()}"
    answers = await _lookup(probe, "A")
    return {"probe": probe, "wildcard": bool(answers), "answers": answers}
