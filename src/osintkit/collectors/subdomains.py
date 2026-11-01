"""Passive subdomain enumeration: certificate logs plus passive DNS plus resolution."""

from __future__ import annotations

import asyncio

import dns.asyncresolver

from ..http import cache_hit, cache_put
from .base import Context, collector
from .ct import _query
from .pastes import hackertarget_hostsearch

NAMESPACE = "subdomains"

COMMON_PREFIXES = (
    "www",
    "mail",
    "api",
    "dev",
    "staging",
    "test",
    "vpn",
    "admin",
    "cdn",
    "static",
    "docs",
    "status",
    "git",
    "ci",
    "app",
)


async def _resolve(name: str, resolvers: list[str]) -> str | None:
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = list(resolvers)
    resolver.timeout = 3.0
    resolver.lifetime = 4.0
    try:
        answer = await resolver.resolve(name, "A", raise_on_no_answer=False, lifetime=4.0)
    except Exception:
        return None
    if answer.rrset is None:
        return None
    return str(next(iter(answer))).rstrip(".")


@collector(
    "passive_subdomains",
    ("domain",),
    "Subdomains from cert logs, passive DNS, resolution",
    order=25,
    ttl=3600,
)
async def passive_subdomains(ctx: Context) -> dict:
    domain = ctx.target.lower()
    key = f"{domain}|{','.join(ctx.settings.resolvers)}"
    cached = cache_hit(ctx.settings, NAMESPACE, key, ctx.cache_ttl)
    if cached is not None:
        return cached
    entries = await _query(ctx, f"%.{domain}", "crt")
    names: set[str] = set()

    for entry in entries:
        for line in f"{entry.get('name_value') or ''}\n{entry.get('common_name') or ''}".splitlines():
            name = line.strip().lower().lstrip("*.").strip()
            if name.endswith("." + domain) and "." in name:
                names.add(name)

    try:
        passive = await hackertarget_hostsearch(ctx)
    except Exception:
        passive = {"hosts": []}
    for row in passive.get("hosts") or []:
        name = str(row.get("host") or "").lower()
        if name.endswith("." + domain):
            names.add(name)

    candidates = sorted(names)
    resolved = await asyncio.gather(
        *(_resolve(n, ctx.settings.resolvers) for n in candidates[:80])
    )
    live = {name: ip for name, ip in zip(candidates[:80], resolved, strict=True) if ip}

    unresolved_prefixes = []
    for prefix in COMMON_PREFIXES:
        candidate = f"{prefix}.{domain}"
        if candidate in names:
            continue
        ip = await _resolve(candidate, ctx.settings.resolvers)
        if ip:
            unresolved_prefixes.append({"host": candidate, "ip": ip})

    result = {
        "domain": domain,
        "discovered_count": len(names),
        "live_hosts": [{"host": h, "ip": ip} for h, ip in sorted(live.items())],
        "common_prefix_hits": unresolved_prefixes,
        "sources": ["crt.sh", "hackertarget", "dns"],
        "note": "passive only: no brute force beyond a short common-prefix list",
    }
    cache_put(ctx.settings, NAMESPACE, key, result)
    return result
