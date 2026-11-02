"""Certificate transparency via crt.sh."""

from __future__ import annotations

import json
import re
from urllib.parse import quote

from .base import Context, collector

CRT = "https://crt.sh/"


def _entries(body: object) -> list[dict]:
    if not isinstance(body, list):
        return []
    return [e for e in body if isinstance(e, dict)]


def _parse(response: object) -> list[dict]:
    """crt.sh sometimes wraps JSON in an HTML header block."""
    text = getattr(response, "text", "").strip()
    if text.startswith("[BEGIN_HEADERS]"):
        text = text.split("[END_HEADERS]", 1)[-1].replace("<BR>", "").strip()
    if not text.startswith(("[", "{")):
        return []
    try:
        return _entries(json.loads(text))
    except ValueError:
        return []


def _names(entries: list[dict], domain: str) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for entry in entries:
        blob = f"{entry.get('name_value') or ''}\n{entry.get('common_name') or ''}"
        for line in blob.splitlines():
            name = line.strip().lower().lstrip("*.").strip()
            if not name or name == domain or "." not in name:
                continue
            if not name.endswith("." + domain):
                continue
            if name in seen:
                continue
            seen.add(name)
            out.append(name)
    return sorted(out)


async def _query(ctx: Context, query: str, namespace: str) -> list[dict]:
    response = await ctx.http.get(
        CRT,
        namespace=namespace,
        params={"q": query, "output": "json", "exclude": "expired"},
        accept="application/json",
        empty_on=(404,),
        timeout=ctx.http_timeout,
    )
    if response.status_code != 200:
        return []
    return _parse(response)


@collector(
    "crt_sh_subdomains",
    ("domain",),
    "Subdomains from certificate transparency",
    order=20,
    timeout=90,
    ttl=21600,
)
async def crt_sh_subdomains(ctx: Context) -> list[str]:
    entries = await _query(ctx, f"%.{ctx.target}", "crt")
    return _names(entries, ctx.target.lower())


@collector("crt_sh_certificates", ("domain",), "Issued certificates from crt.sh", order=21, timeout=90)
async def crt_sh_certificates(ctx: Context) -> list[dict]:
    entries = await _query(ctx, f"%.{ctx.target}", "crt")
    certs = []
    for entry in entries[:60]:
        issuer = str(entry.get("issuer_name") or "")
        certs.append(
            {
                "id": entry.get("id"),
                "common_name": entry.get("common_name"),
                "names": (entry.get("name_value") or "").splitlines()[:10],
                "issuer": issuer.split("O=")[-1].split(",")[0] if "O=" in issuer else issuer[:80],
                "not_before": entry.get("not_before"),
                "not_after": entry.get("not_after"),
                "serial": entry.get("serial_number"),
                "source": "crt.sh",
            }
        )
    return certs


def _company_domains(company: str) -> list[str]:
    """Guess likely apex domains from a company name."""
    slug = re.sub(r"[^a-z0-9]+", "", company.lower())
    slug = re.sub(r"(inc|llc|ltd|limited|gmbh|corp|corporation|plc)$", "", slug)
    candidates = []
    for suffix in (".com", ".net", ".io"):
        candidate = slug + suffix
        if len(slug) >= 2 and candidate not in candidates:
            candidates.append(candidate)
    return candidates


def _summarise(entries: list[dict]) -> dict:
    domains: dict[str, int] = {}
    for entry in entries:
        for name in (entry.get("name_value") or "").splitlines():
            name = name.strip().lower().lstrip("*.")
            if "." in name and not name.startswith("."):
                domains[name] = domains.get(name, 0) + 1
    ranked = sorted(domains.items(), key=lambda kv: kv[1], reverse=True)[:50]
    return {
        "certificates_seen": len(entries),
        "domains": [{"domain": d, "certificate_count": n} for d, n in ranked],
        "sample_certificates": [
            {
                "common_name": e.get("common_name"),
                "issuer": e.get("issuer_name"),
                "not_before": e.get("not_before"),
            }
            for e in entries[:20]
        ],
    }


@collector(
    "crt_sh_organization",
    ("company",),
    "Certificates issued to an organisation",
    order=20,
    timeout=90,
    ttl=21600,
)
async def crt_sh_organization(ctx: Context) -> dict:
    entries = await _query(ctx, f"O={quote(ctx.target)}", "crt")
    if entries:
        return {**_summarise(entries), "method": "organization match"}

    entries = []
    matched: list[str] = []
    for domain in _company_domains(ctx.target):
        found = await _query(ctx, f"%.{domain}", "crt")
        if found:
            entries.extend(found)
            matched.append(domain)
        if len(entries) > 400:
            break
    if not entries:
        return {
            **_summarise([]),
            "method": "no organization match",
            "note": "crt.sh had no O= matches and the guessed domains were empty",
        }
    return {
        **_summarise(entries),
        "method": "guessed domain identity",
        "matched_domains": matched,
    }
