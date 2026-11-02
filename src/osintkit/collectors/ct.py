"""Certificate transparency via crt.sh."""

from __future__ import annotations

from urllib.parse import quote

from .base import Context, collector

CRT = "https://crt.sh/"


def _entries(body: object) -> list[dict]:
    if not isinstance(body, list):
        return []
    return [e for e in body if isinstance(e, dict)]


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
    try:
        return _entries(response.json())
    except ValueError:
        return []


@collector(
    "crt_sh_subdomains",
    ("domain",),
    "Subdomains from certificate transparency",
    order=20,
    timeout=90,
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


@collector(
    "crt_sh_organization",
    ("company",),
    "Certificates issued to an organisation",
    order=20,
    timeout=90,
)
async def crt_sh_organization(ctx: Context) -> dict:
    entries = await _query(ctx, f"O=%{quote(ctx.target)}%", "crt")
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
