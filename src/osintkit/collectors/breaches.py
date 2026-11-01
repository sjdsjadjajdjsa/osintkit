"""Breach exposure checks against public, login-free indexes."""

from __future__ import annotations

from urllib.parse import quote

from .. import errors
from .base import Context, collector

HIBP = "https://haveibeenpwned.com/api/v3"


def _summarise_hibp(entries: list[dict]) -> list[dict]:
    out = []
    for entry in entries:
        out.append(
            {
                "name": entry.get("Name") or entry.get("Title"),
                "domain": entry.get("Domain"),
                "date": entry.get("BreachDate"),
                "added": entry.get("AddedDate"),
                "pwn_count": entry.get("PwnCount"),
                "data_types": entry.get("DataClasses") or [],
                "verified": entry.get("IsVerified"),
                "description": (entry.get("Description") or "")[:500],
                "source": "haveibeenpwned",
            }
        )
    return out


@collector(
    "hibp_breaches",
    ("email",),
    "Have I Been Pwned breach membership",
    requires="hibp",
    order=10,
)
async def hibp_breaches(ctx: Context) -> list[dict]:
    headers = {"hibp-api-key": ctx.hibp_key or "", "User-Agent": "osintkit/0.1"}
    response = await ctx.http.get(
        f"{HIBP}/breachedaccount/{quote(ctx.target)}",
        namespace="hibp",
        params={"truncateResponse": "false"},
        headers=headers,
        empty_on=(404,),
    )
    if response.status_code == 404:
        return []
    body = response.json()
    if not isinstance(body, list):
        return []
    return _summarise_hibp(body)


@collector(
    "hibp_pastes",
    ("email",),
    "Have I Been Pwned paste exposure",
    requires="hibp",
    order=11,
)
async def hibp_pastes(ctx: Context) -> list[dict]:
    headers = {"hibp-api-key": ctx.hibp_key or "", "User-Agent": "osintkit/0.1"}
    response = await ctx.http.get(
        f"{HIBP}/pasteaccount/{quote(ctx.target)}",
        namespace="hibp",
        headers=headers,
        empty_on=(404,),
    )
    if response.status_code == 404:
        return []
    body = response.json()
    if not isinstance(body, list):
        return []
    return [
        {
            "source": entry.get("Source"),
            "id": entry.get("Id"),
            "title": entry.get("Title"),
            "date": entry.get("Date"),
            "email_count": entry.get("EmailCount"),
            "origin": "haveibeenpwned-pastes",
        }
        for entry in body
    ]


@collector("xposed_or_not", ("email",), "XposedOrNot public breach lookup", order=12)
async def xposed_or_not(ctx: Context) -> dict:
    response = await ctx.http.get(
        f"https://api.xposedornot.com/v1/check-email/{quote(ctx.target)}",
        namespace="xposedornot",
        empty_on=(404, 422),
    )
    if response.status_code != 200:
        return {"found": 0, "breaches": []}
    try:
        body = response.json()
    except ValueError:
        return {"found": 0, "breaches": []}
    raw = body.get("breaches") or []
    names: list[str] = []
    for item in raw:
        if isinstance(item, list):
            names.extend(str(n) for n in item)
        elif isinstance(item, str):
            names.append(item)
    details = body.get("breach_details") if isinstance(body, dict) else None
    breaches = []
    if isinstance(details, dict):
        for entry in details.get("breaches") or []:
            if not isinstance(entry, dict):
                continue
            breaches.append(
                {
                    "name": entry.get("breach") or entry.get("name"),
                    "domain": entry.get("domain"),
                    "date": entry.get("xposed_date") or entry.get("breached_date"),
                    "data_types": entry.get("xposed_data") or entry.get("data_classes") or [],
                    "source": "xposedornot",
                }
            )
    if not breaches:
        breaches = [{"name": name, "source": "xposedornot"} for name in names]
    return {"found": len(breaches), "breaches": breaches}


@collector("leakcheck_public", ("email",), "LeakCheck public (free tier)", order=13)
async def leakcheck_public(ctx: Context) -> dict:
    response = await ctx.http.get(
        "https://leakcheck.io/api/public",
        namespace="leakcheck",
        params={"check": ctx.target},
        empty_on=(404, 400),
    )
    if response.status_code != 200:
        raise errors.SourceUnavailable("leakcheck public endpoint unavailable")
    try:
        body = response.json()
    except ValueError:
        return {"found": 0, "sources": []}
    sources = []
    for entry in body.get("result") or []:
        for src in entry.get("sources") or []:
            sources.append(
                {
                    "name": src.get("name"),
                    "date": src.get("date"),
                    "source": "leakcheck",
                }
            )
    deduped: dict[str, dict] = {}
    for src in sources:
        deduped.setdefault(str(src.get("name")), src)
    return {"found": len(deduped), "sources": list(deduped.values())}
