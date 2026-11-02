"""Info-stealer log exposure via Hudson Rock's keyless endpoint."""

from __future__ import annotations

from urllib.parse import quote

from .base import Context, collector

BASE = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by"
MAX_STEALERS = 5


def _clean(value: object) -> str | None:
    text = str(value or "").strip()
    if not text or text.lower() == "not found":
        return None
    return text[:120]


def _summary(body: object) -> dict:
    if not isinstance(body, dict):
        return {"infected": False, "infections": 0, "stealers": []}
    raw = body.get("stealers") or []
    stealers = []
    for row in raw[:MAX_STEALERS]:
        if not isinstance(row, dict):
            continue
        stealers.append(
            {
                "date": (row.get("date_compromised") or "")[:10] or None,
                "computer": _clean(row.get("computer_name")),
                "os": _clean(row.get("operating_system")),
                "ip": _clean(row.get("ip")),
                "antiviruses": [av for av in row.get("antiviruses") or [] if av != "None"][:5],
                "logins": [str(item) for item in (row.get("top_logins") or [])[:5]],
                "passwords": [str(item) for item in (row.get("top_passwords") or [])[:5]],
            }
        )
    return {
        "infected": bool(stealers),
        "infections": len(raw),
        "corporate_services": body.get("total_corporate_services"),
        "user_services": body.get("total_user_services"),
        "stealers": stealers,
        "source": "hudsonrock",
    }


async def _lookup(ctx: Context, kind: str) -> dict:
    response = await ctx.http.get(
        f"{BASE}-{kind}",
        namespace="hudsonrock",
        params={kind: ctx.target},
        empty_on=(404, 429),
        timeout=ctx.http_timeout or 45,
    )
    if response.status_code != 200:
        return {"infected": False, "infections": 0, "stealers": [], "note": f"HTTP {response.status_code}"}
    try:
        return _summary(response.json())
    except ValueError:
        return {"infected": False, "infections": 0, "stealers": [], "note": "non-JSON"}


@collector("infostealer", ("email", "username", "domain"), "Info-stealer log infections", order=5, ttl=43200)
async def infostealer(ctx: Context) -> dict:
    kind = {"email": "email", "username": "username", "domain": "domain"}[ctx.target_type]
    result = await _lookup(ctx, kind)
    result["target_kind"] = kind
    result["checked"] = quote(ctx.target)
    return result
