"""XposedOrNot breach analytics: dated, typed membership plus pastes."""

from __future__ import annotations

from typing import Any

from .base import Context, collector

URL = "https://api.xposedornot.com/v1/breach-analytics"
MAX_LISTED = 80


def _types(value: Any) -> list[str]:
    return [part.strip() for part in str(value or "").split(";") if part.strip()]


def _breach(row: dict[str, Any]) -> dict[str, Any] | None:
    name = str(row.get("breach") or "").strip()
    if not name:
        return None
    date = str(row.get("xposed_date") or "").strip() or None
    return {
        "name": name,
        "date": date,
        "data_types": _types(row.get("xposed_data")),
        "domain": row.get("domain"),
        "pwn_count": row.get("xposed_records"),
        "verified": str(row.get("verified") or "").lower() == "yes",
        "password_risk": row.get("password_risk"),
        "source": "xposedornot-analytics",
    }


def _paste(row: dict[str, Any]) -> dict[str, Any] | None:
    paste_id = str(row.get("paste_id") or row.get("id") or "").strip()
    if not paste_id and not row.get("title"):
        return None
    return {
        "id": paste_id or None,
        "title": row.get("title"),
        "date": row.get("date") or row.get("xposed_date"),
        "source": row.get("source") or "xposedornot-analytics",
        "origin": "xposedornot",
    }


@collector("xposed_analytics", ("email",), "Dated breach and paste membership", order=14, ttl=21600)
async def xposed_analytics(ctx: Context) -> dict:
    response = await ctx.http.get(
        URL,
        namespace="xposed-analytics",
        params={"email": ctx.target},
        empty_on=(404, 422, 429),
        timeout=ctx.http_timeout or 60,
    )
    if response.status_code != 200:
        return {"breaches": [], "pastes": [], "note": f"HTTP {response.status_code}"}
    try:
        body = response.json()
    except ValueError:
        return {"breaches": [], "pastes": [], "note": "non-JSON"}

    raw = ((body.get("ExposedBreaches") or {}).get("breaches_details")) or []
    breaches = [entry for entry in (_breach(row) for row in raw if isinstance(row, dict)) if entry]
    raw_pastes = ((body.get("ExposedPastes") or {}).get("pastes_details")) or []
    pastes = [entry for entry in (_paste(row) for row in raw_pastes if isinstance(row, dict)) if entry]
    breaches.sort(key=lambda row: str(row.get("date") or ""), reverse=True)
    return {
        "found": len(breaches),
        "breaches": breaches[:MAX_LISTED],
        "pastes": pastes[:25],
        "source": "xposedornot-analytics",
    }
