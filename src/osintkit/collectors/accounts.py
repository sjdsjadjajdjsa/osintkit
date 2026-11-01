"""Username correlation across public profiles that answer 404 for unknown handles."""

from __future__ import annotations

import asyncio
import hashlib
from urllib.parse import quote

from .base import Context, collector

SITES: tuple[tuple[str, str], ...] = (
    ("github", "https://github.com/{u}"),
    ("gitlab", "https://gitlab.com/{u}"),
    ("codeberg", "https://codeberg.org/{u}"),
    ("bitbucket", "https://bitbucket.org/{u}"),
    ("keybase", "https://keybase.io/{u}"),
    ("pypi", "https://pypi.org/user/{u}/"),
    ("npm", "https://www.npmjs.com/~{u}"),
    ("reddit", "https://www.reddit.com/user/{u}"),
    ("mastodon.social", "https://mastodon.social/@{u}"),
    ("dev.to", "https://dev.to/{u}"),
    ("dribbble", "https://dribbble.com/{u}"),
    ("behance", "https://www.behance.net/{u}"),
    ("kaggle", "https://www.kaggle.com/{u}"),
    ("huggingface", "https://huggingface.co/{u}"),
    ("codepen", "https://codepen.io/{u}"),
    ("twitch", "https://www.twitch.tv/{u}"),
    ("soundcloud", "https://soundcloud.com/{u}"),
    ("replit", "https://replit.com/@{u}"),
)

SEMAPHORE = 8


async def _probe(ctx: Context, site: str, template: str) -> dict | None:
    handle = ctx.target
    url = template.format(u=quote(handle))
    try:
        status = await ctx.http.head_ok(url, namespace="presence")
    except Exception as exc:
        return {"site": site, "url": url, "status": "error", "detail": type(exc).__name__}
    if status == 404:
        return None
    return {
        "site": site,
        "url": url,
        "status": "found" if status < 400 else "unreachable",
        "http_status": status,
    }


@collector("username_presence", ("username",), "Public profile presence", order=60, ttl=21600)
async def username_presence(ctx: Context) -> dict:
    semaphore = asyncio.Semaphore(SEMAPHORE)

    async def guarded(site: str, template: str) -> dict | None:
        async with semaphore:
            return await _probe(ctx, site, template)

    results = await asyncio.gather(*(guarded(s, t) for s, t in SITES))
    found = [r for r in results if r and r["status"] == "found"]
    unknown = [r for r in results if r and r["status"] != "found"]
    return {
        "handle": ctx.target,
        "checked": len(SITES),
        "found": found,
        "unconfirmed": unknown,
    }


@collector("gravatar", ("email",), "Gravatar presence for the address", order=61)
async def gravatar(ctx: Context) -> dict:
    digest = hashlib.md5(ctx.target.strip().lower().encode("utf-8")).hexdigest()
    url = f"https://gravatar.com/avatar/{digest}?d=404"
    try:
        status = await ctx.http.head_ok(url, namespace="gravatar")
    except Exception as exc:
        return {"checked": False, "detail": type(exc).__name__}
    return {
        "checked": True,
        "present": status == 200,
        "profile": f"https://gravatar.com/{digest}" if status == 200 else None,
    }
