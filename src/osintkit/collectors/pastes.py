"""Paste dumps and public code mentions."""

from __future__ import annotations

import re
from urllib.parse import quote

from .base import Context, collector

PSBDMP = "https://psbdmp.ws/api/v3"
TAG_RE = re.compile(r"<[^>]+>")
SPACE_RE = re.compile(r"\s+")


def snippet(text: str, needle: str, width: int = 140) -> str:
    """Plain-text window around the needle."""
    clean = SPACE_RE.sub(" ", TAG_RE.sub(" ", text or "")).strip()
    if not clean:
        return ""
    index = clean.lower().find(needle.lower())
    if index == -1:
        return clean[:width]
    start = max(0, index - width // 2)
    end = min(len(clean), index + len(needle) + width // 2)
    return ("…" if start else "") + clean[start:end] + ("…" if end < len(clean) else "")


@collector("psbdmp_search", ("email", "username", "domain"), "Psbdmp paste archive mentions", order=70)
async def psbdmp_search(ctx: Context) -> dict:
    response = await ctx.http.get(
        f"{PSBDMP}/search/{quote(ctx.target)}",
        namespace="psbdmp",
        empty_on=(404, 500),
    )
    if response.status_code != 200:
        return {"count": 0, "pastes": []}
    try:
        body = response.json()
    except ValueError:
        return {"count": 0, "pastes": []}
    entries = body.get("data") if isinstance(body, dict) else None
    if not isinstance(entries, list):
        return {"count": 0, "pastes": []}
    pastes = []
    for entry in entries[:25]:
        if not isinstance(entry, dict):
            continue
        paste_id = entry.get("id")
        pastes.append(
            {
                "id": paste_id,
                "url": f"https://pastebin.com/{paste_id}" if paste_id else None,
                "archive_url": f"https://psbdmp.ws/api/v3/dump/{paste_id}" if paste_id else None,
                "tags": entry.get("tags"),
                "length": entry.get("len"),
                "created": entry.get("time"),
                "snippet": (entry.get("snippet") or "")[:400],
            }
        )
    return {"count": body.get("count", len(pastes)), "pastes": pastes}


@collector("code_mentions", ("email", "domain"), "Public code/repository mentions", order=71)
async def code_mentions(ctx: Context) -> dict:
    response = await ctx.http.get(
        "https://grep.app/api/search",
        namespace="grep.app",
        params={"q": ctx.target},
        empty_on=(404, 429),
    )
    if response.status_code != 200:
        return {"count": 0, "hits": []}
    try:
        body = response.json()
    except ValueError:
        return {"count": 0, "hits": []}
    facet = body.get("facets") if isinstance(body, dict) else None
    hits_raw = body.get("hits", {}).get("hits", []) if isinstance(body, dict) else []
    hits = []
    for hit in hits_raw[:20]:
        if not isinstance(hit, dict):
            continue
        repo = (hit.get("repo") or {}).get("raw") if isinstance(hit.get("repo"), dict) else None
        path = (hit.get("path") or {}).get("raw") if isinstance(hit.get("path"), dict) else None
        snippet = ((hit.get("content") or {}).get("snippet") or "")[:400]
        hits.append({"repo": repo, "path": path, "snippet": snippet})
    total = None
    if isinstance(facet, dict):
        total = facet.get("repo", {}).get("total") if isinstance(facet.get("repo"), dict) else None
    return {"count": len(hits), "total_repos": total, "hits": hits}


@collector("hackertarget_hostsearch", ("domain",), "Passive DNS host search", order=72)
async def hackertarget_hostsearch(ctx: Context) -> dict:
    response = await ctx.http.get(
        "https://api.hackertarget.com/hostsearch/",
        namespace="hackertarget",
        params={"q": ctx.target},
        accept="text/plain",
        empty_on=(404, 429),
    )
    if response.status_code != 200:
        return {"hosts": []}
    text = response.text.strip()
    if text.lower().startswith("error") or "API count exceeded" in text:
        return {"hosts": [], "note": text[:120]}
    hosts = []
    for line in text.splitlines():
        if "," not in line:
            continue
        name, _, ip = line.partition(",")
        hosts.append({"host": name.strip(), "ip": ip.strip()})
    return {"count": len(hosts), "hosts": hosts[:100]}


@collector("hn_mentions", ("email", "username", "domain", "company"), "Hacker News mentions", order=73)
async def hn_mentions(ctx: Context) -> dict:
    response = await ctx.http.get(
        "https://hn.algolia.com/api/v1/search",
        namespace="hn",
        params={"query": ctx.target, "hitsPerPage": "20"},
        empty_on=(404, 429),
    )
    if response.status_code != 200:
        return {"count": 0, "mentions": []}
    try:
        body = response.json()
    except ValueError:
        return {"count": 0, "mentions": []}
    hits = body.get("hits") if isinstance(body, dict) else None
    if not isinstance(hits, list):
        return {"count": 0, "mentions": []}
    mentions = []
    for hit in hits[:20]:
        if not isinstance(hit, dict):
            continue
        text = hit.get("comment_text") or hit.get("story_text") or ""
        mentions.append(
            {
                "title": hit.get("title") or hit.get("story_title"),
                "url": hit.get("url") or (f"https://news.ycombinator.com/item?id={hit.get('objectID')}"),
                "author": hit.get("author"),
                "created": hit.get("created_at"),
                "snippet": snippet(text, ctx.target),
            }
        )
    return {"count": len(mentions), "total": body.get("nbHits"), "mentions": mentions}


@collector("stackoverflow_mentions", ("email", "username", "domain", "company"), "Stack Exchange mentions", order=74)
async def stackoverflow_mentions(ctx: Context) -> dict:
    response = await ctx.http.get(
        "https://api.stackexchange.com/2.3/search/excerpts",
        namespace="stackexchange",
        params={
            "q": ctx.target,
            "site": "stackoverflow",
            "pagesize": "20",
            "order": "desc",
            "sort": "relevance",
        },
        empty_on=(400, 404, 429),
    )
    if response.status_code != 200:
        return {"count": 0, "items": []}
    try:
        body = response.json()
    except ValueError:
        return {"count": 0, "items": []}
    raw = body.get("items") if isinstance(body, dict) else None
    if not isinstance(raw, list):
        return {"count": 0, "items": []}
    items = []
    for item in raw[:20]:
        if not isinstance(item, dict):
            continue
        items.append(
            {
                "title": item.get("title"),
                "url": item.get("question_id")
                and f"https://stackoverflow.com/q/{item.get('question_id')}",
                "item_type": item.get("item_type"),
                "score": item.get("score"),
                "tags": item.get("tags"),
                "excerpt": snippet(item.get("excerpt") or "", ctx.target),
            }
        )
    return {"count": len(items), "items": items}
