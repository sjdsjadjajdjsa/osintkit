"""GitHub public API collectors."""

from __future__ import annotations

import re
from urllib.parse import quote

from .. import errors
from .base import Context, collector

API = "https://api.github.com"


def _headers(ctx: Context, extra: dict[str, str] | None = None) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if ctx.github_token:
        headers["Authorization"] = f"Bearer {ctx.github_token}"
    if extra:
        headers.update(extra)
    return headers


def _trim_user(user: dict) -> dict:
    return {
        "login": user.get("login"),
        "name": user.get("name"),
        "company": user.get("company"),
        "blog": user.get("blog") or None,
        "location": user.get("location"),
        "bio": user.get("bio"),
        "twitter_username": user.get("twitter_username"),
        "public_repos": user.get("public_repos"),
        "public_gists": user.get("public_gists"),
        "followers": user.get("followers"),
        "following": user.get("following"),
        "created_at": user.get("created_at"),
        "updated_at": user.get("updated_at"),
        "url": user.get("html_url"),
    }


@collector("github_profile", ("username",), "GitHub profile and recent repositories", order=50)
async def github_profile(ctx: Context) -> dict | None:
    login = quote(ctx.target)
    response = await ctx.http.get(
        f"{API}/users/{login}",
        namespace="github",
        headers=_headers(ctx),
        empty_on=(404,),
    )
    if response.status_code == 404:
        return None
    if response.status_code == 403:
        raise errors.RateLimited("GitHub API rate limit reached")
    user = response.json()
    if not isinstance(user, dict):
        return None

    repos: list[dict] = []
    repos_response = await ctx.http.get(
        f"{API}/users/{login}/repos",
        namespace="github",
        params={"per_page": "50", "sort": "updated"},
        headers=_headers(ctx),
        empty_on=(404,),
    )
    if repos_response.status_code == 200:
        payload = repos_response.json()
        if isinstance(payload, list):
            repos = [
                {
                    "name": r.get("name"),
                    "description": (r.get("description") or "")[:200],
                    "language": r.get("language"),
                    "stars": r.get("stargazers_count"),
                    "fork": r.get("fork"),
                    "updated_at": r.get("updated_at"),
                    "url": r.get("html_url"),
                }
                for r in payload
                if isinstance(r, dict)
            ]

    return {"profile": _trim_user(user), "repositories": repos}


@collector("github_commit_search", ("email",), "Commits authored with this email", order=50)
async def github_commit_search(ctx: Context) -> dict:
    response = await ctx.http.get(
        f"{API}/search/commits",
        namespace="github",
        params={"q": f'author-email:"{ctx.target}"', "per_page": "50"},
        headers=_headers(ctx, {"Accept": "application/vnd.github.cloak-preview+json"}),
    )
    body = response.json()
    items = body.get("items") if isinstance(body, dict) else None
    if not isinstance(items, list):
        return {"total": 0, "commits": []}
    commits = []
    for item in items:
        commit = item.get("commit") or {}
        author = commit.get("author") or {}
        commits.append(
            {
                "repo": (item.get("repository") or {}).get("full_name"),
                "message": (commit.get("message") or "").splitlines()[0][:160],
                "author_name": author.get("name"),
                "author_date": author.get("date"),
                "url": item.get("html_url"),
            }
        )
    return {"total": body.get("total_count", len(commits)), "commits": commits}


@collector("github_user_search", ("email", "company"), "GitHub user search", order=51)
async def github_user_search(ctx: Context) -> dict:
    query = f'"{ctx.target}"' if ctx.target_type == "email" else f'company:"{ctx.target}"'
    response = await ctx.http.get(
        f"{API}/search/users",
        namespace="github",
        params={"q": query, "per_page": "30"},
        headers=_headers(ctx),
    )
    body = response.json()
    items = body.get("items") if isinstance(body, dict) else None
    if not isinstance(items, list):
        return {"total": 0, "users": []}
    return {
        "total": body.get("total_count", len(items)),
        "users": [
            {"login": u.get("login"), "url": u.get("html_url"), "type": u.get("type")}
            for u in items
            if isinstance(u, dict)
        ],
    }


LEGAL_SUFFIX = re.compile(
    r"\b(inc|llc|ltd|limited|gmbh|corp|corporation|plc|ag|sa|bv|oy|pty)\.?$", re.I
)


def org_slugs(company: str) -> list[str]:
    base = company.strip().lower()
    variants = [base, LEGAL_SUFFIX.sub("", base).strip()]
    slugs = []
    for variant in variants:
        slug = re.sub(r"[^a-z0-9]+", "-", variant).strip("-")
        if slug and slug not in slugs:
            slugs.append(slug)
    return slugs


@collector("github_org_repos", ("company",), "GitHub repositories owned by the company", order=52)
async def github_org_repos(ctx: Context) -> dict:
    slugs = org_slugs(ctx.target)
    slug = slugs[0]
    response = None
    for candidate in slugs:
        response = await ctx.http.get(
            f"{API}/orgs/{quote(candidate)}/repos",
            namespace="github",
            params={"per_page": "50", "sort": "updated"},
            headers=_headers(ctx),
            empty_on=(404,),
        )
        if response.status_code != 404:
            slug = candidate
            break
    if response is None or response.status_code == 404:
        return {"org": slug, "tried": slugs, "found": False, "repositories": []}
    payload = response.json()
    if not isinstance(payload, list):
        return {"org": slug, "found": False, "repositories": []}
    return {
        "org": slug,
        "found": True,
        "repositories": [
            {
                "name": r.get("name"),
                "description": (r.get("description") or "")[:200],
                "language": r.get("language"),
                "stars": r.get("stargazers_count"),
                "url": r.get("html_url"),
            }
            for r in payload
            if isinstance(r, dict)
        ],
    }
