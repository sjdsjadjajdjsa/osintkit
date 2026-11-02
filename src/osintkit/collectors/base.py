"""Collector registry and safe execution."""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from typing import Any

from .. import errors
from ..config import Settings
from ..http import HttpClient
from ..models import CollectorResult


@dataclass(slots=True)
class Context:
    target: str
    target_type: str
    settings: Settings
    http: HttpClient
    cache_ttl: int | None = None
    http_timeout: float | None = None

    @property
    def hibp_key(self) -> str | None:
        return self.settings.hibp_api_key

    @property
    def github_token(self) -> str | None:
        return self.settings.github_token


CollectorFunc = Callable[[Context], Awaitable[Any]]


@dataclass(frozen=True, slots=True)
class Collector:
    name: str
    target_types: tuple[str, ...]
    func: CollectorFunc
    description: str = ""
    requires: str | None = None
    order: int = 100
    ttl: int | None = None
    timeout: float | None = None


REGISTRY: list[Collector] = []


def collector(
    name: str,
    target_types: tuple[str, ...],
    description: str = "",
    *,
    requires: str | None = None,
    order: int = 100,
    ttl: int | None = None,
    timeout: float | None = None,
) -> Callable[[CollectorFunc], CollectorFunc]:
    def register(func: CollectorFunc) -> CollectorFunc:
        REGISTRY.append(
            Collector(
                name=name,
                target_types=target_types,
                func=func,
                description=description,
                requires=requires,
                order=order,
                ttl=ttl,
                timeout=timeout,
            )
        )
        return func

    return register


def collectors_for(target_type: str) -> list[Collector]:
    found = [c for c in REGISTRY if target_type in c.target_types]
    return sorted(found, key=lambda c: (c.order, c.name))


async def run_collector(spec: Collector, ctx: Context) -> CollectorResult:
    if spec.requires and not _has_requirement(spec.requires, ctx):
        hint = {
            "hibp": "HIBP_API_KEY not set",
            "github": "GITHUB_TOKEN not set",
        }.get(spec.requires, f"{spec.requires} unavailable")
        return CollectorResult(
            collector=spec.name,
            target=ctx.target,
            target_type=ctx.target_type,
            ok=False,
            skipped=True,
            note=f"skipped: {hint}",
        )

    if spec.ttl is not None or spec.timeout is not None:
        ctx = replace(
            ctx,
            cache_ttl=spec.ttl if spec.ttl is not None else ctx.cache_ttl,
            http_timeout=spec.timeout,
        )

    started = time.perf_counter()
    try:
        data = await spec.func(ctx)
    except errors.RateLimited as exc:
        return _result(spec, ctx, started, ok=False, error=f"rate limited: {exc}")
    except errors.SourceUnavailable as exc:
        return _result(spec, ctx, started, ok=False, error=str(exc))
    except TimeoutError:
        return _result(spec, ctx, started, ok=False, error="timed out")
    except Exception as exc:  # a broken source must never sink the run
        return _result(spec, ctx, started, ok=False, error=f"{type(exc).__name__}: {exc}")

    return _result(spec, ctx, started, ok=True, data=data)


def _result(spec: Collector, ctx: Context, started: float, **kwargs: Any) -> CollectorResult:
    elapsed_ms = int((time.perf_counter() - started) * 1000)
    return CollectorResult(
        collector=spec.name,
        target=ctx.target,
        target_type=ctx.target_type,
        elapsed_ms=elapsed_ms,
        **kwargs,
    )


def _has_requirement(requirement: str, ctx: Context) -> bool:
    if requirement == "hibp":
        return bool(ctx.hibp_key)
    if requirement == "github":
        return bool(ctx.github_token)
    return True
