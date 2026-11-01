"""Resilient HTTP client: retries, exponential backoff, and a warm cache."""

from __future__ import annotations

import asyncio
import json
import random
import time
from collections.abc import Iterable, Mapping
from typing import Any, Self

import httpx

from .config import Settings, cache_read, cache_write
from .errors import RateLimited, SourceUnavailable

USER_AGENT = "osintkit/0.1 (+public-data-osint; contact: local user)"
RETRY_STATUS = {429, 500, 502, 503, 504}


class HttpClient:
    """Thin async wrapper with bounded retries and transparent caching.

    Only GETs are needed by the collectors, so that is all this exposes.
    """

    def __init__(self, settings: Settings, client: httpx.AsyncClient | None = None) -> None:
        self.settings = settings
        self._own_client = client is None
        self._client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(settings.timeout),
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        )

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._own_client:
            await self._client.aclose()

    @staticmethod
    def _cache_key(url: str, params: Mapping[str, Any] | None) -> str:
        if not params:
            return url
        return f"{url}?{json.dumps(params, sort_keys=True, default=str)}"

    async def get(
        self,
        url: str,
        *,
        namespace: str,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        accept: str = "application/json",
        empty_on: Iterable[int] = (404,),
    ) -> httpx.Response:
        return await self._request(
            "GET",
            url,
            namespace=namespace,
            params=params,
            headers=headers,
            accept=accept,
            empty_on=empty_on,
        )

    async def post_json(
        self,
        url: str,
        *,
        namespace: str,
        payload: Mapping[str, Any],
        headers: Mapping[str, str] | None = None,
    ) -> httpx.Response:
        return await self._request(
            "POST",
            url,
            namespace=namespace,
            payload=payload,
            headers=headers,
            empty_on=(),
        )

    async def _request(
        self,
        method: str,
        url: str,
        *,
        namespace: str,
        params: Mapping[str, Any] | None = None,
        payload: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        accept: str = "application/json",
        empty_on: Iterable[int] = (),
    ) -> httpx.Response:
        key = self._cache_key(url, payload if method != "GET" else params)
        if self.settings.use_cache:
            cached = cache_read(namespace, key, self.settings.cache_ttl)
            if cached is not None:
                return httpx.Response(
                    status_code=cached["status"],
                    headers=cached.get("headers", {}),
                    content=cached.get("body", "").encode("utf-8"),
                    request=httpx.Request(method, url),
                )

        last_error: Exception | None = None
        for attempt in range(1, self.settings.max_attempts + 1):
            try:
                request_headers = {"Accept": accept}
                if headers:
                    request_headers.update(headers)
                if method == "GET":
                    response = await self._client.get(url, params=params, headers=request_headers)
                else:
                    response = await self._client.post(
                        url, json=dict(payload or {}), headers=request_headers
                    )
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_error = exc
                if attempt >= self.settings.max_attempts:
                    raise SourceUnavailable(f"{url}: {type(exc).__name__}") from exc
                await self._sleep(attempt, None)
                continue

            if response.status_code in empty_on:
                self._store(namespace, key, response)
                return response

            if response.status_code in RETRY_STATUS:
                retry_after = _retry_after(response)
                if attempt >= self.settings.max_attempts:
                    raise RateLimited(
                        f"{url}: HTTP {response.status_code} after {attempt} attempts",
                        retry_after=retry_after,
                    )
                await self._sleep(attempt, retry_after)
                continue

            if response.status_code == 403 and _quota_exhausted(response):
                if attempt >= self.settings.max_attempts:
                    raise RateLimited(f"{url}: quota exhausted after {attempt} attempts")
                await self._sleep(attempt, _retry_after(response))
                continue

            if response.status_code >= 400:
                raise SourceUnavailable(f"{url}: HTTP {response.status_code}")

            self._store(namespace, key, response)
            return response

        raise SourceUnavailable(f"{url}: {last_error}")

    async def get_json(self, url: str, **kwargs: Any) -> Any:
        response = await self.get(url, **kwargs)
        if response.status_code in set(kwargs.get("empty_on") or (404,)):
            return None
        try:
            return response.json()
        except (json.JSONDecodeError, ValueError) as exc:  # pragma: no cover - malformed upstream
            raise SourceUnavailable(f"{url}: invalid JSON") from exc

    async def head_ok(self, url: str, *, namespace: str = "presence", **kwargs: Any) -> int:
        """Return the final status code, treating any HTTP answer as a hit."""
        response = await self.get(url, namespace=namespace, empty_on=tuple(range(400, 500)), **kwargs)
        return response.status_code

    def _store(self, namespace: str, key: str, response: httpx.Response) -> None:
        if not self.settings.use_cache:
            return
        try:
            body = response.text
        except Exception:  # pragma: no cover - undecodable body
            body = ""
        headers = {
            name: value
            for name, value in response.headers.items()
            if name.lower() not in {"content-encoding", "content-length", "transfer-encoding"}
        }
        cache_write(
            namespace,
            key,
            {"status": response.status_code, "headers": headers, "body": body},
        )

    async def _sleep(self, attempt: int, retry_after: float | None) -> None:
        if retry_after:
            delay = min(retry_after, 30.0)
        else:
            delay = min(0.5 * (2 ** (attempt - 1)), 8.0)
            delay += random.uniform(0, delay / 2)
        await asyncio.sleep(delay)


def _quota_exhausted(response: httpx.Response) -> bool:
    return response.headers.get("x-ratelimit-remaining") == "0"


def _retry_after(response: httpx.Response) -> float | None:
    raw = response.headers.get("retry-after")
    if not raw:
        return None
    try:
        return float(raw)
    except ValueError:
        return None


def cache_hit(settings: Settings, namespace: str, key: str) -> Any | None:
    """Read a cached non-HTTP collector result (DNS, WHOIS, TCP probes)."""
    if not settings.use_cache:
        return None
    return cache_read(namespace, key, settings.cache_ttl)


def cache_put(settings: Settings, namespace: str, key: str, value: Any) -> None:
    if settings.use_cache:
        cache_write(namespace, key, value)


def stopwatch() -> float:
    return time.perf_counter()
