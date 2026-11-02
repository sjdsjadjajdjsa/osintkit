import gzip

import httpx
import pytest
import respx

from osintkit.errors import RateLimited, SourceUnavailable
from osintkit.http import HttpClient

URL = "https://api.test/item"


@respx.mock
async def test_returns_body_on_success(http):
    respx.get(URL).mock(return_value=httpx.Response(200, json={"ok": True}))
    assert await http.get_json(URL, namespace="t") == {"ok": True}


@respx.mock
async def test_retries_server_errors_then_succeeds(http):
    route = respx.get(URL).mock(
        side_effect=[
            httpx.Response(503),
            httpx.Response(200, json={"ok": True}),
        ]
    )
    assert await http.get_json(URL, namespace="t") == {"ok": True}
    assert route.call_count == 2


@respx.mock
async def test_gives_up_after_max_attempts(settings):
    settings.max_attempts = 3
    async with HttpClient(settings) as client:
        respx.get(URL).mock(return_value=httpx.Response(429))
        with pytest.raises(RateLimited):
            await client.get_json(URL, namespace="t")
        assert respx.get(URL).call_count == 3


@respx.mock
async def test_client_errors_do_not_retry(http):
    respx.get(URL).mock(return_value=httpx.Response(403))
    with pytest.raises(SourceUnavailable):
        await http.get_json(URL, namespace="t")
    assert respx.get(URL).call_count == 1


@respx.mock
async def test_empty_on_returns_none(http):
    respx.get(URL).mock(return_value=httpx.Response(404))
    assert await http.get_json(URL, namespace="t") is None


@respx.mock
async def test_transport_error_becomes_source_unavailable(http):
    respx.get(URL).mock(side_effect=httpx.ConnectError("nope"))
    with pytest.raises(SourceUnavailable):
        await http.get_json(URL, namespace="t")


@respx.mock
async def test_cache_prevents_second_request(settings):
    settings.use_cache = True
    async with HttpClient(settings) as client:
        route = respx.get(URL).mock(return_value=httpx.Response(200, json={"n": 1}))
        assert await client.get_json(URL, namespace="c") == {"n": 1}
        assert await client.get_json(URL, namespace="c") == {"n": 1}
        assert route.call_count == 1


@respx.mock
async def test_no_cache_always_requests(settings):
    settings.use_cache = False
    async with HttpClient(settings) as client:
        route = respx.get(URL).mock(return_value=httpx.Response(200, json={"n": 1}))
        await client.get_json(URL, namespace="c")
        await client.get_json(URL, namespace="c")
        assert route.call_count == 2


@respx.mock
async def test_cached_replay_drops_encoding_headers(settings):
    settings.use_cache = True
    async with HttpClient(settings) as client:
        compressed = gzip.compress(b'{"ok": true}')
        respx.get(URL).mock(
            return_value=httpx.Response(200, content=compressed, headers={"content-encoding": "gzip"})
        )
        assert await client.get_json(URL, namespace="enc") == {"ok": True}
        assert await client.get_json(URL, namespace="enc") == {"ok": True}


@respx.mock
async def test_github_quota_403_is_retried_as_rate_limit(settings):
    settings.max_attempts = 2
    async with HttpClient(settings) as client:
        respx.get(URL).mock(return_value=httpx.Response(403, headers={"x-ratelimit-remaining": "0"}))
        with pytest.raises(RateLimited):
            await client.get_json(URL, namespace="q")
        assert respx.get(URL).call_count == 2


@respx.mock
async def test_plain_403_is_not_retried(http):
    respx.get(URL).mock(return_value=httpx.Response(403))
    with pytest.raises(SourceUnavailable):
        await http.get_json(URL, namespace="q")
    assert respx.get(URL).call_count == 1


@respx.mock
async def test_concurrent_identical_requests_are_coalesced(settings):
    import asyncio

    calls = {"n": 0}

    async def slow(request):
        calls["n"] += 1
        await asyncio.sleep(0.05)
        return httpx.Response(200, json={"ok": True})

    respx.get(URL).mock(side_effect=slow)
    async with HttpClient(settings) as client:
        results = await asyncio.gather(*(client.get_json(URL, namespace="dedupe") for _ in range(4)))
    assert results == [{"ok": True}] * 4
    assert calls["n"] == 1


@respx.mock
async def test_failed_inflight_task_does_not_stick(http):
    respx.get(URL).mock(return_value=httpx.Response(500))
    with pytest.raises(RateLimited):
        await http.get_json(URL, namespace="d")
    respx.get(URL).mock(return_value=httpx.Response(200, json={"ok": True}))
    assert await http.get_json(URL, namespace="d") == {"ok": True}


async def test_connection_limit_is_applied(settings):
    settings.max_connections = 4
    async with HttpClient(settings) as client:
        assert client._client._transport._pool._max_connections == 4
