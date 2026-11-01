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
            return_value=httpx.Response(
                200, content=compressed, headers={"content-encoding": "gzip"}
            )
        )
        assert await client.get_json(URL, namespace="enc") == {"ok": True}
        assert await client.get_json(URL, namespace="enc") == {"ok": True}
