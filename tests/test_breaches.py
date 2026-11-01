import httpx
import pytest
import respx

from osintkit.collectors import breaches


@respx.mock
async def test_hibp_pastes_parse(make_context, monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "k")
    ctx = make_context("alice@example.com", "email")
    respx.get(url__startswith="https://haveibeenpwned.com/api/v3/pasteaccount/").mock(
        return_value=httpx.Response(
            200,
            json=[{"Source": "Pastebin", "Id": "abc", "Title": "t", "Date": "2020-01-01", "EmailCount": 3}],
        )
    )
    result = await breaches.hibp_pastes(ctx)
    assert result[0]["source"] == "Pastebin"
    assert result[0]["origin"] == "haveibeenpwned-pastes"


@respx.mock
async def test_hibp_pastes_404_is_empty(make_context, monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "k")
    ctx = make_context("alice@example.com", "email")
    respx.get(url__startswith="https://haveibeenpwned.com/api/v3/pasteaccount/").mock(
        return_value=httpx.Response(404)
    )
    assert await breaches.hibp_pastes(ctx) == []


@respx.mock
async def test_leakcheck_sources_are_deduped(make_context):
    ctx = make_context("alice@example.com", "email")
    respx.get(url__startswith="https://leakcheck.io/").mock(
        return_value=httpx.Response(
            200,
            json={
                "result": [
                    {"sources": [{"name": "Acme", "date": "2020"}, {"name": "Acme", "date": "2021"}]}
                ]
            },
        )
    )
    result = await breaches.leakcheck_public(ctx)
    assert result["found"] == 1
    assert result["sources"][0]["name"] == "Acme"


@respx.mock
async def test_leakcheck_error_status_raises(make_context):
    from osintkit.errors import SourceUnavailable

    ctx = make_context("alice@example.com", "email")
    respx.get(url__startswith="https://leakcheck.io/").mock(return_value=httpx.Response(404))
    with pytest.raises(SourceUnavailable):
        await breaches.leakcheck_public(ctx)


@respx.mock
async def test_xposed_error_status_is_empty(make_context):
    ctx = make_context("alice@example.com", "email")
    respx.get(url__startswith="https://api.xposedornot.com/").mock(return_value=httpx.Response(422))
    assert await breaches.xposed_or_not(ctx) == {"found": 0, "breaches": []}
