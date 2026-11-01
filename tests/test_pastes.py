import httpx
import respx

from osintkit.collectors import pastes


@respx.mock
async def test_code_mentions_parses_snippets(make_context):
    ctx = make_context("alice@example.com", "email")
    respx.get(url__startswith="https://grep.app/").mock(
        return_value=httpx.Response(
            200,
            json={
                "facets": {"repo": {"total": 2}},
                "hits": {
                    "hits": [
                        {
                            "repo": {"raw": "a/b"},
                            "path": {"raw": "c.py"},
                            "content": {"snippet": "<b>alice</b>"},
                        }
                    ]
                },
            },
        )
    )
    result = await pastes.code_mentions(ctx)
    assert result["hits"][0]["repo"] == "a/b"
    assert result["total_repos"] == 2


@respx.mock
async def test_code_mentions_rate_limited_is_empty(make_context):
    ctx = make_context("alice@example.com", "email")
    respx.get(url__startswith="https://grep.app/").mock(return_value=httpx.Response(429))
    assert await pastes.code_mentions(ctx) == {"count": 0, "hits": []}


@respx.mock
async def test_hackertarget_parses_csv(make_context):
    ctx = make_context("example.com")
    respx.get(url__startswith="https://api.hackertarget.com/").mock(
        return_value=httpx.Response(200, text="www.example.com,1.2.3.4\nmail.example.com,5.6.7.8")
    )
    result = await pastes.hackertarget_hostsearch(ctx)
    assert result["hosts"][0] == {"host": "www.example.com", "ip": "1.2.3.4"}


@respx.mock
async def test_hackertarget_error_text_is_noted(make_context):
    ctx = make_context("example.com")
    respx.get(url__startswith="https://api.hackertarget.com/").mock(
        return_value=httpx.Response(200, text="error: API count exceeded")
    )
    result = await pastes.hackertarget_hostsearch(ctx)
    assert result["hosts"] == []
    assert "API count exceeded" in result["note"]


@respx.mock
async def test_gist_fallback_dedupes_and_caps(make_context):
    ctx = make_context("alice", "username")
    respx.get(url__startswith="https://psbdmp.ws/").mock(return_value=httpx.Response(500))
    links = "".join(
        f'<a href="/owner/{index:040x}">x</a>' for index in range(40)
    )
    links += '<a href="/owner/' + f"{0:040x}" + '">dup</a>'
    respx.get(url__startswith="https://gist.github.com/search").mock(
        return_value=httpx.Response(200, text=links)
    )
    result = await pastes.psbdmp_search(ctx)
    assert len(result["pastes"]) == 15
    assert len({p["id"] for p in result["pastes"]}) == 15
