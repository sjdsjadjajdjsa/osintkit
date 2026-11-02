import httpx
import respx

from osintkit.collectors import infostealer

URL = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email"


@respx.mock
async def test_infections_are_summarised(make_context):
    ctx = make_context("a@b.co", "email")
    respx.get(URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "stealers": [
                    {
                        "date_compromised": "2026-10-31T00:00:00.000Z",
                        "computer_name": "DESKTOP-1 (David)",
                        "operating_system": "Not Found",
                        "ip": "105.118.***.**",
                        "antiviruses": ["None"],
                        "top_logins": ["a***n"],
                        "top_passwords": ["v**************E"],
                    }
                ],
                "total_corporate_services": 3,
                "total_user_services": 9,
            },
        )
    )
    result = await infostealer.infostealer(ctx)
    assert result["infected"] is True
    assert result["infections"] == 1
    assert result["stealers"][0]["date"] == "2026-10-31"
    assert result["stealers"][0]["os"] is None
    assert result["stealers"][0]["antiviruses"] == []


@respx.mock
async def test_clean_target(make_context):
    ctx = make_context("a@b.co", "email")
    respx.get(URL).mock(return_value=httpx.Response(200, json={"stealers": []}))
    result = await infostealer.infostealer(ctx)
    assert result["infected"] is False


@respx.mock
async def test_rate_limited_is_not_an_error(make_context):
    ctx = make_context("a@b.co", "email")
    respx.get(URL).mock(return_value=httpx.Response(429))
    result = await infostealer.infostealer(ctx)
    assert result["infections"] == 0
    assert "429" in result["note"]


@respx.mock
async def test_domain_uses_domain_endpoint(make_context):
    ctx = make_context("example.com", "domain")
    route = respx.get("https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain").mock(
        return_value=httpx.Response(200, json={"stealers": []})
    )
    await infostealer.infostealer(ctx)
    assert route.calls[0].request.url.params["domain"] == "example.com"
