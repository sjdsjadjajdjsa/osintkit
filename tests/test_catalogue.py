import httpx
import respx

from osintkit import catalogue
from osintkit.http import HttpClient

HIBP = "https://haveibeenpwned.com/api/v3/breaches"
XPOSED = "https://api.xposedornot.com/v1/breaches"


@respx.mock
async def test_hibp_catalogue_is_parsed(http):
    respx.get(HIBP).mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "Name": "Acme Corp",
                    "BreachDate": "2020-09-01",
                    "DataClasses": ["Emails"],
                    "Domain": "acme.test",
                    "PwnCount": 100,
                }
            ],
        )
    )
    data = await catalogue.fetch(http)
    assert data["acmecorp"]["date"] == "2020-09-01"
    assert data["acmecorp"]["data_types"] == ["Emails"]


@respx.mock
async def test_xposed_is_the_fallback(http):
    respx.get(HIBP).mock(return_value=httpx.Response(503))
    respx.get(XPOSED).mock(
        return_value=httpx.Response(
            200,
            json={
                "exposedBreaches": [
                    {"breachID": "Acme", "breachedDate": "2019-05-05T00:00:00+00:00", "exposedData": ["Emails"]}
                ]
            },
        )
    )
    data = await catalogue.fetch(http)
    assert data["acme"]["date"] == "2019-05-05"


@respx.mock
async def test_both_failing_is_empty(http):
    respx.get(HIBP).mock(return_value=httpx.Response(503))
    respx.get(XPOSED).mock(return_value=httpx.Response(503))
    assert await catalogue.fetch(http) == {}


@respx.mock
async def test_result_is_cached(settings):
    settings.use_cache = True
    async with HttpClient(settings) as client:
        route = respx.get(HIBP).mock(
            return_value=httpx.Response(200, json=[{"Name": "Acme", "BreachDate": "2020-01-01"}])
        )
        await catalogue.fetch(client)
        await catalogue.fetch(client)
        assert route.call_count == 1


def test_null_rows_are_skipped():
    assert catalogue._from_hibp([None, {}, {"Name": ""}]) == {}
    assert catalogue._from_xposed({"exposedBreaches": [None, {"breachID": ""}]}) == {}
