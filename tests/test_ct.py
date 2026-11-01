import httpx
import respx

from osintkit.collectors import ct


@respx.mock
async def test_certificates_trim_issuer_and_names(make_context):
    ctx = make_context("example.com")
    respx.get(url__startswith="https://crt.sh/").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "id": 1,
                    "common_name": "example.com",
                    "name_value": "example.com\nwww.example.com\nmore.example.com",
                    "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
                    "not_before": "2024-01-01",
                    "not_after": "2024-04-01",
                    "serial_number": "aa",
                }
            ],
        )
    )
    certs = await ct.crt_sh_certificates(ctx)
    assert certs[0]["issuer"] == "Let's Encrypt"
    assert len(certs[0]["names"]) == 3


@respx.mock
async def test_org_search_empty(make_context):
    ctx = make_context("Acme", "company")
    respx.get(url__startswith="https://crt.sh/").mock(return_value=httpx.Response(200, json=[]))
    result = await ct.crt_sh_organization(ctx)
    assert result["certificates_seen"] == 0
    assert result["domains"] == []


@respx.mock
async def test_non_200_returns_empty_names(make_context):
    ctx = make_context("example.com")
    respx.get(url__startswith="https://crt.sh/").mock(return_value=httpx.Response(404))
    assert await ct.crt_sh_subdomains(ctx) == []


@respx.mock
async def test_malformed_json_returns_empty(make_context):
    ctx = make_context("example.com")
    respx.get(url__startswith="https://crt.sh/").mock(return_value=httpx.Response(200, text="<html>"))
    assert await ct.crt_sh_subdomains(ctx) == []
