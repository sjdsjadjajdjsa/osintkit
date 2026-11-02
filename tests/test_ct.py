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


@respx.mock
async def test_html_wrapped_json_is_parsed(make_context):
    ctx = make_context("example.com")
    body = (
        "[BEGIN_HEADERS] Content-Type: application/json [END_HEADERS] <BR><BR>"
        '[{"name_value": "api.example.com", "common_name": "api.example.com"}]'
    )
    respx.get(url__startswith="https://crt.sh/").mock(
        return_value=httpx.Response(200, text=body, headers={"content-type": "text/html"})
    )
    assert await ct.crt_sh_subdomains(ctx) == ["api.example.com"]


@respx.mock
async def test_org_search_falls_back_to_guessed_domains(make_context):
    ctx = make_context("Cloudflare", "company")

    def handler(request):
        query = request.url.params["q"]
        if query.startswith("O="):
            return httpx.Response(200, json=[])
        return httpx.Response(200, json=[{"name_value": "www.cloudflare.com"}])

    respx.get(url__startswith="https://crt.sh/").mock(side_effect=handler)
    result = await ct.crt_sh_organization(ctx)
    assert result["method"] == "guessed domain identity"
    assert result["matched_domains"] == ["cloudflare.com", "cloudflare.net", "cloudflare.io"]
    assert result["domains"][0]["domain"] == "www.cloudflare.com"


@respx.mock
async def test_org_search_reports_no_match(make_context):
    ctx = make_context("Zzz Nope", "company")
    respx.get(url__startswith="https://crt.sh/").mock(return_value=httpx.Response(200, json=[]))
    result = await ct.crt_sh_organization(ctx)
    assert result["method"] == "no organization match"
    assert result["domains"] == []


def test_company_domain_guesses_strip_legal_suffix():
    assert ct._company_domains("Cloudflare, Inc.") == ["cloudflare.com", "cloudflare.net", "cloudflare.io"]
    assert ct._company_domains("A") == []
    assert ct._company_domains("Example GmbH")[:1] == ["example.com"]
