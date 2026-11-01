import httpx
import respx

from osintkit.collectors import (
    base,
    breaches,
    ct,
    dns,
    github,
    pastes,
    ports,
    subdomains,
    whois_lookup,
)
from osintkit.collectors.base import run_collector


@respx.mock
async def test_hibp_success_is_summarised(make_context, monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "k")
    ctx = make_context("alice@example.com", "email")
    respx.get(url__startswith="https://haveibeenpwned.com/api/v3/breachedaccount/").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "Name": "Acme",
                    "Domain": "acme.test",
                    "BreachDate": "2020-01-02",
                    "PwnCount": 10,
                    "DataClasses": ["Emails", "Passwords"],
                    "IsVerified": True,
                    "Description": "d",
                }
            ],
        )
    )
    result = await breaches.hibp_breaches(ctx)
    assert result[0]["name"] == "Acme"
    assert result[0]["data_types"] == ["Emails", "Passwords"]
    assert result[0]["source"] == "haveibeenpwned"


@respx.mock
async def test_hibp_404_means_clean(make_context, monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "k")
    ctx = make_context("alice@example.com", "email")
    respx.get(url__startswith="https://haveibeenpwned.com/api/v3/breachedaccount/").mock(
        return_value=httpx.Response(404)
    )
    assert await breaches.hibp_breaches(ctx) == []


@respx.mock
async def test_xposed_parses_breach_details(make_context):
    ctx = make_context("alice@example.com", "email")
    respx.get(url__startswith="https://api.xposedornot.com/").mock(
        return_value=httpx.Response(
            200,
            json={
                "breach_details": {
                    "breaches": [
                        {"breach": "Acme", "domain": "acme.test", "xposed_data": "Emails"}
                    ]
                }
            },
        )
    )
    result = await breaches.xposed_or_not(ctx)
    assert result["found"] == 1
    assert result["breaches"][0]["name"] == "Acme"


@respx.mock
async def test_xposed_falls_back_to_name_lists(make_context):
    ctx = make_context("alice@example.com", "email")
    respx.get(url__startswith="https://api.xposedornot.com/").mock(
        return_value=httpx.Response(200, json={"breaches": [["Acme", "Beta"]]})
    )
    result = await breaches.xposed_or_not(ctx)
    assert [b["name"] for b in result["breaches"]] == ["Acme", "Beta"]


@respx.mock
async def test_crt_sh_names_are_filtered_to_the_apex(make_context):
    ctx = make_context("example.com")
    respx.get(url__startswith="https://crt.sh/").mock(
        return_value=httpx.Response(
            200,
            json=[
                {"name_value": "api.example.com\nexample.com", "common_name": "*.dev.example.com"},
                {"name_value": "other.test", "common_name": "other.test"},
            ],
        )
    )
    names = await ct.crt_sh_subdomains(ctx)
    assert names == ["api.example.com", "dev.example.com"]


@respx.mock
async def test_crt_sh_organization_counts_domains(make_context):
    ctx = make_context("Acme Ltd", "company")
    respx.get(url__startswith="https://crt.sh/").mock(
        return_value=httpx.Response(
            200,
            json=[{"name_value": "acme.test", "common_name": "acme.test", "issuer_name": "O=CA"}],
        )
    )
    result = await ct.crt_sh_organization(ctx)
    assert result["domains"][0]["domain"] == "acme.test"


async def test_dns_records_shapes_output(make_context, monkeypatch):
    ctx = make_context("example.com")

    async def fake_lookup(_ctx, host, rtype):
        return {"A": ["93.184.216.34"], "MX": ["10 mail.example.com"]}.get(rtype, [])

    monkeypatch.setattr(dns, "_lookup", fake_lookup)
    result = await dns.dns_records(ctx)
    assert result == {"A": ["93.184.216.34"], "MX": ["10 mail.example.com"]}


async def test_dns_mail_posture_flags_spf_strict(make_context, monkeypatch):
    ctx = make_context("example.com")

    async def fake_lookup(_ctx, host, rtype):
        if host == "example.com":
            return ["v=spf1 -all"]
        if host.startswith("_dmarc."):
            return ["v=DMARC1; p=reject"]
        return []

    monkeypatch.setattr(dns, "_lookup", fake_lookup)
    result = await dns.dns_mail_posture(ctx)
    assert result["spf_present"] and result["spf_strict"]
    assert result["spf_all"] == "-all"
    assert result["dmarc_present"] and result["dmarc_policy"] == "reject"


async def test_whois_returns_clean_fields(make_context, monkeypatch):
    ctx = make_context("example.com")
    monkeypatch.setattr(
        whois_lookup, "_blocking_lookup", lambda domain: {"registrar": "Example Registrar"}
    )
    result = await whois_lookup.whois_registration(ctx)
    assert result["registrar"] == "Example Registrar"


@respx.mock
async def test_github_profile_returns_none_on_404(make_context):
    ctx = make_context("ghost", "username")
    respx.get("https://api.github.com/users/ghost").mock(return_value=httpx.Response(404))
    assert await github.github_profile(ctx) is None


@respx.mock
async def test_github_profile_collects_repos(make_context):
    ctx = make_context("alice", "username")
    respx.get("https://api.github.com/users/alice").mock(
        return_value=httpx.Response(200, json={"login": "alice", "public_repos": 1})
    )
    respx.get("https://api.github.com/users/alice/repos").mock(
        return_value=httpx.Response(200, json=[{"name": "one", "language": "Go"}])
    )
    result = await github.github_profile(ctx)
    assert result["profile"]["login"] == "alice"
    assert result["repositories"][0]["name"] == "one"


@respx.mock
async def test_github_commit_search_flattens_items(make_context):
    ctx = make_context("alice@example.com", "email")
    respx.get(url__startswith="https://api.github.com/search/commits").mock(
        return_value=httpx.Response(
            200,
            json={
                "total_count": 1,
                "items": [
                    {
                        "repository": {"full_name": "alice/repo"},
                        "commit": {"message": "fix\n\nbody", "author": {"name": "A", "date": "2021"}},
                        "html_url": "https://github.com/alice/repo/commit/1",
                    }
                ],
            },
        )
    )
    result = await github.github_commit_search(ctx)
    assert result["commits"][0]["message"] == "fix"


@respx.mock
async def test_username_presence_reports_found(make_context):
    ctx = make_context("alice", "username")
    for _site, template in __import__("osintkit.collectors.accounts", fromlist=["SITES"]).SITES:
        respx.get(template.format(u="alice")).mock(return_value=httpx.Response(404))
    respx.get("https://github.com/alice").mock(return_value=httpx.Response(200))
    from osintkit.collectors import accounts

    result = await accounts.username_presence(ctx)
    assert [f["site"] for f in result["found"]] == ["github"]


@respx.mock
async def test_psbdmp_parses_pastes(make_context):
    ctx = make_context("alice", "username")
    respx.get(url__startswith="https://psbdmp.ws/").mock(
        return_value=httpx.Response(
            200, json={"count": 1, "data": [{"id": "abc", "tags": ["t"], "len": 5}]}
        )
    )
    result = await pastes.psbdmp_search(ctx)
    assert result["pastes"][0]["url"] == "https://pastebin.com/abc"


@respx.mock
async def test_hn_mentions_snippet_is_plain(make_context):
    ctx = make_context("example.com")
    respx.get(url__startswith="https://hn.algolia.com/").mock(
        return_value=httpx.Response(
            200,
            json={"nbHits": 1, "hits": [{"objectID": "1", "comment_text": "<p>see example.com</p>"}]},
        )
    )
    result = await pastes.hn_mentions(ctx)
    assert result["mentions"][0]["snippet"] == "see example.com"


async def test_ports_skips_closed_and_records_banner(make_context, monkeypatch):
    ctx = make_context("example.com")

    class FakeReader:
        async def read(self, n):
            return b"SSH-2.0-OpenSSH\nmore"

    class FakeWriter:
        def close(self):
            pass

        async def wait_closed(self):
            pass

    async def fake_connect(host, port):
        if port == 22:
            return FakeReader(), FakeWriter()
        raise OSError("closed")

    monkeypatch.setattr(ports.asyncio, "open_connection", fake_connect)
    result = await ports.tcp_ports(ctx)
    assert result["open"] == [{"port": 22, "service": "ssh", "banner": "SSH-2.0-OpenSSH"}]


async def test_passive_subdomains_merges_sources(make_context, monkeypatch):
    ctx = make_context("example.com")

    async def fake_query(ctx, query, ns):
        return [{"name_value": "api.example.com"}]

    async def fake_hosts(ctx):
        return {"hosts": [{"host": "vpn.example.com", "ip": "1.2.3.4"}]}

    async def fake_resolve(name, resolvers):
        return "1.2.3.4" if name == "api.example.com" else None

    monkeypatch.setattr(subdomains, "_query", fake_query)
    monkeypatch.setattr(subdomains, "hackertarget_hostsearch", fake_hosts)
    monkeypatch.setattr(subdomains, "_resolve", fake_resolve)
    result = await subdomains.passive_subdomains(ctx)
    assert result["live_hosts"] == [{"host": "api.example.com", "ip": "1.2.3.4"}]
    assert result["discovered_count"] == 2


async def test_run_collector_skips_without_requirement(make_context):
    ctx = make_context("alice@example.com", "email")
    spec = base.Collector(name="hibp_breaches", target_types=("email",),
                          func=breaches.hibp_breaches, requires="hibp")
    result = await run_collector(spec, ctx)
    assert result.skipped and "HIBP_API_KEY" in result.note


async def test_run_collector_captures_exceptions(make_context):
    ctx = make_context()

    async def boom(_ctx):
        raise RuntimeError("kaput")

    spec = base.Collector(name="boom", target_types=("domain",), func=boom)
    result = await run_collector(spec, ctx)
    assert not result.ok and "kaput" in result.error


async def test_run_collector_times_work(make_context):
    ctx = make_context()

    async def quick(_ctx):
        return [1]

    spec = base.Collector(name="quick", target_types=("domain",), func=quick)
    result = await run_collector(spec, ctx)
    assert result.ok and result.data == [1]


async def test_dns_uses_configured_resolvers(make_context):
    ctx = make_context("example.com")
    ctx.settings.resolvers = ["10.0.0.1", "10.0.0.2"]
    resolver = dns._resolver(ctx)
    assert resolver.nameservers == ["10.0.0.1", "10.0.0.2"]


@respx.mock
async def test_psbdmp_falls_back_to_gists_on_failure(make_context):
    ctx = make_context("alice", "username")
    respx.get(url__startswith="https://psbdmp.ws/").mock(return_value=httpx.Response(500))
    respx.get(url__startswith="https://gist.github.com/search").mock(
        return_value=httpx.Response(
            200,
            text='<a href="/owner/71c75995cf81fdc9e32fd17c1b5a43a0">x</a>',
            headers={"content-type": "text/html"},
        )
    )
    result = await pastes.psbdmp_search(ctx)
    assert result["source"] == "github-gists"
    assert result["pastes"][0]["url"].endswith("71c75995cf81fdc9e32fd17c1b5a43a0")
    assert "psbdmp HTTP 500" in result["note"]


@respx.mock
async def test_psbdmp_empty_result_also_falls_back(make_context):
    ctx = make_context("alice", "username")
    respx.get(url__startswith="https://psbdmp.ws/").mock(
        return_value=httpx.Response(200, json={"count": 0, "data": []})
    )
    respx.get(url__startswith="https://gist.github.com/search").mock(
        return_value=httpx.Response(200, text="<p>nothing</p>")
    )
    result = await pastes.psbdmp_search(ctx)
    assert result["pastes"] == []
    assert result["note"] == "psbdmp had no hits"


@respx.mock
async def test_psbdmp_fallback_failure_is_reported(make_context):
    ctx = make_context("alice", "username")
    respx.get(url__startswith="https://psbdmp.ws/").mock(return_value=httpx.Response(503))
    respx.get(url__startswith="https://gist.github.com/search").mock(
        return_value=httpx.Response(429)
    )
    result = await pastes.psbdmp_search(ctx)
    assert result["pastes"] == []
    assert "gist search HTTP 429" in result["note"]


async def test_run_collector_applies_collector_ttl(make_context):
    ctx = make_context()
    seen = {}

    async def record(inner_ctx):
        seen["ttl"] = inner_ctx.cache_ttl
        return {}

    spec = base.Collector(name="ttl", target_types=("domain",), func=record, ttl=42)
    await run_collector(spec, ctx)
    assert seen["ttl"] == 42


async def test_org_slug_variants_strip_legal_suffix():
    from osintkit.collectors.github import org_slugs

    assert org_slugs("Example Ltd.") == ["example-ltd", "example"]
    assert org_slugs("Deep Mind") == ["deep-mind"]


@respx.mock
async def test_github_org_repos_tries_suffix_variant(make_context):
    ctx = make_context("Example Ltd", "company")
    respx.get("https://api.github.com/orgs/example-ltd/repos").mock(
        return_value=httpx.Response(404)
    )
    respx.get("https://api.github.com/orgs/example/repos").mock(
        return_value=httpx.Response(200, json=[{"name": "repo"}])
    )
    result = await github.github_org_repos(ctx)
    assert result["org"] == "example"
    assert result["repositories"][0]["name"] == "repo"


async def test_collector_timeout_reaches_context(make_context):
    seen = {}

    async def record(ctx):
        seen["timeout"] = ctx.http_timeout
        return {}

    spec = base.Collector(name="t", target_types=("domain",), func=record, timeout=12.5)
    await base.run_collector(spec, make_context())
    assert seen["timeout"] == 12.5


@respx.mock
async def test_github_commit_search_empty_payload(make_context):
    ctx = make_context("alice@example.com", "email")
    respx.get(url__startswith="https://api.github.com/search/commits").mock(
        return_value=httpx.Response(200, json={"total_count": 0, "items": []})
    )
    assert await github.github_commit_search(ctx) == {"total": 0, "commits": []}


@respx.mock
async def test_github_user_search_company_query(make_context):
    ctx = make_context("Acme", "company")
    route = respx.get(url__startswith="https://api.github.com/search/users").mock(
        return_value=httpx.Response(200, json={"total_count": 1, "items": [{"login": "acme"}]})
    )
    result = await github.github_user_search(ctx)
    assert result["users"][0]["login"] == "acme"
    assert "company" in route.calls[0].request.url.params["q"]


@respx.mock
async def test_github_org_repos_not_found(make_context):
    ctx = make_context("Ghost Ltd", "company")
    respx.get(url__startswith="https://api.github.com/orgs/").mock(return_value=httpx.Response(404))
    result = await github.github_org_repos(ctx)
    assert result["found"] is False
    assert result["tried"] == ["ghost-ltd", "ghost"]


async def test_dns_wildcard_reports_answers(make_context, monkeypatch):
    ctx = make_context("example.com")

    async def fake_lookup(_ctx, host, rtype):
        return ["1.2.3.4"]

    monkeypatch.setattr(dns, "_lookup", fake_lookup)
    result = await dns.dns_wildcard(ctx)
    assert result["wildcard"] is True


def test_dns_formatting_handles_mx_and_txt():
    class Record:
        preference = 10
        exchange = "mail.example.com."
        strings = (b"v=spf1 ", b"-all")

    assert dns._format("MX", Record()) == "10 mail.example.com."
    assert dns._format("TXT", Record()) == "v=spf1 -all"


async def test_dns_lookup_returns_empty_on_nxdomain(make_context, monkeypatch):
    ctx = make_context("nope.example")

    async def raise_nxdomain(*args, **kwargs):
        raise dns.dns.resolver.NXDOMAIN

    monkeypatch.setattr(dns, "_resolver", lambda _ctx: type("R", (), {"resolve": raise_nxdomain})())
    assert await dns._lookup(ctx, "nope.example", "A") == []
