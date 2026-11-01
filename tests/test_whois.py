import asyncio

from osintkit.collectors import whois_lookup


async def test_whois_cleans_and_truncates(make_context, monkeypatch):
    ctx = make_context("example.com")
    long_text = "x" * 2000
    monkeypatch.setattr(
        whois_lookup.whois,
        "whois",
        lambda domain: {"registrar": long_text, "name_servers": ["a", "b"], "creation_date": None},
    )
    result = await whois_lookup.whois_registration(ctx)
    assert len(result["registrar"]) == whois_lookup.FIELD_LIMIT
    assert result["name_servers"] == ["a", "b"]
    assert "creation_date" not in result


async def test_whois_failure_is_noted(make_context, monkeypatch):
    ctx = make_context("example.com")

    def boom(domain):
        raise RuntimeError("whois exploded")

    monkeypatch.setattr(whois_lookup.whois, "whois", boom)
    result = await whois_lookup.whois_registration(ctx)
    assert result["note"].startswith("whois unavailable: RuntimeError")


async def test_whois_timeout_is_noted(make_context, monkeypatch):
    ctx = make_context("example.com")
    ctx.http_timeout = 0.01

    def slow(domain):
        import time as _time

        _time.sleep(0.2)
        return {"registrar": "late"}

    monkeypatch.setattr(whois_lookup.whois, "whois", slow)
    result = await whois_lookup.whois_registration(ctx)
    assert result == {"note": "whois lookup timed out"}


async def test_whois_empty_record(make_context, monkeypatch):
    monkeypatch.setattr(whois_lookup.whois, "whois", lambda domain: None)
    assert await whois_lookup.whois_registration(make_context("example.com")) == {}


def test_clean_handles_dates_and_lists():
    import datetime

    assert whois_lookup._clean(datetime.date(2020, 1, 2)) == "2020-01-02"
    assert whois_lookup._clean(["a"] * 30) == ["a"] * 20
    assert whois_lookup._clean(None) is None
    assert whois_lookup._clean(7) == "7"
    assert asyncio.iscoroutinefunction(whois_lookup.whois_registration)
