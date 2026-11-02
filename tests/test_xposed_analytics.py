import httpx
import respx

from osintkit.collectors import xposed_analytics as xa

URL = "https://api.xposedornot.com/v1/breach-analytics"


@respx.mock
async def test_breaches_are_normalised_and_sorted(make_context):
    ctx = make_context("a@b.co", "email")
    respx.get(URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "ExposedBreaches": {
                    "breaches_details": [
                        {"breach": "Old", "xposed_date": "2019", "xposed_data": "Emails;Passwords"},
                        {"breach": "New", "xposed_date": "2026", "xposed_records": 10, "verified": "Yes"},
                    ]
                }
            },
        )
    )
    result = await xa.xposed_analytics(ctx)
    assert [row["name"] for row in result["breaches"]] == ["New", "Old"]
    assert result["breaches"][1]["data_types"] == ["Emails", "Passwords"]
    assert result["breaches"][0]["verified"] is True


@respx.mock
async def test_pastes_are_normalised(make_context):
    ctx = make_context("a@b.co", "email")
    respx.get(URL).mock(
        return_value=httpx.Response(
            200,
            json={"ExposedPastes": {"pastes_details": [{"paste_id": "abc", "title": "t"}]}},
        )
    )
    result = await xa.xposed_analytics(ctx)
    assert result["pastes"][0]["id"] == "abc"


@respx.mock
async def test_error_status_is_a_note_not_a_crash(make_context):
    ctx = make_context("a@b.co", "email")
    respx.get(URL).mock(return_value=httpx.Response(429))
    result = await xa.xposed_analytics(ctx)
    assert result["breaches"] == []
    assert "429" in result["note"]


@respx.mock
async def test_junk_rows_are_dropped(make_context):
    ctx = make_context("a@b.co", "email")
    respx.get(URL).mock(
        return_value=httpx.Response(
            200, json={"ExposedBreaches": {"breaches_details": [None, {}, {"breach": ""}]}}
        )
    )
    assert (await xa.xposed_analytics(ctx))["breaches"] == []
