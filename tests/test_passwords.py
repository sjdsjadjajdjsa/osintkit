import hashlib

import httpx
import respx

from osintkit import passwords

PASSWORD = "hunter2"
SHA = hashlib.sha1(PASSWORD.encode()).hexdigest().upper()


def test_digest_splits_the_hash():
    prefix, suffix = passwords.digest(PASSWORD)
    assert prefix == SHA[:5]
    assert suffix == SHA[5:]


def test_parse_range_matches_suffix_only():
    text = f"{'A' * 35}:5\r\n{SHA[5:]}:42\r\n"
    assert passwords.parse_range(text, SHA[5:]) == 42
    assert passwords.parse_range(text, "F" * 35) == 0


def test_rating_bands():
    assert passwords.rating(0) == "not seen"
    assert passwords.rating(10) == "rare"
    assert passwords.rating(500) == "common"
    assert passwords.rating(50_000) == "very common"
    assert passwords.rating(9_000_000) == "extremely common"


@respx.mock
async def test_check_reports_hits(http):
    respx.get(f"https://api.pwnedpasswords.com/range/{SHA[:5]}").mock(
        return_value=httpx.Response(200, text=f"{SHA[5:]}:42\r\n{'B' * 35}:1\r\n")
    )
    result = await passwords.check(http, PASSWORD)
    assert result["pwned"] is True
    assert result["count"] == 42


@respx.mock
async def test_check_reports_misses(http):
    respx.get(f"https://api.pwnedpasswords.com/range/{SHA[:5]}").mock(
        return_value=httpx.Response(200, text=f"{'B' * 35}:1\r\n")
    )
    result = await passwords.check(http, PASSWORD)
    assert result["pwned"] is False


@respx.mock
async def test_range_request_sends_only_the_prefix(http):
    route = respx.get(f"https://api.pwnedpasswords.com/range/{SHA[:5]}").mock(
        return_value=httpx.Response(200, text="")
    )
    await passwords.check(http, PASSWORD)
    assert route.calls[0].request.headers["add-padding"] == "true"
    assert PASSWORD not in str(route.calls[0].request.url)
