import httpx
import respx

from osintkit.collectors import identifiers
from osintkit.targets import detect_type, resolve


def test_detects_phone_and_btc():
    assert detect_type("+15551234567") == "phone"
    assert detect_type("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq") == "crypto"
    assert detect_type("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2") == "crypto"


def test_normalising_keeps_phone_together():
    assert resolve("+15551234567") == ("+15551234567", "phone")
    assert resolve("+15551234567", "phone")[1] == "phone"


def test_bad_phone_and_btc_rejected():
    import pytest

    from osintkit.errors import TargetParseError

    with pytest.raises(TargetParseError):
        resolve("5551234567", "phone")
    with pytest.raises(TargetParseError):
        resolve("notanaddress", "crypto")


async def test_phone_metadata(make_context):
    ctx = make_context("+14155552671", "phone")
    result = await identifiers.phone_info(ctx)
    assert result["valid"] is True
    assert result["region"] == "US"
    assert result["timezones"]


async def test_invalid_phone_is_reported(make_context):
    ctx = make_context("+15005550006", "phone")
    result = await identifiers.phone_info(ctx)
    assert "valid" in result


@respx.mock
async def test_btc_balance_is_computed(make_context):
    ctx = make_context("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "crypto")
    respx.get(url__startswith="https://blockstream.info/api/address/").mock(
        return_value=httpx.Response(
            200,
            json={"chain_stats": {"funded_txo_sum": 200000000, "spent_txo_sum": 50000000, "tx_count": 3}},
        )
    )
    result = await identifiers.btc_address(ctx)
    assert result["balance_btc"] == 1.5
    assert result["tx_count"] == 3


@respx.mock
async def test_btc_unknown_address(make_context):
    ctx = make_context("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "crypto")
    respx.get(url__startswith="https://blockstream.info/api/address/").mock(return_value=httpx.Response(400))
    assert (await identifiers.btc_address(ctx))["found"] is False
