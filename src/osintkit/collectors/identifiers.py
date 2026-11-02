"""Phone metadata (offline) and Bitcoin address history."""

from __future__ import annotations

import phonenumbers
from phonenumbers import PhoneNumberType, carrier, geocoder, timezone

from .base import Context, collector

BTC = "https://blockstream.info/api/address"
LINE_TYPES = {
    value: name
    for name, value in vars(PhoneNumberType).items()
    if isinstance(value, int) and not name.startswith("_")
}


@collector("phone_info", ("phone",), "Phone region, carrier, and line type", order=15, ttl=2592000)
async def phone_info(ctx: Context) -> dict:
    try:
        parsed = phonenumbers.parse(ctx.target, None)
    except phonenumbers.NumberParseException as exc:
        return {"valid": False, "note": str(exc)}
    return {
        "valid": phonenumbers.is_valid_number(parsed),
        "possible": phonenumbers.is_possible_number(parsed),
        "region": phonenumbers.region_code_for_number(parsed),
        "country": geocoder.description_for_number(parsed, "en") or None,
        "carrier": carrier.name_for_number(parsed, "en") or None,
        "line_type": LINE_TYPES.get(phonenumbers.number_type(parsed), "UNKNOWN"),
        "timezones": list(timezone.time_zones_for_number(parsed)),
        "e164": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
        "international": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        "source": "libphonenumber",
    }


@collector("btc_address", ("crypto",), "Bitcoin address balances and transaction history", order=16, ttl=3600)
async def btc_address(ctx: Context) -> dict:
    response = await ctx.http.get(
        f"{BTC}/{ctx.target}",
        namespace="blockstream",
        empty_on=(400, 404),
        timeout=ctx.http_timeout or 30,
    )
    if response.status_code != 200:
        return {"found": False, "note": f"HTTP {response.status_code}"}
    try:
        body = response.json()
    except ValueError:
        return {"found": False, "note": "non-JSON"}

    chain = body.get("chain_stats") or {}
    mempool = body.get("mempool_stats") or {}
    funded = int(chain.get("funded_txo_sum") or 0)
    spent = int(chain.get("spent_txo_sum") or 0)
    return {
        "found": True,
        "balance_sats": funded - spent,
        "balance_btc": round((funded - spent) / 100_000_000, 8),
        "tx_count": int(chain.get("tx_count") or 0),
        "received_sats": funded,
        "mempool_tx_count": int(mempool.get("tx_count") or 0),
        "source": "blockstream.info",
    }
