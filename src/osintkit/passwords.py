"""Pwned Passwords range check (k-anonymity, no key, no plaintext sent)."""

from __future__ import annotations

import hashlib

from .errors import OsintKitError
from .http import HttpClient, cache_hit, cache_put

NAMESPACE = "pwnedpasswords"
TTL = 24 * 3600
RANGE = "https://api.pwnedpasswords.com/range/"


def digest(password: str) -> tuple[str, str]:
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return sha1[:5], sha1[5:]


def parse_range(text: str, suffix: str) -> int:
    for line in text.splitlines():
        hash_part, _, count = line.partition(":")
        if hash_part.strip().upper() == suffix:
            try:
                return int(count.strip())
            except ValueError:
                return 0
    return 0


def rating(count: int) -> str:
    if count == 0:
        return "not seen"
    if count < 100:
        return "rare"
    if count < 10_000:
        return "common"
    if count < 1_000_000:
        return "very common"
    return "extremely common"


async def check(http: HttpClient, password: str) -> dict[str, object]:
    prefix, suffix = digest(password)
    key = f"{prefix}:{suffix}"
    cached = cache_hit(http.settings, NAMESPACE, key, TTL)
    if cached is not None:
        count = int(cached)
    else:
        response = await http.get(
            f"{RANGE}{prefix}",
            namespace=NAMESPACE,
            accept="text/plain",
            headers={"Add-Padding": "true"},
        )
        if response.status_code != 200:
            raise OsintKitError(f"pwned passwords returned HTTP {response.status_code}")
        count = parse_range(response.text, suffix)
        cache_put(http.settings, NAMESPACE, key, count)
    return {
        "pwned": count > 0,
        "count": count,
        "rating": rating(count),
        "prefix": prefix,
        "checked_by": "api.pwnedpasswords.com",
    }
