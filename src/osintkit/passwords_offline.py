"""Offline check against the bundled most-common password list."""

from __future__ import annotations

from functools import cache
from importlib.resources import files

PACKAGE = "osintkit.data"
FILENAME = "common-passwords.txt"


@cache
def _ranks() -> dict[str, int]:
    text = files(PACKAGE).joinpath(FILENAME).read_text("utf-8")
    ranks: dict[str, int] = {}
    for index, line in enumerate(text.splitlines(), start=1):
        value = line.strip()
        if value and value not in ranks:
            ranks[value] = index
    return ranks


def size() -> int:
    return len(_ranks())


def check(password: str) -> int | None:
    """Return the popularity rank if the password is in the list, else None."""
    return _ranks().get(password.lower())
