"""Errors and shared type aliases."""

from __future__ import annotations

from typing import Literal

TargetType = Literal["email", "username", "domain", "company"]


class OsintKitError(Exception):
    """Base error for osintkit."""


class CollectorError(OsintKitError):
    """A collector could not complete its work."""


class RateLimited(OsintKitError):
    """An upstream source asked us to slow down."""

    def __init__(self, message: str, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class SourceUnavailable(OsintKitError):
    """An upstream source is down or blocked."""


class SynthesisError(OsintKitError):
    """The model returned something we could not validate."""


class MissingAPIKey(OsintKitError):
    """No API key was supplied and none was found in the environment."""


class TargetParseError(OsintKitError):
    """A target string could not be typed."""


__all__ = [
    "CollectorError",
    "MissingAPIKey",
    "OsintKitError",
    "RateLimited",
    "SourceUnavailable",
    "SynthesisError",
    "TargetParseError",
    "TargetType",
]
