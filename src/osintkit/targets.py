"""Target typing and normalisation."""

from __future__ import annotations

import re

from .errors import TargetParseError

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,38})$")
COMPANY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 .,&'()+-]*$")
PHONE_RE = re.compile(r"^\+[1-9]\d{7,14}$")
BTC_RE = re.compile(r"^(bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$")
COMPANY_HINTS = re.compile(r"\b(inc|llc|ltd|gmbh|corp|corporation|limited|plc|ag|sa|bv|oy|pty)\b", re.I)

VALID_TYPES = ("email", "username", "domain", "company", "phone", "crypto")


def normalise(target: str) -> str:
    target = target.strip()
    if target.lower().startswith("http://") or target.lower().startswith("https://"):
        target = target.split("://", 1)[1]
    target = target.strip().strip("<>\"'")
    if "@" not in target:
        target = target.split("/", 1)[0]
    if PHONE_RE.match(target):
        return target
    if target.lower().startswith("www."):
        target = target[4:]
    return target.rstrip("/")


def detect_type(target: str) -> str:
    if EMAIL_RE.match(target):
        return "email"
    if PHONE_RE.match(target):
        return "phone"
    if BTC_RE.match(target):
        return "crypto"
    if DOMAIN_RE.match(target):
        return "domain"
    if " " in target or COMPANY_HINTS.search(target):
        return "company"
    if USERNAME_RE.match(target):
        return "username"
    raise TargetParseError(f"could not tell what {target!r} is; pass --type explicitly")


def resolve(target: str, declared: str | None = None) -> tuple[str, str]:
    clean = normalise(target)
    if not clean:
        raise TargetParseError("empty target")
    kind = (declared or "").lower() or None
    if kind and kind not in VALID_TYPES:
        raise TargetParseError(f"unknown type {kind!r}; expected one of {', '.join(VALID_TYPES)}")
    if kind:
        _check_shape(clean, kind)
        return clean, kind
    kind = detect_type(clean)
    _check_shape(clean, kind)
    return clean, kind


def _check_shape(target: str, kind: str) -> None:
    if kind == "email" and not EMAIL_RE.match(target):
        raise TargetParseError(f"{target!r} is not a valid email")
    if kind == "domain" and not DOMAIN_RE.match(target):
        raise TargetParseError(f"{target!r} is not a valid domain")
    if kind == "username" and not USERNAME_RE.match(target):
        raise TargetParseError(f"{target!r} is not a valid username")
    if kind == "phone" and not PHONE_RE.match(target):
        raise TargetParseError(f"{target!r} is not an E.164 phone number (start with +country code)")
    if kind == "crypto" and not BTC_RE.match(target):
        raise TargetParseError(f"{target!r} is not a Bitcoin address")
    if kind == "company" and not COMPANY_RE.match(target):
        raise TargetParseError(f"{target!r} does not look like a company name")
