"""Collector package: importing it registers every collector."""

from __future__ import annotations

from .base import REGISTRY, Collector, Context, collectors_for, gather, run_collector

from . import (  # noqa: F401,E402  (import order matters: side-effect registration)
    accounts,
    breaches,
    ct,
    dns,
    github,
    pastes,
    ports,
    subdomains,
    whois_lookup,
)

__all__ = [
    "REGISTRY",
    "Collector",
    "Context",
    "collectors_for",
    "gather",
    "run_collector",
]
