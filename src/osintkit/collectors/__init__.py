"""Collector package: importing it registers every collector."""

from __future__ import annotations

from . import (  # noqa: F401  (import order matters: side-effect registration)
    accounts,
    breaches,
    ct,
    dns,
    github,
    infostealer,
    pastes,
    ports,
    subdomains,
    whois_lookup,
)
from .base import REGISTRY, Collector, Context, collectors_for, run_collector

__all__ = [
    "REGISTRY",
    "Collector",
    "Context",
    "collectors_for",
    "run_collector",
]
