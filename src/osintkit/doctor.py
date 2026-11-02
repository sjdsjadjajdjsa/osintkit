"""Environment checks behind `osintkit doctor`."""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path

from .config import Settings, cache_dir, ensure_dirs, log_dir
from .http import HttpClient


@dataclass(slots=True)
class Check:
    name: str
    status: str
    detail: str


def _writable(path: Path) -> bool:
    try:
        ensure_dirs()
        path.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=path, delete=True):
            return True
    except OSError:
        return False


async def _reach_endpoint(settings: Settings) -> Check:
    key = settings.resolved_api_key()
    if not key:
        return Check("model endpoint", "warn", "no API key; synthesis will fail, dry runs still work")
    url = f"{settings.base_url.rstrip('/')}/models"
    try:
        fresh = replace(settings, use_cache=False)
        async with HttpClient(fresh) as http:
            response = await http.get(
                url,
                namespace="doctor",
                headers={"Authorization": f"Bearer {key}"},
                empty_on=tuple(range(400, 500)),
                timeout=10.0,
            )
    except Exception as exc:
        return Check("model endpoint", "fail", f"{settings.base_url}: {type(exc).__name__}")
    if response.status_code == 401:
        return Check("model endpoint", "fail", "reachable, but the API key was rejected (401)")
    if response.status_code >= 400:
        # Not every compatible server implements /models; a 404 still means it answered.
        state = "warn" if response.status_code == 404 else "fail"
        return Check("model endpoint", state, f"HTTP {response.status_code} from {url}")
    return Check("model endpoint", "ok", f"{settings.base_url} answered")


def collect_checks(settings: Settings) -> list[Check]:
    key = settings.resolved_api_key()
    checks = [
        Check(
            "api key",
            "ok" if key else "warn",
            "set" if key else "API_KEY is not set",
        ),
        Check(
            "cache dir",
            "ok" if _writable(cache_dir()) else "fail",
            str(cache_dir()),
        ),
        Check(
            "log dir",
            "ok" if _writable(log_dir()) else "fail",
            str(log_dir()),
        ),
    ]
    for name, variable, why in (
        ("Have I Been Pwned", "HIBP_API_KEY", "breach collectors will be skipped"),
        ("GitHub", "GITHUB_TOKEN", "GitHub is limited to 60 requests/hour"),
    ):
        present = bool(os.environ.get(variable))
        checks.append(Check(name, "ok" if present else "warn", "set" if present else why))
    if key:
        checks.append(Check("api key shape", "ok" if len(key) >= 20 else "warn", f"{len(key)} chars"))
    return checks


async def diagnose(settings: Settings) -> list[Check]:
    return [*collect_checks(settings), await _reach_endpoint(settings)]


def failed(checks: list[Check]) -> bool:
    return any(check.status == "fail" for check in checks)
