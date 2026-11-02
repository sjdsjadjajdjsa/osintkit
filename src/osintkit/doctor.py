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


async def _reach_endpoint(settings: Settings, deep: bool = False) -> Check:
    key = settings.resolved_api_key()
    if not key:
        return Check("model endpoint", "warn", "no API key; synthesis will fail, dry runs still work")
    base = settings.base_url.rstrip("/")
    headers = {"Authorization": f"Bearer {key}"}
    fresh = replace(settings, use_cache=False)

    try:
        async with HttpClient(fresh) as http:
            response = await http.get(
                f"{base}/models",
                namespace="doctor",
                headers=headers,
                empty_on=tuple(range(400, 500)),
                timeout=10.0,
            )
            if response.status_code >= 400 and response.status_code != 404:
                return Check("model endpoint", "fail", f"HTTP {response.status_code} from {base}/models")

            if not deep:
                detail = (
                    f"{base} answered; key not exercised, use --deep"
                    if response.status_code < 400
                    else f"HTTP {response.status_code} from {base}/models; use --deep"
                )
                return Check("model endpoint", "ok" if response.status_code < 400 else "warn", detail)

            probe = await http.post_json(
                f"{base}/chat/completions",
                namespace="doctor",
                headers=headers,
                payload={
                    "model": settings.model,
                    "messages": [{"role": "user", "content": "ping"}],
                    "max_tokens": 1,
                    "temperature": 0,
                },
                timeout=20.0,
                empty_on=tuple(range(400, 500)),
            )
    except Exception as exc:
        return Check("model endpoint", "fail", f"{base}: {type(exc).__name__}")

    if probe.status_code in (401, 403):
        return Check("model endpoint", "fail", f"key rejected (HTTP {probe.status_code})")
    if probe.status_code == 404:
        return Check("model endpoint", "fail", f"model {settings.model!r} or route not found (404)")
    if probe.status_code >= 400:
        return Check("model endpoint", "fail", f"completion probe failed (HTTP {probe.status_code})")
    return Check("model endpoint", "ok", f"{base} accepted a completion for {settings.model}")


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


async def diagnose(settings: Settings, *, deep: bool = False) -> list[Check]:
    return [*collect_checks(settings), await _reach_endpoint(settings, deep)]


def failed(checks: list[Check]) -> bool:
    return any(check.status == "fail" for check in checks)
