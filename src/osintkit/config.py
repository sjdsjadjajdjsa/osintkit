"""Runtime settings, on-disk paths, and the response cache."""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

APP_HOME_ENV = "OSINTKIT_HOME"
DEFAULT_BASE_URL = "https://api.venice.ai/api/v1"
DEFAULT_MODEL = "deepseek-v4-1-flash-1017-uncensored"
DEFAULT_TEMPERATURE = 0.3
DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_TIMEOUT = 30.0
DEFAULT_CACHE_TTL = 24 * 60 * 60
DEFAULT_RESOLVERS = ("1.1.1.1", "8.8.8.8", "9.9.9.9")


def app_home() -> Path:
    override = os.environ.get(APP_HOME_ENV)
    if override:
        return Path(override).expanduser()
    return Path.home() / ".osintkit"


def cache_dir() -> Path:
    return app_home() / "cache"


def log_dir() -> Path:
    return app_home() / "logs"


def reports_dir() -> Path:
    return app_home() / "reports"


def ensure_dirs() -> None:
    for path in (cache_dir(), log_dir()):
        path.mkdir(parents=True, exist_ok=True)


@dataclass(slots=True)
class Settings:
    """Everything the run needs, resolved once from flags and the environment."""

    target: str = ""
    target_type: str = ""
    base_url: str = DEFAULT_BASE_URL
    model: str = DEFAULT_MODEL
    api_key: str | None = None
    temperature: float = DEFAULT_TEMPERATURE
    timeout: float = DEFAULT_TIMEOUT
    max_attempts: int = DEFAULT_MAX_ATTEMPTS
    use_cache: bool = True
    cache_ttl: int = DEFAULT_CACHE_TTL
    resolvers: list[str] = field(default_factory=lambda: list(DEFAULT_RESOLVERS))
    dry_run: bool = False
    raw: bool = False
    output_json: bool = False
    output_markdown: bool = False
    verbose: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def hibp_api_key(self) -> str | None:
        return os.environ.get("HIBP_API_KEY") or None

    @property
    def github_token(self) -> str | None:
        return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or None

    def resolved_api_key(self) -> str | None:
        return self.api_key or os.environ.get("API_KEY") or os.environ.get("OPENAI_API_KEY")


def _cache_key(namespace: str, key: str) -> Path:
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]
    safe_ns = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in namespace)
    return cache_dir() / safe_ns / f"{digest}.json"


def cache_read(namespace: str, key: str, ttl: int = DEFAULT_CACHE_TTL) -> Any | None:
    path = _cache_key(namespace, key)
    try:
        stat = path.stat()
    except OSError:
        return None
    if ttl > 0 and time.time() - stat.st_mtime > ttl:
        return None
    try:
        return json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def cache_write(namespace: str, key: str, value: Any) -> None:
    path = _cache_key(namespace, key)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(value, ensure_ascii=False, default=str), "utf-8")
        tmp.replace(path)
    except OSError:
        return


def cache_clear() -> int:
    root = cache_dir()
    if not root.exists():
        return 0
    removed = 0
    for path in root.rglob("*.json"):
        try:
            path.unlink()
            removed += 1
        except OSError:
            continue
    return removed


def cache_stats() -> tuple[int, int]:
    root = cache_dir()
    if not root.exists():
        return (0, 0)
    files = list(root.rglob("*.json"))
    size = sum(p.stat().st_size for p in files if p.exists())
    return (len(files), size)
