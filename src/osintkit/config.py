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
DEFAULT_MODEL = "deepseek-v4-1-flash"
DEFAULT_TEMPERATURE = 0.3
DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_TIMEOUT = 30.0
DEFAULT_CACHE_TTL = 24 * 60 * 60
DEFAULT_RESOLVERS = ("1.1.1.1", "8.8.8.8", "9.9.9.9")

PROVIDERS: dict[str, tuple[str, str]] = {
    "venice": (DEFAULT_BASE_URL, DEFAULT_MODEL),
    "openrouter": ("https://openrouter.ai/api/v1", "deepseek/deepseek-v4.1-flash-1017"),
    "openai": ("https://api.openai.com/v1", "gpt-4.1-mini"),
    "deepseek": ("https://api.deepseek.com/v1", "deepseek-chat"),
    "mistral": ("https://api.mistral.ai/v1", "mistral-small-latest"),
    "groq": ("https://api.groq.com/openai/v1", "llama-3.3-70b-versatile"),
    "together": ("https://api.together.xyz/v1", "meta-llama/Llama-3.3-70B-Instruct-Turbo"),
    "anthropic": ("https://api.anthropic.com/v1", "claude-sonnet-4-5"),
    "ollama": ("http://localhost:11434/v1", "llama3.2"),
}
KEYLESS_PROVIDERS = frozenset({"ollama"})
KEY_PREFIXES: dict[str, str] = {
    "sk-or-": "openrouter",
    "sk-proj-": "openai",
    "gsk_": "groq",
    "sk-ant-": "anthropic",
}
PROVIDER_ENV: dict[str, str] = {
    "VENICE_API_KEY": "venice",
    "OPENROUTER_API_KEY": "openrouter",
    "OPENAI_API_KEY": "openai",
    "DEEPSEEK_API_KEY": "deepseek",
    "MISTRAL_API_KEY": "mistral",
    "GROQ_API_KEY": "groq",
    "TOGETHER_API_KEY": "together",
    "ANTHROPIC_API_KEY": "anthropic",
}
GENERIC_KEY_ENVS = ("API_KEY",)


def provider_from_key(api_key: str | None) -> str | None:
    """Infer a provider name from a recognisable key prefix."""
    if not api_key:
        return None
    for prefix, provider in KEY_PREFIXES.items():
        if api_key.startswith(prefix):
            return provider
    return None


def env_key_for(provider: str) -> str | None:
    for variable, name in PROVIDER_ENV.items():
        if name == provider and os.environ.get(variable):
            return os.environ[variable]
    return None


def provider_from_env() -> str | None:
    """Infer a provider from whichever provider-specific variable is set."""
    for variable, provider in PROVIDER_ENV.items():
        if os.environ.get(variable):
            return provider
    return None


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
    provider: str = "venice"
    base_url: str = DEFAULT_BASE_URL
    model: str = DEFAULT_MODEL
    api_key: str | None = None
    temperature: float = DEFAULT_TEMPERATURE
    max_tokens: int = 4000
    timeout: float = DEFAULT_TIMEOUT
    max_connections: int = 16
    max_attempts: int = DEFAULT_MAX_ATTEMPTS
    use_cache: bool = True
    cache_ttl: int = DEFAULT_CACHE_TTL
    resolvers: list[str] = field(default_factory=lambda: list(DEFAULT_RESOLVERS))
    dry_run: bool = False
    offline: bool = False
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
        if self.api_key:
            return self.api_key
        for variable, provider in PROVIDER_ENV.items():
            if provider == self.provider and os.environ.get(variable):
                return os.environ[variable]
        for variable in GENERIC_KEY_ENVS:
            if os.environ.get(variable):
                return os.environ[variable]
        return None

    @property
    def needs_key(self) -> bool:
        return self.provider not in KEYLESS_PROVIDERS


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
