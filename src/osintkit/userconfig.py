"""Persistent user configuration at ~/.config/osintkit/config.toml."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

FILENAME = "config.toml"
KEYS = ("provider", "model", "base_url", "api_key", "hibp_api_key", "resolvers")
SECRET_KEYS = frozenset({"api_key", "hibp_api_key"})


def config_home() -> Path:
    override = os.environ.get("XDG_CONFIG_HOME")
    if override:
        return Path(override).expanduser() / "osintkit"
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(base) / "osintkit"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "osintkit"
    return Path.home() / ".config" / "osintkit"


def config_path() -> Path:
    return config_home() / FILENAME


def _parse(text: str) -> dict[str, Any]:
    import tomllib

    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return data


def load() -> dict[str, Any]:
    try:
        raw = config_path().read_text("utf-8")
    except OSError:
        return {}
    data = _parse(raw)
    out: dict[str, Any] = {}
    for key in KEYS:
        value = data.get(key)
        if isinstance(value, str) and value:
            out[key] = value
        elif key == "resolvers" and isinstance(value, list):
            out[key] = [str(item) for item in value if item]
    return out


def _quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render(data: dict[str, Any]) -> str:
    lines = ["# osintkit configuration", ""]
    for key in KEYS:
        value = data.get(key)
        if not value:
            continue
        if isinstance(value, list):
            rendered = ", ".join(_quote(item) for item in value)
            lines.append(f"{key} = [{rendered}]")
        else:
            lines.append(f"{key} = {_quote(str(value))}")
    return "\n".join(lines) + "\n"


def save(data: dict[str, Any]) -> Path:
    home = config_home()
    home.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(home, 0o700)
    except OSError:
        pass
    path = config_path()
    tmp = path.with_suffix(".tmp")
    tmp.write_text(render(data), "utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(path)
    return path


def mask(secret: str) -> str:
    if len(secret) <= 8:
        return "*" * len(secret)
    return f"{secret[:6]}…{secret[-4:]}"


def as_settings(data: dict[str, Any]) -> dict[str, Any]:
    """Map config keys onto Settings field names."""
    mapping = {"base_url": "base_url", "model": "model", "resolvers": "resolvers"}
    return {target: data[source] for source, target in mapping.items() if data.get(source)}
