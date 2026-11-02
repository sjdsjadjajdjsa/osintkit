import os
from pathlib import Path

import pytest
from rich.console import Console

from osintkit.config import Settings
from osintkit.http import HttpClient


@pytest.fixture(autouse=True)
def isolated_home(tmp_path: Path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("OSINTKIT_HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / "config"))
    monkeypatch.delenv("API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.chdir(tmp_path)
    home.mkdir(parents=True, exist_ok=True)
    return home


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    async def _instant(self, attempt, retry_after):
        return None

    monkeypatch.setattr(HttpClient, "_sleep", _instant)


@pytest.fixture
def settings():
    return Settings(use_cache=False, max_attempts=3, timeout=2.0, api_key="test-key")


@pytest.fixture
def console():
    return Console(width=100, force_terminal=False, highlight=False, record=True)


@pytest.fixture
def text_of(console):
    def _render():
        return console.export_text()

    return _render


@pytest.fixture
async def http(settings):
    async with HttpClient(settings) as client:
        yield client


@pytest.fixture
def make_context(settings, http):
    from osintkit.collectors.base import Context

    def _make(target="example.com", target_type="domain"):
        return Context(target=target, target_type=target_type, settings=settings, http=http)

    return _make


@pytest.fixture
def cache_off(settings):
    settings.use_cache = False
    return settings


def make_settings(**kwargs):
    base = {"use_cache": False, "max_attempts": 3, "timeout": 2.0, "api_key": "test-key"}
    base.update(kwargs)
    return Settings(**base)


os.environ.setdefault("OSINTKIT_HOME", "/tmp/osintkit-tests")
