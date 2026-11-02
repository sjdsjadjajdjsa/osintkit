import os
import stat

import pytest

from osintkit import userconfig


@pytest.fixture(autouse=True)
def xdg(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))


def test_roundtrip_and_permissions():
    path = userconfig.save({"provider": "deepseek", "api_key": "sk-test-123456"})
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    loaded = userconfig.load()
    assert loaded["provider"] == "deepseek"
    assert loaded["api_key"] == "sk-test-123456"


def test_render_quotes_specials():
    text = userconfig.render({"api_key": 'we"ird\\key', "resolvers": ["1.1.1.1"]})
    assert 'api_key = "we\\"ird\\\\key"' in text
    assert 'resolvers = ["1.1.1.1"]' in text


def test_load_missing_is_empty():
    assert userconfig.load() == {}


def test_load_malformed_is_empty():
    path = userconfig.config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("not toml at all = [", "utf-8")
    assert userconfig.load() == {}


def test_unknown_keys_are_dropped():
    path = userconfig.config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('provider = "x"\nbogus = "y"\n', "utf-8")
    assert userconfig.load() == {"provider": "x"}


def test_mask_short_and_long():
    assert userconfig.mask("short") == "*****"
    assert userconfig.mask("sk-or-abcdef123456") == "sk-or-…3456"


def test_config_home_follows_xdg(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert str(tmp_path) in str(userconfig.config_path())


def test_save_creates_private_directory(tmp_path):
    path = userconfig.save({"provider": "venice"})
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert os.access(path, os.R_OK)
