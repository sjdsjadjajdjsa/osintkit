import time

from osintkit import config


def test_cache_roundtrip():
    config.cache_write("ns", "key", {"a": 1})
    assert config.cache_read("ns", "key") == {"a": 1}


def test_cache_respects_ttl():
    config.cache_write("ns", "key", {"a": 1})
    time.sleep(0.01)
    assert config.cache_read("ns", "key", ttl=3600) == {"a": 1}


def test_cache_miss_returns_none():
    assert config.cache_read("ns", "absent") is None


def test_cache_clear_removes_files():
    config.cache_write("ns", "one", 1)
    config.cache_write("ns", "two", 2)
    assert config.cache_clear() == 2
    assert config.cache_stats() == (0, 0)


def test_cache_survives_unwritable_home(tmp_path, monkeypatch):
    monkeypatch.setenv("OSINTKIT_HOME", str(tmp_path / "deep" / "home"))
    config.cache_write("ns", "key", 1)
    assert config.cache_read("ns", "key") == 1


def test_settings_resolves_key_precedence(monkeypatch):
    from osintkit.config import Settings

    monkeypatch.setenv("API_KEY", "from-env")
    assert Settings(api_key="explicit").resolved_api_key() == "explicit"
    assert Settings().resolved_api_key() == "from-env"


def test_settings_without_key(monkeypatch):
    from osintkit.config import Settings

    monkeypatch.delenv("API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert Settings().resolved_api_key() is None
