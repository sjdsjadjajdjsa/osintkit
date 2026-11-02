import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from osintkit import pipeline
from osintkit.cli import app
from osintkit.collectors import base

runner = CliRunner()


ANSI = re.compile(r"\x1b\[[0-9;]*m")


def plain(output):
    return ANSI.sub("", output).replace("│", " ")


def jsonish(output):
    starts = [i for i in (output.find("{"), output.find("[")) if i != -1]
    start = min(starts)
    end = max(output.rfind("}"), output.rfind("]"))
    return json.loads(output[start : end + 1])


VALID = {
    "summary": "ok",
    "breaches": [],
    "associated_accounts": [],
    "infrastructure_notes": [],
    "subdomains": [],
    "risk_level": "low",
    "recommendations": ["do a thing"],
}


@pytest.fixture(autouse=True)
def api_key(monkeypatch):
    monkeypatch.setenv("API_KEY", "test-key")


@pytest.fixture(autouse=True)
def fake_collector(monkeypatch):
    async def fake(ctx):
        return {"k": "v"}

    spec = base.Collector(
        name="fake_source", target_types=("domain", "email", "username", "company"), func=fake
    )
    monkeypatch.setattr(base, "REGISTRY", [spec])
    monkeypatch.setattr("osintkit.collectors.REGISTRY", base.REGISTRY)
    monkeypatch.setattr("osintkit.cli.REGISTRY", base.REGISTRY)


class FakeLLM:
    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None

    async def chat(self, messages, **kwargs):
        return json.dumps(VALID)


def test_help_lists_commands():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in ("lookup", "batch", "history", "collectors", "cache"):
        assert command in result.output


def test_version():
    from osintkit import __version__

    result = runner.invoke(app, ["--version"])
    assert __version__ in result.output


def test_dry_run_needs_no_key():
    result = runner.invoke(app, ["lookup", "--domain", "example.com", "--dry-run"])
    assert result.exit_code == 0
    assert "defensive OSINT analyst" in result.output


def test_json_output_is_structured(monkeypatch):
    monkeypatch.setattr(pipeline, "LLMClient", FakeLLM)
    result = runner.invoke(app, ["lookup", "--domain", "example.com", "--json"])
    assert result.exit_code == 0
    payload = jsonish(result.output)
    assert payload["target"] == "example.com"
    assert payload["analysis"]["risk_level"] == "low"


def test_markdown_export_writes_file(monkeypatch):
    monkeypatch.setattr(pipeline, "LLMClient", FakeLLM)
    result = runner.invoke(app, ["lookup", "--domain", "example.com", "--markdown"])
    assert result.exit_code == 0
    assert "markdown written" in result.output
    assert (Path.cwd() / "example.com-osint.md").exists()


def test_bad_target_exits_two():
    result = runner.invoke(app, ["lookup", "--email", "not-an-email"])
    assert result.exit_code == 2
    assert "not a valid email" in result.output


def test_missing_target_exits_two():
    result = runner.invoke(app, ["lookup"])
    assert result.exit_code == 2


def test_multiple_type_flags_rejected():
    result = runner.invoke(app, ["lookup", "--email", "a@b.co", "--username", "ab"])
    assert result.exit_code == 2


def test_missing_key_exits_one(monkeypatch):
    monkeypatch.delenv("API_KEY")
    result = runner.invoke(app, ["lookup", "--domain", "example.com"])
    assert result.exit_code == 1
    assert "API key" in result.output


def test_batch_runs_each_row(monkeypatch, tmp_path):
    monkeypatch.setattr(pipeline, "LLMClient", FakeLLM)
    csv_file = tmp_path / "targets.csv"
    csv_file.write_text("target,type\nexample.com,domain\nalice@example.com,email\n")
    result = runner.invoke(app, ["batch", "--file", str(csv_file)])
    assert result.exit_code == 0
    assert "batch summary" in result.output


def test_batch_json_array(monkeypatch, tmp_path):
    monkeypatch.setattr(pipeline, "LLMClient", FakeLLM)
    csv_file = tmp_path / "targets.csv"
    csv_file.write_text("example.com\n")
    result = runner.invoke(app, ["batch", "--file", str(csv_file), "--json"])
    payload = jsonish(result.output)
    assert payload[0]["target"] == "example.com"


def test_batch_empty_file_exits_two(tmp_path):
    empty = tmp_path / "empty.csv"
    empty.write_text("target\n")
    result = runner.invoke(app, ["batch", "--file", str(empty)])
    assert result.exit_code == 2


def test_history_empty():
    result = runner.invoke(app, ["history"])
    assert result.exit_code == 0
    assert "no runs" in result.output


def test_history_json_empty():
    result = runner.invoke(app, ["history", "--json"])
    assert result.exit_code == 0
    assert json.loads(result.output) == []


def test_collectors_lists_fake():
    result = runner.invoke(app, ["collectors"])
    assert result.exit_code == 0
    assert "fake_source" in result.output


def test_cache_clear_reports_count():
    result = runner.invoke(app, ["cache", "--clear"])
    assert result.exit_code == 0
    assert "cleared" in result.output


def test_raw_dumps_collected_data(monkeypatch):
    monkeypatch.setattr(pipeline, "LLMClient", None)
    result = runner.invoke(app, ["lookup", "--domain", "example.com", "--raw"])
    assert result.exit_code == 0
    payload = jsonish(result.output)
    assert payload["target"] == "example.com"
    assert payload["results"][0]["collector"] == "fake_source"
    assert payload["results"][0]["data"] == {"k": "v"}


def test_history_show_by_run_id(monkeypatch):
    monkeypatch.setattr(pipeline, "LLMClient", FakeLLM)
    runner.invoke(app, ["lookup", "--domain", "example.com"])
    run_id = jsonish(runner.invoke(app, ["history", "--json"]).output)[0]["run_id"]
    replay = runner.invoke(app, ["history", "--show", run_id, "--json"])
    assert replay.exit_code == 0
    assert jsonish(replay.output)["target"] == "example.com"


def test_history_show_unknown_run(monkeypatch):
    result = runner.invoke(app, ["history", "--show", "nope"])
    assert result.exit_code == 1
    assert "cannot read report" in result.output


def test_batch_preserves_order(monkeypatch, tmp_path):
    monkeypatch.setattr(pipeline, "LLMClient", FakeLLM)
    csv_file = tmp_path / "t.csv"
    csv_file.write_text("a.com\nb.com\nc.com\n")
    result = runner.invoke(app, ["batch", "--file", str(csv_file), "--concurrency", "2"])
    assert result.exit_code == 0
    positions = [
        result.output.index(f"{name}.com ", result.output.index("batch summary")) for name in ("a", "b", "c")
    ]
    assert positions == sorted(positions)


def test_batch_raw_returns_bundles(monkeypatch, tmp_path):
    monkeypatch.setattr(pipeline, "LLMClient", None)
    csv_file = tmp_path / "t.csv"
    csv_file.write_text("a.com\nb.com\n")
    result = runner.invoke(app, ["batch", "--file", str(csv_file), "--raw"])
    assert result.exit_code == 0
    payload = jsonish(result.output)
    assert [entry["target"] for entry in payload] == ["a.com", "b.com"]
    assert payload[0]["results"][0]["data"] == {"k": "v"}


def test_batch_honours_skip(monkeypatch, tmp_path):
    monkeypatch.setattr(pipeline, "LLMClient", None)
    csv_file = tmp_path / "t.csv"
    csv_file.write_text("a.com\n")
    result = runner.invoke(app, ["batch", "--file", str(csv_file), "--raw", "--skip", "fake_source"])
    assert result.exit_code == 0
    assert jsonish(result.output)[0]["results"] == []


def test_invalid_resolver_rejected():
    result = runner.invoke(app, ["--resolver", "dns.example", "lookup", "--domain", "a.com", "--raw"])
    assert result.exit_code == 2
    assert "not an IP address" in result.output


def test_resolver_flag_is_accepted(monkeypatch):
    monkeypatch.setattr(pipeline, "LLMClient", None)
    result = runner.invoke(app, ["--resolver", "1.1.1.1", "lookup", "--domain", "a.com", "--raw"])
    assert result.exit_code == 0


def test_doctor_reports_failure_on_bad_key(monkeypatch):
    import httpx
    import respx

    monkeypatch.setenv("API_KEY", "k" * 25)
    with respx.mock:
        respx.get("https://api.venice.ai/api/v1/models").mock(return_value=httpx.Response(401))
        result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 1
    assert "401" in result.output


def test_doctor_json_output(monkeypatch):
    import httpx
    import respx

    monkeypatch.setenv("API_KEY", "k" * 25)
    with respx.mock:
        respx.get("https://api.venice.ai/api/v1/models").mock(return_value=httpx.Response(200, json={}))
        result = runner.invoke(app, ["doctor", "--json"])
    assert result.exit_code == 0
    assert any(check["status"] == "ok" for check in jsonish(result.output))


def test_prune_dry_run():
    result = runner.invoke(app, ["prune", "--days", "7", "--dry-run"])
    assert result.exit_code == 0
    assert "would remove" in result.output


def test_cache_reports_disk_usage():
    result = runner.invoke(app, ["cache"])
    assert result.exit_code == 0
    assert "total on disk" in result.output


def test_schema_prints_json_schema():
    result = runner.invoke(app, ["schema"])
    assert result.exit_code == 0
    schema = jsonish(result.output)
    assert set(schema["properties"]) >= {"summary", "breaches", "risk_level"}


def test_schema_writes_file(tmp_path):
    destination = tmp_path / "schema.json"
    result = runner.invoke(app, ["schema", "--out", str(destination)])
    assert result.exit_code == 0
    assert "risk_level" in destination.read_text()


def test_openrouter_key_selects_preset_endpoint(monkeypatch):
    monkeypatch.setenv("API_KEY", "sk-or-v1-abc123")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(pipeline, "LLMClient", FakeLLM)
    result = runner.invoke(app, ["lookup", "--domain", "a.com", "--json"])
    payload = jsonish(result.output)
    assert payload["base_url"] == "https://openrouter.ai/api/v1"
    assert payload["model"] == "deepseek/deepseek-v4.1-flash-1017"


def test_explicit_endpoint_beats_preset(monkeypatch):
    monkeypatch.setenv("API_KEY", "sk-or-v1-abc123")
    monkeypatch.setattr(pipeline, "LLMClient", FakeLLM)
    result = runner.invoke(
        app,
        ["--base-url", "https://proxy.test/v1", "--model", "m", "lookup", "--domain", "a.com", "--json"],
    )
    payload = jsonish(result.output)
    assert payload["base_url"] == "https://proxy.test/v1"
    assert payload["model"] == "m"


def test_unknown_key_keeps_venice_default(monkeypatch):
    monkeypatch.setenv("API_KEY", "sk-venice-abc")
    monkeypatch.setattr(pipeline, "LLMClient", FakeLLM)
    result = runner.invoke(app, ["lookup", "--domain", "a.com", "--json"])
    payload = jsonish(result.output)
    assert payload["base_url"] == "https://api.venice.ai/api/v1"


def test_markdown_out_directory_gets_default_filename(monkeypatch, tmp_path):
    monkeypatch.setattr(pipeline, "LLMClient", FakeLLM)
    target_dir = tmp_path / "out"
    target_dir.mkdir()
    result = runner.invoke(app, ["lookup", "--domain", "example.com", "--markdown", "-o", str(target_dir)])
    assert result.exit_code == 0
    assert (target_dir / "example.com-osint.md").exists()


def test_unknown_only_collector_suggests_alternative():
    result = runner.invoke(app, ["lookup", "--domain", "a.com", "--dry-run", "--only", "fake_sourc"])
    assert result.exit_code == 2
    flat = " ".join(plain(result.output).split())
    assert "did you mean fake_source" in flat


def test_invalid_port_rejected():
    result = runner.invoke(app, ["lookup", "--domain", "a.com", "--dry-run", "--ports", "notaport"])
    assert result.exit_code == 2
    assert "not a port number" in result.output


def test_out_of_range_port_rejected():
    result = runner.invoke(app, ["lookup", "--domain", "a.com", "--dry-run", "--ports", "70000"])
    assert result.exit_code == 2
    assert "out of range" in result.output


def test_json_and_markdown_together(monkeypatch, tmp_path):
    monkeypatch.setattr(pipeline, "LLMClient", FakeLLM)
    destination = tmp_path / "r.md"
    result = runner.invoke(
        app, ["lookup", "--domain", "example.com", "--json", "--markdown", "-o", str(destination)]
    )
    assert result.exit_code == 0
    assert destination.exists()
    assert jsonish(result.output)["target"] == "example.com"


def _archived(tmp_path, name, risk, breaches=()):
    from osintkit.models import Analysis, Report

    report = Report(
        target="example.com",
        target_type="domain",
        analysis=Analysis(summary="s", risk_level=risk, breaches=[{"name": b} for b in breaches]),
    )
    path = tmp_path / name
    path.write_text(report.model_dump_json())
    return str(path)


def test_diff_reports_changes(tmp_path):
    old = _archived(tmp_path, "old.json", "low", ["Acme"])
    new = _archived(tmp_path, "new.json", "high", ["Acme", "Beta"])
    result = runner.invoke(app, ["diff", old, new])
    assert result.exit_code == 0
    assert "Beta" in result.output
    assert "low ->" in " ".join(result.output.split())


def test_diff_json(tmp_path):
    old = _archived(tmp_path, "old.json", "low")
    new = _archived(tmp_path, "new.json", "low", ["Beta"])
    result = runner.invoke(app, ["diff", old, new, "--json"])
    assert jsonish(result.output)["breaches"]["added"] == ["Beta"]


def test_diff_missing_report(tmp_path):
    result = runner.invoke(app, ["diff", "nope", str(tmp_path / "x.json")])
    assert result.exit_code == 1
    assert "cannot read report" in result.output


def test_diff_identical_says_so(tmp_path):
    path = _archived(tmp_path, "a.json", "low")
    result = runner.invoke(app, ["diff", path, path])
    assert "no material changes" in result.output


def test_provider_flag_selects_preset(monkeypatch):
    monkeypatch.setenv("API_KEY", "sk-anything")
    monkeypatch.setattr(pipeline, "LLMClient", FakeLLM)
    result = runner.invoke(app, ["--provider", "openrouter", "lookup", "--domain", "a.com", "--json"])
    payload = jsonish(result.output)
    assert payload["base_url"] == "https://openrouter.ai/api/v1"


def test_unknown_provider_rejected():
    result = runner.invoke(app, ["--provider", "nope", "lookup", "--domain", "a.com", "--dry-run"])
    assert result.exit_code == 2
    assert "unknown provider" in result.output


def test_explicit_base_url_beats_provider(monkeypatch):
    monkeypatch.setattr(pipeline, "LLMClient", FakeLLM)
    result = runner.invoke(
        app,
        [
            "--provider",
            "openrouter",
            "--base-url",
            "https://proxy.test/v1",
            "lookup",
            "--domain",
            "a.com",
            "--json",
        ],
    )
    assert jsonish(result.output)["base_url"] == "https://proxy.test/v1"


def test_collectors_json():
    result = runner.invoke(app, ["collectors", "--json"])
    payload = jsonish(result.output)
    assert payload[0]["name"] == fake_name()


def fake_name():
    return "fake_source"


def test_offline_mode_needs_no_key(monkeypatch):
    monkeypatch.delenv("API_KEY")
    monkeypatch.setattr(pipeline, "LLMClient", None)
    result = runner.invoke(app, ["lookup", "--domain", "example.com", "--offline"])
    assert result.exit_code == 0
    assert "no model call" in result.output


def test_offline_json_is_a_normal_report(monkeypatch):
    monkeypatch.delenv("API_KEY")
    result = runner.invoke(app, ["lookup", "--domain", "example.com", "--offline", "--json"])
    payload = jsonish(result.output)
    assert payload["analysis"]["risk_level"] == "low"
    assert payload["target"] == "example.com"


def test_offline_batch(monkeypatch, tmp_path):
    monkeypatch.delenv("API_KEY")
    csv_file = tmp_path / "t.csv"
    csv_file.write_text("a.com\n")
    result = runner.invoke(app, ["batch", "--file", str(csv_file), "--offline", "--json"])
    assert result.exit_code == 0
    assert jsonish(result.output)[0]["analysis"]["risk_level"] == "low"


def test_missing_key_mentions_offline(monkeypatch):
    monkeypatch.delenv("API_KEY")
    monkeypatch.setattr(pipeline, "LLMClient", None)
    result = runner.invoke(app, ["lookup", "--domain", "example.com"])
    assert "--offline" in " ".join(result.output.split())


def test_deepseek_env_selects_provider(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "d" * 30)
    monkeypatch.setattr(pipeline, "LLMClient", FakeLLM)
    result = runner.invoke(app, ["lookup", "--domain", "a.com", "--json"])
    assert jsonish(result.output)["base_url"] == "https://api.deepseek.com/v1"


def test_mistral_env_selects_provider(monkeypatch):
    monkeypatch.setenv("MISTRAL_API_KEY", "m" * 30)
    monkeypatch.setattr(pipeline, "LLMClient", FakeLLM)
    result = runner.invoke(app, ["lookup", "--domain", "a.com", "--json"])
    assert jsonish(result.output)["base_url"] == "https://api.mistral.ai/v1"


def test_explicit_provider_beats_env(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "d" * 30)
    monkeypatch.setattr(pipeline, "LLMClient", FakeLLM)
    result = runner.invoke(app, ["--provider", "mistral", "lookup", "--domain", "a.com", "--json"])
    assert jsonish(result.output)["base_url"] == "https://api.mistral.ai/v1"


def test_ollama_needs_no_key(monkeypatch):
    monkeypatch.delenv("API_KEY")
    monkeypatch.setattr(pipeline, "LLMClient", FakeLLM)
    result = runner.invoke(app, ["--provider", "ollama", "lookup", "--domain", "a.com", "--json"])
    assert result.exit_code == 0
    assert jsonish(result.output)["base_url"] == "http://localhost:11434/v1"


@pytest.fixture
def xdg(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))


def test_init_writes_config_and_verifies(monkeypatch, xdg):
    import httpx
    import respx

    from osintkit import userconfig

    with respx.mock:
        respx.get("https://api.deepseek.com/v1/models").mock(return_value=httpx.Response(200, json={}))
        respx.post("https://api.deepseek.com/v1/chat/completions").mock(
            return_value=httpx.Response(200, json={"choices": [{"message": {"content": "p"}}]})
        )
        result = runner.invoke(app, ["init", "--provider", "deepseek", "--api-key", "sk-" + "d" * 30])
    assert result.exit_code == 0
    stored = userconfig.load()
    assert stored["provider"] == "deepseek"
    assert "try: osintkit lookup" in result.output


def test_init_refuses_existing_without_force(xdg):
    from osintkit import userconfig

    userconfig.save({"provider": "venice"})
    result = runner.invoke(app, ["init", "--api-key", "k" * 30, "--no-verify"])
    assert result.exit_code == 1
    assert "already exists" in result.output


def test_init_force_replaces(xdg):
    from osintkit import userconfig

    userconfig.save({"provider": "venice", "api_key": "old"})
    result = runner.invoke(
        app, ["init", "--provider", "mistral", "--api-key", "m" * 30, "--force", "--no-verify"]
    )
    assert result.exit_code == 0
    assert userconfig.load()["provider"] == "mistral"


def test_init_unknown_provider(xdg):
    result = runner.invoke(app, ["init", "--provider", "nope", "--api-key", "k", "--no-verify"])
    assert result.exit_code == 2
    assert "unknown provider" in result.output


def test_init_ollama_needs_no_key(xdg, monkeypatch):
    from osintkit import userconfig

    monkeypatch.delenv("API_KEY", raising=False)
    result = runner.invoke(app, ["init", "--provider", "ollama", "--no-verify"])
    assert result.exit_code == 0
    assert "api_key" not in userconfig.load()


def test_config_masks_and_reveals(xdg):
    from osintkit import userconfig

    userconfig.save({"provider": "venice", "api_key": "sk-venice-abcdef123456"})
    masked = runner.invoke(app, ["config"])
    assert "sk-ven…3456" in masked.output
    assert "abcdef123456" not in masked.output
    revealed = runner.invoke(app, ["config", "--reveal"])
    assert "sk-venice-abcdef123456" in revealed.output


def test_config_unset_and_path(xdg):
    from osintkit import userconfig

    userconfig.save({"provider": "venice", "model": "m"})
    removed = runner.invoke(app, ["config", "--unset", "model"])
    assert removed.exit_code == 0
    assert "model" not in userconfig.load()
    path = runner.invoke(app, ["config", "--path"])
    assert str(userconfig.config_path()) in path.output


def test_stored_key_is_used(monkeypatch, xdg):
    from osintkit import userconfig

    userconfig.save({"provider": "venice", "api_key": "stored-key-123"})
    monkeypatch.delenv("API_KEY")
    monkeypatch.setattr(pipeline, "LLMClient", FakeLLM)
    result = runner.invoke(app, ["lookup", "--domain", "a.com", "--json"])
    assert result.exit_code == 0
    assert jsonish(result.output)["base_url"] == "https://api.venice.ai/api/v1"


def test_env_beats_stored_provider(monkeypatch, xdg):
    from osintkit import userconfig

    userconfig.save({"provider": "venice", "api_key": "stored"})
    monkeypatch.setenv("MISTRAL_API_KEY", "m" * 30)
    monkeypatch.setattr(pipeline, "LLMClient", FakeLLM)
    result = runner.invoke(app, ["lookup", "--domain", "a.com", "--json"])
    assert jsonish(result.output)["base_url"] == "https://api.mistral.ai/v1"


def test_flag_beats_stored_config(monkeypatch, xdg):
    from osintkit import userconfig

    userconfig.save({"provider": "venice", "api_key": "stored", "model": "stored-model"})
    monkeypatch.setattr(pipeline, "LLMClient", FakeLLM)
    result = runner.invoke(app, ["--model", "flag-model", "lookup", "--domain", "a.com", "--json"])
    assert jsonish(result.output)["model"] == "flag-model"


def test_password_command_hit_and_miss(monkeypatch):
    import httpx
    import respx

    from osintkit import passwords

    prefix, suffix = passwords.digest("hunter2")
    miss_prefix = passwords.digest("hunter3")[0]
    with respx.mock:
        respx.get(f"https://api.pwnedpasswords.com/range/{prefix}").mock(
            return_value=httpx.Response(200, text=f"{suffix}:5")
        )
        hit = runner.invoke(app, ["password", "hunter2"])
    assert hit.exit_code == 1
    assert "pwned" in hit.output

    with respx.mock:
        respx.get(f"https://api.pwnedpasswords.com/range/{miss_prefix}").mock(
            return_value=httpx.Response(200, text="")
        )
        miss = runner.invoke(app, ["password", "hunter3", "--json"])
    assert miss.exit_code == 0
    assert jsonish(miss.output)["pwned"] is False


def test_init_stores_optional_hibp_key(xdg):
    from osintkit import userconfig

    result = runner.invoke(
        app,
        ["init", "--provider", "venice", "--api-key", "k" * 30, "--hibp-key", "h" * 32, "--no-verify"],
    )
    assert result.exit_code == 0
    assert userconfig.load()["hibp_api_key"] == "h" * 32
    shown = runner.invoke(app, ["config"])
    assert "hhhhhh…" in shown.output
    assert "h" * 32 not in shown.output


def test_stored_hibp_key_reaches_settings(xdg, monkeypatch):
    from osintkit import userconfig

    userconfig.save({"provider": "venice", "api_key": "k" * 30, "hibp_api_key": "stored-hibp"})
    captured = {}

    async def spy(target, settings, *args, **kwargs):
        captured["hibp"] = settings.hibp_api_key
        raise RuntimeError("stop")

    monkeypatch.setattr(pipeline, "execute", spy)
    runner.invoke(app, ["lookup", "--domain", "a.com"])
    assert captured["hibp"] == "stored-hibp"


def test_env_hibp_key_beats_stored(xdg, monkeypatch):
    from osintkit import userconfig

    userconfig.save({"provider": "venice", "api_key": "k" * 30, "hibp_api_key": "stored-hibp"})
    monkeypatch.setenv("HIBP_API_KEY", "env-hibp")
    captured = {}

    async def spy(target, settings, *args, **kwargs):
        captured["hibp"] = settings.hibp_api_key
        raise RuntimeError("stop")

    monkeypatch.setattr(pipeline, "execute", spy)
    runner.invoke(app, ["lookup", "--domain", "a.com"])
    assert captured["hibp"] == "env-hibp"
