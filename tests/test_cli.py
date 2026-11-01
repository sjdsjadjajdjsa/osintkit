import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from osintkit import pipeline
from osintkit.cli import app
from osintkit.collectors import base

runner = CliRunner()

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

    spec = base.Collector(name="fake_source", target_types=("domain", "email", "username", "company"),
                          func=fake)
    monkeypatch.setattr(base, "REGISTRY", [spec])
    monkeypatch.setattr("osintkit.collectors.REGISTRY", base.REGISTRY)


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
    result = runner.invoke(app, ["--version"])
    assert "0.1.0" in result.output


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
    positions = [result.output.index(f"{name}.com ", result.output.index("batch summary"))
                 for name in ("a", "b", "c")]
    assert positions == sorted(positions)
