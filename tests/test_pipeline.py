import json

import pytest

from osintkit import pipeline
from osintkit.collectors import base
from osintkit.errors import SynthesisError
from osintkit.logging_store import RunLogger, read_runs

VALID = {
    "summary": "ok",
    "breaches": [],
    "associated_accounts": [],
    "infrastructure_notes": [],
    "subdomains": [],
    "risk_level": "low",
    "recommendations": [],
}


@pytest.fixture
def fake_collector(monkeypatch):
    async def fake(ctx):
        return {"k": "v"}

    spec = base.Collector(name="fake_source", target_types=("domain",), func=fake)
    monkeypatch.setattr(base, "REGISTRY", [spec])
    monkeypatch.setattr("osintkit.collectors.REGISTRY", base.REGISTRY)
    return spec


class FakeLLM:
    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None

    async def chat(self, messages, **kwargs):
        return json.dumps(VALID)


async def test_execute_collects_synthesises_and_archives(settings, fake_collector, monkeypatch, console):
    monkeypatch.setattr(pipeline, "LLMClient", FakeLLM)
    logger = RunLogger("run1")
    outcome = await pipeline.execute("example.com", settings, logger, console)
    assert outcome.error is None
    assert outcome.archived and outcome.archived.exists()
    assert outcome.report.analysis.risk_level == "low"
    assert [c.collector for c in outcome.report.collectors] == ["fake_source"]
    logged = (logger.path).read_text().splitlines()
    kinds = [json.loads(line)["kind"] for line in logged]
    assert "collector" in kinds and "run_end" in kinds


async def test_execute_dry_run_skips_model(settings, fake_collector, monkeypatch, console):
    monkeypatch.setattr(pipeline, "LLMClient", None)
    settings.dry_run = True
    logger = RunLogger("run2")
    outcome = await pipeline.execute("example.com", settings, logger, console)
    assert outcome.report.analysis is None
    assert "prompt" in outcome.extra
    assert "defensive OSINT analyst" in outcome.extra["prompt"]
    assert outcome.archived and outcome.archived.exists()


async def test_execute_without_key_reports_cleanly(settings, fake_collector, console):
    settings.api_key = None
    logger = RunLogger("run3")
    outcome = await pipeline.execute("example.com", settings, logger, console)
    assert outcome.error and "API key" in outcome.error
    assert outcome.archived is not None


async def test_execute_archives_even_when_synthesis_fails(settings, fake_collector, monkeypatch, console):
    class Broken(FakeLLM):
        async def chat(self, messages, **kwargs):
            raise SynthesisError("model down")

    monkeypatch.setattr(pipeline, "LLMClient", Broken)
    logger = RunLogger("run4")
    outcome = await pipeline.execute("example.com", settings, logger, console)
    assert outcome.error == "model down"
    assert outcome.archived and outcome.archived.exists()


async def test_only_and_skip_filter_collectors(settings, fake_collector, monkeypatch, console):
    monkeypatch.setattr(pipeline, "LLMClient", FakeLLM)
    logger = RunLogger("run5")
    outcome = await pipeline.execute("example.com", settings, logger, console, skip={"fake_source"})
    assert outcome.report.collectors == []


async def test_bad_target_raises(settings, console):
    logger = RunLogger("run6")
    from osintkit.errors import TargetParseError

    with pytest.raises(TargetParseError):
        await pipeline.execute("!!!", settings, logger, console)


def test_history_reads_runs(tmp_path):
    logger = RunLogger("abc", "example.com", "domain")
    logger.event("run_start")
    logger.collector(collector="x", ok=True, skipped=False, note=None, error=None, elapsed_ms=1, size=3)
    logger.event("run_end", risk_level="low", report_path=None)
    runs = read_runs()
    assert runs[0]["run_id"] == "abc"
    assert runs[0]["collectors_ok"] == 1
    assert runs[0]["risk"] == "low"


async def test_max_tokens_reaches_synthesis(settings, fake_collector, monkeypatch, console):
    seen = {}

    async def fake_synth(client, bundle, *, logger=None, max_tokens=2400):
        seen["max_tokens"] = max_tokens
        from osintkit.models import Analysis

        return Analysis(summary="s", risk_level="low")

    monkeypatch.setattr(pipeline.synthesis, "synthesize", fake_synth)
    monkeypatch.setattr(pipeline, "LLMClient", FakeLLM)
    settings.max_tokens = 999
    await pipeline.execute("example.com", settings, RunLogger("run7"), console)
    assert seen["max_tokens"] == 999


async def test_duplicate_breaches_are_merged_before_prompting(settings, monkeypatch, console):
    async def one(ctx):
        return [{"name": "Acme", "date": "2019-01-01", "data_types": ["Emails"], "source": "a"}]

    async def two(ctx):
        return [{"name": "ACME", "data_types": ["Passwords"], "source": "b"}]

    monkeypatch.setattr(
        base,
        "REGISTRY",
        [
            base.Collector(name="hibp_breaches", target_types=("email",), func=one),
            base.Collector(name="xposed_or_not", target_types=("email",), func=two),
        ],
    )
    prompt = {}

    class Capture(FakeLLM):
        async def chat(self, messages, **kwargs):
            prompt["user"] = messages[1]["content"]
            return json.dumps(VALID)

    monkeypatch.setattr(pipeline, "LLMClient", Capture)
    outcome = await pipeline.execute("a@b.co", settings, RunLogger("merge"), console)

    assert any("merged" in note for note in outcome.report.notes)
    assert "breach_index" in prompt["user"]
    assert prompt["user"].count('"name": "Acme"') == 1
    assert '"sources": [' in prompt["user"]
    assert [r.collector for r in outcome.report.collectors] == ["hibp_breaches", "xposed_or_not"]


async def test_risk_floor_overrides_a_timid_model(settings, monkeypatch, console):
    async def breachy(ctx):
        return [{"name": f"B{index}", "data_types": ["Passwords"], "source": "s"} for index in range(4)]

    monkeypatch.setattr(
        base, "REGISTRY", [base.Collector(name="xposed_or_not", target_types=("email",), func=breachy)]
    )
    monkeypatch.setattr("osintkit.collectors.REGISTRY", base.REGISTRY)
    monkeypatch.setattr(pipeline, "LLMClient", FakeLLM)
    outcome = await pipeline.execute("a@b.co", settings, RunLogger("floor"), console)
    assert outcome.report.analysis.risk_level == "high"


async def test_no_breaches_keep_the_model_choice(settings, monkeypatch, console):
    async def empty(ctx):
        return []

    monkeypatch.setattr(
        base, "REGISTRY", [base.Collector(name="xposed_or_not", target_types=("email",), func=empty)]
    )
    monkeypatch.setattr("osintkit.collectors.REGISTRY", base.REGISTRY)
    monkeypatch.setattr(pipeline, "LLMClient", FakeLLM)
    outcome = await pipeline.execute("a@b.co", settings, RunLogger("floor2"), console)
    assert outcome.report.analysis.risk_level == "low"


async def test_offline_builds_analysis_without_model(settings, fake_collector, monkeypatch, console):
    monkeypatch.setattr(pipeline, "LLMClient", None)
    settings.offline = True
    outcome = await pipeline.execute("example.com", settings, RunLogger("off"), console)
    assert outcome.report.analysis is not None
    assert outcome.report.model is None
    assert any("offline" in note for note in outcome.report.notes)
