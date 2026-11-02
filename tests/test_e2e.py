import json
from pathlib import Path

import httpx
import respx

from osintkit import pipeline
from osintkit.collectors import base
from osintkit.config import Settings
from osintkit.logging_store import RunLogger

FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "model_reply.json").read_text())
ENDPOINT = "https://api.test/v1/chat/completions"


async def test_full_run_against_mocked_model(settings, monkeypatch, console):
    async def fake(ctx):
        return {"breaches": [{"name": "Acme"}]}

    monkeypatch.setattr(
        base, "REGISTRY", [base.Collector(name="xposed_or_not", target_types=("email",), func=fake)]
    )
    monkeypatch.setattr("osintkit.collectors.REGISTRY", base.REGISTRY)
    settings.base_url = "https://api.test/v1"

    with respx.mock:
        route = respx.post(ENDPOINT).mock(
            return_value=httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(FIXTURE)}}]})
        )
        outcome = await pipeline.execute("alice@example.com", settings, RunLogger("e2e"), console)

    assert outcome.error is None
    report = outcome.report
    assert report.analysis.risk_level == "medium"
    assert report.analysis.breaches[0].data_types == ["Emails", "Password hashes"]
    assert report.analysis.recommendations

    sent = json.loads(route.calls[0].request.content)
    assert sent["messages"][0]["role"] == "system"
    assert "Acme" in sent["messages"][1]["content"]
    assert sent["temperature"] == 0.3


async def test_run_survives_wrapped_code_fence(settings, monkeypatch, console):
    async def fake(ctx):
        return {"breaches": []}

    monkeypatch.setattr(base, "REGISTRY", [base.Collector(name="x", target_types=("email",), func=fake)])
    monkeypatch.setattr("osintkit.collectors.REGISTRY", base.REGISTRY)
    settings.base_url = "https://api.test/v1"

    fenced = "```json\n" + json.dumps(FIXTURE) + "\n```"
    with respx.mock:
        respx.post(ENDPOINT).mock(
            return_value=httpx.Response(200, json={"choices": [{"message": {"content": fenced}}]})
        )
        outcome = await pipeline.execute("alice@example.com", settings, RunLogger("e2e2"), console)

    assert outcome.report.analysis is not None


def test_settings_defaults_match_spec():
    settings = Settings()
    assert settings.temperature == 0.3
    assert settings.max_tokens == 2400
    assert settings.base_url == "https://api.venice.ai/api/v1"
    assert settings.model == "deepseek-v4-1-flash"
    assert settings.max_attempts == 3


async def test_report_carries_schema_version(settings, monkeypatch, console):
    async def fake(ctx):
        return {}

    monkeypatch.setattr(base, "REGISTRY", [base.Collector(name="x", target_types=("email",), func=fake)])
    monkeypatch.setattr("osintkit.collectors.REGISTRY", base.REGISTRY)
    settings.dry_run = True
    outcome = await pipeline.execute("alice@example.com", settings, RunLogger("ver"), console)
    assert outcome.report.model_dump()["schema_version"] == "1"


def test_version_is_semver():
    import re

    from osintkit import __version__

    assert re.fullmatch(r"\d+\.\d+\.\d+", __version__)
