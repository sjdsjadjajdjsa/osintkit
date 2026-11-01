import json

import pytest

from osintkit.errors import SynthesisError
from osintkit.models import Analysis, CollectorResult, PromptBundle
from osintkit.synthesis import build_messages, extract_json, render_prompt, synthesize


class FakeClient:
    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    async def chat(self, messages, **kwargs):
        self.calls.append(messages)
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply


def bundle():
    return PromptBundle(
        target="alice@example.com",
        target_type="email",
        results=[
            CollectorResult(
                collector="xposed_or_not",
                target="alice@example.com",
                target_type="email",
                data={"found": 1, "breaches": [{"name": "Acme", "source": "xposedornot"}]},
            ),
            CollectorResult(
                collector="hibp_breaches",
                target="alice@example.com",
                target_type="email",
                ok=False,
                skipped=True,
                note="skipped: HIBP_API_KEY not set",
            ),
        ],
    )


VALID = {
    "summary": "Small footprint.",
    "breaches": [{"name": "Acme", "date": "2020-01-01", "data_types": ["Emails"], "source": "xposedornot"}],
    "associated_accounts": [{"platform": "GitHub", "handle": "alice"}],
    "infrastructure_notes": ["No domain supplied."],
    "subdomains": [],
    "risk_level": "medium",
    "recommendations": ["Rotate the leaked password."],
}


def test_prompt_marks_failed_sources_and_keeps_data():
    messages = build_messages(bundle())
    assert messages[0]["role"] == "system"
    payload = messages[1]["content"]
    assert "Acme" in payload
    assert "HIBP_API_KEY" in payload


def test_render_prompt_includes_both_turns():
    text = render_prompt(bundle())
    assert "### system" in text and "### user" in text


@pytest.mark.parametrize(
    "raw",
    [
        json.dumps(VALID),
        "```json\n" + json.dumps(VALID) + "\n```",
        "Here you go:\n" + json.dumps(VALID) + "\nDone.",
    ],
)
async def test_synthesize_accepts_wrapped_json(raw):
    client = FakeClient([raw])
    analysis = await synthesize(client, bundle())
    assert analysis.risk_level == "medium"
    assert analysis.breaches[0].name == "Acme"


async def test_synthesize_repairs_once():
    broken = '{"summary": "x", "risk_level": "medium"'
    client = FakeClient([broken, json.dumps(VALID)])
    analysis = await synthesize(client, bundle())
    assert len(client.calls) == 2
    assert "schema" in client.calls[1][-1]["content"]
    assert analysis.summary == "Small footprint."


async def test_synthesize_fails_after_second_failure():
    client = FakeClient(["nope", "still nope"])
    with pytest.raises(SynthesisError, match="repair"):
        await synthesize(client, bundle())


async def test_network_error_propagates_without_repair():
    client = FakeClient([SynthesisError("boom")])
    with pytest.raises(SynthesisError):
        await synthesize(client, bundle())
    assert len(client.calls) == 1


def test_extract_json_rejects_missing_object():
    with pytest.raises(SynthesisError):
        extract_json("no braces here")


def test_extract_json_rejects_array():
    with pytest.raises(SynthesisError):
        extract_json("[1, 2]")


@pytest.mark.parametrize(
    "payload,expected",
    [
        ({"risk_level": "HIGH"}, "high"),
        ({"risk_level": "Medium risk"}, "medium"),
        ({"risk_level": None}, "low"),
        ({"risk_level": "unknown"}, "low"),
    ],
)
def test_risk_level_is_coerced(payload, expected):
    analysis = Analysis.model_validate({**VALID, **payload})
    assert analysis.risk_level == expected


def test_strings_coerce_into_lists_and_objects():
    analysis = Analysis.model_validate(
        {
            "summary": "s",
            "breaches": "Acme",
            "associated_accounts": ["GitHub"],
            "infrastructure_notes": "one; two",
            "subdomains": ["A.example.com", "a.example.com"],
            "recommendations": None,
            "risk_level": "low",
        }
    )
    assert analysis.breaches[0].name == "Acme"
    assert analysis.associated_accounts[0].platform == "GitHub"
    assert analysis.infrastructure_notes == ["one", "two"]
    assert analysis.subdomains == ["A.example.com"]
    assert analysis.recommendations == []
