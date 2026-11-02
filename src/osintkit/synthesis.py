"""Prompt construction, model call, strict validation, and the single repair retry."""

from __future__ import annotations

import json
import time
from typing import Any

from .errors import SourceUnavailable, SynthesisError
from .llm import LLMClient
from .models import Analysis, PromptBundle

SYSTEM_PROMPT = """\
You are a defensive OSINT analyst. You receive raw results gathered from public sources \
about a single target. Work only from the supplied data plus well-known public facts about \
the platforms named in it. Never invent a breach, an account, or a hostname.

Produce a compact, source-grounded briefing for someone doing a personal privacy check or \
authorised research.

Rules:
- Cite the supplied source name in every breach entry. Mark dates as found; use null when unknown.
- If a source reports more breaches than it listed, say so and Take only the 15 most material, ordering
  credential-bearing and recent incidents first.
- Distinguish confirmed findings from plausible inference in the summary and notes.
- Risk level reflects exposure only: high means credential-bearing breaches or a wide,
  live attack surface.
- Recommendations must be concrete and actionable, not generic advice.
- If a source failed or was skipped, note the gap in infrastructure_notes.

Return ONLY a JSON object, no prose and no code fences, with exactly these keys:
{
  "summary": "3-6 sentence overview of the public footprint",
  "breaches": [{"name": "str", "date": "YYYY-MM-DD or null", "data_types": ["str"], "source": "str"}],
  "associated_accounts": [
    {"platform": "str", "url": "str or null", "handle": "str or null", "note": "str or null"}
  ],
  "infrastructure_notes": ["str"],
  "subdomains": ["str"],
  "risk_level": "low" | "medium" | "high",
  "recommendations": ["str"]
}
Use empty arrays when a section has no findings.\
"""

USER_TEMPLATE = """\
Target: {target}
Target type: {target_type}

Raw public-source data:
```json
{payload}
```

Write the briefing now as strict JSON.\
"""

REPAIR_PROMPT = """\
That response was not valid against the required schema. Error: {error}

Return the corrected JSON object only. All seven keys are required, arrays instead of prose \
for every list field, and risk_level must be exactly one of "low", "medium", or "high".\
"""


def build_messages(bundle: PromptBundle) -> list[dict[str, str]]:
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": USER_TEMPLATE.format(
                target=bundle.target,
                target_type=bundle.target_type,
                payload=bundle.to_prompt_json(),
            ),
        },
    ]


def render_prompt(bundle: PromptBundle) -> str:
    parts = []
    for message in build_messages(bundle):
        parts.append(f"### {message['role']}\n\n{message['content']}")
    return "\n\n".join(parts)


def extract_json(text: str) -> dict[str, Any]:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("\n", 1)[-1]
        if cleaned.rstrip().endswith("```"):
            cleaned = cleaned.rstrip()[:-3]
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise SynthesisError("no JSON object in model output")
    blob = cleaned[start : end + 1]
    try:
        parsed = json.loads(blob)
    except json.JSONDecodeError as exc:
        raise SynthesisError(f"invalid JSON: {exc.msg} at offset {exc.pos}") from exc
    if not isinstance(parsed, dict):
        raise SynthesisError("model output was JSON but not an object")
    return parsed


async def synthesize(
    client: LLMClient,
    bundle: PromptBundle,
    *,
    logger: Any | None = None,
    max_tokens: int = 2400,
) -> Analysis:
    messages = build_messages(bundle)

    settings = getattr(client, "settings", None)

    async def call(current: list[dict[str, str]], attempt: int) -> str:
        if logger is not None:
            logger.request(
                base_url=getattr(settings, "base_url", "unknown"),
                model=getattr(settings, "model", "unknown"),
                attempt=attempt,
                dry_run=False,
                messages=current,
                max_tokens=max_tokens,
            )
        started = time.perf_counter()
        try:
            try:
                content = await client.chat(
                    current,
                    max_tokens=max_tokens,
                    response_format={"type": "json_object"},
                )
            except SourceUnavailable as exc:
                if "HTTP 400" not in str(exc):
                    raise
                content = await client.chat(current, max_tokens=max_tokens)
        except Exception as exc:
            if logger is not None:
                logger.response(
                    attempt=attempt,
                    ok=False,
                    error=str(exc),
                    elapsed_ms=int((time.perf_counter() - started) * 1000),
                    content=None,
                )
            raise
        if logger is not None:
            logger.response(
                attempt=attempt,
                ok=True,
                error=None,
                elapsed_ms=int((time.perf_counter() - started) * 1000),
                content=content,
            )
        return content

    raw = ""
    try:
        raw = await call(messages, 1)
        return Analysis.model_validate(extract_json(raw))
    except (SynthesisError, ValueError) as first_error:
        repair = [
            *messages,
            {"role": "assistant", "content": raw or "(empty)"},
            {"role": "user", "content": REPAIR_PROMPT.format(error=str(first_error)[:400])},
        ]
        raw_retry = await call(repair, 2)
        try:
            return Analysis.model_validate(extract_json(raw_retry))
        except (SynthesisError, ValueError) as second_error:
            raise SynthesisError(
                f"model output still invalid after one repair attempt: {second_error}"
            ) from second_error
