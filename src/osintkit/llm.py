"""Minimal OpenAI-compatible chat client (Venice by default)."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from .config import Settings
from .errors import MissingAPIKey, SynthesisError
from .http import HttpClient


class LLMClient:
    def __init__(self, settings: Settings, http: HttpClient | None = None) -> None:
        self.settings = settings
        self._own_http = http is None
        self._http = http or HttpClient(settings)

    async def __aenter__(self) -> "LLMClient":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._own_http:
            await self._http.aclose()

    def endpoint(self) -> str:
        return f"{self.settings.base_url.rstrip('/')}/chat/completions"

    async def chat(
        self,
        messages: Sequence[Mapping[str, str]],
        *,
        temperature: float | None = None,
        max_tokens: int = 2400,
        response_format: Mapping[str, Any] | None = None,
    ) -> str:
        api_key = self.settings.resolved_api_key()
        if not api_key:
            raise MissingAPIKey(
                "No API key. Set API_KEY in the environment or pass --api-key."
            )

        payload: dict[str, Any] = {
            "model": self.settings.model,
            "messages": [dict(m) for m in messages],
            "temperature": self.settings.temperature if temperature is None else temperature,
            "max_tokens": max_tokens,
            "stream": False,
        }
        if response_format:
            payload["response_format"] = dict(response_format)

        response = await self._http.post_json(
            self.endpoint(),
            namespace="llm",
            payload=payload,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
        )
        try:
            body = response.json()
        except ValueError as exc:
            raise SynthesisError("Model endpoint returned non-JSON") from exc
        return extract_content(body)


def extract_content(body: Any) -> str:
    if not isinstance(body, dict):
        raise SynthesisError("Unexpected model response shape")
    choices = body.get("choices")
    if not isinstance(choices, list) or not choices:
        error = body.get("error")
        if isinstance(error, dict) and error.get("message"):
            raise SynthesisError(str(error["message"]))
        raise SynthesisError("Model response had no choices")
    message = choices[0].get("message") or {}
    content = message.get("content")
    if isinstance(content, list):
        parts = [c.get("text", "") for c in content if isinstance(c, dict)]
        content = "".join(parts)
    if not isinstance(content, str) or not content.strip():
        raise SynthesisError("Model returned empty content")
    return content
