"""Minimal OpenAI-compatible chat client."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Self

from .config import Settings
from .errors import MissingAPIKey, SourceUnavailable, SynthesisError
from .http import HttpClient


class LLMClient:
    def __init__(self, settings: Settings, http: HttpClient | None = None) -> None:
        self.settings = settings
        self._own_http = http is None
        self._http = http or HttpClient(settings)

    async def __aenter__(self) -> Self:
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
        max_tokens: int = 4000,
        response_format: Mapping[str, Any] | None = None,
    ) -> str:
        api_key = self.settings.resolved_api_key()
        if not api_key and self.settings.needs_key:
            raise MissingAPIKey("No API key. Set API_KEY in the environment or pass --api-key.")

        payload: dict[str, Any] = {
            "model": self.settings.model,
            "messages": [dict(m) for m in messages],
            "temperature": self.settings.temperature if temperature is None else temperature,
            "max_tokens": max_tokens,
            "stream": False,
        }
        if response_format:
            payload["response_format"] = dict(response_format)

        content, finish = await self._post(payload, api_key)
        if finish == "length" and not content and max_tokens < 8000:
            payload["max_tokens"] = min(8000, max_tokens * 2)
            content, finish = await self._post(payload, api_key)
        if finish == "length" and not content:
            raise SynthesisError("model ran out of tokens before answering")
        return content

    async def _post(self, payload: dict[str, Any], api_key: str | None) -> tuple[str, str | None]:
        try:
            response = await self._http.post_json(
                self.endpoint(),
                namespace="llm",
                payload=payload,
                headers={
                    **({"Authorization": f"Bearer {api_key}"} if api_key else {}),
                    "Content-Type": "application/json",
                },
            )
        except SourceUnavailable as exc:
            if "HTTP 401" in str(exc) or "HTTP 403" in str(exc):
                raise SynthesisError("API key rejected; run `osintkit doctor --deep` to confirm it") from exc
            raise
        try:
            body = response.json()
        except ValueError as exc:
            raise SynthesisError("Model endpoint returned non-JSON") from exc
        return extract_content(body), extract_finish(body)


def extract_finish(body: Any) -> str | None:
    if not isinstance(body, dict):
        return None
    choices = body.get("choices")
    if not isinstance(choices, list) or not choices:
        return None
    finish = choices[0].get("finish_reason")
    return finish if isinstance(finish, str) else None


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
    if not isinstance(content, str):
        return ""
    return content
