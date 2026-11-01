import httpx
import pytest
import respx

from osintkit.errors import MissingAPIKey, SynthesisError
from osintkit.llm import LLMClient, extract_content

URL = "https://api.test/v1/chat/completions"


def client(settings):
    settings.base_url = "https://api.test/v1/"
    return LLMClient(settings)


def test_endpoint_collapses_trailing_slash(settings):
    settings.base_url = "https://api.test/v1/"
    assert LLMClient(settings).endpoint() == URL


def test_endpoint_default_is_venice(settings):
    from osintkit.config import DEFAULT_BASE_URL, DEFAULT_MODEL

    fresh = type(settings)()
    assert fresh.base_url == DEFAULT_BASE_URL
    assert fresh.model == DEFAULT_MODEL
    assert LLMClient(fresh).endpoint().startswith("https://api.venice.ai/api/v1")


@respx.mock
async def test_chat_sends_auth_temperature_and_returns_content(settings):
    settings.temperature = 0.3
    route = respx.post(URL).mock(
        return_value=httpx.Response(200, json={"choices": [{"message": {"content": "hi"}}]})
    )
    async with client(settings) as llm:
        assert await llm.chat([{"role": "user", "content": "x"}]) == "hi"
    request = route.calls[0].request
    assert request.headers["authorization"] == "Bearer test-key"
    import json as _json

    body = _json.loads(request.content)
    assert body["temperature"] == 0.3
    assert body["model"] == settings.model
    assert body["stream"] is False


@respx.mock
async def test_chat_honours_response_format(settings):
    route = respx.post(URL).mock(
        return_value=httpx.Response(200, json={"choices": [{"message": {"content": "{}"}}]})
    )
    async with client(settings) as llm:
        await llm.chat([{"role": "user", "content": "x"}], response_format={"type": "json_object"})
    import json as _json

    assert _json.loads(route.calls[0].request.content)["response_format"] == {"type": "json_object"}


async def test_chat_without_key_raises(settings):
    settings.api_key = None
    async with client(settings) as llm:
        with pytest.raises(MissingAPIKey):
            await llm.chat([{"role": "user", "content": "x"}])


def test_extract_content_accepts_text_parts():
    body = {"choices": [{"message": {"content": [{"text": "a"}, {"text": "b"}]}}]}
    assert extract_content(body) == "ab"


def test_extract_content_surfaces_api_error():
    with pytest.raises(SynthesisError, match="quota"):
        extract_content({"error": {"message": "quota exceeded"}})


@pytest.mark.parametrize("body", [{}, {"choices": []}, {"choices": [{}]}, "nope"])
def test_extract_content_rejects_bad_shapes(body):
    with pytest.raises(SynthesisError):
        extract_content(body)
