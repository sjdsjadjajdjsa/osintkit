import httpx
import respx

from osintkit import doctor
from osintkit.config import Settings


def test_checks_report_missing_optional_keys():
    checks = doctor.collect_checks(Settings())
    by_name = {check.name: check for check in checks}
    assert by_name["api key"].status == "warn"
    assert by_name["GitHub"].status == "warn"
    assert by_name["cache dir"].status == "ok"


def test_failed_detects_failures():
    assert doctor.failed([doctor.Check("x", "fail", "d")])
    assert not doctor.failed([doctor.Check("x", "warn", "d")])


@respx.mock
async def test_endpoint_ok():
    respx.get("https://api.test/v1/models").mock(return_value=httpx.Response(200, json={}))
    checks = await doctor.diagnose(Settings(base_url="https://api.test/v1", api_key="k" * 25))
    endpoint = checks[-1]
    assert endpoint.status == "ok"


@respx.mock
async def test_endpoint_rejects_bad_key():
    respx.get("https://api.test/v1/models").mock(return_value=httpx.Response(401))
    checks = await doctor.diagnose(Settings(base_url="https://api.test/v1", api_key="k" * 25))
    assert checks[-1].status == "fail"
    assert "401" in checks[-1].detail


@respx.mock
async def test_missing_models_route_is_a_warning():
    respx.get("https://api.test/v1/models").mock(return_value=httpx.Response(404))
    checks = await doctor.diagnose(Settings(base_url="https://api.test/v1", api_key="k" * 25))
    assert checks[-1].status == "warn"


async def test_no_key_skips_endpoint_call():
    checks = await doctor.diagnose(Settings(base_url="https://api.test/v1"))
    assert checks[-1].status == "warn"
    assert "no API key" in checks[-1].detail


@respx.mock
async def test_deep_probe_accepts_completion():
    respx.get("https://api.test/v1/models").mock(return_value=httpx.Response(200, json={}))
    respx.post("https://api.test/v1/chat/completions").mock(
        return_value=httpx.Response(200, json={"choices": [{"message": {"content": "p"}}]})
    )
    checks = await doctor.diagnose(Settings(base_url="https://api.test/v1", api_key="k" * 25), deep=True)
    assert checks[-1].status == "ok"
    assert "accepted" in checks[-1].detail


@respx.mock
async def test_deep_probe_flags_rejected_key():
    respx.get("https://api.test/v1/models").mock(return_value=httpx.Response(200, json={}))
    respx.post("https://api.test/v1/chat/completions").mock(return_value=httpx.Response(401))
    checks = await doctor.diagnose(Settings(base_url="https://api.test/v1", api_key="k" * 25), deep=True)
    assert checks[-1].status == "fail"
    assert "key rejected" in checks[-1].detail


@respx.mock
async def test_deep_probe_flags_missing_model():
    respx.get("https://api.test/v1/models").mock(return_value=httpx.Response(404))
    respx.post("https://api.test/v1/chat/completions").mock(return_value=httpx.Response(404))
    checks = await doctor.diagnose(Settings(base_url="https://api.test/v1", api_key="k" * 25), deep=True)
    assert checks[-1].status == "fail"
    assert "not found" in checks[-1].detail


@respx.mock
async def test_shallow_probe_does_not_call_the_model():
    respx.get("https://api.test/v1/models").mock(return_value=httpx.Response(200, json={}))
    checks = await doctor.diagnose(Settings(base_url="https://api.test/v1", api_key="k" * 25))
    assert "not exercised" in checks[-1].detail
