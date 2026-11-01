import httpx
import respx

from osintkit.collectors import accounts


@respx.mock
async def test_gravatar_present(make_context):
    ctx = make_context("Alice@Example.com", "email")
    respx.get(url__startswith="https://gravatar.com/avatar/").mock(return_value=httpx.Response(200))
    result = await accounts.gravatar(ctx)
    assert result["present"] is True
    assert result["profile"].startswith("https://gravatar.com/")


@respx.mock
async def test_gravatar_absent(make_context):
    ctx = make_context("alice@example.com", "email")
    respx.get(url__startswith="https://gravatar.com/avatar/").mock(return_value=httpx.Response(404))
    result = await accounts.gravatar(ctx)
    assert result == {"checked": True, "present": False, "profile": None}


@respx.mock
async def test_gravatar_transport_error(make_context):
    ctx = make_context("alice@example.com", "email")
    respx.get(url__startswith="https://gravatar.com/avatar/").mock(
        side_effect=httpx.ConnectError("down")
    )
    result = await accounts.gravatar(ctx)
    assert result["checked"] is False


@respx.mock
async def test_presence_marks_unreachable_sites(make_context):
    ctx = make_context("alice", "username")
    for _site, template in accounts.SITES:
        respx.get(template.format(u="alice")).mock(return_value=httpx.Response(500))
    result = await accounts.username_presence(ctx)
    assert result["found"] == []
    assert len(result["unconfirmed"]) == len(accounts.SITES)
