import pytest

from osintkit import watch
from osintkit.models import Analysis, Report


def report(risk="low", breaches=()):
    return Report(
        target="example.com",
        target_type="domain",
        analysis=Analysis(summary="s", risk_level=risk, breaches=[{"name": b} for b in breaches]),
    )


def test_parse_duration():
    assert watch.parse_duration("30m") == 1800
    assert watch.parse_duration("2h") == 7200
    assert watch.parse_duration("1d") == 86400


@pytest.mark.parametrize("text", ["10s", "soon", "5x", ""])
def test_parse_duration_rejects(text):
    with pytest.raises(ValueError):
        watch.parse_duration(text)


def test_describe_lists_changes():
    change = {
        "risk": {"old": "low", "new": "high"},
        "risk_rose": True,
        "risk_fell": False,
        "breaches": {"added": ["Acme"], "removed": []},
        "subdomains": {"added": ["x.example.com"], "removed": []},
        "collectors": {"started_failing": ["crt_sh_subdomains"], "started_working": []},
    }
    lines = watch.describe(change)
    assert "risk rose low -> high" in lines
    assert "new breach: Acme" in lines
    assert "new host: x.example.com" in lines
    assert "source failing: crt_sh_subdomains" in lines


async def test_run_reports_baseline_then_only_changes():
    sequence = [report(), report(), report(risk="high"), report(risk="high")]
    events = []
    slept = []

    async def run_once():
        return sequence.pop(0)

    async def sleeper(seconds):
        slept.append(seconds)

    changes = await watch.run(
        "example.com",
        run_once,
        lambda rep, lines, baseline: events.append((baseline, list(lines))),
        every=60,
        cycles=4,
        sleep=sleeper,
    )
    assert changes == 1
    assert events[0] == (True, [])
    assert events[1][0] is False
    assert any("risk rose" in line for line in events[1][1])


async def test_run_respects_cycles():
    events = []

    async def run_once():
        return report()

    async def sleeper(seconds):
        return None

    changes = await watch.run(
        "example.com", run_once, lambda *a: events.append(a), every=60, cycles=3, sleep=sleeper
    )
    assert changes == 0
    assert len(events) == 1


def test_notify_command_prefers_notify_send(monkeypatch):
    monkeypatch.setattr(
        watch.shutil, "which", lambda name: "/usr/bin/notify-send" if name == "notify-send" else None
    )
    assert watch._notify_command("t", "b")[0] == "notify-send"


def test_notify_command_uses_osascript_on_mac(monkeypatch):
    monkeypatch.setattr(
        watch.shutil, "which", lambda name: "/usr/bin/osascript" if name == "osascript" else None
    )
    assert watch._notify_command("t", "b")[:2] == ["osascript", "-e"]


def test_notify_command_none_when_nothing_available(monkeypatch):
    monkeypatch.setattr(watch.shutil, "which", lambda name: None)
    monkeypatch.setattr(watch.os, "name", "posix")
    assert watch._notify_command("t", "b") is None
