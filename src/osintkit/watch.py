"""Repeat a lookup on an interval and speak only when something changed."""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import subprocess
from collections.abc import Awaitable, Callable

from . import diff, render
from .models import Report

UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
DURATION_RE = re.compile(r"^(\d+)([smhd])$")
MIN_INTERVAL = 60


def parse_duration(text: str) -> int:
    match = DURATION_RE.match(text.strip().lower())
    if not match:
        raise ValueError(f"{text!r} is not a duration like 30m, 6h, or 1d")
    value = int(match.group(1)) * UNITS[match.group(2)]
    if value < MIN_INTERVAL:
        raise ValueError(f"interval must be at least {MIN_INTERVAL}s")
    return value


def describe(change: dict) -> list[str]:
    lines: list[str] = []
    if change["risk_rose"]:
        lines.append(f"risk rose {change['risk']['old']} -> {change['risk']['new']}")
    if change["risk_fell"]:
        lines.append(f"risk fell {change['risk']['old']} -> {change['risk']['new']}")
    for name in change["breaches"]["added"]:
        lines.append(f"new breach: {name}")
    for name in change["subdomains"]["added"]:
        lines.append(f"new host: {name}")
    for name in change["collectors"]["started_failing"]:
        lines.append(f"source failing: {name}")
    for name in change["collectors"]["started_working"]:
        lines.append(f"source recovered: {name}")
    return lines


def _notify_command(title: str, body: str) -> list[str] | None:
    if shutil.which("notify-send"):
        return ["notify-send", "osintkit", title, body]
    if shutil.which("osascript"):
        script = f'display notification "{body}" with title "{title}"'
        return ["osascript", "-e", script]
    power = shutil.which("powershell") or shutil.which("pwsh")
    if os.name == "nt" and power:
        script = (
            "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications,"
            " ContentType = WindowsRuntime] > $null; "
            f"$t = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent(0);"
            f'$t.GetElementsByTagName("text")[0].AppendChild($t.CreateTextNode("{body}")) > $null;'
            "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("
            f"'osintkit').Show([Windows.UI.Notifications.ToastNotification]::new($t))"
        )
        return [power, "-NoProfile", "-Command", script]
    return None


def notify(title: str, body: str) -> bool:
    command = _notify_command(title, body)
    if command is None:
        return False
    try:
        subprocess.run(command, check=False, timeout=10)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


async def run(
    target: str,
    run_once: Callable[[], Awaitable[Report]],
    on_report: Callable[[Report, list[str], bool], None],
    *,
    every: int,
    cycles: int = 0,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> int:
    """Run `run_once` on an interval. Returns the number of change events."""
    previous: Report | None = None
    changes = 0
    done = 0
    while True:
        report = await run_once()
        done += 1
        lines: list[str] = []
        if previous is not None:
            comparison = diff.compare(previous, report)
            if not diff.is_empty(comparison):
                changes += 1
                lines = describe(comparison)
        if previous is None or lines:
            on_report(report, lines, previous is None)
        previous = report
        if cycles and done >= cycles:
            return changes
        await sleep(every)


def render_event(report: Report, lines: list[str], baseline: bool, console, *, full: bool) -> None:
    stamp = render.escape(report.generated_at)
    if baseline:
        console.print(f"[dim]{stamp} baseline for {render.escape(report.target)}[/dim]")
        render.render_report(report, console)
        return
    console.print(f"[yellow]change[/yellow] {stamp} {render.escape(report.target)}")
    for line in lines:
        console.print(f"  - {render.escape(line)}")
    if full:
        render.render_report(report, console)
