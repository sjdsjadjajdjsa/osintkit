"""Rich console rendering plus JSON and Markdown export."""

from __future__ import annotations

import json
from collections.abc import Iterable

from rich import box
from rich.console import Console, Group
from rich.json import JSON
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .models import CollectorResult, Report

RISK_STYLE = {"low": "bold green", "medium": "bold yellow", "high": "bold red"}
RANKS = ("low", "medium", "high")


def console(width: int | None = None) -> Console:
    return Console(width=width, highlight=False, soft_wrap=False)


def risk_style(level: str) -> str:
    return RISK_STYLE.get(level, "bold white")


def bar(level: str) -> Text:
    rank = RANKS.index(level) if level in RANKS else 0
    text = Text()
    for index, name in enumerate(RANKS):
        text.append("▇" if index <= rank else "▁", style=risk_style(name))
    text.append(f"  {level.upper()}", style=risk_style(level))
    return text


def render_report(report: Report, out: Console, *, verbose: bool = False) -> None:
    out.print(_header(report))
    if report.analysis is None:
        out.print("[yellow]No analysis available.[/yellow]")
        if report.notes:
            out.print(_bullets("Notes", report.notes, "yellow"))
        if verbose:
            out.print(_raw_data(report.collectors))
        out.print(_coverage(report.collectors))
        return

    analysis = report.analysis
    out.print(Panel(escape(analysis.summary or "No summary returned."), title="Summary", box=box.ROUNDED))

    if analysis.breaches:
        table = Table(title="Known breaches", box=box.SIMPLE_HEAD, expand=True)
        table.add_column("Breach", style="bold")
        table.add_column("Date", no_wrap=True)
        table.add_column("Exposed data")
        table.add_column("Source", style="dim", no_wrap=True)
        for breach in analysis.breaches:
            table.add_row(
                escape(breach.name),
                escape(breach.date or "unknown"),
                escape(", ".join(breach.data_types) or "undisclosed"),
                escape(breach.source or "-"),
            )
        out.print(table)
    else:
        out.print("[green]No breach records found in the queried sources.[/green]")

    if analysis.associated_accounts:
        table = Table(title="Associated accounts", box=box.SIMPLE_HEAD, expand=True)
        table.add_column("Platform", style="bold")
        table.add_column("Handle")
        table.add_column("Link", overflow="fold")
        table.add_column("Note")
        for account in analysis.associated_accounts:
            link = account.url or ""
            table.add_row(
                escape(account.platform),
                escape(account.handle or "-"),
                escape(link),
                escape(account.note or ""),
            )
        out.print(table)

    if analysis.infrastructure_notes:
        out.print(_bullets("Infrastructure and attack surface", analysis.infrastructure_notes, "cyan"))
    if analysis.subdomains:
        out.print(_bullets("Subdomains", analysis.subdomains, "magenta"))
    if analysis.recommendations:
        out.print(_bullets("Recommendations", analysis.recommendations, "green"))

    if report.notes:
        out.print(_bullets("Notes", report.notes, "yellow"))
    if verbose:
        out.print(_raw_data(report.collectors))
    out.print(_coverage(report.collectors))


def _header(report: Report) -> Panel:
    head = Text()
    head.append(report.target, style="bold")
    head.append(f"  ({report.target_type})", style="dim")

    risk = Text("Risk: ")
    if report.analysis:
        risk.append_text(bar(report.analysis.risk_level))
    else:
        risk.append("unknown", style="dim")

    meta = Text(
        f"generated {report.generated_at} · {report.elapsed_ms} ms"
        + (f" · {report.model}" if report.model else ""),
        style="dim",
    )
    return Panel(Group(head, risk, meta), title="osintkit", box=box.DOUBLE)


def _bullets(title: str, items: Iterable[str], style: str) -> Panel:
    body = Text()
    for item in items:
        body.append("• ", style=style)
        body.append(item + "\n")
    return Panel(body, title=title, box=box.ROUNDED, title_align="left")


def _coverage(results: list[CollectorResult]) -> Panel:
    table = Table(box=box.MINIMAL, expand=True, show_header=True, header_style="dim")
    table.add_column("collector")
    table.add_column("result")
    table.add_column("detail", overflow="fold")
    for result in results:
        if result.skipped:
            status = Text("skipped", style="yellow")
        elif not result.ok:
            status = Text("failed", style="red")
        elif result.has_data:
            status = Text("ok", style="green")
        else:
            status = Text("empty", style="dim")
        table.add_row(
            escape(result.collector),
            status,
            escape(result.note or result.error or ""),
        )
    return Panel(table, title="Source coverage", box=box.ROUNDED, title_align="left")


def _raw_data(results: list[CollectorResult]) -> Panel:
    body = Text()
    for result in results:
        if not result.has_data:
            continue
        body.append(f"{result.collector}\n", style="bold cyan")
        body.append(json.dumps(result.data, indent=2, ensure_ascii=False, default=str)[:4000] + "\n\n")
    if not body.plain:
        body.append("no collected data", style="dim")
    return Panel(body, title="Raw source data", box=box.ROUNDED, title_align="left")


def print_json(report: Report) -> None:
    payload = report.model_dump(mode="json")
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def to_markdown(report: Report) -> str:
    analysis = report.analysis
    lines = [
        f"# OSINT report: {report.target}",
        "",
        f"- Type: `{report.target_type}`",
        f"- Generated: {report.generated_at}",
        f"- Model: `{report.model or 'n/a'}`",
        f"- Risk: **{(analysis.risk_level if analysis else 'unknown')}**",
        "",
    ]
    if analysis is None:
        lines += ["> No analysis available.", ""]
        _md_list(lines, "Notes", report.notes)
    else:
        lines += ["## Summary", "", analysis.summary or "No summary returned.", ""]
        lines += ["## Breaches", ""]
        if analysis.breaches:
            lines += ["| Breach | Date | Exposed data | Source |", "| --- | --- | --- | --- |"]
            for breach in analysis.breaches:
                lines.append(
                    f"| {breach.name} | {breach.date or 'unknown'} | "
                    f"{', '.join(breach.data_types) or 'undisclosed'} | {breach.source or '-'} |"
                )
            lines.append("")
        else:
            lines += ["None found in the queried sources.", ""]
        _md_list(
            lines,
            "Associated accounts",
            [
                f"{a.platform}{f' ({a.handle})' if a.handle else ''}"
                f"{f' - {a.url}' if a.url else ''}{f': {a.note}' if a.note else ''}"
                for a in analysis.associated_accounts
            ],
        )
        _md_list(lines, "Infrastructure and attack surface", analysis.infrastructure_notes)
        _md_list(lines, "Subdomains", analysis.subdomains)
        _md_list(lines, "Recommendations", analysis.recommendations)

    lines += ["## Source coverage", ""]
    for result in report.collectors:
        if result.skipped:
            verdict = "skipped"
        elif not result.ok:
            verdict = f"failed ({result.error})"
        elif result.has_data:
            verdict = "ok"
        else:
            verdict = "empty"
        lines.append(f"- `{result.collector}`: {verdict}")
    lines += ["", "_Public data only. Accuracy depends on the upstream sources._", ""]
    return "\n".join(lines)


def _md_list(lines: list[str], heading: str, items: list[str]) -> None:
    lines += [f"## {heading}", ""]
    if not items:
        lines += ["None noted.", ""]
        return
    for item in items:
        lines.append(f"- {item}")
    lines.append("")


def print_prompt(prompt: str, out: Console) -> None:
    out.print(Panel.fit("[bold]dry run[/bold] · synthesis prompt only, no model call"))
    for chunk in prompt.split("\n\n### "):
        if not chunk.startswith("###"):
            chunk = "### " + chunk
        out.print(Panel(chunk.strip(), box=box.ROUNDED, title_align="left"))


def print_json_block(data: object, out: Console) -> None:
    out.print(JSON(json.dumps(data, default=str, ensure_ascii=False)))
