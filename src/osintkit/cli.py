"""Command line interface."""

from __future__ import annotations

import asyncio
import csv
import ipaddress
import json
import os
import sys
from dataclasses import asdict
from difflib import get_close_matches
from pathlib import Path

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__, diff, doctor, pipeline, render, retention
from .collectors import REGISTRY
from .config import (
    PROVIDERS,
    Settings,
    cache_clear,
    cache_stats,
    provider_from_key,
)
from .errors import OsintKitError, TargetParseError
from .logging_store import RunLogger, find_report_for_run, read_report, read_runs, run_exists
from .targets import VALID_TYPES

app = typer.Typer(
    add_completion=True,
    no_args_is_help=True,
    help="Public-data OSINT aggregator for emails, usernames, domains, and companies.",
    rich_markup_mode="rich",
)

STATE: dict[str, object] = {}


def _settings(**overrides: object) -> Settings:
    base: Settings = STATE["settings"]  # type: ignore[assignment]
    for key, value in overrides.items():
        setattr(base, key, value)
    return base


def _console():
    return render.console()


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"osintkit {__version__}")
        raise typer.Exit()


@app.callback()
def root(
    provider: str | None = typer.Option(
        None, "--provider", help="Endpoint preset: venice, openrouter, or openai."
    ),
    base_url: str | None = typer.Option(
        None, "--base-url", help="OpenAI-compatible base URL (overrides the provider)."
    ),
    model: str | None = typer.Option(None, "--model", help="Model name (overrides the provider default)."),
    api_key: str | None = typer.Option(None, "--api-key", help="API key (or set API_KEY)."),
    temperature: float = typer.Option(0.3, "--temperature", min=0.0, max=2.0),
    max_tokens: int = typer.Option(2400, "--max-tokens", min=256, max=16000),
    timeout: float = typer.Option(30.0, "--timeout", help="HTTP timeout in seconds."),
    max_connections: int = typer.Option(16, "--max-connections", min=1, max=64),
    max_attempts: int = typer.Option(3, "--max-attempts", min=1, max=6),
    no_cache: bool = typer.Option(False, "--no-cache", help="Bypass the 24h cache."),
    cache_ttl: int = typer.Option(86400, "--cache-ttl", help="Cache lifetime in seconds."),
    resolver: list[str] | None = typer.Option(None, "--resolver", help="DNS resolver IP to use, repeatable."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show collector detail."),
    _version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="Print version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    if provider and provider not in PROVIDERS:
        raise typer.BadParameter(f"unknown provider {provider!r}; choose from {', '.join(PROVIDERS)}")
    effective_key = api_key or os.environ.get("API_KEY") or os.environ.get("OPENAI_API_KEY")
    chosen = provider or provider_from_key(effective_key) or "venice"
    preset = PROVIDERS[chosen]
    settings = Settings(
        base_url=base_url or preset[0],
        model=model or preset[1],
        api_key=api_key,
        temperature=temperature,
        max_tokens=max_tokens,
        timeout=timeout,
        max_connections=max_connections,
        max_attempts=max_attempts,
        use_cache=not no_cache,
        cache_ttl=cache_ttl,
        verbose=verbose,
    )
    if resolver:
        for entry in resolver:
            try:
                ipaddress.ip_address(entry)
            except ValueError:
                raise typer.BadParameter(f"{entry!r} is not an IP address") from None
        settings.resolvers = list(resolver)
    STATE["settings"] = settings


def _pick_target(
    target: str | None,
    email: str | None,
    username: str | None,
    domain: str | None,
    company: str | None,
) -> tuple[str, str | None]:
    supplied = [
        (name, value)
        for name, value in (
            ("email", email),
            ("username", username),
            ("domain", domain),
            ("company", company),
        )
        if value
    ]
    if len(supplied) > 1:
        raise TargetParseError("pass only one of --email/--username/--domain/--company")
    if supplied:
        kind, value = supplied[0]
        return value, kind
    if not target:
        raise TargetParseError("give a target or one of --email/--username/--domain/--company")
    return target, None


def _parse_sets(values: list[str] | None, flag: str = "--only") -> set[str] | None:
    if not values:
        return None
    items: set[str] = set()
    for value in values:
        items.update(part.strip() for part in value.split(",") if part.strip())
    if not items:
        return None
    known = {spec.name for spec in REGISTRY}
    unknown = sorted(items - known)
    if unknown:
        hint = ""
        close = get_close_matches(unknown[0], sorted(known), n=3)
        if close:
            hint = f"; did you mean {', '.join(close)}?"
        raise typer.BadParameter(f"{flag} got unknown collector {unknown[0]!r}{hint}")
    return items


def _parse_ports(values: list[str] | None) -> list[str] | None:
    if not values:
        return None
    ports: list[str] = []
    for value in values:
        for part in value.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                port = int(part)
            except ValueError:
                raise typer.BadParameter(f"{part!r} is not a port number") from None
            if not 1 <= port <= 65535:
                raise typer.BadParameter(f"port {port} is out of range")
            if str(port) not in ports:
                ports.append(str(port))
    return ports or None


def _finish(outcome: pipeline.Outcome, settings: Settings, out) -> int:
    report = outcome.report
    if settings.output_markdown:
        destination = Path(settings.extra.get("markdown_path") or pipeline.default_markdown_path(report.target))
        if destination.is_dir() or str(destination).endswith(("/", os.sep)):
            destination = destination / pipeline.default_markdown_path(report.target).name
        path = pipeline.write_markdown(report, destination)
        out.print(f"[green]markdown written[/green] {path}")

    if settings.raw:
        bundle = outcome.extra["bundle"]
        print(json.dumps(bundle.model_dump(mode="json"), indent=2, ensure_ascii=False, default=str))
    elif settings.dry_run and settings.output_json:
        print(
            json.dumps(
                {
                    "target": report.target,
                    "target_type": report.target_type,
                    "prompt": outcome.extra.get("prompt"),
                },
                indent=2,
            )
        )
    elif settings.output_json:
        render.print_json(report)
    elif settings.output_markdown:
        destination = Path(settings.extra.get("markdown_path") or pipeline.default_markdown_path(report.target))
        if destination.is_dir() or str(destination).endswith(("/", os.sep)):
            destination = destination / pipeline.default_markdown_path(report.target).name
        path = pipeline.write_markdown(report, destination)
        out.print(f"[green]markdown written[/green] {path}")
    else:
        render.render_report(report, out, verbose=settings.verbose)

    if outcome.archived:
        sink = Console(stderr=True) if (settings.output_json or settings.raw) else out
        sink.print(f"[dim]archived: {outcome.archived}[/dim]", highlight=False)
    if outcome.error:
        out.print(Panel(render.escape(outcome.error), title="synthesis failed", border_style="red"))
        return 1
    return 0


@app.command()
def lookup(
    target: str | None = typer.Argument(None, help="Email, username, domain, or company."),
    email: str | None = typer.Option(None, "--email", help="Email target."),
    username: str | None = typer.Option(None, "--username", help="Username target."),
    domain: str | None = typer.Option(None, "--domain", help="Domain target."),
    company: str | None = typer.Option(None, "--company", help="Company target."),
    json_out: bool = typer.Option(False, "--json", help="Raw structured JSON on stdout."),
    markdown: bool = typer.Option(False, "--markdown", help="Write a Markdown report."),
    out_path: Path | None = typer.Option(None, "--out", "-o", help="Markdown destination."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print the prompt, skip the model."),
    raw: bool = typer.Option(False, "--raw", help="Dump collected data as JSON, skip the model."),
    offline: bool = typer.Option(False, "--offline", help="Report from collected data only; no model, no key."),
    only: list[str] | None = typer.Option(None, "--only", help="Run only these collectors."),
    skip: list[str] | None = typer.Option(None, "--skip", help="Skip these collectors."),
    ports: list[str] | None = typer.Option(None, "--ports", help="Ports to probe, e.g. 22,443."),
) -> None:
    """Look up one target."""
    out = _console()
    settings = _settings(
        output_json=json_out,
        output_markdown=markdown,
        dry_run=dry_run,
        raw=raw,
        offline=offline,
    )
    try:
        settings.extra["ports"] = _parse_ports(ports)
    except typer.BadParameter as exc:
        out.print(f"[red]{exc.message}[/red]")
        raise typer.Exit(2) from exc

    if out_path:
        settings.extra["markdown_path"] = str(out_path)
    try:
        raw, declared = _pick_target(target, email, username, domain, company)
    except TargetParseError as exc:
        out.print(f"[red]{exc}[/red]")
        raise typer.Exit(2) from exc

    logger = RunLogger(pipeline.new_run_id())
    try:
        outcome = asyncio.run(
            pipeline.execute(
                raw,
                settings,
                logger,
                out,
                declared_type=declared,
                only=_parse_sets(only, "--only"),
                skip=_parse_sets(skip, "--skip"),
            )
        )
    except TargetParseError as exc:
        out.print(f"[red]{exc}[/red]")
        raise typer.Exit(2) from exc
    except KeyboardInterrupt:  # pragma: no cover
        out.print("[yellow]interrupted[/yellow]")
        raise typer.Exit(130) from None

    raise typer.Exit(_finish(outcome, settings, out))


def _read_batch(path: Path) -> list[tuple[str, str | None]]:
    rows: list[tuple[str, str | None]] = []
    with path.open(newline="", encoding="utf-8-sig") as handle:
        sample = handle.read(2048)
        handle.seek(0)
        has_header = "target" in sample.splitlines()[0].lower() if sample.splitlines() else False
        if has_header:
            reader = csv.DictReader(handle)
            for row in reader:
                value = (row.get("target") or "").strip()
                if not value or value.startswith("#"):
                    continue
                kind = (row.get("type") or row.get("target_type") or "").strip().lower() or None
                if kind and kind not in VALID_TYPES:
                    kind = None
                rows.append((value, kind))
        else:
            for row in csv.reader(handle):
                if not row:
                    continue
                value = row[0].strip()
                if not value or value.startswith("#"):
                    continue
                kind = row[1].strip().lower() if len(row) > 1 and row[1].strip() in VALID_TYPES else None
                rows.append((value, kind))
    return rows


@app.command()
def batch(
    file: Path = typer.Option(
        ..., "--file", "-f", exists=True, dir_okay=False, help="CSV with target[,type] rows."
    ),
    json_out: bool = typer.Option(False, "--json", help="JSON array of reports on stdout."),
    markdown: bool = typer.Option(False, "--markdown", help="Write one Markdown file per target."),
    out_dir: Path | None = typer.Option(None, "--out", "-o", help="Markdown output directory."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print prompts, skip the model."),
    raw: bool = typer.Option(False, "--raw", help="JSON array of collected data, skip the model."),
    offline: bool = typer.Option(False, "--offline", help="Report from collected data only; no model, no key."),
    fail_fast: bool = typer.Option(False, "--fail-fast", help="Stop reporting at the first error."),
    concurrency: int = typer.Option(3, "--concurrency", "-c", min=1, max=10, help="Targets to run at once."),
    only: list[str] | None = typer.Option(None, "--only", help="Run only these collectors."),
    skip: list[str] | None = typer.Option(None, "--skip", help="Skip these collectors."),
    ports: list[str] | None = typer.Option(None, "--ports", help="Ports to probe, e.g. 22,443."),
) -> None:
    """Run every target in a CSV."""
    out = _console()
    settings = _settings(
        output_json=json_out,
        output_markdown=markdown,
        dry_run=dry_run,
        raw=raw,
        offline=offline,
    )
    try:
        settings.extra["ports"] = _parse_ports(ports)
    except typer.BadParameter as exc:
        out.print(f"[red]{exc.message}[/red]")
        raise typer.Exit(2) from exc

    settings.extra["quiet_progress"] = True
    try:
        settings.extra["ports"] = _parse_ports(ports)
    except typer.BadParameter as exc:
        out.print(f"[red]{exc.message}[/red]")
        raise typer.Exit(2) from exc
    try:
        rows = _read_batch(file)
    except OSError as exc:
        out.print(f"[red]{exc}[/red]")
        raise typer.Exit(2) from exc
    if not rows:
        out.print("[yellow]no targets in file[/yellow]")
        raise typer.Exit(2)

    target_dir = Path(out_dir) if out_dir else Path.cwd()
    try:
        only_set, skip_set = _parse_sets(only, "--only"), _parse_sets(skip, "--skip")
    except typer.BadParameter as exc:
        out.print(f"[red]{exc.message}[/red]")
        raise typer.Exit(2) from exc

    async def run_all():
        gate = asyncio.Semaphore(concurrency)

        async def one(item):
            index, value, declared = item
            logger = RunLogger(pipeline.new_run_id())
            async with gate:
                try:
                    outcome = await pipeline.execute(
                        value,
                        settings,
                        logger,
                        out,
                        declared_type=declared,
                        only=only_set,
                        skip=skip_set,
                    )
                except TargetParseError as exc:
                    return index, value, exc
                return index, value, outcome

        return await asyncio.gather(*(one((i, v, d)) for i, (v, d) in enumerate(rows, start=1)))

    reports = []
    bundles = []
    failures = 0
    for index, value, outcome in asyncio.run(run_all()):
        if not json_out and not raw:
            out.rule(f"[dim]{index}/{len(rows)} · {value}[/dim]")
        if isinstance(outcome, TargetParseError):
            failures += 1
            out.print(f"[red]skipped {value}: {outcome}[/red]")
            if fail_fast:
                break
            continue
        report = outcome.report
        if raw:
            bundles.append(outcome.extra["bundle"].model_dump(mode="json"))
        else:
            reports.append(report.model_dump(mode="json"))
        if outcome.error:
            failures += 1
        if not json_out and not raw:
            if markdown:
                name = pipeline.default_markdown_path(report.target).name
                path = pipeline.write_markdown(report, target_dir / name)
                out.print(f"[green]markdown written[/green] {path}")
            else:
                render.render_report(report, out, verbose=settings.verbose)
        if fail_fast and outcome.error:
            break

    if raw:
        print(json.dumps(bundles, indent=2, ensure_ascii=False))
        raise typer.Exit(1 if failures else 0)
    if json_out:
        print(json.dumps(reports, indent=2, ensure_ascii=False))

    table = Table(title="batch summary", box=box.SIMPLE_HEAVY)
    table.add_column("target")
    table.add_column("risk")
    table.add_column("breaches")
    for entry in reports:
        analysis = entry.get("analysis") or {}
        table.add_row(
            render.escape(str(entry.get("target"))),
            str(analysis.get("risk_level") or "-"),
            str(len(analysis.get("breaches") or [])),
        )
    if not json_out:
        out.print(table)
    raise typer.Exit(1 if failures else 0)


@app.command()
def history(
    limit: int = typer.Option(20, "--limit", "-n", min=1, max=200),
    show: str | None = typer.Option(None, "--show", help="Replay a stored report by archive path or run id."),
    json_out: bool = typer.Option(False, "--json", help="JSON output."),
) -> None:
    """Show past runs, or replay one archived report."""
    out = _console()
    if show:
        payload = _load_report(show)
        if payload is None and run_exists(show):
            out.print(f"[red]run {show} has no archived report (dry run or early failure)[/red]")
            raise typer.Exit(1)
        if payload is None:
            out.print(f"[red]cannot read report {show}[/red]")
            raise typer.Exit(1)
        if json_out:
            print(json.dumps(payload, indent=2, ensure_ascii=False))
            return
        from .models import Report

        try:
            render.render_report(Report.model_validate(payload), out)
        except ValueError as exc:
            out.print(f"[red]unreadable report: {exc}[/red]")
            raise typer.Exit(1) from exc
        return

    runs = read_runs(limit)
    if json_out:
        print(json.dumps(runs, indent=2, ensure_ascii=False))
        return
    if not runs:
        out.print("[dim]no runs logged yet[/dim]")
        return

    table = Table(title="run history", box=box.SIMPLE_HEAVY)
    table.add_column("run", no_wrap=True)
    table.add_column("started", no_wrap=True)
    table.add_column("target")
    table.add_column("type")
    table.add_column("sources")
    table.add_column("risk")
    for run in runs:
        table.add_row(
            str(run.get("run_id")),
            str(run.get("started", ""))[:19].replace("T", " "),
            render.escape(str(run.get("target") or "-")),
            str(run.get("target_type") or "-"),
            f"{run['collectors_ok']} ok / {run['collectors_failed']} failed / "
            f"{run['collectors_skipped']} skipped",
            str(run.get("risk") or "-"),
        )
    out.print(table)
    out.print("[dim]replay one with: osintkit history --show <run id>[/dim]")


@app.command("collectors")
def list_collectors(
    json_out: bool = typer.Option(False, "--json", help="JSON output."),
) -> None:
    """List available collectors and the target types they serve."""
    from .collectors import REGISTRY

    if json_out:
        print(
            json.dumps(
                [
                    {
                        "name": spec.name,
                        "targets": list(spec.target_types),
                        "requires": spec.requires,
                        "description": spec.description,
                    }
                    for spec in sorted(REGISTRY, key=lambda c: (c.order, c.name))
                ],
                indent=2,
            )
        )
        return

    table = Table(box=box.SIMPLE_HEAD)
    table.add_column("collector", style="bold")
    table.add_column("targets")
    table.add_column("requires")
    table.add_column("what it does")
    for spec in sorted(REGISTRY, key=lambda c: (c.order, c.name)):
        table.add_row(
            spec.name,
            ", ".join(spec.target_types),
            spec.requires or "-",
            spec.description,
        )
    render.console().print(table)


@app.command("doctor")
def doctor_cmd(
    json_out: bool = typer.Option(False, "--json", help="JSON output."),
    deep: bool = typer.Option(False, "--deep", help="Send a 1-token completion to verify the key."),
) -> None:
    """Check the key, endpoint, and writable directories."""
    out = _console()
    settings: Settings = STATE["settings"]  # type: ignore[assignment]
    checks = asyncio.run(doctor.diagnose(settings, deep=deep))
    if json_out:
        print(json.dumps([asdict(check) for check in checks], indent=2))
    else:
        table = Table(title="doctor", box=box.SIMPLE_HEAVY)
        table.add_column("check")
        table.add_column("status")
        table.add_column("detail", overflow="fold")
        style = {"ok": "green", "warn": "yellow", "fail": "red"}
        for check in checks:
            table.add_row(check.name, f"[{style[check.status]}]{check.status}[/]", render.escape(check.detail))
        out.print(table)
    raise typer.Exit(1 if doctor.failed(checks) else 0)


@app.command()
def prune(
    days: int = typer.Option(30, "--days", min=1, help="Delete anything older than this."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Report what would go."),
) -> None:
    """Delete old cache entries, logs, and archived reports."""
    out = _console()
    counts = retention.prune(days, dry_run=dry_run)
    verb = "would remove" if dry_run else "removed"
    out.print(f"{verb}: {counts['cache']} cached, {counts['logs']} log, {counts['reports']} report files")


def _load_report(ref: str) -> dict | None:
    target = ref
    if not Path(ref).exists():
        found = find_report_for_run(ref)
        if found:
            target = found
    return read_report(target)


@app.command("diff")
def diff_cmd(
    old_ref: str = typer.Argument(..., help="Older run id or report path."),
    new_ref: str = typer.Argument(..., help="Newer run id or report path."),
    json_out: bool = typer.Option(False, "--json", help="JSON output."),
) -> None:
    """Compare two archived runs."""
    from .models import Report

    out = _console()
    loaded = []
    for ref in (old_ref, new_ref):
        payload = _load_report(ref)
        if payload is None:
            out.print(f"[red]cannot read report {ref}[/red]")
            raise typer.Exit(1)
        try:
            loaded.append(Report.model_validate(payload))
        except ValueError as exc:
            out.print(f"[red]unreadable report {ref}: {exc}[/red]")
            raise typer.Exit(1) from exc

    result = diff.compare(loaded[0], loaded[1])
    if json_out:
        print(json.dumps(result, indent=2))
        raise typer.Exit(0)

    if result["target_changed"]:
        out.print(
            f"[yellow]different targets: {render.escape(result['old_target'])} -> "
            f"{render.escape(result['new_target'])}[/yellow]"
        )
    old_risk, new_risk = result["risk"]["old"] or "-", result["risk"]["new"] or "-"
    style = "red" if result["risk_rose"] else "green" if result["risk_fell"] else "dim"
    out.print(f"risk: {old_risk} -> [{style}]{new_risk}[/]")
    if not diff.is_empty(result):
        table = Table(box=box.SIMPLE_HEAD, title="changes")
        table.add_column("area")
        table.add_column("added/failing")
        table.add_column("removed/recovered")
        table.add_row(
            "breaches",
            render.escape(", ".join(result["breaches"]["added"]) or "-"),
            render.escape(", ".join(result["breaches"]["removed"]) or "-"),
        )
        table.add_row(
            "subdomains",
            render.escape(", ".join(result["subdomains"]["added"]) or "-"),
            render.escape(", ".join(result["subdomains"]["removed"]) or "-"),
        )
        table.add_row(
            "collectors",
            render.escape(", ".join(result["collectors"]["started_failing"]) or "-"),
            render.escape(", ".join(result["collectors"]["started_working"]) or "-"),
        )
        out.print(table)
        out.print(f"[dim]{result['breaches']['unchanged']} breaches unchanged[/dim]")
    else:
        out.print("[dim]no material changes[/dim]")


@app.command()
def schema(out: Path | None = typer.Option(None, "--out", "-o", help="Write to a file.")) -> None:
    """Print the JSON schema the model must satisfy."""
    from .models import Analysis

    payload = json.dumps(Analysis.model_json_schema(), indent=2)
    if out:
        out.write_text(payload + "\n", "utf-8")
        _console().print(f"[green]schema written[/green] {out}")
        return
    print(payload)


@app.command("cache")
def cache_cmd(
    clear: bool = typer.Option(False, "--clear", help="Delete every cached response."),
) -> None:
    """Inspect or clear the response cache."""
    out = _console()
    if clear:
        removed = cache_clear()
        out.print(f"[green]cleared {removed} cached responses[/green]")
        return
    count, size = cache_stats()
    usage = retention.disk_usage()
    out.print(f"{count} files, {size / 1024:.1f} KiB in the cache")
    out.print(
        f"total on disk: {usage['total'] / 1024:.1f} KiB "
        f"({usage['logs'] / 1024:.1f} KiB logs, {usage['reports'] / 1024:.1f} KiB reports)"
    )


def main() -> None:  # pragma: no cover - console script shim
    try:
        app()
    except OsintKitError as exc:
        render.console().print(f"[red]{exc}[/red]")
        sys.exit(1)


if __name__ == "__main__":  # pragma: no cover
    main()
