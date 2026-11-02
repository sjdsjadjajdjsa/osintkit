"""The orchestration: collect in parallel, synthesise, render, export."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Console

from . import collectors, normalise, render, retention, synthesis
from .config import Settings
from .errors import MissingAPIKey, OsintKitError, SynthesisError, TargetParseError
from .http import HttpClient
from .llm import LLMClient
from .logging_store import RunLogger, archive_report
from .models import CollectorResult, PromptBundle, Report
from .targets import resolve


@dataclass
class Outcome:
    report: Report
    error: str | None = None
    archived: Path | None = None
    extra: dict = field(default_factory=dict)


def _status(progress: Console, settings: Settings, message: str):
    if settings.extra.get("quiet_progress"):
        return contextlib.nullcontext()
    return progress.status(message, spinner="dots")


_PRUNED = False


def _auto_prune() -> None:
    global _PRUNED
    if _PRUNED:
        return
    _PRUNED = True
    raw = os.environ.get("OSINTKIT_RETENTION_DAYS", "30")
    try:
        days = int(raw)
    except ValueError:
        return
    if days > 0:
        retention.prune(days)


def new_run_id() -> str:
    return uuid.uuid4().hex[:12]


def _slug(target: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", target).strip("-")
    return (slug[:50] or "target").lower()


async def collect(
    target: str,
    target_type: str,
    settings: Settings,
    logger: RunLogger,
    http: HttpClient,
    only: set[str] | None,
    skip: set[str] | None,
) -> list[CollectorResult]:
    ctx = collectors.Context(target=target, target_type=target_type, settings=settings, http=http)
    specs = collectors.collectors_for(target_type)
    if only:
        specs = [s for s in specs if s.name in only]
    if skip:
        specs = [s for s in specs if s.name not in skip]

    results: list[CollectorResult] = []
    queue: asyncio.Queue = asyncio.Queue()
    for spec in specs:
        queue.put_nowait(spec)

    async def worker() -> None:
        while True:
            try:
                spec = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            try:
                result = await collectors.run_collector(spec, ctx)
            except Exception as exc:  # belt and braces, run_collector already catches
                result = CollectorResult(
                    collector=spec.name,
                    target=target,
                    target_type=target_type,
                    ok=False,
                    error=str(exc),
                )
            size = len(json.dumps(result.data, default=str)) if result.data is not None else 0
            logger.collector(
                collector=result.collector,
                ok=result.ok,
                skipped=result.skipped,
                note=result.note,
                error=result.error,
                elapsed_ms=result.elapsed_ms,
                size=size,
            )
            results.append(result)

    await asyncio.gather(*(worker() for _ in range(min(6, len(specs) or 1))))
    order = {spec.name: index for index, spec in enumerate(specs)}
    results.sort(key=lambda r: order.get(r.collector, 999))
    return results


async def execute(
    raw_target: str,
    settings: Settings,
    logger: RunLogger,
    console: Console,
    *,
    declared_type: str | None = None,
    only: set[str] | None = None,
    skip: set[str] | None = None,
) -> Outcome:
    started = time.perf_counter()
    progress = Console(stderr=True)
    _auto_prune()
    try:
        target, target_type = resolve(raw_target, declared_type)
    except TargetParseError as exc:
        logger.event("run_error", error=str(exc))
        raise

    logger.target = target
    logger.target_type = target_type
    logger.event(
        "run_start",
        base_url=settings.base_url,
        model=settings.model,
        dry_run=settings.dry_run,
        cache=settings.use_cache,
    )

    report = Report(
        target=target,
        target_type=target_type,
        model=settings.model,
        base_url=settings.base_url,
    )

    async with HttpClient(settings) as http:
        with _status(progress, settings, f"[cyan]running collectors for {target}…[/cyan]"):
            results = await collect(target, target_type, settings, logger, http, only, skip)
        report.collectors = results

        prompt_results, duplicates = normalise.merge_breaches(results)
        if duplicates:
            report.notes.append(f"{duplicates} duplicate breach records were merged across sources")
            logger.event("breaches_merged", duplicates=duplicates)

        bundle = PromptBundle(target=target, target_type=target_type, results=prompt_results)

        if settings.raw:
            report.notes.append("raw output: model not called")
            report.elapsed_ms = int((time.perf_counter() - started) * 1000)
            archived = archive_report(report.model_dump(mode="json"))
            logger.event("run_end", raw=True, report_path=str(archived) if archived else None)
            return Outcome(report=report, extra={"bundle": bundle}, archived=archived)

        if settings.dry_run:
            report.notes.append("dry run: model not called")
            report.elapsed_ms = int((time.perf_counter() - started) * 1000)
            synthesis_prompt = synthesis.render_prompt(bundle)
            if not settings.output_json:
                render.print_prompt(synthesis_prompt, console)
            archived = archive_report(report.model_dump(mode="json"))
            logger.event(
                "run_end",
                dry_run=True,
                prompt=synthesis_prompt,
                report_path=str(archived) if archived else None,
            )
            return Outcome(report=report, extra={"prompt": synthesis_prompt}, archived=archived)

        try:
            if not settings.resolved_api_key():
                raise MissingAPIKey("No API key. Set API_KEY or pass --api-key (dry run works without one).")
            async with LLMClient(settings, http) as client:
                with _status(progress, settings, "[cyan]synthesising briefing…[/cyan]"):
                    report.analysis = await synthesis.synthesize(
                        client, bundle, logger=logger, max_tokens=settings.max_tokens
                    )
        except (OsintKitError, SynthesisError) as exc:
            report.notes.append(f"synthesis failed: {exc}")
            logger.event("run_error", error=str(exc))
            report.elapsed_ms = int((time.perf_counter() - started) * 1000)
            path = archive_report(report.model_dump(mode="json"))
            return Outcome(report=report, error=str(exc), archived=path)

    report.elapsed_ms = int((time.perf_counter() - started) * 1000)
    path = archive_report(report.model_dump(mode="json"))
    logger.event(
        "run_end",
        risk_level=report.analysis.risk_level if report.analysis else None,
        model=settings.model,
        report_path=str(path) if path else None,
        elapsed_ms=report.elapsed_ms,
    )
    return Outcome(report=report, archived=path)


def write_markdown(report: Report, destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render.to_markdown(report), "utf-8")
    return destination


def default_markdown_path(target: str) -> Path:
    return Path.cwd() / f"{_slug(target)}-osint.md"
