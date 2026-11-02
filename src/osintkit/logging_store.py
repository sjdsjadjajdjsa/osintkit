"""Timestamped JSONL run logs and the report archive behind `history`."""

from __future__ import annotations

import json
import os
import re
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .config import ensure_dirs, log_dir, reports_dir


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


def _slug(target: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", target).strip("-")
    return slug[:60] or "target"


class RunLogger:
    """Appends JSONL lines. One file per day, shared by all runs."""

    def __init__(self, run_id: str, target: str = "", target_type: str = "") -> None:
        ensure_dirs()
        self.run_id = run_id
        self.target = target
        self.target_type = target_type
        self.path = log_dir() / f"{datetime.now(UTC):%Y-%m-%d}.jsonl"

    def event(self, kind: str, **fields: Any) -> None:
        record = {
            "ts": _now(),
            "run_id": self.run_id,
            "kind": kind,
            "target": self.target,
            "target_type": self.target_type,
            **fields,
        }
        line = json.dumps(record, ensure_ascii=False, default=str)
        try:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        except OSError:
            return

    def collector(
        self,
        *,
        collector: str,
        ok: bool,
        skipped: bool,
        note: str | None,
        error: str | None,
        elapsed_ms: int,
        size: int,
    ) -> None:
        self.event(
            "collector",
            collector=collector,
            ok=ok,
            skipped=skipped,
            note=note,
            error=error,
            elapsed_ms=elapsed_ms,
            payload_size=size,
        )

    def request(
        self,
        *,
        base_url: str,
        model: str,
        attempt: int,
        dry_run: bool,
        messages: list[dict[str, str]],
        max_tokens: int,
    ) -> None:
        self.event(
            "model_request",
            base_url=base_url,
            model=model,
            attempt=attempt,
            dry_run=dry_run,
            max_tokens=max_tokens,
            messages=messages,
        )

    def response(
        self, *, attempt: int, ok: bool, error: str | None, elapsed_ms: int, content: str | None
    ) -> None:
        self.event(
            "model_response",
            attempt=attempt,
            ok=ok,
            error=error,
            elapsed_ms=elapsed_ms,
            content_length=len(content or ""),
            content=content,
        )


def archive_report(report: dict[str, Any]) -> Path | None:
    """Persist a full report so `history --show` can replay it."""
    try:
        ensure_dirs()
        root = reports_dir()
        root.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
        path = (
            root / f"{stamp}-{_slug(str(report.get('target', 'target')))}-{int(time.time() * 1000) % 1000}.json"
        )
        path.write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str), "utf-8")
        return path
    except OSError:
        return None


def iter_log_files() -> list[Path]:
    root = log_dir()
    if not root.exists():
        return []
    return sorted(root.glob("*.jsonl"), reverse=True)


def read_runs(limit: int = 20) -> list[dict[str, Any]]:
    """Collapse log lines into one summary per run, newest first."""
    runs: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for path in iter_log_files():
        try:
            lines = path.read_text("utf-8").splitlines()
        except OSError:
            continue
        for line in lines:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            run_id = record.get("run_id")
            if not run_id:
                continue
            if run_id not in runs:
                runs[run_id] = {
                    "run_id": run_id,
                    "started": record.get("ts"),
                    "target": record.get("target"),
                    "target_type": record.get("target_type"),
                    "report": None,
                    "collectors_ok": 0,
                    "collectors_failed": 0,
                    "collectors_skipped": 0,
                    "risk": None,
                    "model": None,
                }
                order.append(run_id)
            entry = runs[run_id]
            kind = record.get("kind")
            if kind == "collector":
                if record.get("skipped"):
                    entry["collectors_skipped"] += 1
                elif record.get("ok"):
                    entry["collectors_ok"] += 1
                else:
                    entry["collectors_failed"] += 1
            elif kind == "run_end":
                entry["report"] = record.get("report_path")
                entry["risk"] = record.get("risk_level")
                entry["model"] = record.get("model")
                entry["ended"] = record.get("ts")
    summaries = list(reversed(order))[:limit]
    return [runs[r] for r in summaries]


def find_report_for_run(run_id: str) -> str | None:
    """Return the archived report path recorded for a run id, if any."""
    for path in iter_log_files():
        try:
            lines = path.read_text("utf-8").splitlines()
        except OSError:
            continue
        for line in lines:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record.get("run_id") == run_id and record.get("kind") == "run_end":
                return record.get("report_path")
    return None


def run_exists(run_id: str) -> bool:
    return any(run["run_id"] == run_id for run in read_runs(limit=500))


def read_report(path: str | Path) -> dict[str, Any] | None:
    try:
        return json.loads(Path(path).read_text("utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
