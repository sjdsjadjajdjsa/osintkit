"""Age-based pruning for the cache, logs, and archived reports."""

from __future__ import annotations

import time
from pathlib import Path

from .config import cache_dir, ensure_dirs, log_dir, reports_dir

DAY = 86_400


def _sweep(root: Path, cutoff: float) -> list[Path]:
    if not root.exists():
        return []
    removed: list[Path] = []
    for path in sorted(root.rglob("*"), reverse=True):
        if not path.is_file():
            continue
        try:
            if path.stat().st_mtime < cutoff:
                path.unlink()
                removed.append(path)
        except OSError:
            continue
    for directory in sorted(root.rglob("*"), reverse=True):
        if directory.is_dir():
            try:
                directory.rmdir()
            except OSError:
                continue
    return removed


def prune(days: int = 30, *, dry_run: bool = False) -> dict[str, int]:
    """Delete cache, log, and report files older than `days`.

    Returns the number of files that were (or would be) removed per area.
    """
    ensure_dirs()
    cutoff = time.time() - max(days, 1) * DAY
    if dry_run:
        counts = {}
        for name, root in (("cache", cache_dir()), ("logs", log_dir()), ("reports", reports_dir())):
            counts[name] = _count_older(root, cutoff)
        return counts

    return {
        "cache": len(_sweep(cache_dir(), cutoff)),
        "logs": len(_sweep(log_dir(), cutoff)),
        "reports": len(_sweep(reports_dir(), cutoff)),
    }


def _count_older(root: Path, cutoff: float) -> int:
    if not root.exists():
        return 0
    total = 0
    for path in root.rglob("*"):
        try:
            if path.is_file() and path.stat().st_mtime < cutoff:
                total += 1
        except OSError:
            continue
    return total


def disk_usage() -> dict[str, int]:
    sizes: dict[str, int] = {}
    for name, root in (("cache", cache_dir()), ("logs", log_dir()), ("reports", reports_dir())):
        total = 0
        if root.exists():
            for path in root.rglob("*"):
                try:
                    if path.is_file():
                        total += path.stat().st_size
                except OSError:
                    continue
        sizes[name] = total
    sizes["total"] = sum(sizes.values())
    return sizes
