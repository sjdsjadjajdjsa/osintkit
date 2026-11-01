import os
import time
from pathlib import Path

from osintkit import retention
from osintkit.config import cache_write


def _age(path: Path, days: int) -> None:
    stamp = time.time() - days * retention.DAY
    os.utime(path, (stamp, stamp))


def test_prune_removes_only_old_files():
    cache_write("ns", "old", 1)
    cache_write("ns", "new", 2)
    old = next((Path(os.environ["OSINTKIT_HOME"]) / "cache").rglob("*.json"))
    _age(old, 40)
    result = retention.prune(30)
    assert result["cache"] >= 1
    remaining = list((Path(os.environ["OSINTKIT_HOME"]) / "cache").rglob("*.json"))
    assert len(remaining) == 1


def test_prune_dry_run_keeps_files():
    cache_write("ns", "old", 1)
    old = next((Path(os.environ["OSINTKIT_HOME"]) / "cache").rglob("*.json"))
    _age(old, 40)
    counts = retention.prune(30, dry_run=True)
    assert counts["cache"] == 1
    assert old.exists()


def test_disk_usage_counts_bytes():
    cache_write("ns", "k", {"payload": "x" * 100})
    usage = retention.disk_usage()
    assert usage["cache"] > 100
    assert usage["total"] >= usage["cache"]


def test_prune_reports_zero_without_dirs():
    counts = retention.prune(1)
    assert counts == {"cache": 0, "logs": 0, "reports": 0}
