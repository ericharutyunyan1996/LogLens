"""Alerts on appended lines and folder newest-file following (headless)."""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from pathlib import Path

from PySide6.QtWidgets import QApplication

from loglens.core.highlight import default_rules
from loglens.core.search import SearchQuery, shutdown_pool
from loglens.core.watch import Alert, AlertRule, WatchProfile, new_pattern_rule
from loglens.services.log_document import LogDocument
from loglens.services.watch_service import AlertMonitor, FolderWatcher


def test_alert_fires_on_appended_lines(qapp: QApplication, wait_for: Callable[..., None], tmp_path: Path) -> None:
    path = tmp_path / "live.log"
    path.write_text("2026-11-13 10:00:00 INFO start\n2026-11-13 10:00:01 ERROR old error\n", encoding="utf-8")
    doc = LogDocument(path, default_rules())
    doc.start()
    wait_for(lambda: not doc.is_indexing)
    monitor = AlertMonitor([AlertRule("errors", SearchQuery("ERROR"), threshold=2)])
    fired: list[Alert] = []
    monitor.alertFired.connect(lambda alert, _doc: fired.append(alert))
    monitor.watch(doc)

    with path.open("a", encoding="utf-8") as f:
        f.write("2026-11-13 10:00:02 ERROR one\n2026-11-13 10:00:03 INFO ok\n")
    doc.check_file()
    wait_for(lambda: doc.source.line_count() == 4)
    assert fired == []  # existing lines don't count, and one new error is below the threshold
    with path.open("a", encoding="utf-8") as f:
        f.write("2026-11-13 10:00:04 ERROR two\n")
    doc.check_file()
    wait_for(lambda: len(fired) == 1)
    assert fired[0].count == 2 and fired[0].first_line == 2 and fired[0].last_line == 4
    assert "errors: 2 matches in live.log" in AlertMonitor.describe(fired[0])
    doc.close()
    shutdown_pool()


def test_new_pattern_alert(qapp: QApplication, wait_for: Callable[..., None], tmp_path: Path) -> None:
    path = tmp_path / "live.log"
    known = [f"2026-11-13 10:00:{i:02d} INFO Sync - copied {i * 3} files to share {i}" for i in range(30)]
    path.write_text("\n".join(known) + "\n", encoding="utf-8")
    doc = LogDocument(path, default_rules())
    doc.start()
    wait_for(lambda: not doc.is_indexing)
    monitor = AlertMonitor([new_pattern_rule()])
    fired: list[Alert] = []
    monitor.alertFired.connect(lambda alert, _doc: fired.append(alert))
    monitor.watch(doc)

    def append(line: str) -> None:
        with path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
        count = doc.source.line_count()
        doc.check_file()
        wait_for(lambda: doc.source.line_count() == count + 1)

    append("2026-11-13 10:01:00 INFO Sync - copied 99 files to share 7")  # first batch: learns the baseline
    wait_for(lambda: monitor._detectors.get(id(doc)) is not None)
    append("2026-11-13 10:01:01 INFO Sync - copied 12 files to share 2")  # same kind of message: quiet
    wait_for(lambda: not monitor._busy)  # the batch was evaluated (on a worker)
    assert fired == []
    append("2026-11-13 10:01:02 ERROR Sync - certificate for share 2 expired")
    wait_for(lambda: len(fired) == 1)
    assert "certificate" in fired[0].sample
    assert "a new kind of message" in AlertMonitor.describe(fired[0])
    doc.close()
    shutdown_pool()


def test_folder_watcher_reports_newer_file(qapp: QApplication, wait_for: Callable[..., None], tmp_path: Path) -> None:
    first = tmp_path / "app-1.log"
    first.write_text("x", encoding="utf-8")
    watcher = FolderWatcher(WatchProfile("logs", str(tmp_path)), first)
    seen: list[str] = []
    watcher.newestChanged.connect(seen.append)
    second = tmp_path / "app-2.log"
    second.write_text("y", encoding="utf-8")
    later = time.time() + 10
    os.utime(second, (later, later))
    watcher.poll()
    wait_for(lambda: bool(seen))
    assert seen == [str(second)]
    watcher.stop()
