"""LogDocument records, time-range filters and per-log clock (headless)."""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import numpy as np
import pytest
from PySide6.QtWidgets import QApplication

from loglens.core.filters import FilterSpec, FilterTerm, TimeRange, with_context
from loglens.core.highlight import default_rules
from loglens.core.records import RecordLayout
from loglens.core.search import SearchQuery, shutdown_pool
from loglens.core.timeparse import LineClock
from loglens.services.log_document import LogDocument


@pytest.fixture
def record_log(tmp_path: Path) -> Path:
    lines = []
    for minute in range(60):
        lines.append(
            f"2026-11-13 10:{minute:02d}:00,000 [7] {'ERROR' if minute % 10 == 0 else 'INFO '} Svc - step {minute}"
        )
        if minute % 10 == 0:
            lines += ["System.TimeoutException: timed out", "   at Svc.Step()", "   at Svc.Run()"]
    path = tmp_path / "records.log"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def test_records_detected_and_text(qapp: QApplication, wait_for: Callable[..., None], record_log: Path) -> None:
    doc = LogDocument(record_log, default_rules())
    doc.start()
    wait_for(lambda: doc.records.multi_line)
    assert doc.record_range(2) == (0, 4)
    assert doc.record_text(3).splitlines() == [
        "2026-11-13 10:00:00,000 [7] ERROR Svc - step 0",
        "System.TimeoutException: timed out",
        "   at Svc.Step()",
        "   at Svc.Run()",
    ]
    assert doc.record_range(4) == (4, 5)
    with record_log.open("a", encoding="utf-8") as f:  # tail growth extends the record layout
        f.write("2026-11-13 11:00:00,000 [7] ERROR Svc - late\nSystem.Exception: late\n")
    doc.check_file()
    wait_for(lambda: doc.source.line_count() == 80 and doc.record_range(79) == (78, 80))
    doc.close()
    shutdown_pool()


def test_file_rotated_during_background_job_is_not_an_error(
    qapp: QApplication, wait_for: Callable[..., None], record_log: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Regression: a log rotated (renamed + recreated) while the histogram is computed is transient, not an error."""
    doc = LogDocument(record_log, default_rules())
    doc.start()
    wait_for(lambda: doc.records.multi_line)
    record_log.rename(record_log.with_suffix(".log.1"))  # the writer rotated; the new file isn't there yet
    with caplog.at_level(logging.INFO, logger="loglens.services.log_document"):
        doc.enable_histogram(True)
        wait_for(lambda: any("changed while reading" in r.message for r in caplog.records), timeout=10)
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]
    doc.close()
    shutdown_pool()


def test_time_range_and_go_to_time(qapp: QApplication, wait_for: Callable[..., None], record_log: Path) -> None:
    doc = LogDocument(record_log, default_rules())
    finished: list[int] = []
    doc.searchFinished.connect(lambda count, _s: finished.append(count))
    doc.start()
    wait_for(lambda: doc.records.multi_line)
    local = datetime(2026, 11, 13, 10, 20).astimezone()
    window = TimeRange(local, local + timedelta(minutes=15))
    doc.run_filter(FilterSpec((FilterTerm(SearchQuery("ERROR")),), time_range=window))
    wait_for(lambda: bool(finished))
    assert [doc.source.get_line(i).split(" - ")[1] for i in doc.hits] == ["step 20", "step 30"]

    finished.clear()
    doc.run_filter(FilterSpec(time_range=TimeRange(local, local + timedelta(minutes=2))))  # range only
    wait_for(lambda: bool(finished))
    assert [doc.source.get_line(i)[11:16] for i in doc.hits][:1] == ["10:20"] and len(doc.hits) == 5

    assert doc.source.get_line(doc.line_at_time(local + timedelta(seconds=30))).startswith("2026-11-13 10:21")
    first, last = doc.time_bounds()
    assert first is not None and last is not None and (last - first) == timedelta(minutes=59)

    doc.set_clock(LineClock(UTC))  # the log was written in UTC: same wall time, different instant
    utc_moment = datetime(2026, 11, 13, 10, 30, tzinfo=UTC)
    assert doc.source.get_line(doc.line_at_time(utc_moment)).startswith("2026-11-13 10:30")
    doc.close()
    shutdown_pool()


def test_with_context_whole_records() -> None:
    layout = RecordLayout("iso8601", np.array([0, 4, 5, 9]))
    rows = with_context(np.array([4, 6]), 0, 0, 12, records=layout)
    assert rows.lines.tolist() == [4, 5, 6, 7, 8]
    assert rows.is_hit.tolist() == [True, False, True, False, False]
    rows = with_context(np.array([0, 10]), 0, 0, 12, records=layout)
    assert rows.lines.tolist() == [0, 1, 2, 3, 9, 10, 11] and rows.gap_before.tolist()[4]


def test_clock_keeps_explicit_offsets() -> None:
    clock = LineClock(UTC, timedelta(minutes=5))
    explicit = clock("2026-11-13T10:00:00+02:00 boom")
    assert explicit == datetime(2026, 11, 13, 8, 5, tzinfo=UTC)
    naive = clock("2026-11-13 10:00:00 boom")
    assert naive == datetime(2026, 11, 13, 10, 5, tzinfo=UTC)
    assert "UTC" in clock.describe() and "+00:05" in clock.describe()
