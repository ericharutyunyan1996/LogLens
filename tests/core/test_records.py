"""Multi-line records, record expansion and time navigation."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import numpy as np

from loglens.core.records import RecordLayout, expand_to_records, line_at_time, record_start_query, time_bounds
from loglens.core.search import search_source
from tests.helpers import make_source

RECORDS = [
    "2026-11-13 10:00:00,000 [1] INFO  Svc - started",
    "2026-11-13 10:00:01,000 [1] ERROR Svc - failed",
    "System.InvalidOperationException: boom",
    "   at Svc.Run()",
    "   at Svc.Main()",
    "2026-11-13 10:00:02,000 [1] INFO  Svc - retry",
    "Content-Type : application/json",
    "2026-11-13 10:05:00,000 [1] INFO  Svc - done",
]


def test_detect_record_starts_and_ranges(tmp_path: Path) -> None:
    source = make_source(tmp_path, ("\n".join(RECORDS) + "\n").encode())
    name, query = record_start_query(source)
    assert name == "iso8601" and query is not None
    starts = search_source(source, query, parallel=False)
    assert starts.tolist() == [0, 1, 5, 7]
    layout = RecordLayout(name, starts)
    assert layout.record_of(3, 8) == (1, 5) and layout.record_of(6, 8) == (5, 7) and layout.record_of(7, 8) == (7, 8)


def test_single_line_logs_need_no_grouping(tmp_path: Path) -> None:
    lines = [f"2026-11-13 10:00:{i:02d},000 INFO line {i}" for i in range(50)]
    source = make_source(tmp_path, ("\n".join(lines)).encode())
    assert record_start_query(source) == ("iso8601", None)
    assert RecordLayout("iso8601", None).record_of(7, 50) == (7, 8)


def test_expand_hits_to_whole_records() -> None:
    layout = RecordLayout("iso8601", np.array([0, 1, 5, 7]))
    assert expand_to_records(np.array([3]), layout, 8).tolist() == [1, 2, 3, 4]
    assert expand_to_records(np.array([0, 2, 6]), layout, 8).tolist() == [0, 1, 2, 3, 4, 5, 6]
    assert expand_to_records(np.array([2]), RecordLayout(None, None), 8).tolist() == [2]


def test_line_at_time_and_bounds(tmp_path: Path) -> None:
    source = make_source(tmp_path, ("\n".join(RECORDS) + "\n").encode())
    starts = np.array([0, 1, 5, 7])
    at = datetime(2026, 11, 13, 10, 0, 1).astimezone()
    assert line_at_time(source, at, starts) == 1
    assert line_at_time(source, datetime(2026, 11, 13, 10, 3).astimezone(), starts) == 7
    assert line_at_time(source, datetime(2026, 11, 13, 11, 0).astimezone(), starts) == 8  # after the end
    assert line_at_time(source, at) == 1  # without record starts (line-level binary search)
    first, last = time_bounds(source)
    assert first is not None and last is not None and (last - first).seconds == 300
