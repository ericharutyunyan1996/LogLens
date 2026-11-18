"""Timeline histogram: bins by binary search, per-bin series, spikes."""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import numpy as np

from loglens.core.histogram import build_histogram, find_spikes, nice_step, per_bin
from tests.helpers import make_source


def test_bins_count_lines_per_minute(tmp_path: Path) -> None:
    lines = []
    for minute in range(10):
        per_minute = 50 if minute == 6 else 5  # a burst at 10:06
        lines += [f"2026-11-13 10:{minute:02d}:{s:02d} INFO tick" for s in range(per_minute)]
    source = make_source(tmp_path, ("\n".join(lines) + "\n").encode())
    first = datetime(2026, 11, 13, 10, 0).astimezone()
    last = datetime(2026, 11, 13, 10, 9, 4).astimezone()
    errors = np.array([0, 30, 31], dtype=np.int64)  # e.g. error marks
    histogram = build_histogram(source, (first, last), bins=10, series={"Error": errors})
    assert histogram.step == timedelta(minutes=1) and histogram.bins == 10
    assert histogram.counts.tolist() == [5, 5, 5, 5, 5, 5, 50, 5, 5, 5]
    assert histogram.series["Error"].tolist()[:2] == [1, 0] and histogram.series["Error"][6] == 2
    assert histogram.spikes() == [6]
    assert histogram.bin_of_line(32) == 6 and histogram.line_edges[6] == 30


def test_helpers() -> None:
    assert nice_step(timedelta(hours=10), 120) == timedelta(minutes=5)
    assert per_bin(np.array([1, 2, 7]), np.array([0, 5, 10])).tolist() == [2, 1]
    assert find_spikes([3, 4, 3, 5, 4]) == []  # too small to call anything a spike
    assert find_spikes([20, 21, 19, 200, 22]) == [3]
