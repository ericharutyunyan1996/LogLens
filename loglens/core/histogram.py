"""Timeline histogram of a log: lines (or records) per time bin, issue counts per bin, and spikes.

No per-line timestamp parsing: bin edges are turned into line numbers by binary search (``records.line_at_time``),
so a histogram costs O(bins · log n) line reads whatever the file size. Counts of any line set (error marks, search
hits) per bin are then a ``searchsorted`` over those edges. Assumes time grows through the file, like the rest of
time navigation.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta

import numpy as np

from .records import line_at_time
from .text_source import TextLogSource
from .timeparse import parse_line_time

DEFAULT_BINS = 120
# "Nice" bin widths so bins line up with clock boundaries a human reads easily.
NICE_STEPS = tuple(
    timedelta(seconds=s)
    for s in (1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400, 172800, 604800)
)
SPIKE_Z = 3.5  # robust z-score (median / MAD) above which a bin counts as a spike
SPIKE_MIN_COUNT = 10  # ignore "spikes" in nearly empty logs


@dataclass(frozen=True)
class Histogram:
    start: datetime
    step: timedelta
    line_edges: np.ndarray  # len(bins) + 1 line numbers: bin i covers lines [line_edges[i], line_edges[i+1])
    counts: np.ndarray  # lines (or records) per bin
    series: dict[str, np.ndarray] = field(default_factory=dict)  # name -> count per bin (errors, warnings, hits)

    @property
    def bins(self) -> int:
        return len(self.counts)

    def bin_start(self, index: int) -> datetime:
        return self.start + self.step * index

    def bin_of_line(self, line: int) -> int:
        return int(np.clip(np.searchsorted(self.line_edges, line, side="right") - 1, 0, max(self.bins - 1, 0)))

    def spikes(self, name: str | None = None) -> list[int]:
        """Bins whose count (or ``series[name]``) is far above the typical bin (robust z-score)."""
        values = self.counts if name is None else self.series.get(name, np.zeros(0))
        return find_spikes(values)


def nice_step(span: timedelta, bins: int) -> timedelta:
    """The smallest nice bin width giving at most ``bins`` bins over ``span``; past the table (a span of years,
    e.g. a stray old timestamp), whole days — so a histogram never has more than about ``bins`` bins."""
    target = span / max(bins, 1)
    nice = next((step for step in NICE_STEPS if step >= target), None)
    return nice if nice is not None else timedelta(days=math.ceil(target / timedelta(days=1)))


def _floor(moment: datetime, step: timedelta) -> datetime:
    seconds = int(step.total_seconds())
    local = moment.astimezone()
    midnight = local.replace(hour=0, minute=0, second=0, microsecond=0)
    offset = int((local - midnight).total_seconds()) // seconds * seconds
    return midnight + timedelta(seconds=offset)


def build_histogram(
    source: TextLogSource,
    bounds: tuple[datetime, datetime],
    *,
    bins: int = DEFAULT_BINS,
    starts: np.ndarray | None = None,
    time_of: Callable[[str], datetime | None] = parse_line_time,
    series: dict[str, np.ndarray] | None = None,
) -> Histogram:
    """Histogram over [first, last] time; ``series`` are sorted line arrays counted per bin (e.g. error lines)."""
    first, last = bounds
    step = nice_step(max(last - first, timedelta(seconds=1)), bins)
    start = _floor(first, step)
    count = max(int((last - start) / step) + 1, 1)
    total = source.line_count()
    edges = [0]
    for index in range(1, count):
        edges.append(max(line_at_time(source, start + step * index, starts, time_of), edges[-1]))
    edges.append(total)
    line_edges = np.asarray(edges, dtype=np.int64)
    counts = per_bin(starts, line_edges) if starts is not None else np.diff(line_edges)
    return Histogram(start, step, line_edges, counts, {k: per_bin(v, line_edges) for k, v in (series or {}).items()})


def per_bin(lines: np.ndarray, line_edges: np.ndarray) -> np.ndarray:
    """How many of the sorted ``lines`` fall into each bin."""
    positions = np.searchsorted(lines, line_edges, side="left")
    return np.diff(positions).astype(np.int64)


def find_spikes(values: Sequence[int] | np.ndarray) -> list[int]:
    data = np.asarray(values, dtype=np.float64)
    if len(data) < 3 or data.max(initial=0) < SPIKE_MIN_COUNT:
        return []
    median = float(np.median(data))
    mad = float(np.median(np.abs(data - median))) or 1.0
    scores = 0.6745 * (data - median) / mad  # 0.6745: makes the MAD comparable to a standard deviation
    return [int(i) for i in np.flatnonzero(scores > SPIKE_Z)]
