"""Multi-line records and time navigation.

A *record* is a line that starts with a timestamp plus the continuation lines after it (stack traces, dumped bodies,
header blocks). Record starts are found with the file's dominant timestamp pattern, searched like any other query
(parallel for big files). Time navigation uses binary search over record starts, so it is O(log n) line reads.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

import numpy as np

from .search import SearchQuery
from .text_source import TextLogSource
from .timeparse import parse_line_time
from .timestamps import MAX_OFFSET, dominant_pattern, find_timestamp

SAMPLE_LINES = 2_000
ALL_RECORDS_SHARE = 0.995  # if nearly every line has a timestamp, records are single lines
MIN_RECORD_SHARE = 0.02  # below this the "timestamp" is noise, not a record header
MAX_RECORD_LINES = 2_000  # a record longer than this is shown/expanded clipped (to a window around the line asked for)
MAX_EXPANDED_LINES = 2_000_000
CONTINUATION_PROBE = 50  # first block read around a binary-search probe without a timestamp (a record's continuations)
TIME_PROBE = 2_000  # lines scanned back (then forward) for a timestamp around such a probe; beyond: time unknown
BOUNDS_PROBE = 200  # lines scanned at each end of the file for the first/last timestamp


@dataclass(frozen=True)
class RecordLayout:
    """Where records start; ``starts`` is None when every line is its own record."""

    pattern_name: str | None
    starts: np.ndarray | None

    @property
    def multi_line(self) -> bool:
        return self.starts is not None

    def record_of(self, line: int, total_lines: int) -> tuple[int, int]:
        """[start, end) of the record containing ``line``; a record longer than :data:`MAX_RECORD_LINES` is clipped
        to that many lines around ``line`` (from the record start when ``line`` is near it)."""
        if self.starts is None or not len(self.starts):
            return line, line + 1
        begin, end = _clipped_windows(np.asarray([line], dtype=np.int64), self.starts, total_lines)
        return int(begin[0]), int(end[0])


def _clipped_windows(hits: np.ndarray, starts: np.ndarray, total_lines: int) -> tuple[np.ndarray, np.ndarray]:
    """Per hit, [begin, end) of its record, clipped to MAX_RECORD_LINES lines that still contain the hit.

    Lines before the first record start form a pseudo-record (a header block). Both arrays are non-decreasing when
    ``hits`` is sorted.
    """
    index = np.searchsorted(starts, hits, side="right") - 1
    record_begin = np.where(index >= 0, starts[np.maximum(index, 0)], 0).astype(np.int64)
    record_end = np.where(index + 1 < len(starts), starts[np.minimum(index + 1, len(starts) - 1)], total_lines)
    record_end = record_end.astype(np.int64)
    centred = np.minimum(hits - MAX_RECORD_LINES // 2, record_end - MAX_RECORD_LINES)  # a hit deep in a long record
    begin = np.where(hits < record_begin + MAX_RECORD_LINES, record_begin, centred)
    end = np.minimum(record_end, begin + MAX_RECORD_LINES)
    return begin, end


def compact_lines(lines: np.ndarray) -> np.ndarray:
    """Store line numbers as int32 when they fit (record starts of a 10 M-line log: 40 MB instead of 80 MB)."""
    if len(lines) and int(lines[-1]) >= np.iinfo(np.int32).max:
        return lines.astype(np.int64, copy=False)
    return lines.astype(np.int32, copy=False)


def record_start_query(source: TextLogSource) -> tuple[str | None, SearchQuery | None]:
    """Detect the dominant timestamp layout from a sample; return a query matching record-start lines.

    Returns (pattern name, None) when no grouping is needed (no timestamps, or every line has one).
    """
    count = source.line_count()
    if count == 0:
        return None, None
    rows = np.unique(np.linspace(0, count - 1, min(count, SAMPLE_LINES)).astype(np.int64))
    sample = source.get_lines_at(rows)
    pattern, share = dominant_pattern(sample)
    if pattern is None or share >= ALL_RECORDS_SHARE or share < MIN_RECORD_SHARE:
        return (pattern.name if pattern else None), None
    offsets = [m.start for line in sample if (m := find_timestamp(line)) and m.pattern is pattern]
    max_offset = min(max(offsets, default=0), MAX_OFFSET)
    regex = f"^.{{0,{max_offset}}}?(?:{pattern.regex.pattern})" if max_offset else f"^(?:{pattern.regex.pattern})"
    return pattern.name, SearchQuery(regex, regex=True, case_sensitive=True)


def expand_to_records(hits: np.ndarray, layout: RecordLayout, total_lines: int) -> np.ndarray:
    """All lines of the records containing the sorted ``hits`` (sorted, unique); hits unchanged for single-line
    records. A record longer than :data:`MAX_RECORD_LINES` contributes windows of that size around its hits, so every
    hit is always in the result."""
    if layout.starts is None or not len(hits) or not len(layout.starts):
        return hits
    begin, end = _clipped_windows(np.asarray(hits, dtype=np.int64), layout.starts, total_lines)
    reach = np.maximum.accumulate(end)  # union of the windows: a new run starts past everything so far
    first = np.flatnonzero(np.concatenate([[True], begin[1:] > reach[:-1]]))
    last = np.concatenate([first[1:] - 1, [len(begin) - 1]])
    run_begin, run_end = begin[first], reach[last]
    lengths = run_end - run_begin
    if int(lengths.sum()) > MAX_EXPANDED_LINES:
        return hits
    offsets = np.repeat(run_begin - np.cumsum(np.concatenate([[0], lengths[:-1]])), lengths)
    expanded: np.ndarray = np.arange(int(lengths.sum()), dtype=np.int64) + offsets
    return expanded


def line_at_time(
    source: TextLogSource,
    moment: datetime,
    starts: np.ndarray | None = None,
    time_of: Callable[[str], datetime | None] = parse_line_time,
) -> int:
    """First line whose timestamp is >= ``moment`` (binary search; assumes time grows through the file).

    A line without a timestamp has the time of the record it belongs to (the nearest timestamp before it); lines
    before the first timestamp take the first one's. Only a probe with no timestamp within :data:`TIME_PROBE` lines
    either way counts as earlier than ``moment``.
    """
    candidates = starts if starts is not None else None
    total = source.line_count()
    low, high = 0, len(candidates) if candidates is not None else total
    while low < high:
        middle = (low + high) // 2
        line = int(candidates[middle]) if candidates is not None else middle
        stamp = _time_near(source, line, total, time_of)
        if stamp is None or stamp < moment:
            low = middle + 1
        else:
            high = middle
    if candidates is not None:
        return int(candidates[low]) if low < len(candidates) else total
    return low


def _time_near(
    source: TextLogSource, line: int, total: int, time_of: Callable[[str], datetime | None]
) -> datetime | None:
    """Time of the record ``line`` belongs to: its own timestamp, else the nearest one before it (continuation lines,
    dumps), else — lines before the first record — the nearest one after it; None if none within TIME_PROBE lines.

    Lines are read in blocks growing from CONTINUATION_PROBE, so the usual short record costs one small read.
    """
    stamp = time_of(source.get_line(line))
    if stamp is not None:
        return stamp
    floor, end, block = max(0, line - TIME_PROBE), line, CONTINUATION_PROBE
    while end > floor:
        begin = max(floor, end - block)
        stamp = next((t for text in reversed(source.get_lines(begin, end - begin)) if (t := time_of(text))), None)
        if stamp is not None:
            return stamp
        end, block = begin, block * 2
    ceiling, begin, block = min(total, line + 1 + TIME_PROBE), line + 1, CONTINUATION_PROBE
    while begin < ceiling:
        count = min(block, ceiling - begin)
        stamp = next((t for text in source.get_lines(begin, count) if (t := time_of(text))), None)
        if stamp is not None:
            return stamp
        begin, block = begin + count, block * 2
    return None


def time_bounds(
    source: TextLogSource, time_of: Callable[[str], datetime | None] = parse_line_time
) -> tuple[datetime | None, datetime | None]:
    """Timestamps of the first and last timestamped lines (for default time-range values)."""
    total = source.line_count()
    first = next((t for i in range(min(total, BOUNDS_PROBE)) if (t := time_of(source.get_line(i)))), None)
    last = next(
        (t for i in range(total - 1, max(total - BOUNDS_PROBE, -1), -1) if (t := time_of(source.get_line(i)))), None
    )
    return first, last


def line_range_for(
    source: TextLogSource,
    start: datetime | None,
    end: datetime | None,
    *,
    starts: np.ndarray | None = None,
    time_of: Callable[[str], datetime | None] = parse_line_time,
) -> tuple[int, int]:
    """Lines [first, last) whose time is in [start, end); open sides extend to the file's start/end."""
    total = source.line_count()
    first = line_at_time(source, start, starts, time_of) if start is not None else 0
    last = line_at_time(source, end, starts, time_of) if end is not None else total
    return first, max(first, last)
