"""Unified timeline: merge several logs (and Windows events) into one time-ordered file.

Each source is read record by record (a timestamped line plus its continuation lines) and the records are merged by
their real time — each source's :class:`~loglens.core.timeparse.LineClock` turns its timestamps into aware datetimes,
so logs written in different time zones line up. Every merged record starts with a uniform local timestamp and the
source label, so time navigation, the histogram and filters work on the result; the original line follows unchanged.

Streaming k-way merge: memory holds one record per source, whatever the file sizes.
"""

from __future__ import annotations

import heapq
import threading
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import numpy as np

from .text_source import TextLogSource
from .timeparse import parse_line_time

CHUNK_LINES = 20_000
MAX_TIMELINE_LINES = 10_000_000  # merged output stops here (with a note) — a timeline beyond this is not readable
MAX_RECORD_LINES = 500  # continuation lines kept per record in the timeline
_BEGINNING = datetime.min.replace(tzinfo=UTC)
_UNKNOWN_STAMP = "????-??-?? ??:??:??.???"


@dataclass(frozen=True)
class TimelineSource:
    label: str  # shown in every merged record, e.g. the file name
    source: TextLogSource
    time_of: Callable[[str], datetime | None] = parse_line_time
    starts: np.ndarray | None = None  # record starts when known (skips parsing continuation lines)


@dataclass(frozen=True, slots=True)
class _Record:
    time: datetime
    lines: tuple[str, ...]


def _start_flags(starts: np.ndarray | None, first: int, count: int) -> list[bool] | None:
    """Which of lines [first, first + count) are record starts (None: any line may be one) — O(count) memory,
    whatever the number of starts."""
    if starts is None:
        return None
    low, high = np.searchsorted(starts, (first, first + count), side="left")
    flags = np.zeros(count, dtype=bool)
    flags[np.asarray(starts[low:high], dtype=np.int64) - first] = True
    return flags.tolist()


def _records(item: TimelineSource, cancel: threading.Event | None) -> Iterator[_Record]:
    """Records of one source in file order; lines before the first timestamp go with the file's first moment."""
    source, starts = item.source, item.starts
    total = source.line_count()
    current: list[str] = []
    current_time: datetime | None = None
    for first in range(0, total, CHUNK_LINES):
        if cancel is not None and cancel.is_set():
            return
        lines = source.get_lines(first, min(CHUNK_LINES, total - first))
        flags = _start_flags(starts, first, len(lines))
        for offset, line in enumerate(lines):
            moment = item.time_of(line) if flags is None or flags[offset] else None
            if moment is not None:
                if current:
                    yield _Record(current_time or moment, tuple(current))
                current, current_time = [line], moment
            elif len(current) < MAX_RECORD_LINES:
                current.append(line)
    if current:
        yield _Record(current_time or _BEGINNING, tuple(current))


def merge_records(
    sources: Sequence[TimelineSource], cancel: threading.Event | None = None
) -> Iterator[tuple[datetime, str, tuple[str, ...]]]:
    """(time, label, lines) of all sources' records in time order (stable: equal times keep source order)."""
    streams = [_keyed(index, item, cancel) for index, item in enumerate(sources)]
    for moment, index, _sequence, lines in heapq.merge(*streams):
        yield moment, sources[index].label, lines


def _keyed(
    index: int, item: TimelineSource, cancel: threading.Event | None
) -> Iterator[tuple[datetime, int, int, tuple[str, ...]]]:
    """Merge keys for one source: (time, source index, sequence) keeps equal times stable."""
    for sequence, record in enumerate(_records(item, cancel)):
        yield record.time, index, sequence, record.lines


def _local_stamp(moment: datetime) -> str:
    """``moment`` as local ``YYYY-MM-DD HH:MM:SS.mmm``, or a placeholder when it has no local time (the file's
    unknown beginning, or an instant the C runtime can't convert — Windows only knows 1970–3000)."""
    if moment is _BEGINNING:
        return _UNKNOWN_STAMP
    try:
        local = moment.astimezone()
    except (OSError, OverflowError, ValueError):
        return _UNKNOWN_STAMP
    return local.strftime("%Y-%m-%d %H:%M:%S.") + f"{local.microsecond // 1000:03d}"


def format_record(moment: datetime, label: str, lines: Sequence[str]) -> list[str]:
    first = f"{_local_stamp(moment)} ‹{label}› {lines[0]}"
    return [first, *(f"    {line}" for line in lines[1:])]


def write_timeline(
    sources: Sequence[TimelineSource],
    target: Path,
    *,
    cancel: threading.Event | None = None,
    progress: Callable[[int], None] | None = None,
) -> tuple[int, bool]:
    """Write the merged timeline; returns (lines written, truncated at MAX_TIMELINE_LINES)."""
    written = 0
    with target.open("w", encoding="utf-8", newline="\n") as out:
        for moment, label, lines in merge_records(sources, cancel):
            block = format_record(moment, label, lines)
            out.write("\n".join(block) + "\n")
            written += len(block)
            if progress is not None and written % CHUNK_LINES < len(block):
                progress(written)
            if written >= MAX_TIMELINE_LINES:
                return written, True
            if cancel is not None and cancel.is_set():
                break
    return written, False
