"""Charts from any log: counts, sums, averages, minima, maxima and percentiles of a value over time.

The value comes from a field of the log's format, from a number captured by a regular expression ("took (\\d+) ms"),
or is just "one per line" (optionally only lines matching a pattern), so any log can be charted without a schema.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

import numpy as np

from .formats.base import LogFormat
from .highlight import compile_safely
from .histogram import nice_step
from .timeparse import LineClock, parse_line_time

AGGREGATES = {
    "count": "Count",
    "sum": "Sum",
    "avg": "Average",
    "min": "Minimum",
    "max": "Maximum",
    "p50": "Median (p50)",
    "p95": "95th percentile",
    "p99": "99th percentile",
}
MAX_POINTS = 2_000_000
DEFAULT_BINS = 60
_NUMBER = re.compile(r"[-+]?\d[\d,]*(?:\.\d+)?(?:[eE][-+]?\d+)?")


class ChartError(Exception):
    """The chart definition cannot be used (message is shown to the user)."""


@dataclass(frozen=True, slots=True)
class ChartSpec:
    """What to chart. ``source``: ``"lines"`` (one per line, ``pattern`` optionally narrows them), ``"field"``
    (a field of the log's format, named by ``name``) or ``"regex"`` (the first group of ``pattern`` as a number)."""

    title: str = "Chart"
    source: str = "lines"
    name: str = ""
    pattern: str = ""
    aggregate: str = "count"
    bins: int = DEFAULT_BINS

    def to_dict(self) -> dict[str, Any]:
        return {k: getattr(self, k) for k in self.__dataclass_fields__}

    @classmethod
    def from_dict(cls, data: object) -> ChartSpec | None:
        if not isinstance(data, dict):
            return None
        known = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        try:
            spec = cls(**known)
        except TypeError:
            return None
        valid = spec.source in ("lines", "field", "regex") and spec.aggregate in AGGREGATES
        return spec if valid and isinstance(spec.bins, int) and 2 <= spec.bins <= 500 else None


@dataclass(slots=True)
class ChartData:
    spec: ChartSpec
    starts: list[datetime] = field(default_factory=list)
    step: timedelta = timedelta(minutes=1)
    values: list[float | None] = field(default_factory=list)  # None: no data in that bin
    samples: int = 0
    skipped: int = 0  # lines that had no time or no value

    @property
    def is_empty(self) -> bool:
        return not any(v is not None for v in self.values)


def to_number(text: str) -> float | None:
    """The first number in ``text`` ("35ms", "1,204", "2.5s" → 2.5); units are not converted."""
    match = _NUMBER.search(text)
    if match is None:
        return None
    try:
        return float(match.group(0).replace(",", ""))
    except ValueError:
        return None


def check(spec: ChartSpec) -> str | None:  # noqa: PLR0911 - one message per unusable definition
    """Why ``spec`` cannot be drawn, None when it is fine."""
    if spec.aggregate not in AGGREGATES:
        return "Choose how to combine the values."
    if spec.source == "field" and not spec.name:
        return "Choose a field."
    if spec.source == "regex":
        if not spec.pattern:
            return "Enter a pattern with one group around the number, e.g. took (\\d+) ms."
        compiled = compile_safely(spec.pattern)
        if isinstance(compiled, str):
            return f"The pattern {compiled}."
        if compiled.groups < 1:
            return "The pattern needs one group around the number, e.g. took (\\d+) ms."
    if spec.source == "lines" and spec.pattern:
        compiled = compile_safely(spec.pattern)
        if isinstance(compiled, str):
            return f"The pattern {compiled}."
    return None


def points(
    lines: Iterable[tuple[int, str]],
    spec: ChartSpec,
    *,
    fmt: LogFormat | None = None,
    context: Sequence[str] = (),
    clock: LineClock | None = None,
) -> tuple[np.ndarray, np.ndarray, int]:
    """(epoch seconds, values, skipped lines) for ``spec`` over ``lines``."""
    problem = check(spec)
    if problem:
        raise ChartError(problem)
    time_of = clock or parse_line_time
    compiled = compile_safely(spec.pattern) if spec.pattern else None
    regex = compiled if not isinstance(compiled, str) else None
    parser = None
    if spec.source == "field":
        if fmt is None:
            raise ChartError("The log's format is not known yet: try again in a moment.")
        parser = fmt.new_parser()
        for line in context:
            if not parser.consume_meta(line):
                parser.parse(line)
    times: list[float] = []
    values: list[float] = []
    skipped = 0
    for _number, text in lines:
        if len(times) >= MAX_POINTS:
            break
        if parser is not None and parser.consume_meta(text):
            continue
        moment = time_of(text)
        if moment is None:
            skipped += 1
            continue
        stamp = moment.timestamp()
        if spec.source == "lines":
            if regex is not None and regex.search(text) is None:
                continue
            value = 1.0
        elif spec.source == "regex":
            found = regex.search(text) if regex is not None else None
            number = to_number(found.group(1)) if found is not None and found.group(1) else None
            if number is None:
                skipped += 1
                continue
            value = number
        else:
            fields = parser.parse(text) if parser is not None else None
            number = to_number(fields.get(spec.name, "")) if fields else None
            if number is None:
                skipped += 1
                continue
            value = number
        times.append(stamp)
        values.append(value)
    return np.asarray(times), np.asarray(values), skipped


def _combine(aggregate: str, chunk: np.ndarray) -> float:
    if aggregate == "count":
        return float(len(chunk))
    if aggregate == "sum":
        return float(chunk.sum())
    if aggregate == "avg":
        return float(chunk.mean())
    if aggregate == "min":
        return float(chunk.min())
    if aggregate == "max":
        return float(chunk.max())
    return float(np.percentile(chunk, int(aggregate[1:])))


def aggregate(times: np.ndarray, values: np.ndarray, spec: ChartSpec, skipped: int = 0) -> ChartData:
    """Combine the values of each time bin (counts and sums are 0 in an empty bin, the others have no value)."""
    data = ChartData(spec, skipped=skipped, samples=len(times))
    if not len(times):
        return data
    first, last = float(times.min()), float(times.max())
    step = nice_step(timedelta(seconds=max(last - first, 1.0)), spec.bins)
    seconds = step.total_seconds()
    base = first - (first % seconds)
    count = int((last - base) // seconds) + 1
    index = ((times - base) // seconds).astype(np.int64)
    order = np.argsort(index, kind="stable")
    sorted_index, sorted_values = index[order], values[order]
    bounds = np.searchsorted(sorted_index, np.arange(count + 1))
    data.step = step
    for i in range(count):
        chunk = sorted_values[bounds[i] : bounds[i + 1]]
        data.starts.append(datetime.fromtimestamp(base + i * seconds).astimezone())
        if len(chunk):
            data.values.append(_combine(spec.aggregate, chunk))
        else:
            data.values.append(0.0 if spec.aggregate in ("count", "sum") else None)
    return data


def chart(
    lines: Iterable[tuple[int, str]],
    spec: ChartSpec,
    *,
    fmt: LogFormat | None = None,
    context: Sequence[str] = (),
    clock: LineClock | None = None,
) -> ChartData:
    times, values, skipped = points(lines, spec, fmt=fmt, context=context, clock=clock)
    return aggregate(times, values, spec, skipped)
