"""Triage summary and anomaly highlights: what a log is about, and what to look at first.

One pass over the lines (a bounded sample for huge logs) collects levels, times, message patterns and HTTP
timings; everything the summary says is a plain count or a line number, so each statement can be checked by
jumping to the line. Nothing here uses AI.
"""

from __future__ import annotations

import heapq
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

import numpy as np

from .highlight import default_rules
from .histogram import SPIKE_MIN_COUNT, find_spikes, nice_step
from .http import parse_line
from .patterns import PatternMiner
from .timeparse import LineClock, parse_line_time

TRIAGE_MAX_LINES = 500_000  # lines examined at most (the summary says so when a log is longer)
HTTP_MAX_LINES = 200_000  # lines tried as HTTP requests (slowest requests)
BINS = 60
TOP = 5
NEW_PATTERN_MIN_COUNT = 3  # a "new kind of message" must repeat, a single odd line is not a trend
NEW_PATTERN_AFTER = 0.3  # ... and first appear after this share of the log's lines
LEVELS = ("Fatal / Critical", "Error", "Warning")
_HINT = re.compile(r"(?i)fatal|crit|emerg|alert|err|fail|exception|warn|wrn|traceback")


@dataclass(frozen=True, slots=True)
class LineRef:
    line: int  # 0-based
    text: str
    time: datetime | None = None
    level: str = ""


@dataclass(frozen=True, slots=True)
class PatternRow:
    template: str
    count: int
    first_line: int
    sample: str
    level: str = ""


@dataclass(frozen=True, slots=True)
class PeriodRow:
    start: datetime
    end: datetime
    lines: int
    errors: int
    first_line: int


@dataclass(frozen=True, slots=True)
class SlowRequest:
    line: int
    endpoint: str
    status: int | None
    duration_ms: float
    time: datetime | None


@dataclass(frozen=True, slots=True)
class Anomaly:
    kind: str  # "rate spike" | "error spike" | "new message" | "silence"
    line: int  # where to jump
    time: datetime | None
    summary: str
    score: float = 0.0


@dataclass(slots=True)
class Triage:
    total_lines: int = 0
    examined: int = 0
    first_time: datetime | None = None
    last_time: datetime | None = None
    levels: dict[str, int] = field(default_factory=dict)
    first_problem: LineRef | None = None
    first_fatal: LineRef | None = None
    last_problem: LineRef | None = None
    problem_patterns: list[PatternRow] = field(default_factory=list)
    noisiest: list[PatternRow] = field(default_factory=list)
    busiest: PeriodRow | None = None
    quietest: PeriodRow | None = None
    worst_period: PeriodRow | None = None
    longest_silence: tuple[datetime, datetime, int] | None = None  # start, end, line after the gap
    slowest: list[SlowRequest] = field(default_factory=list)
    http_requests: int = 0
    http_errors: int = 0
    anomalies: list[Anomaly] = field(default_factory=list)
    look_first: list[str] = field(default_factory=list)

    @property
    def problems(self) -> int:
        return self.levels.get("Fatal / Critical", 0) + self.levels.get("Error", 0)

    @property
    def truncated(self) -> bool:
        return self.examined < self.total_lines


class _Levels:
    """Severity of a record's first line, with the same rules that colour the log."""

    def __init__(self) -> None:
        self._rules = [
            (rule.name, pattern)
            for name in LEVELS
            for rule in default_rules()
            if rule.name == name and (pattern := rule.compiled()) is not None
        ]

    def of(self, text: str) -> str:
        if not text or text[0] in " \t" or not _HINT.search(text):  # indented lines continue a record above
            return ""
        for name, pattern in self._rules:
            if pattern.search(text):
                return name
        return ""


def _short(text: str, limit: int = 220) -> str:
    text = text.strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def triage(  # noqa: PLR0915 - one pass that feeds every part of the summary
    lines: Iterable[tuple[int, str]], total_lines: int | None = None, *, clock: LineClock | None = None
) -> Triage:
    """Summarise ``lines`` ((0-based line number, text)); ``total_lines`` is the log's real length when sampled."""
    levels = _Levels()
    time_of = clock or parse_line_time
    result = Triage()
    counts = dict.fromkeys(LEVELS, 0)
    all_miner, problem_miner = PatternMiner(), PatternMiner()
    pattern_level: dict[int, str] = {}
    numbers: list[int] = []
    stamps: list[float] = []
    problem_lines: list[int] = []
    problem_stamps: list[float] = []
    slow: list[tuple[float, int, SlowRequest]] = []
    last_moment: datetime | None = None
    examined = 0
    for number, text in lines:
        examined += 1
        if examined > TRIAGE_MAX_LINES:
            examined -= 1
            break
        level = levels.of(text)
        moment = time_of(text)
        if moment is not None:
            last_moment = moment
            numbers.append(number)
            stamps.append(moment.timestamp())
            if result.first_time is None or moment < result.first_time:
                result.first_time = moment
            if result.last_time is None or moment > result.last_time:
                result.last_time = moment
        if level:
            counts[level] += 1
            if level != "Warning":
                ref = LineRef(number, _short(text), moment or last_moment, level)
                result.first_problem = result.first_problem or ref
                result.last_problem = ref
                if level == "Fatal / Critical" and result.first_fatal is None:
                    result.first_fatal = ref
                problem_miner.add(number, text)
                problem_lines.append(number)
                if moment is not None:
                    problem_stamps.append(moment.timestamp())
        pid = all_miner.add(number, text)
        if level and pid not in pattern_level:
            pattern_level[pid] = level
        if examined <= HTTP_MAX_LINES:
            http = parse_line(text, number)
            if http is not None:
                result.http_requests += 1
                if http.status is not None and http.status >= 500:
                    result.http_errors += 1
                if http.duration_ms is not None:
                    row = SlowRequest(number, http.endpoint, http.status, http.duration_ms, http.time)
                    entry = (http.duration_ms, number, row)
                    if len(slow) < TOP:
                        heapq.heappush(slow, entry)
                    else:
                        heapq.heappushpop(slow, entry)
    result.total_lines = total_lines if total_lines is not None else examined
    result.examined = examined
    result.levels = {k: v for k, v in counts.items() if v}
    result.slowest = [row for _d, _n, row in sorted(slow, reverse=True)]
    result.problem_patterns = [
        PatternRow(p.template, p.count, p.first_line, _short(p.sample)) for p in problem_miner.clusters()[:TOP]
    ]
    mined = all_miner.clusters()
    result.noisiest = [
        PatternRow(p.template, p.count, p.first_line, _short(p.sample), pattern_level.get(p.id, ""))
        for p in mined[:TOP]
    ]
    _periods(result, np.asarray(numbers, dtype=np.int64), np.asarray(stamps), np.asarray(problem_stamps))
    _anomalies(result, mined, pattern_level, np.asarray(numbers, dtype=np.int64), np.asarray(stamps))
    _look_first(result)
    return result


def _moment(stamp: float) -> datetime:
    return datetime.fromtimestamp(stamp).astimezone()


def _bins(stamps: np.ndarray) -> tuple[float, float, int]:
    first, last = float(stamps.min()), float(stamps.max())
    step = nice_step(timedelta(seconds=max(last - first, 1.0)), BINS).total_seconds()
    return first, step, int((last - first) // step) + 1


def _periods(result: Triage, numbers: np.ndarray, stamps: np.ndarray, problem_stamps: np.ndarray) -> None:
    if len(stamps) < 2:
        return
    first, step, count = _bins(stamps)
    index = ((stamps - first) // step).astype(np.int64)
    per = np.bincount(index, minlength=count)
    errors = (
        np.bincount(((problem_stamps - first) // step).astype(np.int64), minlength=count)
        if len(problem_stamps)
        else np.zeros(count, dtype=np.int64)
    )

    def row(i: int) -> PeriodRow:
        hits = np.flatnonzero(index == i)
        line = int(numbers[hits[0]]) if len(hits) else 0
        return PeriodRow(_moment(first + i * step), _moment(first + (i + 1) * step), int(per[i]), int(errors[i]), line)

    result.busiest = row(int(per.argmax()))
    if count >= 4:
        inner = per[1:-1]  # the first and last bins are usually partial
        filled = np.flatnonzero(inner > 0)
        if len(filled):
            result.quietest = row(int(filled[inner[filled].argmin()]) + 1)
    if errors.max(initial=0) > 0:
        result.worst_period = row(int(errors.argmax()))
    ordered = np.sort(stamps)
    gaps = np.diff(ordered)
    if len(gaps):
        biggest = int(gaps.argmax())
        if gaps[biggest] >= max(5 * step, 60.0) and gaps[biggest] > 10 * float(np.median(gaps) or 1.0):
            after = np.flatnonzero(stamps > ordered[biggest])
            line = int(numbers[after[0]]) if len(after) else 0
            result.longest_silence = (_moment(float(ordered[biggest])), _moment(float(ordered[biggest + 1])), line)


def _anomalies(
    result: Triage, mined: list, pattern_level: dict[int, str], numbers: np.ndarray, stamps: np.ndarray
) -> None:
    found: list[Anomaly] = []
    if len(stamps) >= 10:
        first, step, count = _bins(stamps)
        index = ((stamps - first) // step).astype(np.int64)
        per = np.bincount(index, minlength=count)
        for i in find_spikes(per):
            hits = np.flatnonzero(index == i)
            at = _moment(first + i * step)
            found.append(
                Anomaly(
                    "rate spike",
                    int(numbers[hits[0]]),
                    at,
                    f"{int(per[i]):,} lines in {_span(step)} starting {at:%H:%M:%S} "
                    f"(typically {int(np.median(per)):,})",
                    float(per[i]) / max(float(np.median(per)), 1.0),
                )
            )
    # a kind of message that was not there at the start, and then repeats
    total = max(result.examined, 1)
    for pattern in mined:
        if pattern.count >= NEW_PATTERN_MIN_COUNT and pattern.first_line >= NEW_PATTERN_AFTER * total:
            level = pattern_level.get(pattern.id, "")
            seen = _time_of_line(numbers, stamps, pattern.first_line)
            when = f" at {seen:%H:%M:%S}" if seen else ""
            found.append(
                Anomaly(
                    "new message",
                    pattern.first_line,
                    seen,
                    f"A kind of message first seen{when} and repeated {pattern.count:,}×"
                    + (f" ({level.lower()})" if level else "")
                    + f": {_short(pattern.template, 120)}",
                    pattern.count * (3.0 if level in ("Error", "Fatal / Critical") else 1.0),
                )
            )
    if result.longest_silence is not None:
        start, end, line = result.longest_silence
        found.append(Anomaly("silence", line, end, f"Nothing logged from {start:%H:%M:%S} to {end:%H:%M:%S}", 1.0))
    found.sort(key=lambda a: -a.score)
    result.anomalies = found[:30]


def _time_of_line(numbers: np.ndarray, stamps: np.ndarray, line: int) -> datetime | None:
    if not len(numbers):
        return None
    at = int(np.searchsorted(numbers, line, side="left"))
    return _moment(float(stamps[min(at, len(stamps) - 1)]))


def _span(seconds: float) -> str:
    if seconds >= 3600:
        return f"{seconds / 3600:g} h"
    return f"{seconds / 60:g} min" if seconds >= 60 else f"{seconds:g} s"


def _look_first(result: Triage) -> None:
    notes: list[str] = []
    if result.first_fatal is not None:
        notes.append(f"Line {result.first_fatal.line + 1}: the first fatal / critical message.")
    if result.first_problem is not None and result.first_problem != result.first_fatal:
        notes.append(
            f"Line {result.first_problem.line + 1}: the first error: everything after it may be a consequence."
        )
    if result.problem_patterns:
        top = result.problem_patterns[0]
        notes.append(f"Line {top.first_line + 1}: the most frequent error ({top.count:,}×).")
    if result.worst_period is not None and result.worst_period.errors >= SPIKE_MIN_COUNT // 2:
        notes.append(
            f"Line {result.worst_period.first_line + 1}: the worst period, {result.worst_period.errors:,} errors "
            f"around {result.worst_period.start:%H:%M}."
        )
    if result.slowest and result.slowest[0].duration_ms >= 1000:
        notes.append(
            f"Line {result.slowest[0].line + 1}: the slowest request, {result.slowest[0].duration_ms / 1000:.1f} s."
        )
    if not notes:
        notes.append("No errors or warnings were recognised: the log looks quiet.")
    result.look_first = notes


# ---- the one-page report ------------------------------------------------------------------------------------------
def render_markdown(result: Triage, title: str = "Log summary") -> str:
    out = [f"# {title}", ""]
    scope = (
        f"{result.examined:,} of {result.total_lines:,} lines examined"
        if result.truncated
        else f"{result.total_lines:,} lines"
    )
    when = ""
    if result.first_time and result.last_time:
        when = f", {result.first_time:%Y-%m-%d %H:%M:%S} to {result.last_time:%Y-%m-%d %H:%M:%S}"
    out += [f"{scope}{when}.", ""]
    if result.levels:
        out += ["**Levels:** " + ", ".join(f"{k} {v:,}" for k, v in result.levels.items()), ""]
    out += ["## What to look at first", ""] + [f"- {n}" for n in result.look_first] + [""]
    if result.first_problem:
        p = result.first_problem
        out += [
            "## First error",
            "",
            f"Line {p.line + 1}" + (f" ({p.time:%H:%M:%S})" if p.time else "") + f": `{p.text}`",
            "",
        ]
    if result.problem_patterns:
        out += ["## Most frequent errors", ""]
        out += [
            f"- {p.count:,}× (first at line {p.first_line + 1}): `{_short(p.template, 160)}`"
            for p in result.problem_patterns
        ]
        out.append("")
    if result.noisiest:
        out += ["## Noisiest messages", ""]
        out += [f"- {p.count:,}× `{_short(p.template, 160)}`" for p in result.noisiest]
        out.append("")
    periods = [("Busiest", result.busiest), ("Quietest", result.quietest), ("Most errors", result.worst_period)]
    shown = [(n, p) for n, p in periods if p is not None]
    if shown:
        out += ["## Periods", ""]
        out += [
            f"- {n}: {p.start:%H:%M} to {p.end:%H:%M}, {p.lines:,} lines, {p.errors:,} errors (line {p.first_line + 1})"
            for n, p in shown
        ]
        out.append("")
    if result.http_requests:
        out += ["## HTTP", "", f"{result.http_requests:,} requests, {result.http_errors:,} with a 5xx status."]
        out += [f"- {s.duration_ms:,.0f} ms: {s.endpoint} (line {s.line + 1})" for s in result.slowest]
        out.append("")
    if result.anomalies:
        out += ["## Unusual", ""] + [f"- {a.summary} (line {a.line + 1})" for a in result.anomalies[:10]] + [""]
    return "\n".join(out)
