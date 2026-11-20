"""Follow one trace / correlation / request id across logs (services, servers) as a waterfall of lanes.

Each open log is a lane; its lines carrying the id are events placed on one shared time axis, so the order of a
request through several services (and where it went wrong) is visible at a glance.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime

from .highlight import default_rules
from .timeparse import LineClock, parse_line_time

MIN_ID_LENGTH = 6
_KEYED = re.compile(
    r"(?i)\b(?:trace[_-]?id|traceid|correlation[_-]?id|correlationid|request[_-]?id|requestid|x-request-id|"
    r"transaction[_-]?id|activity[_-]?id|operation[_-]?id|session[_-]?id|span[_-]?id|call[_-]?id)"
    r"[\"']?\s*[=:]\s*[\"']?([\w.\-{}:]{6,100})"
)
_GUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
_HEX32 = re.compile(r"\b[0-9a-f]{32}\b")
_ERROR_RULES = [r.compiled() for r in default_rules() if r.name in ("Fatal / Critical", "Error")]


@dataclass(frozen=True, slots=True)
class TraceEvent:
    lane: int
    line: int  # 0-based line in that log
    time: datetime | None
    text: str
    is_error: bool = False


@dataclass(slots=True)
class Lane:
    label: str
    key: object = None  # the caller's handle for the log
    events: list[TraceEvent] = field(default_factory=list)
    total: int = 0  # matches in the log (events may be fewer: the first ones are kept)

    @property
    def start(self) -> datetime | None:
        times = [e.time for e in self.events if e.time]
        return min(times) if times else None

    @property
    def end(self) -> datetime | None:
        times = [e.time for e in self.events if e.time]
        return max(times) if times else None

    @property
    def errors(self) -> int:
        return sum(e.is_error for e in self.events)


@dataclass(slots=True)
class Trace:
    trace_id: str
    lanes: list[Lane] = field(default_factory=list)

    @property
    def start(self) -> datetime | None:
        starts = [lane.start for lane in self.lanes if lane.start]
        return min(starts) if starts else None

    @property
    def end(self) -> datetime | None:
        ends = [lane.end for lane in self.lanes if lane.end]
        return max(ends) if ends else None

    @property
    def duration_ms(self) -> float:
        if self.start is None or self.end is None:
            return 0.0
        return (self.end - self.start).total_seconds() * 1000

    @property
    def event_count(self) -> int:
        return sum(len(lane.events) for lane in self.lanes)

    def timeline(self) -> list[TraceEvent]:
        """Every event in time order (events without a time keep their position at the end of their lane)."""
        timed = [e for lane in self.lanes for e in lane.events if e.time]
        untimed = [e for lane in self.lanes for e in lane.events if not e.time]
        return sorted(timed, key=lambda e: (e.time, e.lane, e.line)) + untimed

    def first_error(self) -> TraceEvent | None:
        return next((e for e in self.timeline() if e.is_error), None)


def trace_ids(line: str) -> list[str]:
    """Candidate ids in ``line``: keyed ones first (traceId=…), then GUIDs and 32-digit hex ids."""
    found: list[str] = []
    for pattern in (_KEYED, _GUID, _HEX32):
        for match in pattern.finditer(line):
            value = (match.group(1) if pattern is _KEYED else match.group(0)).strip("{}\"'")
            if len(value) >= MIN_ID_LENGTH and value not in found:
                found.append(value)
    return found


def is_error_line(text: str) -> bool:
    return not text.startswith((" ", "\t")) and any(rule.search(text) for rule in _ERROR_RULES if rule is not None)


def build_trace(
    trace_id: str,
    logs: Iterable[tuple[str, object, int, Sequence[tuple[int, str]]]],
    *,
    clock: LineClock | None = None,
) -> Trace:
    """``logs``: (label, key, total matches, [(line, text)]) per log. Logs without matches are left out."""
    time_of = clock or parse_line_time
    trace = Trace(trace_id)
    for label, key, total, lines in logs:
        if not lines:
            continue
        lane = Lane(label, key, total=total)
        index = len(trace.lanes)
        for number, text in lines:
            lane.events.append(TraceEvent(index, number, time_of(text), text.strip(), is_error_line(text)))
        trace.lanes.append(lane)
    trace.lanes.sort(key=lambda lane: (lane.start is None, lane.start or datetime.max.astimezone()))
    for index, lane in enumerate(trace.lanes):  # lane numbers follow the final order
        lane.events = [TraceEvent(index, e.line, e.time, e.text, e.is_error) for e in lane.events]
    return trace


def render_markdown(trace: Trace) -> str:
    out = [f"# Trace {trace.trace_id}", ""]
    if trace.start and trace.end:
        out.append(f"{trace.event_count} events in {len(trace.lanes)} logs over {trace.duration_ms:,.0f} ms.")
        out.append("")
    for lane in trace.lanes:
        out.append(f"## {lane.label} ({len(lane.events)} events, {lane.errors} errors)")
        out += [
            f"- {e.time:%H:%M:%S.%f}"[:-3] + f" line {e.line + 1}: {e.text[:200]}"
            if e.time
            else f"- line {e.line + 1}: {e.text[:200]}"
            for e in lane.events
        ]
        out.append("")
    return "\n".join(out)
