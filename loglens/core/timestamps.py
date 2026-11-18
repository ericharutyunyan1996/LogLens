"""Generic timestamp detection near the start of a log line.

Used to tell record-start lines from continuation lines (stack traces, dumped bodies) without knowing the format,
and as the seed of format auto-detection. The *leftmost* timestamp within :data:`MAX_OFFSET` characters of the line
start wins (the record header comes before any timestamp quoted in the message); patterns are ordered from most to
least specific, which breaks ties at the same position. A bare epoch number is weak evidence (ids and counters look
the same), so it is only used when no date-shaped timestamp is in reach.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass

MAX_OFFSET = 64  # a timestamp further into the line is part of the message, not the record header


@dataclass(frozen=True, slots=True)
class TimestampPattern:
    name: str
    regex: re.Pattern[str]
    example: str


def _p(name: str, pattern: str, example: str) -> TimestampPattern:
    return TimestampPattern(name, re.compile(pattern), example)


PATTERNS: tuple[TimestampPattern, ...] = (
    _p(
        "iso8601",
        r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?(?:Z|\s?[+-]\d{2}:?\d{2})?",
        "2026-11-13 10:15:02,123",
    ),
    _p("iso-dashed-time", r"\d{4}-\d{2}-\d{2}-\d{2}\.\d{2}\.\d{2}(?:\.\d+)?", "2005-06-03-15.42.50.675872"),
    _p("slashed-ymd", r"\d{4}/\d{2}/\d{2}[ :]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?", "2026/11/13 10:15:02.5442492"),
    _p("clf", r"\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}(?: [+-]\d{4})?", "10/Oct/2000:13:55:36 -0700"),
    _p("ctime", r"[A-Z][a-z]{2} [A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}(?:\.\d+)? \d{4}", "Sun Dec 04 04:47:44 2005"),
    _p(
        "dmy-or-mdy",
        r"\d{1,2}[/.-]\d{1,2}[/.-]\d{4},? \d{1,2}:\d{2}:\d{2}(?:[.,]\d+)?(?:\s?[AP]M)?",
        "11/13/2026 4:53:45 PM",
    ),
    _p("ymd-compact-time", r"\d{8}-\d{2}:\d{2}:\d{2}(?:[:.]\d+)?", "20171223-22:15:29:606"),
    _p("syslog", r"[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}", "Jun 14 15:16:01"),
    _p("md-time", r"\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}", "03-17 16:13:38.811"),
    _p("compact", r"\d{6} \d{6}", "081109 203615"),
    _p("time-ms", r"\d{2}:\d{2}:\d{2}[.,:]\d{3}", "10:17:05.123"),
    _p("epoch", r"\b1\d{9}(?:\d{3})?(?:\.\d+)?\b", "1131566461"),
)


@dataclass(frozen=True, slots=True)
class TimestampMatch:
    pattern: TimestampPattern
    start: int
    end: int
    text: str


HEAD_ROOM = 40  # characters read past ``max_offset``: room for the timestamp itself
WEAK_PATTERNS = frozenset({"epoch"})  # only used when no other pattern matches within reach
_STRONG = tuple(p for p in PATTERNS if p.name not in WEAK_PATTERNS)
_WEAK = tuple(p for p in PATTERNS if p.name in WEAK_PATTERNS)


def _lead(pattern: TimestampPattern) -> str:
    """Characters a match of ``pattern`` can start with (any, unless its regex visibly starts with digit / capital)."""
    source = pattern.regex.pattern
    if source.startswith((r"\d", r"\b1")):
        return r"\d"
    return "[A-Z]" if source.startswith("[A-Z]") else "."


def _alternation(patterns: tuple[TimestampPattern, ...]) -> re.Pattern[str]:
    """``patterns`` as one regex: matching at a position tries them in order, so ties go to the earlier pattern."""
    return re.compile("|".join(f"(?P<_{index}>{p.regex.pattern})" for index, p in enumerate(patterns)))


_STRONG_AT = _alternation(_STRONG)
_CAN_START = re.compile("|".join(sorted({_lead(p) for p in _STRONG})), re.DOTALL)  # where any strong one may start


def _first_by_priority(head: str, patterns: tuple[TimestampPattern, ...], max_offset: int) -> TimestampMatch | None:
    for pattern in patterns:
        m = pattern.regex.search(head)
        if m is not None and m.start() <= max_offset:
            return TimestampMatch(pattern, m.start(), m.end(), m.group(0))
    return None


def _leftmost_strong(head: str, max_offset: int) -> TimestampMatch | None:
    """Leftmost strong timestamp, ties going to the earlier pattern.

    Fast path: the first pattern (in priority order) that matches anywhere — one search for the usual timestamp at
    the line start. Only if it starts later are the few positions before it where a timestamp could start checked
    with all patterns at once.
    """
    found = _first_by_priority(head, _STRONG, max_offset)
    if found is None or found.start == 0:
        return found
    for candidate in _CAN_START.finditer(head, 0, found.start):
        m = _STRONG_AT.match(head, candidate.start())
        if m is not None:
            name = m.lastgroup  # the pattern's own group closes last (patterns use non-capturing groups)
            assert name is not None
            return TimestampMatch(_STRONG[int(name[1:])], m.start(), m.end(), m.group(0))
    return found


def find_timestamp(line: str, max_offset: int = MAX_OFFSET) -> TimestampMatch | None:
    """The leftmost known timestamp starting within ``max_offset`` characters of the line start (ties: the more
    specific pattern); a weak pattern (bare epoch number) only when no other timestamp is in reach."""
    head = line[: max_offset + HEAD_ROOM]
    return _leftmost_strong(head, max_offset) or _first_by_priority(head, _WEAK, max_offset)


def dominant_pattern(lines: Iterable[str]) -> tuple[TimestampPattern | None, float]:
    """Most common timestamp pattern among ``lines`` and the share of lines that have any timestamp."""
    counts: Counter[str] = Counter()
    by_name = {p.name: p for p in PATTERNS}
    total = 0
    for line in lines:
        total += 1
        match = find_timestamp(line)
        if match is not None:
            counts[match.pattern.name] += 1
    if not counts:
        return None, 0.0
    name, _ = counts.most_common(1)[0]
    return by_name[name], sum(counts.values()) / total
