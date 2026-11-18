"""Detect a log's format from a sample of its lines.

Every candidate parses the sample with a fresh parser (so header rows and directives work). Its score is the share of
*record-start* lines it parses: blank and header/directive lines don't count, and for multi-line formats lines that
don't look like a record start (no timestamp near the line start, or not matching the format's ``record_start``) are
continuation lines, not failures. Scores are smoothed with one virtual failure, so a handful of matching lines is
weaker evidence than hundreds. Ties go to user formats, then to more specific formats (more fields), then to catalog
order. Generic fallback formats are down-weighted so any specific format that fits wins over them; a file nothing fits
(plain text) gets the generic format with confidence 0.

Pass the *first* lines of a file: CSV headers and W3C ``#Fields:`` directives are needed to parse what follows.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import PurePath

from .base import LogFormat
from .builtin import BUILTIN_FORMATS, GENERIC
from .generic import timestamp_of

MAX_SAMPLE_LINES = 2_000  # non-blank lines scored; more only costs time
GIVE_UP_AFTER = 100  # a candidate that parsed none of its first 100 scored lines is out (keeps detection fast)
SMOOTHING = 1.0  # one virtual failure: 3 / 3 matching lines score 0.75, 300 / 300 score 0.997
FALLBACK_WEIGHT = 0.5  # a generic fallback must parse twice the share of lines to beat a specific format
FILENAME_BONUS = 0.05  # a matching file name (u_ex*.log, *.jsonl …) settles near-ties, never overrides content
MIN_CONFIDENCE = 0.25  # below this the generic fallback is returned (it handles any file gracefully)
SCORE_DIGITS = 3  # scores equal to 3 decimals are a tie (resolved by priority / specificity)


@dataclass(frozen=True, slots=True)
class Detection:
    """Detected format, its confidence in [0, 1] and the other candidates that fit at all (best first)."""

    format: LogFormat
    confidence: float
    alternatives: tuple[tuple[LogFormat, float], ...] = ()


class _Sample:
    """Non-blank sample lines with a lazily computed "has a timestamp near the start" flag per line."""

    __slots__ = ("_stamped", "lines")

    def __init__(self, lines: Sequence[str]) -> None:
        self.lines = [line for line in lines if line.strip()][:MAX_SAMPLE_LINES]
        self._stamped: list[bool | None] = [None] * len(self.lines)

    def stamped(self, index: int) -> bool:
        known = self._stamped[index]
        if known is None:
            known = self._stamped[index] = timestamp_of(self.lines[index]) is not None
        return known


def _starts_record(fmt: LogFormat, sample: _Sample, index: int) -> bool:
    if fmt.record_start is not None:
        return fmt.record_start.match(sample.lines[index]) is not None
    return sample.stamped(index)


def score_format(fmt: LogFormat, sample_lines: Sequence[str]) -> float:
    """Smoothed share of record-start lines in ``sample_lines`` that ``fmt`` parses (0 when it parses none)."""
    return _score(fmt, _Sample(sample_lines))


def _score(fmt: LogFormat, sample: _Sample) -> float:
    lines = sample.lines
    if fmt.evidence is not None and not any(fmt.evidence.match(line) for line in lines):
        return 0.0
    parser = fmt.new_parser()
    records = misses = 0
    for index, line in enumerate(lines):
        if parser.consume_meta(line):
            continue
        if parser.parse(line) is not None or (fmt.joined and _starts_record(fmt, sample, index)):
            records += 1
        elif fmt.multiline and records and not _starts_record(fmt, sample, index):
            continue  # continuation line of the record above
        else:
            misses += 1
            if not records and misses >= GIVE_UP_AFTER:
                return 0.0
    return records / (records + misses + SMOOTHING) if records else 0.0


def _name_matches(fmt: LogFormat, filename: str) -> bool:
    if not filename or not fmt.filename_hints:
        return False
    name = PurePath(filename.replace("\\", "/")).name.lower()
    return any(fnmatch.fnmatchcase(name, hint.lower()) for hint in fmt.filename_hints)


def detect_format(
    sample_lines: Sequence[str], *, filename: str = "", candidates: Sequence[LogFormat] | None = None
) -> Detection:
    """Best-fitting format for ``sample_lines`` (the first ≤ 2,000 lines of a file).

    ``candidates`` defaults to the built-in catalog; pass user formats along with it to let them compete.
    """
    formats = tuple(candidates) if candidates is not None else BUILTIN_FORMATS
    sample = _Sample(sample_lines)
    ranked: list[tuple[tuple[float, int, int, int], LogFormat, float]] = []
    for order, fmt in enumerate(formats):
        raw = _score(fmt, sample)
        if raw <= 0.0:
            continue
        weighted = raw * (FALLBACK_WEIGHT if fmt.fallback else 1.0)
        bonus = FILENAME_BONUS if _name_matches(fmt, filename) else 0.0
        key = (round(weighted + bonus, SCORE_DIGITS), fmt.priority, fmt.detail, -order)
        ranked.append((key, fmt, round(min(weighted, 1.0), SCORE_DIGITS)))
    ranked.sort(key=lambda item: item[0], reverse=True)
    fallback = next((fmt for fmt in formats if fmt.fallback), GENERIC)
    if not ranked:
        return Detection(fallback, 0.0)
    best = ranked[0]
    if best[2] < MIN_CONFIDENCE and not best[1].fallback:
        others = tuple((fmt, score) for _, fmt, score in ranked if fmt is not fallback)
        fallback_score = next((score for _, fmt, score in ranked if fmt is fallback), 0.0)
        return Detection(fallback, fallback_score, others)
    return Detection(best[1], best[2], tuple((fmt, score) for _, fmt, score in ranked[1:]))
