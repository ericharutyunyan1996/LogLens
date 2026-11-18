"""Filter chains: several search terms (include all / include any / exclude) plus level selections.

All terms run in one pass (``search_multi``); per block of lines the per-term hit arrays are combined with set
operations, so results still stream in block by block. A time range narrows the searched lines (resolved to a line
range by binary search, see ``records.line_at_time``). Everything here is pure numpy — no Qt.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from functools import reduce

import numpy as np

from .records import RecordLayout, expand_to_records
from .search import SearchQuery
from .timeparse import to_local

_EMPTY = np.empty(0, dtype=np.int64)
MAX_CONTEXT_HITS = 200_000  # context expansion beyond this many hits would explode memory; disabled above it


class FilterMode(StrEnum):
    ALL = "all"  # line must match (AND)
    ANY = "any"  # line must match at least one ANY term (OR group)
    NONE = "none"  # line must not match (NOT)


@dataclass(frozen=True, slots=True)
class FilterTerm:
    query: SearchQuery
    mode: FilterMode = FilterMode.ALL

    @property
    def label(self) -> str:
        prefix = {FilterMode.ALL: "", FilterMode.ANY: "any: ", FilterMode.NONE: "not: "}[self.mode]
        return prefix + self.query.pattern


@dataclass(frozen=True, slots=True)
class TimeRange:
    """[start, end) in real time; either side may be open."""

    start: datetime | None = None
    end: datetime | None = None

    @property
    def is_open(self) -> bool:
        return self.start is None and self.end is None

    def label(self) -> str:
        def fmt(moment: datetime | None) -> str:
            return to_local(moment).strftime("%Y-%m-%d %H:%M:%S") if moment else "…"

        return f"{fmt(self.start)} → {fmt(self.end)}"


@dataclass(frozen=True)
class FilterSpec:
    """A complete filter: text terms, selected level queries (any selected level matches) and a time range."""

    terms: tuple[FilterTerm, ...] = ()
    levels: tuple[SearchQuery, ...] = ()
    level_names: tuple[str, ...] = field(default=(), compare=False)
    time_range: TimeRange | None = None

    @property
    def is_empty(self) -> bool:
        return not self.terms and not self.levels and (self.time_range is None or self.time_range.is_open)

    def validate(self) -> str | None:
        for term in self.terms:
            error = term.query.validate()
            if error:
                return f"{term.query.pattern!r}: {error}"
        return None

    def queries(self) -> list[SearchQuery]:
        """All queries to run, in the order :meth:`combine` expects their results."""
        return [t.query for t in self.terms] + list(self.levels)

    def combine(self, results: Sequence[np.ndarray], first_line: int, line_count: int) -> np.ndarray:
        """Matching lines of the block [first_line, first_line + line_count) from per-query hits."""
        term_hits = results[: len(self.terms)]
        level_hits = results[len(self.terms) :]
        by_mode: dict[FilterMode, list[np.ndarray]] = {mode: [] for mode in FilterMode}
        for term, hits in zip(self.terms, term_hits, strict=True):
            by_mode[term.mode].append(hits)

        selected: np.ndarray | None = None
        for hits in by_mode[FilterMode.ALL]:
            selected = hits if selected is None else np.intersect1d(selected, hits, assume_unique=True)
        groups = [by_mode[FilterMode.ANY], list(level_hits)]
        for group in groups:
            if group:
                union = reduce(np.union1d, group)
                selected = union if selected is None else np.intersect1d(selected, union, assume_unique=True)
        if selected is None:  # only exclusions: start from every line of the block
            selected = np.arange(first_line, first_line + line_count, dtype=np.int64)
        for hits in by_mode[FilterMode.NONE]:
            selected = np.setdiff1d(selected, hits, assume_unique=True)
        return selected.astype(np.int64, copy=False)

    def highlight_pattern(self) -> re.Pattern[str] | None:
        """One regex highlighting every positive term (respecting each term's case setting)."""
        parts = []
        for term in self.terms:
            if term.mode is FilterMode.NONE:
                continue
            q = term.query
            inner = q.pattern if q.regex else re.escape(q.pattern)
            parts.append(f"(?:{inner})" if q.case_sensitive else f"(?i:{inner})")
        if not parts:
            return None
        try:
            return re.compile("|".join(parts), re.MULTILINE)
        except re.error:
            return None


@dataclass(frozen=True)
class ContextRows:
    """Filtered view rows with surrounding context lines."""

    lines: np.ndarray  # sorted file line numbers shown as rows
    is_hit: np.ndarray  # bool per row: a real match (False = context line)
    gap_before: np.ndarray  # bool per row: lines were skipped before this row


def with_context(
    hits: np.ndarray, before: int, after: int, total_lines: int, *, records: RecordLayout | None = None
) -> ContextRows:
    """Expand hits by ``before``/``after`` lines of context (clipped to the file) and, when ``records`` is given,
    to the whole multi-line records they belong to (stack traces, dumped bodies)."""
    grouped = records is not None and records.multi_line
    lines = expand_to_records(hits, records, total_lines) if grouped and records is not None else hits
    if (before > 0 or after > 0) and 0 < len(hits) <= MAX_CONTEXT_HITS:
        offsets = np.arange(-before, after + 1, dtype=np.int64)
        around = np.clip((hits[:, None] + offsets[None, :]).ravel(), 0, max(total_lines - 1, 0))
        lines = np.union1d(lines, around)
    is_hit = np.isin(lines, hits, assume_unique=True) if len(lines) != len(hits) else np.ones(len(lines), bool)
    gap_before = np.zeros(len(lines), dtype=bool)
    if len(lines) > 1 and (before > 0 or after > 0 or grouped):  # separators only make sense between groups
        gap_before[1:] = np.diff(lines) > 1
    return ContextRows(lines, is_hit, gap_before)


def empty_hits() -> np.ndarray:
    return _EMPTY
