"""Saved filters and shareable packs (saved filters + highlight rules in one JSON file).

A pack is plain JSON so it can be mailed, committed next to an application, or attached to a ticket::

    {"format": "loglens-pack", "version": 1, "name": "…", "filters": [...], "highlights": [...]}
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from .filters import FilterMode, FilterTerm
from .highlight import HighlightRule, backtracking_risk
from .search import SearchQuery

PACK_FORMAT = "loglens-pack"
PACK_VERSION = 1
MAX_CONTEXT = 50  # same bound as the filter panel's context spin box


class PackError(ValueError):
    """The file is not a LogLens pack, or an entry in it is invalid."""


@dataclass(frozen=True, slots=True)
class SavedFilter:
    """A named filter-panel state. Levels are stored by name and matched to the tab's level chips when applied."""

    name: str
    terms: tuple[FilterTerm, ...] = ()
    levels: tuple[str, ...] = ()
    context: int = 0
    whole_records: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "terms": [
                {
                    "pattern": t.query.pattern,
                    "regex": t.query.regex,
                    "case_sensitive": t.query.case_sensitive,
                    "mode": t.mode.value,
                }
                for t in self.terms
            ],
            "levels": list(self.levels),
            "context": self.context,
            "whole_records": self.whole_records,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SavedFilter:
        try:
            name = str(data["name"]).strip()
            terms = tuple(_term(t) for t in data.get("terms", ()))
            levels = tuple(str(level) for level in data.get("levels", ()))
            context = max(0, min(int(data.get("context", 0)), MAX_CONTEXT))
        except (KeyError, TypeError, ValueError) as exc:
            raise PackError(f"Invalid saved filter: {exc}") from exc
        if not name:
            raise PackError("A saved filter needs a name.")
        return cls(name, terms, levels, context, bool(data.get("whole_records", False)))


def _term(data: dict[str, Any]) -> FilterTerm:
    query = SearchQuery(
        str(data["pattern"]), regex=bool(data.get("regex", False)), case_sensitive=bool(data.get("case_sensitive"))
    )
    error = query.validate()
    if error:
        raise PackError(f"{query.pattern!r}: {error}")
    risk = backtracking_risk(query.pattern, 0 if query.case_sensitive else re.IGNORECASE) if query.regex else None
    if risk:
        raise PackError(f"pattern {query.pattern!r} {risk}")
    return FilterTerm(query, FilterMode(data.get("mode", FilterMode.ALL.value)))


@dataclass(frozen=True)
class Pack:
    name: str = ""
    filters: tuple[SavedFilter, ...] = ()
    highlights: tuple[HighlightRule, ...] = field(default=())

    def to_json(self) -> str:
        data = {
            "format": PACK_FORMAT,
            "version": PACK_VERSION,
            "name": self.name,
            "filters": [f.to_dict() for f in self.filters],
            "highlights": [r.to_dict() for r in self.highlights],
        }
        return json.dumps(data, indent=2, ensure_ascii=False)

    @classmethod
    def from_json(cls, text: str) -> Pack:
        try:
            data = json.loads(text)
        except ValueError as exc:
            raise PackError(f"Not a JSON file: {exc}") from exc
        if not isinstance(data, dict) or data.get("format") != PACK_FORMAT:
            raise PackError("This file is not a LogLens pack.")
        raw_version = data.get("version", 0)
        try:
            version = int(float(str(raw_version)))  # 1, 1.0 and "1.0" alike; NaN / inf / text are rejected
        except (ValueError, OverflowError) as exc:
            raise PackError(f"Invalid pack version {raw_version!r}: expected a number.") from exc
        if version > PACK_VERSION:
            raise PackError("This pack was made by a newer LogLens; please update.")
        filters = tuple(SavedFilter.from_dict(f) for f in _objects(data, "filters"))
        highlights = tuple(_rule(r) for r in _objects(data, "highlights"))
        return cls(str(data.get("name", "")), filters, highlights)


def _objects(data: dict[str, Any], key: str) -> list[dict[str, Any]]:
    """The list of JSON objects under ``key`` (missing: empty); PackError for any other shape."""
    items = data.get(key, [])
    if not isinstance(items, list):
        raise PackError(f"Invalid pack: {key!r} must be a list.")
    for number, item in enumerate(items, start=1):
        if not isinstance(item, dict):
            raise PackError(f"Invalid pack: entry {number} of {key!r} is not an object.")
    return items


# Highlighter fields and the JSON types they accept (from_dict ignores unknown keys).
_RULE_TYPES: dict[str, tuple[type, ...]] = {
    "name": (str,),
    "pattern": (str,),
    "fg": (str, type(None)),
    "bg": (str, type(None)),
    **dict.fromkeys(("regex", "case_sensitive", "whole_line", "scrollbar_mark", "level_filter", "enabled"), (bool,)),
}


def _rule(data: dict[str, Any]) -> HighlightRule:
    wrong = [key for key, types in _RULE_TYPES.items() if key in data and not isinstance(data[key], types)]
    if wrong:
        raise PackError(f"Invalid highlighter {data.get('name')!r}: wrong type for {', '.join(wrong)}.")
    try:
        rule = HighlightRule.from_dict(data)
    except TypeError as exc:  # a required field is missing
        raise PackError(f"Invalid highlighter: {exc}") from exc
    problem = rule.problem()
    if problem is not None:
        raise PackError(f"Highlighter {rule.name!r}: pattern {rule.pattern!r} {problem}.")
    return rule


def merge_filters(existing: Iterable[SavedFilter], incoming: Iterable[SavedFilter]) -> list[SavedFilter]:
    """Existing filters plus incoming ones; a name clash keeps both ("Name (2)") unless the filters are identical."""
    merged = list(existing)
    for item in incoming:
        if item in merged:
            continue
        names = {f.name for f in merged}
        name, number = item.name, 2
        while name in names:
            name, number = f"{item.name} ({number})", number + 1
        merged.append(SavedFilter(name, item.terms, item.levels, item.context, item.whole_records))
    return merged
