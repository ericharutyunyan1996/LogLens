"""Turn a sentence ("errors in the last hour, but not timeouts") into a filter the user can see and edit.

Rule based and fully offline: the words that are understood become filter terms, levels and a time range, and every
part of the result is explained, so nothing is hidden and the user corrects it in the filter panel afterwards.
Words that were not understood are reported rather than guessed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .filters import FilterMode, FilterTerm, TimeRange
from .search import SearchQuery

LEVEL_WORDS = {
    "Fatal / Critical": ("fatal", "fatals", "critical", "criticals", "crash", "crashes", "crashed"),
    "Error": ("error", "errors", "failure", "failures", "failed", "exception", "exceptions", "problem", "problems"),
    "Warning": ("warning", "warnings", "warn", "warns"),
    "Debug / Trace": ("debug", "trace", "verbose"),
}
STOP = {
    "a", "an", "the", "show", "me", "find", "get", "give", "all", "any", "of", "to", "please", "lines", "line", "log",
    "logs", "entries", "entry", "messages", "message", "records", "that", "which", "are", "is", "was", "were", "there",
    "what", "happened", "happen", "i", "want", "see", "look", "at", "only", "just", "and", "or", "but", "also", "then",
    "during", "around", "about", "with", "containing", "contain", "contains", "mentioning", "mention", "for", "in",
    "from", "since", "on", "by",
}  # fmt: skip
NEGATION = ("not", "without", "except", "excluding", "exclude", "no", "ignoring", "ignore", "hide", "hiding")
UNITS = {"second": 1, "sec": 1, "minute": 60, "min": 60, "hour": 3600, "hr": 3600, "day": 86400, "week": 604800}
NUMBER_WORDS = {"a": 1, "an": 1, "one": 1, "two": 2, "three": 3, "five": 5, "ten": 10, "fifteen": 15, "thirty": 30}
CLOCK = r"(\d{1,2})(?::(\d{2}))?(?::(\d{2}))?\s*(am|pm)?"
STATUS = re.compile(r"\b(?:status|http|code)?\s*([1-5])(?:xx|\d\d)\b", re.IGNORECASE)


@dataclass(slots=True)
class PlainQuery:
    terms: list[FilterTerm] = field(default_factory=list)
    levels: list[str] = field(default_factory=list)
    time_range: TimeRange | None = None
    understood: list[str] = field(default_factory=list)  # one plain sentence per part, shown to the user

    @property
    def is_empty(self) -> bool:
        return not self.terms and not self.levels and self.time_range is None


def _number(word: str) -> int | None:
    return int(word) if word.isdigit() else NUMBER_WORDS.get(word)


def _clock(match: re.Match[str], day: datetime, first: int = 1) -> datetime | None:
    """The time of day in groups first..first+3 of ``match`` (hour, minute, second, am/pm) on ``day``."""
    hour, minute = int(match.group(first)), int(match.group(first + 1) or 0)
    second, ampm = int(match.group(first + 2) or 0), match.group(first + 3)
    if ampm:
        hour = hour % 12 + (12 if ampm.lower() == "pm" else 0)
    if hour > 23 or minute > 59 or second > 59:
        return None
    return day.replace(hour=hour, minute=minute, second=second, microsecond=0)


def _time(text: str, reference: datetime, query: PlainQuery) -> str:
    """Find and remove a time phrase from ``text``; sets ``query.time_range``."""
    low = text.lower()
    relative = re.search(
        r"(?:in |during |within |over )?(?:the )?(?:last|past|previous)\s+(\w+)?\s*"
        r"(second|sec|minute|min|hour|hr|day|week)s?\b",
        low,
    )
    if relative:
        count = _number(relative.group(1) or "1")
        if count is not None:
            start = reference - timedelta(seconds=count * UNITS[relative.group(2)])
            query.time_range = TimeRange(start, reference + timedelta(seconds=1))
            query.understood.append(
                f"from {start:%Y-%m-%d %H:%M:%S} (the last {count} {relative.group(2)}s of the log)"
            )
            return low[: relative.start()] + " " + low[relative.end() :]
    day = reference.replace(hour=0, minute=0, second=0, microsecond=0)
    for word, offset in (("yesterday", -1), ("today", 0)):
        found = re.search(rf"\b{word}\b", low)
        if found:
            start = day + timedelta(days=offset)
            query.time_range = TimeRange(start, start + timedelta(days=1))
            query.understood.append(f"on {start:%Y-%m-%d} ({word})")
            return low[: found.start()] + " " + low[found.end() :]
    between = re.search(rf"between\s+{CLOCK}\s+and\s+{CLOCK}", low)
    if between:
        begin, finish = _clock(between, day, 1), _clock(between, day, 5)
        if begin and finish:
            query.time_range = TimeRange(begin, finish + timedelta(seconds=1))
            query.understood.append(f"between {begin:%H:%M:%S} and {finish:%H:%M:%S} on {day:%Y-%m-%d}")
            return low[: between.start()] + " " + low[between.end() :]
    for word, side in (("after", "start"), ("since", "start"), ("before", "end"), ("until", "end")):
        found = re.search(rf"\b{word}\s+{CLOCK}", low)
        if found and (":" in found.group(0) or found.group(4)):
            moment = _clock(found, day)
            if moment:
                query.time_range = TimeRange(moment, None) if side == "start" else TimeRange(None, moment)
                query.understood.append(f"{word} {moment:%H:%M:%S} on {day:%Y-%m-%d}")
                return low[: found.start()] + " " + low[found.end() :]
    return low


def parse(sentence: str, reference: datetime | None = None) -> PlainQuery:
    """Understand ``sentence``; ``reference`` is "now" for the log (its last timestamp, so old logs work too)."""
    query = PlainQuery()
    reference = reference or datetime.now().astimezone()
    text = sentence.strip()
    # quoted phrases are exact terms ("connection refused"); a quote right after a negation word excludes it
    for match in re.finditer(r"(not|without|except|excluding)?\s*[\"“']([^\"”']+)[\"”']", text, flags=re.IGNORECASE):
        mode = FilterMode.NONE if match.group(1) else FilterMode.ALL
        query.terms.append(FilterTerm(SearchQuery(match.group(2).strip()), mode))
        query.understood.append(f"{'without' if mode is FilterMode.NONE else 'containing'} “{match.group(2).strip()}”")
    text = re.sub(r"(not|without|except|excluding)?\s*[\"“'][^\"”']+[\"”']", " ", text, flags=re.IGNORECASE)
    text = _time(text, reference, query)
    status = STATUS.search(text)
    if status:
        digits = status.group(0)
        code = re.search(r"[1-5]\d\d|[1-5]xx", digits, re.IGNORECASE)
        if code:
            pattern = (
                rf"\b{code.group(0)[0]}\d\d\b" if code.group(0).lower().endswith("xx") else rf"\b{code.group(0)}\b"
            )
            query.terms.append(FilterTerm(SearchQuery(pattern, regex=True), FilterMode.ALL))
            query.understood.append(f"HTTP status {code.group(0)}")
            text = text[: status.start()] + " " + text[status.end() :]
    words = re.findall(r"[\w.\-/]+", text)
    negate = False
    for word in words:
        low = word.lower()
        if low in NEGATION:
            negate = True
            continue
        level = next((name for name, group in LEVEL_WORDS.items() if low in group), None)
        if level and not negate:
            if level not in query.levels:
                query.levels.append(level)
                query.understood.append(f"{level.lower()} lines")
            continue
        if low in STOP:
            continue
        mode = FilterMode.NONE if negate else FilterMode.ALL
        query.terms.append(FilterTerm(SearchQuery(word), mode))
        query.understood.append(f"{'without' if negate else 'containing'} “{word}”")
        negate = False
    return query
