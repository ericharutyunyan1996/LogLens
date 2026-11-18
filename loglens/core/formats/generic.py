"""Fallback parser for any log with a timestamp near the line start: time, optional level, optional context, message.

Built on :func:`loglens.core.timestamps.find_timestamp`, so it understands every timestamp shape LogLens knows. After
the timestamp it accepts an optional ``[context]`` (thread, request id …) directly followed by a level word, the level
(optionally bracketed), then the message. A level word in front of the timestamp (``[ERROR] 2026-…``) counts too.
Lines without a timestamp are continuation lines of the record above.
"""

from __future__ import annotations

import re
from functools import lru_cache

from ..timestamps import MAX_OFFSET, TimestampMatch, find_timestamp
from .base import Fields

GENERIC_FIELDS = ("time", "level", "context", "message")
MAX_CONTEXT = 64  # a bracketed token longer than this is message text, not a thread / request id
# find_timestamp() only reads the first MAX_OFFSET + 40 characters; caching on a longer head is exact and keeps the
# cache small whatever the line length.
TIMESTAMP_HEAD = 4 * MAX_OFFSET
TIMESTAMP_CACHE = 4_096  # > the detection sample, so scoring and the generic parser share one lookup per line

_LEVEL_WORDS = (
    "FATAL",
    "CRITICAL",
    "CRIT",
    "EMERG",
    "ALERT",
    "ERROR",
    "ERR",
    "EROR",
    "SEVERE",
    "WARNING",
    "WARN",
    "NOTICE",
    "INFORMATION",
    "INFO",
    "DEBUG",
    "TRACE",
    "VERBOSE",
    "FTL",
    "WRN",
    "INF",
    "DBG",
    "VRB",
    "TRC",
)
# UPPER, Title and lower spellings; longest first so WARNING wins over WARN.
_LEVEL_ALTERNATION = "|".join(
    sorted({v for w in _LEVEL_WORDS for v in (w, w.capitalize(), w.lower())}, key=lambda v: (-len(v), v))
)
_SEPARATORS = r"[\s\]\)>,|;:-]*"
_HEAD = re.compile(
    rf"{_SEPARATORS}(?:\[(?P<context>[^\]]{{1,{MAX_CONTEXT}}})\]{_SEPARATORS})?"
    rf"[\[(<]?(?P<level>{_LEVEL_ALTERNATION})[\])>]?(?![\w-]){_SEPARATORS}"
)
_LEAD = re.compile(_SEPARATORS)
_PREFIX_LEVEL = re.compile(rf"(?<![\w-])(?P<level>{_LEVEL_ALTERNATION})(?![\w-])")


@lru_cache(maxsize=TIMESTAMP_CACHE)
def _timestamp_in(head: str) -> TimestampMatch | None:
    return find_timestamp(head)


def timestamp_of(line: str) -> TimestampMatch | None:
    """:func:`~loglens.core.timestamps.find_timestamp` with a small cache (detection asks twice per line)."""
    return _timestamp_in(line[:TIMESTAMP_HEAD])


class GenericParser:
    """Stateless: timestamp + level + message lines; None for lines without a timestamp near the start."""

    __slots__ = ()

    def consume_meta(self, line: str) -> bool:
        return False

    def parse(self, text: str) -> Fields | None:
        stamp = timestamp_of(text)
        if stamp is None:
            return None
        rest = text[stamp.end :]
        head = _HEAD.match(rest)
        if head is not None:
            level, context, message = head["level"], head["context"] or "", rest[head.end() :]
        else:
            lead = _LEAD.match(rest)
            message = rest[lead.end() :] if lead is not None else rest
            prefix = _PREFIX_LEVEL.search(text, 0, stamp.start)
            level, context = (prefix["level"] if prefix is not None else ""), ""
        return {"time": stamp.text, "level": level, "context": context, "message": message.strip()}
