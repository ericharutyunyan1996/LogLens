"""Shared types of the log-format engine: a format definition, its line-parser protocol and level mapping.

A :class:`LogFormat` turns a line into named fields (the columns of a structured view). Simple formats are one regex
with named groups; structured formats (JSON, CSV, W3C …) supply a parser factory instead, because their field names
come from the data and some parsers keep state (a CSV header row, the latest W3C ``#Fields:`` directive, the current
setupapi section). Parsers are created per pass over a file with :meth:`LogFormat.new_parser`.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Protocol

Fields = dict[str, str]
"""Field name → value of one record (values are text exactly as logged, padding stripped)."""

CANONICAL_LEVELS = ("Critical", "Error", "Warning", "Info", "Debug", "Trace")

# Level tokens used by common logging libraries and standards, lower-cased → canonical level. Format-specific tokens
# (setupapi "!!!", CMTrace type="3", syslog numeric severities …) live in the format's own ``level_map``.
_LEVEL_TOKENS: dict[str, tuple[str, ...]] = {
    "Critical": ("fatal", "ftl", "critical", "crit", "crt", "emerg", "emergency", "alert", "panic"),
    "Error": ("error", "err", "eror", "erro", "severe", "fail"),
    "Warning": ("warning", "warn", "wrn", "warng"),
    "Info": ("info", "inf", "information", "informational", "notice", "off"),  # log4net OFF = always printed
    "Debug": ("debug", "dbg", "dbug", "fine", "config"),
    "Trace": ("trace", "trc", "trce", "verbose", "vrb", "finer", "finest"),
}
DEFAULT_LEVEL_MAP: Mapping[str, str] = MappingProxyType(
    {token: level for level, tokens in _LEVEL_TOKENS.items() for token in tokens}
)


class FormatError(ValueError):
    """A format definition that can't be used (bad regex, unbalanced layout pattern, missing field …)."""


class LayoutError(FormatError):
    """A layout pattern (log4net / log4j / NLog / Serilog) that can't be compiled; ``position`` is -1 if unknown."""

    def __init__(self, message: str, position: int = -1) -> None:
        super().__init__(message if position < 0 else f"{message} (at position {position})")
        self.position = position


class CustomFormatError(FormatError):
    """A user-defined format whose definition is invalid."""


class LineParser(Protocol):
    """Parses the lines of one file in order; may keep state between lines."""

    def consume_meta(self, line: str) -> bool:
        """True if ``line`` is a header / directive line (it may update the parser's state) and not a record."""
        ...

    def parse(self, text: str) -> Fields | None:
        """Fields of a record line (or of a joined multi-line record), None if ``text`` isn't one."""
        ...


Transform = Callable[[Fields], Fields | None]
"""Post-processing of regex groups into the final fields (None rejects the line)."""


class RegexParser:
    """Stateless parser: one regex with named groups, values stripped, optionally post-processed."""

    __slots__ = ("_regex", "_transform")

    def __init__(self, regex: re.Pattern[str], transform: Transform | None = None) -> None:
        self._regex = regex
        self._transform = transform

    def consume_meta(self, line: str) -> bool:
        return False

    def parse(self, text: str) -> Fields | None:
        match = self._regex.match(text)
        if match is None:
            return None
        fields = {name: value.strip() for name, value in match.groupdict("").items()}
        return self._transform(fields) if self._transform is not None else fields


def canonical_level(raw: str, level_map: Mapping[str, str] | None = None) -> str:
    """Canonical level (one of :data:`CANONICAL_LEVELS`) for a level token, ``""`` when unknown or empty.

    ``level_map`` (exact token first, then lower-cased) wins over the common library names.
    """
    token = raw.strip()
    if not token:
        return ""
    if level_map:
        mapped = level_map.get(token) or level_map.get(token.lower())
        if mapped:
            return mapped
    return DEFAULT_LEVEL_MAP.get(token.lower(), "")


@dataclass(frozen=True, slots=True)
class LogFormat:
    """A log format: how to split its lines into named fields.

    Exactly one of ``regex`` (named groups become fields) or ``parser_factory`` is required; with both, the factory
    parses and the regex documents the shape. ``fields`` lists the columns in display order; with ``dynamic_fields``
    more columns come from the data (JSON keys, the CSV header, W3C ``#Fields:``).

    Multi-line records: with ``multiline`` set, lines that don't parse are continuation lines of the record above
    (stack traces). ``record_start`` marks record-start lines that only parse together with their continuation lines
    (``joined``: the record's text is parsed as a whole, e.g. CMTrace messages spanning lines).
    """

    name: str
    display_name: str
    fields: tuple[str, ...]
    regex: re.Pattern[str] | None = None
    parser_factory: Callable[[], LineParser] | None = field(default=None, compare=False)
    multiline: bool = False
    record_start: re.Pattern[str] | None = None
    joined: bool = False
    time_field: str = ""
    level_field: str = ""
    message_field: str = ""
    level_map: Mapping[str, str] = field(default_factory=dict, compare=False)
    filename_hints: tuple[str, ...] = ()  # fnmatch patterns on the file name (case-insensitive)
    evidence: re.Pattern[str] | None = None  # detection requires a sample line starting with a match of this
    dynamic_fields: bool = False
    stateful: bool = False  # parsing depends on earlier lines (header row, directives, sections): pass them as context
    fallback: bool = False  # generic catch-all: only wins when nothing specific fits
    specificity: int = 0  # detection tie-break; 0 = number of fields
    priority: int = 0  # detection tie-break before specificity (user formats beat built-ins)
    description: str = ""
    # Timestamps without an offset are UTC by the format's definition (W3C / IIS), not the writer's local time: a log
    # of this format should default to a UTC clock (``LineClock(zone=UTC)``).
    times_utc: bool = False

    def __post_init__(self) -> None:
        if self.regex is None and self.parser_factory is None:
            raise FormatError(f"format {self.name!r} needs a regex or a parser")
        if self.joined and self.record_start is None:
            raise FormatError(f"format {self.name!r}: joined records need a record_start pattern")

    @property
    def detail(self) -> int:
        """How specific the format is (detection tie-break)."""
        return self.specificity or len(self.fields)

    def new_parser(self) -> LineParser:
        """A fresh parser for one pass over a file, in line order."""
        if self.parser_factory is not None:
            return self.parser_factory()
        assert self.regex is not None  # guaranteed by __post_init__
        return RegexParser(self.regex)

    def parse(self, line: str) -> Fields | None:
        """Fields of a single line parsed on its own (stateful formats only see this one line)."""
        parser = self.new_parser()
        return None if parser.consume_meta(line) else parser.parse(line)

    def is_record_start(self, line: str) -> bool:
        """True if ``line`` starts a record (it parses, or matches ``record_start``)."""
        if self.record_start is not None and self.record_start.match(line):
            return True
        return self.parse(line) is not None

    def level_of(self, fields: Mapping[str, str]) -> str:
        """Canonical level of a parsed record (``""`` without a level field / unknown token)."""
        if not self.level_field:
            return ""
        return canonical_level(fields.get(self.level_field, ""), self.level_map)
