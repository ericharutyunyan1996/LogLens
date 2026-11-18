"""Log formats: detection, field extraction (columns), facets, layout-pattern compiler and user formats.

Usage::

    detection = detect_format(first_lines, filename="u_ex261113.log")
    fmt = detection.format                                  # e.g. the W3C format, confidence 0.99
    records = extract_records(fmt, lines, first_line=1000, context=header_lines)
    facets(records, "cs-method")                            # [("GET", 812), ("POST", 97)]
    compile_layout("%date [%thread] %-5level %logger - %message%newline")   # → LogFormat
    CustomFormat("My app", regex=r"(?P<time>\\S+) (?P<message>.*)").to_format()

New built-in formats are added to :data:`ALL_FORMATS` in :mod:`.builtin`: a regex with named groups, a compiled layout,
or a :class:`LineParser` factory for formats that need state or aren't regular (JSON, CSV, W3C, setupapi).
"""

from __future__ import annotations

from collections.abc import Iterable

from .base import (
    CANONICAL_LEVELS,
    CustomFormatError,
    Fields,
    FormatError,
    LayoutError,
    LineParser,
    LogFormat,
    RegexParser,
    canonical_level,
)
from .builtin import BUILTIN_FORMATS, GENERIC
from .custom import CustomFormat
from .dates import date_format_regex
from .detect import Detection, detect_format, score_format
from .extract import FACET_TOP, Record, extract_fields, extract_records, facets, level_facets
from .layout import LAYOUT_STYLES, LayoutStyle, compile_layout, detect_layout_style

__all__ = [
    "ALL_FORMATS",
    "CANONICAL_LEVELS",
    "FACET_TOP",
    "GENERIC",
    "LAYOUT_STYLES",
    "CustomFormat",
    "CustomFormatError",
    "Detection",
    "Fields",
    "FormatError",
    "LayoutError",
    "LayoutStyle",
    "LineParser",
    "LogFormat",
    "Record",
    "RegexParser",
    "canonical_level",
    "compile_layout",
    "date_format_regex",
    "detect_format",
    "detect_layout_style",
    "extract_fields",
    "extract_records",
    "facets",
    "format_by_name",
    "level_facets",
    "score_format",
]

ALL_FORMATS: tuple[LogFormat, ...] = BUILTIN_FORMATS


def format_by_name(name: str, formats: Iterable[LogFormat] = ALL_FORMATS) -> LogFormat | None:
    """The format called ``name`` among ``formats`` (built-ins by default; pass user formats too), or None."""
    return next((fmt for fmt in formats if fmt.name == name), None)
