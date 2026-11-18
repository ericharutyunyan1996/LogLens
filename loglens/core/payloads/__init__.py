"""Find and pretty-print payloads in log text (stack traces, JSON, XML, JWT, URLs, SQL, fields, base64, headers).

Usage::

    analysis = analyze(line)          # PayloadAnalysis with located + derived sections
    print(analysis.render())          # readable multi-section text for the details pane
    pretty_text(line)                 # shortcut: render() or the line unchanged

Formatters run in priority order; a payload span claimed by an earlier formatter is not reused by a later one
(a URL inside a JSON value stays part of the JSON). New payload kinds are added by implementing
:class:`PayloadFormatter` and listing it in :data:`DEFAULT_FORMATTERS`.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass, field

from .base import PayloadFormatter, Section
from .base64_payload import Base64Formatter
from .header_payload import HeaderBlockFormatter
from .json_payload import JsonFormatter
from .jwt_payload import JwtFormatter
from .keyvalue_payload import KeyValueFormatter
from .sql_payload import SqlFormatter
from .stacktrace_payload import StackTraceFormatter
from .url_payload import UrlFormatter
from .xml_payload import XmlFormatter

__all__ = ["DEFAULT_FORMATTERS", "PayloadAnalysis", "PayloadFormatter", "Section", "analyze", "pretty_text"]

log = logging.getLogger(__name__)

MAX_ANALYZED_CHARS = 8_000_000  # giant single lines are shown raw rather than blocking the UI

DEFAULT_FORMATTERS: tuple[PayloadFormatter, ...] = (
    StackTraceFormatter(),  # first: frames contain paths/URLs that other formatters would otherwise claim
    JsonFormatter(),
    XmlFormatter(),
    JwtFormatter(),
    UrlFormatter(),
    SqlFormatter(),
    HeaderBlockFormatter(),
    KeyValueFormatter(),
    Base64Formatter(),
)


@dataclass(frozen=True)
class PayloadAnalysis:
    text: str
    located: list[Section] = field(default_factory=list)  # sorted by position, non-overlapping
    derived: list[Section] = field(default_factory=list)

    @property
    def kinds(self) -> list[str]:
        return sorted({s.kind for s in self.located})

    def render(self) -> str:
        """Text outside payloads, interleaved with formatted payload sections, then derived sections."""
        if not self.located and not self.derived:
            return self.text
        parts: list[str] = []
        cursor = 0
        for section in self.located:
            gap = self.text[cursor : section.start].strip()
            if gap:
                parts.append(gap)
            parts.append(f"── {section.kind} ──\n{section.body}")
            cursor = section.end
        tail = self.text[cursor:].strip()
        if tail:
            parts.append(tail)
        parts.extend(f"── {s.kind} ──\n{s.body}" for s in self.derived)
        return "\n\n".join(parts)


def analyze(text: str, formatters: Sequence[PayloadFormatter] = DEFAULT_FORMATTERS) -> PayloadAnalysis:
    if len(text) > MAX_ANALYZED_CHARS:
        return PayloadAnalysis(text)
    located: list[Section] = []
    derived: list[Section] = []
    for formatter in formatters:
        try:
            found = formatter.find(text)
        except Exception:  # log text is arbitrary input: one formatter failing must not hide the others' results
            log.exception("%s formatter failed on a %d-character line", formatter.kind, len(text))
            continue
        kept = [s for s in found if s.located and not any(s.overlaps(k) for k in located)]
        located.extend(kept)
        if kept:  # derived sections belong to this formatter's payloads
            derived.extend(s for s in found if not s.located)
    located.sort(key=lambda s: s.start)
    return PayloadAnalysis(text, located, derived)


def pretty_text(text: str) -> str:
    """Readable rendering of ``text`` (unchanged if it contains no recognised payload)."""
    return analyze(text).render()
