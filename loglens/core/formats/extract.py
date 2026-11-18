"""Field extraction (the columns view) and field-value counts (the facets panel).

:func:`extract_records` groups lines into records with one parser pass: for multi-line formats continuation lines
(stack traces, wrapped text) are appended to the record's message; joined formats re-parse the whole record. Lines no
record claims are kept as unparsed records with the line as the message, so a columns view never loses text.
"""

from __future__ import annotations

import textwrap
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from .base import Fields, LineParser, LogFormat

FACET_TOP = 20  # default number of values per facet: what fits a side panel without scrolling


@dataclass(frozen=True, slots=True)
class Record:
    """One record: its first line number, how many lines it spans, and its fields (``parsed`` False = raw text)."""

    line: int
    line_count: int
    fields: Fields
    parsed: bool = True


@dataclass(slots=True)
class _Open:
    """The record being collected."""

    start: int
    lines: list[str]
    fields: Fields | None  # None: a joined record that only parses as a whole


def _message_key(fmt: LogFormat) -> str:
    return fmt.message_field or "message"


def _close(fmt: LogFormat, parser: LineParser, current: _Open | None, out: list[Record]) -> None:
    if current is None:
        return
    fields = current.fields
    if len(current.lines) > 1 or fields is None:
        if fmt.joined:
            joined = parser.parse("\n".join(current.lines))
            fields = joined if joined is not None else fields
        elif fields is not None:
            key = _message_key(fmt)
            extra = "\n".join(current.lines[1:]).rstrip()
            head = fields.get(key, "")
            # a message that starts on the next line (indented below a header line) loses the common indentation
            fields = {**fields, key: f"{head}\n{extra}" if head else textwrap.dedent(extra).strip()}
    if fields is None:
        out.append(Record(current.start, len(current.lines), {_message_key(fmt): "\n".join(current.lines)}, False))
    else:
        out.append(Record(current.start, len(current.lines), fields))


def extract_records(
    fmt: LogFormat, lines: Iterable[str], *, first_line: int = 0, context: Iterable[str] = ()
) -> list[Record]:
    """Records of ``lines`` (numbered from ``first_line``).

    ``context``: earlier lines fed to the parser first, for stateful formats parsing from the middle of a file — the
    header row (CSV/TSV), the latest ``#Fields:`` directive (W3C), the section header (setupapi).
    """
    parser = fmt.new_parser()
    for line in context:
        if not parser.consume_meta(line):
            parser.parse(line)
    out: list[Record] = []
    current: _Open | None = None
    for offset, line in enumerate(lines):
        number = first_line + offset
        if parser.consume_meta(line):
            _close(fmt, parser, current, out)
            current = None
            continue
        fields = parser.parse(line)
        if fields is not None or (fmt.joined and fmt.record_start is not None and fmt.record_start.match(line)):
            _close(fmt, parser, current, out)
            current = _Open(number, [line], fields)
        elif fmt.multiline and current is not None:
            current.lines.append(line)
        else:
            _close(fmt, parser, current, out)
            current = None
            if line.strip():
                out.append(Record(number, 1, {_message_key(fmt): line}, False))
    _close(fmt, parser, current, out)
    return out


def extract_fields(fmt: LogFormat, lines: Iterable[str], *, context: Iterable[str] = ()) -> list[Fields]:
    """Fields of every record in ``lines`` (see :func:`extract_records`)."""
    return [record.fields for record in extract_records(fmt, lines, context=context)]


def facets(
    records: Iterable[Record | Mapping[str, str]], field: str, *, top: int | None = FACET_TOP
) -> list[tuple[str, int]]:
    """Most common non-empty values of ``field``: (value, count), most frequent first, ties by value.

    ``top=None`` returns every value.
    """
    counts: Counter[str] = Counter()
    for record in records:
        values = record.fields if isinstance(record, Record) else record
        value = values.get(field)
        if value:
            counts[value] += 1
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return ordered if top is None else ordered[:top]


def level_facets(fmt: LogFormat, records: Iterable[Record | Mapping[str, str]]) -> list[tuple[str, int]]:
    """Counts of canonical levels (Critical … Trace) of parsed records; records without a level are left out."""
    counts: Counter[str] = Counter()
    for record in records:
        values = record.fields if isinstance(record, Record) else record
        level = fmt.level_of(values)
        if level:
            counts[level] += 1
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))
