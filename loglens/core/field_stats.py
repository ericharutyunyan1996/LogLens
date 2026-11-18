"""Field statistics and SQL over parsed log records.

:func:`field_counts` streams lines through a format's parser and counts the values of every field (facets);
:func:`load_sqlite` loads parsed records into an in-memory SQLite table ``log`` so any question can be asked in SQL.
Both stream (bounded memory) and work for any :class:`~loglens.core.formats.LogFormat`.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from .formats import LineParser, LogFormat

MAX_DISTINCT_VALUES = 50_000  # per field; rarer values beyond this are counted as OTHER
MAX_VALUE_CHARS = 300
MAX_SQL_ROWS = 1_000_000  # records loaded into the SQL table
OTHER = "(other values)"
BATCH = 5_000
EXAMPLE_QUERIES: tuple[tuple[str, str], ...] = (
    ("Records per level", "SELECT _level, COUNT(*) AS n FROM log GROUP BY _level ORDER BY n DESC"),
    ("Most frequent messages", "SELECT _message, COUNT(*) AS n FROM log GROUP BY _message ORDER BY n DESC LIMIT 50"),
    (
        "Records per minute",
        "SELECT substr(_time, 1, 16) AS minute, COUNT(*) AS n FROM log GROUP BY minute ORDER BY minute",
    ),
    ("Errors and worse", "SELECT _line, _time, _message FROM log WHERE _level IN ('Critical', 'Error') LIMIT 1000"),
    ("Busiest values of a column", "SELECT * FROM log LIMIT 100"),
)
_IDENTIFIER = re.compile(r"[^0-9A-Za-z_]+")
RESERVED = ("_line", "_time", "_level", "_message")  # columns every SQL table has, whatever the format


@dataclass
class FieldCounts:
    parsed: int = 0
    unparsed: int = 0
    fields: dict[str, Counter[str]] = field(default_factory=dict)

    def top(self, name: str, count: int = 100) -> list[tuple[str, int]]:
        return self.fields.get(name, Counter()).most_common(count)


def _parser(fmt: LogFormat, context: Sequence[str]) -> LineParser:
    parser = fmt.new_parser()
    for line in context:
        if not parser.consume_meta(line):
            parser.parse(line)
    return parser


def field_counts(fmt: LogFormat, lines: Iterable[tuple[int, str]], *, context: Sequence[str] = ()) -> FieldCounts:
    """Value counts of every field over the parsed lines (continuations / unparsed lines are only counted)."""
    parser = _parser(fmt, context)
    result = FieldCounts()
    for _number, text in lines:
        if parser.consume_meta(text):
            continue
        fields = parser.parse(text)
        if fields is None:
            result.unparsed += 1
            continue
        result.parsed += 1
        for name, value in fields.items():
            if name == fmt.message_field:
                continue  # free text: counted in the SQL view / patterns instead
            counter = result.fields.setdefault(name, Counter())
            shown = value[:MAX_VALUE_CHARS]
            if shown in counter or len(counter) < MAX_DISTINCT_VALUES:
                counter[shown] += 1
            else:
                counter[OTHER] += 1
    return result


def column_name(name: str) -> str:
    cleaned = _IDENTIFIER.sub("_", name).strip("_") or "field"
    return cleaned if not cleaned[0].isdigit() else f"f_{cleaned}"


def load_sqlite(
    fmt: LogFormat, lines: Iterable[tuple[int, str]], *, context: Sequence[str] = (), columns: Sequence[str] = ()
) -> tuple[sqlite3.Connection, int]:
    """In-memory table ``log`` with ``_line, _time, _level, _message`` plus one column per field; returns the
    connection and the number of rows. Continuation lines are appended to the previous record's ``_message``."""
    extra: dict[str, str] = {}  # SQL column -> field name (first field wins when two sanitise alike)
    for name in columns or fmt.fields:
        sql = column_name(name)
        if sql not in RESERVED and sql not in extra:
            extra[sql] = name
    connection = sqlite3.connect(":memory:", check_same_thread=False)
    definitions = "".join(f', "{sql}" TEXT' for sql in extra)
    connection.execute(f"CREATE TABLE log (_line INTEGER, _time TEXT, _level TEXT, _message TEXT{definitions})")
    insert = f"INSERT INTO log VALUES ({', '.join('?' * (len(RESERVED) + len(extra)))})"
    parser = _parser(fmt, context)
    batch: list[list[object]] = []
    pending: list[object] | None = None  # the latest record: its continuation lines may still follow
    continuation: list[str] = []
    rows = 0
    for number, text in lines:
        if parser.consume_meta(text):
            continue
        fields = parser.parse(text)
        if fields is None:
            if pending is not None and fmt.multiline:
                continuation.append(text)
            continue
        if pending is not None:
            batch.append(_with_continuation(pending, continuation))
            continuation = []
            if len(batch) >= BATCH:
                connection.executemany(insert, batch)
                batch.clear()
        if rows >= MAX_SQL_ROWS:
            pending = None
            break
        pending = [number + 1, fields.get(fmt.time_field, ""), fmt.level_of(fields), fields.get(fmt.message_field, "")]
        pending += [fields.get(name, "") for name in extra.values()]
        rows += 1
    if pending is not None:
        batch.append(_with_continuation(pending, continuation))
    if batch:
        connection.executemany(insert, batch)
    connection.commit()
    return connection, rows


def _with_continuation(values: list[object], continuation: list[str]) -> list[object]:
    """A record's row with its continuation lines (stack trace …) appended to ``_message``, joined once."""
    if continuation:
        values[3] = "\n".join([str(values[3]), *continuation])
    return values


# ---- query library -----------------------------------------------------------------------------------------------
def load_queries(path: Path) -> list[tuple[str, str]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return [(str(q["name"]), str(q["sql"])) for q in data if isinstance(q, dict) and "name" in q and "sql" in q]


def save_queries(path: Path, queries: Sequence[tuple[str, str]]) -> None:
    path.write_text(json.dumps([{"name": n, "sql": s} for n, s in queries], indent=2), encoding="utf-8")
