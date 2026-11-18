"""Field facets and SQL over parsed records (format detected from synthetic log4net-style lines)."""

from __future__ import annotations

from pathlib import Path

from loglens.core.field_stats import EXAMPLE_QUERIES, field_counts, load_queries, load_sqlite, save_queries
from loglens.core.formats import detect_format

LINES = [
    "2026-11-13 10:00:00,000 [1] INFO  Shop.Orders - order 1 placed",
    "2026-11-13 10:00:01,000 [2] ERROR Shop.Payments - card declined",
    "System.InvalidOperationException: declined",
    "   at Shop.Payments.Charge()",
    "2026-11-13 10:00:02,000 [1] INFO  Shop.Orders - order 2 placed",
    "2026-11-13 10:00:03,000 [3] WARN  Shop.Stock - low stock",
]


def test_field_counts_and_sql() -> None:
    fmt = detect_format(LINES).format
    counts = field_counts(fmt, enumerate(LINES))
    assert counts.parsed == 4 and counts.unparsed == 2
    loggers = dict(counts.top(next(n for n in counts.fields if "logger" in n.lower())))
    assert loggers == {"Shop.Orders": 2, "Shop.Payments": 1, "Shop.Stock": 1}

    connection, rows = load_sqlite(fmt, enumerate(LINES))
    assert rows == 4
    levels = dict(connection.execute(EXAMPLE_QUERIES[0][1]).fetchall())
    assert levels == {"Info": 2, "Error": 1, "Warning": 1}
    message = connection.execute("SELECT _message FROM log WHERE _level = 'Error'").fetchone()[0]
    assert "card declined" in message and "at Shop.Payments.Charge()" in message  # continuation kept
    assert connection.execute("SELECT _line FROM log WHERE _level = 'Warning'").fetchone()[0] == 6


def test_query_library_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "queries.json"
    assert load_queries(path) == []
    save_queries(path, [("Slow", "SELECT 1")])
    assert load_queries(path) == [("Slow", "SELECT 1")]
