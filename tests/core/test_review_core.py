"""Regression tests for review findings in core: time parsing, records, timeline, histogram, packs and regex safety.

Synthetic lines only (same shapes as real logs, no real data).
"""

from __future__ import annotations

import json
import random
import sqlite3
import tracemalloc
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pytest

from loglens.core.field_stats import BATCH, load_sqlite
from loglens.core.formats import detect_format
from loglens.core.formats.builtin import W3C
from loglens.core.highlight import HighlightRule, backtracking_risk, default_rules, style_line
from loglens.core.histogram import build_histogram, nice_step
from loglens.core.http import parse_line
from loglens.core.kb import InvalidEntryError, KnowledgeBase, UserKnowledgeStore, compile_pattern, pack_text
from loglens.core.packs import Pack, PackError
from loglens.core.records import (
    MAX_RECORD_LINES,
    RecordLayout,
    expand_to_records,
    line_at_time,
    line_range_for,
    time_bounds,
)
from loglens.core.timeline import TimelineSource, format_record, merge_records
from loglens.core.timeparse import EARLIEST, LineClock, infer_day_first, parse_line_time, parse_match
from loglens.core.timestamps import PATTERNS, WEAK_PATTERNS, TimestampMatch, find_timestamp
from tests.helpers import make_source

BASE = datetime(2026, 11, 13, 10, 0, 0)


def _stamp(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%d %H:%M:%S,000")


def _match(line: str) -> TimestampMatch:
    match = find_timestamp(line)
    assert match is not None, line
    return match


# ---- 1. extreme timestamps never escape as OSError / break .astimezone() --------------------------------------------
@pytest.mark.parametrize(
    "line",
    [
        "0001-01-01 00:00:00 placeholder (DateTime.MinValue)",
        "1601-01-01 00:00:00 zero FILETIME",
        "1900-01-01 00:00:00 SQL default",
        "1970-01-01 00:00:00 epoch zero",
        "9999-12-31 23:59:59 DateTime.MaxValue",
        "0001-01-01T00:00:00Z placeholder",
        "0001-01-01T00:00:00+05:00 placeholder",
        "9999-12-31T23:59:59-05:00 placeholder",
        "01/01/0001 00:00:00 placeholder",
    ],
)
def test_out_of_range_timestamps_are_no_time(line: str) -> None:
    assert parse_line_time(line) is None
    assert LineClock(UTC)(line) is None
    assert LineClock(shift=timedelta(hours=-3))(line) is None


def test_in_range_timestamps_convert_to_local_time() -> None:
    for line in ("1970-01-03 00:00:00 early", "2026-11-13 10:00:00 now", "2999-06-01 00:00:00 late"):
        moment = parse_line_time(line)
        assert moment is not None and moment >= EARLIEST
        moment.astimezone()  # what the UI, filters and the timeline do with every parsed time
    assert LineClock(shift=-timedelta(days=2))("1970-01-03 00:00:00") is None  # shifted out of range


def test_time_bounds_skip_placeholder_timestamps(tmp_path: Path) -> None:
    lines = ["0001-01-01 00:00:00 INFO start", *(f"{_stamp(BASE + timedelta(seconds=i))} INFO tick" for i in range(5))]
    source = make_source(tmp_path, ("\n".join(lines) + "\n").encode())
    first, last = time_bounds(source)
    assert first == BASE.astimezone() and last == (BASE + timedelta(seconds=4)).astimezone()


def test_timeline_stamp_of_an_unconvertible_moment_is_a_placeholder() -> None:
    extreme = datetime(1, 1, 1, tzinfo=timezone(timedelta(hours=5)))
    assert format_record(extreme, "app.log", ["line"])[0].startswith("????-??-?? ??:??:??.??? ‹app.log›")


# ---- 2. records longer than MAX_RECORD_LINES keep their hits ---------------------------------------------------------
def test_hit_deep_in_a_long_record_is_kept() -> None:
    layout = RecordLayout("iso8601", np.array([0, 6000]))
    expanded = expand_to_records(np.array([3000]), layout, 8000)
    assert 3000 in expanded and len(expanded) == MAX_RECORD_LINES
    start, end = layout.record_of(3000, 8000)
    assert start <= 3000 < end and end - start == MAX_RECORD_LINES
    assert layout.record_of(10, 8000) == (0, MAX_RECORD_LINES)  # near the start: shown from the record header
    assert layout.record_of(5999, 8000) == (6000 - MAX_RECORD_LINES, 6000)


def test_hit_in_a_long_header_block_is_kept() -> None:
    layout = RecordLayout("iso8601", np.array([5000]))
    assert 3000 in expand_to_records(np.array([3000]), layout, 6000)
    start, end = layout.record_of(3000, 6000)
    assert start <= 3000 < end


def test_expand_to_records_parity_with_per_hit_windows() -> None:
    generator = random.Random(7)
    for _ in range(200):
        total = generator.randint(1, 12_000)
        starts = np.array(sorted(generator.sample(range(total), generator.randint(1, min(total, 12)))))
        hits = np.array(sorted(generator.sample(range(total), generator.randint(1, min(total, 30)))))
        layout = RecordLayout("iso8601", starts)
        expected = sorted(set().union(*(range(*layout.record_of(int(hit), total)) for hit in hits)))
        expanded = expand_to_records(hits, layout, total)
        assert expanded.tolist() == expected
        assert set(hits.tolist()) <= set(expected)


# ---- 3. day/month order per file, dot dates, year-less formats -------------------------------------------------------
def test_dot_dates_are_day_first() -> None:
    assert parse_line_time("05.11.2026 10:00:00 INFO x") == datetime(2026, 11, 5, 10).astimezone()


def test_day_first_is_decided_once_per_file() -> None:
    lines = ["12/11/2026 10:00:00 INFO a", "13/11/2026 10:00:00 INFO b", "14/11/2026 09:00:00 INFO c"]
    day_first = infer_day_first(lines)
    assert day_first is True
    clock = LineClock(day_first=day_first)
    times = [clock(line) for line in lines]
    assert times == [datetime(2026, 11, day, hour).astimezone() for day, hour in ((12, 10), (13, 10), (14, 9))]
    assert infer_day_first(["11/13/2026 4:53:45 PM x", "11/12/2026 4:53:45 PM y"]) is False
    assert infer_day_first(["01/02/2026 10:00:00 x", "no timestamp"]) is None  # no evidence either way
    # a line contradicting the file's order is still read the only possible way
    assert parse_match(_match("13/11/2026 10:00:00"), day_first=False) == datetime(2026, 11, 13, 10).astimezone()


@pytest.mark.parametrize(
    ("line", "now", "expected"),
    [
        ("Dec 31 23:00:00 host app: x", datetime(2027, 1, 1, 0, 30), datetime(2026, 12, 31, 23)),  # read in January
        ("Jan 01 00:10:00 host app: x", datetime(2026, 12, 31, 23, 50), datetime(2027, 1, 1, 0, 10)),  # skew
        ("Feb 29 10:00:00 host app: x", datetime(2026, 11, 13), datetime(2024, 2, 29, 10)),  # common year
        ("Nov 20 10:00:00 host app: x", datetime(2026, 11, 13), datetime(2025, 11, 20, 10)),  # not in the future
        ("Nov 13 09:00:00 host app: x", datetime(2026, 11, 13, 12), datetime(2026, 11, 13, 9)),
        ("02-29 10:00:00.123 1702 2395 D Tag: x", datetime(2026, 11, 13), datetime(2024, 2, 29, 10, 0, 0, 123000)),
    ],
)
def test_year_less_dates_are_never_in_the_future(line: str, now: datetime, expected: datetime) -> None:
    assert parse_match(_match(line), now=now) == expected.astimezone()


# ---- 4. binary search across an untimestamped block ------------------------------------------------------------------
def test_line_at_time_across_a_dump_without_timestamps(tmp_path: Path) -> None:
    first = [f"{_stamp(BASE + timedelta(seconds=i))} INFO a{i}" for i in range(1000)]
    dump = [f"    dumped body line {i}" for i in range(100)]
    second = [f"{_stamp(BASE + timedelta(seconds=1000 + i))} INFO b{i}" for i in range(1000)]
    source = make_source(tmp_path, ("\n".join(first + dump + second) + "\n").encode())
    assert line_at_time(source, (BASE + timedelta(seconds=5)).astimezone()) == 5
    assert line_at_time(source, (BASE + timedelta(seconds=1003)).astimezone()) == 1103
    assert line_at_time(source, (BASE + timedelta(seconds=999, milliseconds=500)).astimezone()) == 1100


def test_continuation_lines_have_their_records_time(tmp_path: Path) -> None:
    lines = [
        "2026-11-13 10:00:00,000 INFO started",
        "2026-11-13 10:00:01,000 ERROR failed",
        "System.InvalidOperationException: boom",
        "   at Svc.Run()",
        "2026-11-13 10:00:02,000 INFO retry",
    ]
    source = make_source(tmp_path, ("\n".join(lines) + "\n").encode())
    end = datetime(2026, 11, 13, 10, 0, 2).astimezone()
    assert line_at_time(source, end) == 4  # not 2: the stack trace belongs to the 10:00:01 record
    assert line_range_for(source, None, end) == (0, 4)


# ---- 5. timeline record starts without a set of every start ----------------------------------------------------------
def test_timeline_uses_record_starts_in_bounded_memory(tmp_path: Path) -> None:
    lines = [
        "2026-11-13 10:00:00,000 INFO started",
        "2026-11-13 10:00:01,000 ERROR failed",
        "2026-11-13 10:00:09,000 not a record start (a quoted line in a dump)",
        "2026-11-13 10:00:02,000 INFO done",
    ]
    source = make_source(tmp_path, ("\n".join(lines) + "\n").encode())
    starts = np.array([0, 1, 3, *range(10, 1_000_010)], dtype=np.int64)  # far more starts than one chunk
    tracemalloc.start()
    try:
        merged = list(merge_records([TimelineSource("app.log", source, starts=starts)]))
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert [lines_[0] for _t, _label, lines_ in merged] == [lines[0], lines[1], lines[3]]
    assert merged[1][2] == (lines[1], lines[2])  # line 2 is not a start: it stays in the record above
    assert peak < 8 * 1024 * 1024  # a set of a million line numbers alone takes tens of MB


# ---- 6. leftmost timestamp wins --------------------------------------------------------------------------------------
def test_leftmost_timestamp_wins() -> None:
    match = _match("Nov 13 10:15:02 host app[1]: 2026-01-01T00:00:00Z started")
    assert (match.pattern.name, match.start, match.text) == ("syslog", 0, "Nov 13 10:15:02")


def _reference_find(line: str, max_offset: int = 64) -> tuple[str, int, int, str] | None:
    """Simple implementation: every pattern searched on its own; leftmost start, ties by pattern order; weak
    patterns only when nothing else is in reach."""
    head = line[: max_offset + 40]
    for group in (
        [p for p in PATTERNS if p.name not in WEAK_PATTERNS],
        [p for p in PATTERNS if p.name in WEAK_PATTERNS],
    ):
        found = [
            (m.start(), order, p.name, m.end(), m.group(0))
            for order, p in enumerate(group)
            if (m := p.regex.search(head)) is not None and m.start() <= max_offset
        ]
        if found:
            start, _order, name, end, text = min(found)
            return name, start, end, text
    return None


def test_find_timestamp_parity_with_per_pattern_search() -> None:
    generator = random.Random(11)
    pieces = [p.example for p in PATTERNS] + ["x", "[INFO]", "host app[42]:", "1234", "    at Foo()", " "]
    for _ in range(3000):
        line = " ".join(generator.choice(pieces) for _ in range(generator.randint(1, 5)))
        line = " " * generator.randint(0, 40) + line
        match = find_timestamp(line)
        got = (match.pattern.name, match.start, match.end, match.text) if match is not None else None
        assert got == _reference_find(line), line


# ---- 7. W3C times are UTC by definition ------------------------------------------------------------------------------
def test_w3c_format_declares_utc_times() -> None:
    lines = [
        "#Software: Some Web Server 10.0",
        "#Fields: date time s-ip cs-method cs-uri-stem sc-status time-taken",
        "2026-11-13 10:00:01 10.0.0.1 GET /a 200 15",
    ]
    detected = detect_format(lines).format
    assert detected.times_utc and W3C.times_utc
    assert not detect_format(["2026-11-13 10:00:00,000 [1] INFO  Svc - started"] * 3).format.times_utc


# ---- 8. continuation lines survive the SQL batch flush ---------------------------------------------------------------
def test_sql_keeps_continuations_across_batches() -> None:
    lines: list[str] = []
    for i in range(BATCH + 1):
        lines.append(f"{_stamp(BASE + timedelta(seconds=i))} [1] ERROR Svc.Worker - failure {i}")
        if i in (BATCH - 1, BATCH):  # the record flushed with a full batch, and the last record
            lines += [f"System.Exception: boom {i}", f"   at Svc.Worker.Run{i}()"]
    fmt = detect_format(lines[:50]).format
    connection, rows = load_sqlite(fmt, enumerate(lines))
    assert rows == BATCH + 1
    messages = dict(connection.execute("SELECT _line, _message FROM log").fetchall())
    flushed = next(i for i, text in enumerate(lines) if text.endswith(f"failure {BATCH - 1}"))  # 0-based; _line 1-based
    expected = f"failure {BATCH - 1}\nSystem.Exception: boom {BATCH - 1}\n   at Svc.Worker.Run{BATCH - 1}()"
    assert messages[flushed + 1].endswith(expected)
    assert messages[len(lines) - 2].endswith(f"\n   at Svc.Worker.Run{BATCH}()")


# ---- 9. unusual pattern / pack errors never escape -------------------------------------------------------------------
@pytest.mark.parametrize("pattern", ["a{4294967296}", "(" * 3000 + "a" + ")" * 3000, "("])
def test_unusable_highlight_patterns_disable_the_rule(pattern: str) -> None:
    rule = HighlightRule("bad", pattern)
    assert rule.compiled() is None and rule.problem() is not None
    assert style_line([rule], "anything").bg is None


def test_rule_recompiles_after_its_pattern_changes() -> None:
    rule = HighlightRule("r", "(")
    assert rule.compiled() is None
    rule.pattern = "ERROR"
    compiled = rule.compiled()
    assert compiled is not None and compiled.pattern == "ERROR"


def _pack(**fields: object) -> str:
    return json.dumps({"format": "loglens-pack", "version": 1, **fields})


@pytest.mark.parametrize(
    "text",
    [
        _pack(version="abc"),
        _pack(version=[1]),
        _pack(version=float("nan")),
        _pack(highlights=["not an object"]),
        _pack(highlights={"name": "x"}),
        _pack(highlights=[{"name": "x", "pattern": 5}]),
        _pack(highlights=[{"name": "x", "pattern": "a", "regex": "yes"}]),
        _pack(highlights=[{"name": "x", "pattern": "a{4294967296}"}]),
        _pack(filters=["not an object"]),
        _pack(filters=5),
    ],
)
def test_malformed_packs_raise_pack_error(text: str) -> None:
    with pytest.raises(PackError):
        Pack.from_json(text)


def test_pack_version_written_as_text_is_accepted() -> None:
    assert Pack.from_json(_pack(version="1.0", name="team")).name == "team"


# ---- 10. catastrophic backtracking is rejected / disabled ------------------------------------------------------------
EXPONENTIAL = r"^(\w+\s?)+:$"


@pytest.mark.parametrize(
    "pattern",
    [EXPONENTIAL, r"(a+)+b", r"(a*)*x", r"(a|aa)+$", r"(?:\w+;\w*)+$", r"(.*a){12}", r"(?:.*?x)+y", r"(?i)(?:A+a)+b",
     r"(?=(a+)+b)", r"(?>(\w+\s?)+:)", r"(a?)+b", r"(\s*\w+)*!", r"(?:\S+\s*)+$"],
)  # fmt: skip
def test_exponential_patterns_are_detected(pattern: str) -> None:
    assert backtracking_risk(pattern) is not None


@pytest.mark.parametrize(
    "pattern",
    [r"(\d+\.)+\d+", r"(?:ab+)+", r"(?:[^,]*,)*", r"\b(?:\d{1,3}\.){3}\d{1,3}\b", r"(\w+\s)+", r"(?:\w+\s?)++:",
     r"(?:[A-Z][a-z]+)+", r".*foo.*bar", r"(?:a|b)+", r"(?:\S+\s)+x", r"(?:[一-鿿]+,)+"],
)  # fmt: skip
def test_linear_patterns_pass(pattern: str) -> None:
    assert backtracking_risk(pattern) is None


def test_builtin_rules_and_knowledge_pass_the_check() -> None:
    for rule in default_rules():
        assert rule.compiled() is not None, rule.name
    patterns = [p for entry in KnowledgeBase.builtin().entries for p in entry.patterns]
    assert patterns and [p.pattern for p in patterns if backtracking_risk(p.pattern, p.flags)] == []


def test_exponential_highlight_rule_is_inactive_and_rejected_in_packs() -> None:
    rule = HighlightRule("slow", EXPONENTIAL, bg="#40F04040")
    assert rule.compiled() is None and "exponential" in (rule.problem() or "")
    assert style_line([rule], "word word word word x").bg is None
    with pytest.raises(PackError, match="exponential"):
        Pack.from_json(_pack(highlights=[rule.to_dict()]))
    term = {"pattern": EXPONENTIAL, "regex": True}
    with pytest.raises(PackError, match="exponential"):
        Pack.from_json(_pack(filters=[{"name": "slow", "terms": [term]}]))


def test_exponential_knowledge_patterns_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(InvalidEntryError, match="exponential"):
        compile_pattern(EXPONENTIAL)
    with UserKnowledgeStore(tmp_path / "knowledge.db") as store:
        pack = pack_text([]) + (
            "\n[[entry]]\nid = 'slow-1'\ntitle = 'Slow'\nexplanation = 'x'\npatterns = ['^(\\w+\\s?)+:$']\n"
        )
        result = store.import_pack(pack)
        assert result.added == () and len(result.errors) == 1 and "exponential" in result.errors[0]


def test_stored_exponential_pattern_is_ignored_when_loaded(tmp_path: Path) -> None:
    path = tmp_path / "knowledge.db"
    with UserKnowledgeStore(path) as store:
        store.import_pack(
            pack_text([])
            + "\n[[entry]]\nid = 'old-1'\ntitle = 'Old'\nexplanation = 'x'\npatterns = ['connection reset']\n"
        )
    raw = sqlite3.connect(path)  # as stored by a LogLens that did not check yet
    try:
        raw.execute("UPDATE entries SET patterns = ? WHERE id = 'old-1'", (json.dumps([EXPONENTIAL, "reset by peer"]),))
        raw.commit()
    finally:
        raw.close()
    with UserKnowledgeStore(path) as store:
        loaded = store.get("old-1")
        assert loaded is not None and [p.pattern for p in loaded.patterns] == ["reset by peer"]


# ---- 11. histogram bins stay bounded over a span of years ------------------------------------------------------------
def test_histogram_bins_are_capped_for_long_spans(tmp_path: Path) -> None:
    lines = [
        "2001-01-01 00:00:00 INFO stray old timestamp",
        *(f"{_stamp(BASE + timedelta(seconds=i))} INFO x" for i in range(5)),
    ]
    source = make_source(tmp_path, ("\n".join(lines) + "\n").encode())
    bounds = (datetime(2001, 1, 1).astimezone(), (BASE + timedelta(seconds=4)).astimezone())
    histogram = build_histogram(source, bounds, bins=120)
    assert histogram.bins <= 2 * 120 and int(histogram.counts.sum()) == len(lines)
    span = timedelta(days=9000)
    assert span / nice_step(span, 120) <= 120


# ---- 12. NaN / Infinity in JSON access logs --------------------------------------------------------------------------
def test_json_nan_and_infinity_values_do_not_abort_http_parsing() -> None:
    record = parse_line('{"method": "GET", "path": "/api/a", "status": NaN, "bytes": Infinity}', 3)
    assert record is not None and record.status is None and record.bytes_sent is None
