"""Trace view: ids found in a line, and a request followed across logs as ordered lanes."""

from __future__ import annotations

from loglens.core.trace import build_trace, is_error_line, render_markdown, trace_ids

TID = "4bf92f3577b34da6a3ce929d0e0e4736"


def test_ids_keyed_guid_and_hex() -> None:
    assert trace_ids(f"2026-11-13 10:00:00 INFO handling traceId={TID} user=5")[0] == TID
    assert trace_ids("order 3f2504e0-4f89-41d3-9a0c-0305e82c3301 placed") == ["3f2504e0-4f89-41d3-9a0c-0305e82c3301"]
    assert trace_ids('{"request_id": "req-12345", "msg": "x"}') == ["req-12345"]
    assert trace_ids("nothing to see 12 34") == []


def test_error_detection_ignores_continuation_lines() -> None:
    assert is_error_line("2026-11-13 10:00:00,000 [1] ERROR Pay - declined")
    assert not is_error_line("   at Pay.Run() ERROR")
    assert not is_error_line("2026-11-13 10:00:00,000 [1] INFO Pay - fine")


def logs():
    web = [
        (10, f"2026-11-13 10:00:00,100 [1] INFO  Web - GET /pay traceId={TID}"),
        (14, f"2026-11-13 10:00:00,900 [1] INFO  Web - response 502 traceId={TID}"),
    ]
    pay = [
        (3, f"2026-11-13 10:00:00,200 [7] INFO  Pay - charging traceId={TID}"),
        (4, f"2026-11-13 10:00:00,700 [7] ERROR Pay - gateway timeout traceId={TID}"),
    ]
    return [("web.log", "w", 2, web), ("pay.log", "p", 2, pay), ("empty.log", "e", 0, [])]


def test_lanes_are_ordered_by_first_event_and_empty_logs_are_left_out() -> None:
    trace = build_trace(TID, reversed(logs()))
    assert [lane.label for lane in trace.lanes] == ["web.log", "pay.log"]
    assert trace.event_count == 4 and 790 <= trace.duration_ms <= 810


def test_timeline_is_in_time_order_across_logs_and_finds_the_first_error() -> None:
    trace = build_trace(TID, logs())
    order = [(trace.lanes[e.lane].label, e.line) for e in trace.timeline()]
    assert order == [("web.log", 10), ("pay.log", 3), ("pay.log", 4), ("web.log", 14)]
    first = trace.first_error()
    assert first is not None and "gateway timeout" in first.text and trace.lanes[first.lane].errors == 1


def test_lines_without_a_time_are_kept_at_the_end() -> None:
    trace = build_trace(
        "abc123", [("x.log", None, 2, [(0, "no time abc123"), (1, "2026-11-13 10:00:00,000 INFO abc123")])]
    )
    assert [e.line for e in trace.timeline()] == [1, 0]


def test_markdown_report_lists_every_lane() -> None:
    md = render_markdown(build_trace(TID, logs()))
    assert f"# Trace {TID}" in md and "## web.log" in md and "## pay.log" in md and "gateway timeout" in md
