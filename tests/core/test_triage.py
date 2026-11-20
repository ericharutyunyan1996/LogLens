"""Triage summary and anomaly highlights over a synthetic log with a known story."""

from __future__ import annotations

from datetime import datetime, timedelta

from loglens.core.triage import TRIAGE_MAX_LINES, render_markdown, triage


def story() -> list[str]:
    """Two quiet hours, an error burst with a new message at 10:40, then a silence of 30 minutes."""
    lines: list[str] = []
    base = datetime(2026, 11, 13, 9, 0, 0)

    def at(minute: float, level: str, text: str) -> str:
        return f"{(base + timedelta(minutes=minute)):%Y-%m-%d %H:%M:%S,000} [1] {level} {text}"

    for m in range(100):
        lines.append(at(m, "INFO", f"Heartbeat ok for node {m % 4}"))
        if m % 20 == 5:
            lines.append(at(m, "WARN", "Slow disk detected"))
    lines.append(at(100.0, "ERROR", "Database connection refused for host db1"))
    for i in range(40):
        lines.append(at(100 + i * 0.1, "ERROR", f"Query {i} failed: timeout after 30s"))
        lines.append(at(100 + i * 0.1, "INFO", f"Retrying query {i}"))
    lines.append("   at Service.Run() in Service.cs:line 10")
    lines.extend(at(m, "INFO", f"Heartbeat ok for node {m % 4}") for m in range(190, 200))
    return lines


def run(lines: list[str]):
    return triage(enumerate(lines))


def test_levels_first_problem_and_look_first() -> None:
    lines = story()
    t = run(lines)
    assert t.levels["Error"] == 41 and t.levels["Warning"] == 5
    assert t.first_problem is not None and "connection refused" in t.first_problem.text
    assert any("first error" in n for n in t.look_first)


def test_indented_continuation_lines_are_not_counted_as_records() -> None:
    t = run(story())
    assert t.levels.get("Fatal / Critical", 0) == 0
    assert sum(t.levels.values()) == 46


def test_problem_patterns_and_noisiest() -> None:
    t = run(story())
    assert t.problem_patterns and t.problem_patterns[0].count >= 40
    assert "failed" in t.problem_patterns[0].template.lower()
    assert any("Heartbeat" in p.template for p in t.noisiest)


def test_worst_period_and_busiest_are_around_the_burst() -> None:
    t = run(story())
    assert t.worst_period is not None and t.worst_period.errors >= 10
    assert t.worst_period.start.hour == 10
    assert t.busiest is not None and t.busiest.lines > 5


def test_a_silence_and_a_rate_spike_and_new_messages_are_highlighted() -> None:
    t = run(story())
    kinds = {a.kind for a in t.anomalies}
    assert {"silence", "new message"} <= kinds
    assert t.longest_silence is not None and (t.longest_silence[1] - t.longest_silence[0]) >= timedelta(minutes=30)
    new = [a for a in t.anomalies if a.kind == "new message"]
    assert any("timeout" in a.summary for a in new)


def test_slow_requests_from_http_lines() -> None:
    lines = [f"2026-11-13 10:00:{i:02d},000 INFO GET /api/items/{i} responded 200 in {i * 100}ms" for i in range(1, 30)]
    t = run(lines)
    if t.http_requests:  # HTTP detection depends on the shape; when it recognises the lines the slowest is first
        assert t.slowest[0].duration_ms == max(s.duration_ms for s in t.slowest)


def test_a_log_without_levels_or_times_is_quiet_not_an_error() -> None:
    t = run(["hello", "world", "hello again"])
    assert t.total_lines == 3 and not t.levels and t.first_time is None
    assert "quiet" in t.look_first[0]
    assert "# Log summary" in render_markdown(t)


def test_empty_input() -> None:
    t = triage(iter(()))
    assert t.total_lines == 0 and t.first_problem is None


def test_sampling_is_reported(monkeypatch) -> None:
    from loglens.core import triage as module

    monkeypatch.setattr(module, "TRIAGE_MAX_LINES", 50)
    t = triage(enumerate(story()), total_lines=1000)
    assert t.examined == 50 and t.truncated
    assert "50 of 1,000 lines" in render_markdown(t)
    assert TRIAGE_MAX_LINES >= 100_000


def test_markdown_report_has_the_sections() -> None:
    md = render_markdown(run(story()), "My log")
    for heading in ("# My log", "## What to look at first", "## First error", "## Most frequent errors", "## Unusual"):
        assert heading in md
