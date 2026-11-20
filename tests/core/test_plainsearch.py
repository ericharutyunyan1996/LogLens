"""Plain-words search: sentences become levels, terms and a time range that can be shown and edited."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from loglens.core.filters import FilterMode
from loglens.core.plainsearch import parse

REF = datetime(2026, 11, 13, 15, 30, 0).astimezone()


def terms(q) -> list[tuple[str, str]]:
    return [(t.query.pattern, t.mode.value) for t in q.terms]


def test_errors_in_the_last_hour() -> None:
    q = parse("show me errors in the last hour", REF)
    assert q.levels == ["Error"] and not q.terms
    assert q.time_range is not None and q.time_range.start == REF - timedelta(hours=1)


def test_a_phrase_and_a_negation() -> None:
    q = parse('errors containing "connection refused" but not timeouts', REF)
    assert q.levels == ["Error"]
    assert ("connection refused", "all") in terms(q) and ("timeouts", "none") in terms(q)


def test_quoted_exclusion() -> None:
    q = parse('warnings without "disk slow"', REF)
    assert q.levels == ["Warning"] and terms(q) == [("disk slow", "none")]


def test_critical_and_several_levels() -> None:
    q = parse("critical errors and warnings", REF)
    assert q.levels == ["Fatal / Critical", "Error", "Warning"]


@pytest.mark.parametrize(
    ("text", "start", "end"),
    [
        ("today", datetime(2026, 11, 13), datetime(2026, 11, 14)),
        ("errors yesterday", datetime(2026, 11, 12), datetime(2026, 11, 13)),
    ],
)
def test_days(text: str, start: datetime, end: datetime) -> None:
    q = parse(text, REF)
    assert q.time_range is not None
    assert q.time_range.start.replace(tzinfo=None) == start and q.time_range.end.replace(tzinfo=None) == end


def test_between_and_after() -> None:
    q = parse("errors between 10:00 and 11:30", REF)
    assert q.time_range is not None and q.time_range.start.hour == 10 and q.time_range.end.minute == 30
    after = parse("anything after 2:15pm", REF)
    assert after.time_range is not None and after.time_range.start.hour == 14 and after.time_range.end is None


def test_http_status_codes() -> None:
    q = parse("5xx responses", REF)
    assert any(t.query.regex and t.query.pattern.startswith(r"\b5") for t in q.terms)
    q = parse("status 404 for /api/users", REF)
    assert (r"\b404\b", "all") in terms(q) and any(t.query.pattern == "/api/users" for t in q.terms)


def test_unknown_words_become_visible_terms_not_silent_guesses() -> None:
    q = parse("find payment declined", REF)
    assert terms(q) == [("payment", "all"), ("declined", "all")]
    assert all("containing" in u for u in q.understood)


def test_empty_sentence_is_empty() -> None:
    assert parse("   ", REF).is_empty and parse("show me the logs", REF).is_empty


def test_every_term_is_explained() -> None:
    q = parse('errors in the last 15 minutes without "retry"', REF)
    assert len(q.understood) >= 3 and q.terms[0].mode is FilterMode.NONE
