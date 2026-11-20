"""Aligned comparison of two runs: variable parts are ignored, real differences stand out."""

from __future__ import annotations

from loglens.core import rundiff
from loglens.core.rundiff import diff_runs


def run(*texts: str) -> list[tuple[int, str]]:
    return list(enumerate(texts))


GOOD = run(
    "2026-11-13 10:00:00,100 INFO start job 17",
    "2026-11-13 10:00:01,200 INFO loaded 1200 rows from db1",
    "2026-11-13 10:00:02,300 INFO sent report to alice@example.com",
    "2026-11-13 10:00:03,400 INFO done in 3.3s",
)
BAD = run(
    "2026-11-14 22:10:00,900 INFO start job 18",
    "2026-11-14 22:10:01,950 INFO loaded 77 rows from db1",
    "2026-11-14 22:10:02,100 ERROR connection to smtp lost",
    "2026-11-14 22:10:09,000 INFO done in 9.0s",
)


def test_runs_with_only_different_values_are_identical() -> None:
    other = run(*(line.replace("17", "99").replace("1200", "5") for _n, line in GOOD))
    d = diff_runs(GOOD, other)
    assert d.identical and d.same == 4 and all(r.kind in ("same", "gap") for r in d.rows)


def test_a_new_error_line_is_reported_and_values_are_ignored() -> None:
    d = diff_runs(GOOD, BAD)
    assert d.same == 3 and d.changed + d.only_b == 1
    odd = [r for r in d.rows if r.kind != "same"]
    assert len(odd) == 1 and "smtp" in odd[0].b_text and odd[0].b_line == 2


def test_lines_only_in_one_run() -> None:
    d = diff_runs(run("a one", "b two", "c three"), run("a one", "c three"))
    assert d.only_a == 1 and d.only_b == 0
    only = next(r for r in d.rows if r.kind == "only_a")
    assert only.a_text == "b two" and only.a_line == 1 and only.b_line is None


def test_long_equal_stretches_are_folded() -> None:
    same = [f"step {i % 3} alpha beta" for i in range(40)]
    d = diff_runs(run(*same, "tail a"), run(*same, "tail b different words"), context=2)
    gaps = [r for r in d.rows if r.kind == "gap"]
    assert gaps and gaps[0].skipped > 30
    assert len(d.rows) < 15


def test_empty_runs_and_truncation(monkeypatch) -> None:
    assert diff_runs([], []).identical
    monkeypatch.setattr(rundiff, "MAX_LINES", 5)
    d = diff_runs(run(*[f"x {c}" for c in "abcdefghij"]), run("x a"))
    assert d.truncated
