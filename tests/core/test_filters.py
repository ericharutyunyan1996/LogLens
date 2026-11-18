"""Filter chains (AND / OR / NOT + levels) and context rows."""

from __future__ import annotations

from pathlib import Path

import numpy as np

from loglens.core.filters import FilterMode, FilterSpec, FilterTerm, with_context
from loglens.core.search import SearchQuery, search_multi
from tests.helpers import make_source

LINES = [
    "ERROR db timeout",  # 0
    "INFO ok",  # 1
    "ERROR network timeout",  # 2
    "WARN slow db",  # 3
    "ERROR disk full",  # 4
    "INFO db ok",  # 5
]


def run(tmp_path: Path, spec: FilterSpec) -> list[int]:
    source = make_source(tmp_path, ("\n".join(LINES) + "\n").encode())
    results = search_multi(source, spec.queries(), parallel=False)
    return spec.combine(results, 0, source.line_count()).tolist()


def term(pattern: str, mode: FilterMode = FilterMode.ALL) -> FilterTerm:
    return FilterTerm(SearchQuery(pattern), mode)


def test_and_or_not_combinations(tmp_path: Path) -> None:
    assert run(tmp_path, FilterSpec((term("error"), term("timeout")))) == [0, 2]
    assert run(tmp_path, FilterSpec((term("db", FilterMode.ANY), term("disk", FilterMode.ANY)))) == [0, 3, 4, 5]
    assert run(tmp_path, FilterSpec((term("error"), term("network", FilterMode.NONE)))) == [0, 4]
    assert run(tmp_path, FilterSpec((term("info", FilterMode.NONE),))) == [0, 2, 3, 4]  # exclude-only


def test_levels_combine_with_terms(tmp_path: Path) -> None:
    levels = (SearchQuery("ERROR", case_sensitive=True), SearchQuery("WARN", case_sensitive=True))
    assert run(tmp_path, FilterSpec(levels=levels)) == [0, 2, 3, 4]
    assert run(tmp_path, FilterSpec((term("db"),), levels=levels)) == [0, 3]


def test_validation_and_highlight() -> None:
    spec = FilterSpec((FilterTerm(SearchQuery("(", regex=True)),))
    assert spec.validate() is not None
    spec = FilterSpec(
        (term("Time.out"), FilterTerm(SearchQuery("x", case_sensitive=True)), term("db", FilterMode.NONE))
    )
    pattern = spec.highlight_pattern()
    assert pattern is not None
    assert pattern.search("TIME.OUT") and not pattern.search("timeXout")  # literal, case-insensitive
    assert pattern.search("x") and not pattern.search("X") and not pattern.search("db")


def test_context_rows() -> None:
    rows = with_context(np.array([5, 6, 20]), before=1, after=1, total_lines=21)
    assert rows.lines.tolist() == [4, 5, 6, 7, 19, 20]
    assert rows.is_hit.tolist() == [False, True, True, False, False, True]
    assert rows.gap_before.tolist() == [False, False, False, False, True, False]
    plain = with_context(np.array([1, 3]), 0, 0, 10)
    assert plain.is_hit.all() and not plain.gap_before.any()  # no separators without context
