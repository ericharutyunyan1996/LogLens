"""Search: literal/regex/invert, blocks, parallel parity, UTF-16, broken process pools, unusable patterns."""

from __future__ import annotations

import codecs
import os
import re
from concurrent.futures.process import BrokenProcessPool
from pathlib import Path

import numpy as np
import pytest

import loglens.core.search as search_mod
from loglens.core.search import SearchQuery, matching_lines, search_source
from tests.helpers import make_source


def test_matching_lines_one_hit_per_line() -> None:
    text = "error a error\nok\nERROR b\nfine\nerror"
    pat = SearchQuery("error").compile()
    assert matching_lines(text, pat, 10) == [10, 12, 14]


def test_matching_lines_anchors() -> None:
    text = "foo\nbar foo\nfoo bar"
    pat = SearchQuery(r"^foo", regex=True).compile()
    assert matching_lines(text, pat, 0) == [0, 2]
    pat = SearchQuery(r"foo$", regex=True).compile()
    assert matching_lines(text, pat, 0) == [0, 1]


def test_search_source_blocks_and_crlf(tmp_path: Path) -> None:
    lines = [f"{i:06d} {'ERROR' if i % 100 == 0 else 'INFO'} message" for i in range(20000)]
    src = make_source(tmp_path, ("\r\n".join(lines) + "\r\n").encode())
    hits = search_source(src, SearchQuery(r"ERROR message$", regex=True, case_sensitive=True))
    assert hits.tolist() == list(range(0, 20000, 100))
    inv = search_source(src, SearchQuery("INFO", invert=True))
    assert inv.tolist() == list(range(0, 20000, 100))


def test_parallel_search_matches_single(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    lines = [f"{i:06d} {'Error' if i % 7 == 0 else 'ok'} élan line" for i in range(30000)]
    src = make_source(tmp_path, ("\n".join(lines)).encode())
    monkeypatch.setattr(search_mod, "PARALLEL_RANGE_BYTES", 50_000)  # force many ranges
    try:
        for q in [SearchQuery("ERROR"), SearchQuery(r"^\d+5 ", regex=True), SearchQuery("ok", invert=True)]:
            single = search_source(src, q, parallel=False)
            par = search_source(src, q, parallel=True)
            assert np.array_equal(single, par), q
    finally:
        search_mod.shutdown_pool()


def test_search_utf16(tmp_path: Path) -> None:
    text = "alpha\r\nБета ошибка\r\ngamma\r\nОШИБКА again"
    src = make_source(tmp_path, codecs.BOM_UTF16_LE + text.encode("utf-16-le"))
    assert search_source(src, SearchQuery("ошибка")).tolist() == [1, 3]


def test_query_validation() -> None:
    assert SearchQuery("").validate()
    assert SearchQuery("(", regex=True).validate()
    assert SearchQuery("(", regex=False).validate() is None


@pytest.mark.parametrize("pattern", ["a{4294967296}", "(" * 2000 + "a" + ")" * 2000])
def test_validation_reports_patterns_re_rejects_with_other_errors(pattern: str) -> None:
    """``re`` raises OverflowError / RecursionError for these, not re.error."""
    query = SearchQuery(pattern, regex=True)
    message = query.validate()
    assert message is not None and message.startswith("Invalid regex")
    with pytest.raises(re.error):
        query.compile()


def test_broken_pool_is_replaced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A worker process that died breaks its pool for good; the next search must get a fresh pool."""
    src = make_source(tmp_path, "\n".join(f"{i:05d} {'hit' if i % 3 == 0 else 'miss'}" for i in range(3000)).encode())
    monkeypatch.setattr(search_mod, "PARALLEL_RANGE_BYTES", 4_000)  # several ranges
    try:
        broken = search_mod.get_pool()
        with pytest.raises(BrokenProcessPool):
            broken.submit(os._exit, 1).result()  # a worker dies (killed, crashed, out of memory)
        hits = search_source(src, SearchQuery("hit"), parallel=True)
        assert hits.tolist() == list(range(0, 3000, 3))
        assert search_mod.get_pool() is not broken
    finally:
        search_mod.shutdown_pool()


class _AlwaysBrokenPool:
    """Stands in for a ProcessPoolExecutor whose workers keep dying."""

    def __init__(self) -> None:
        self.shut_down = False

    def submit(self, *_args: object, **_kwargs: object) -> None:
        raise BrokenProcessPool("a worker process died")

    def shutdown(self, *_args: object, **_kwargs: object) -> None:
        self.shut_down = True


def test_broken_pool_is_retried_once_then_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src = make_source(tmp_path, b"hit\nmiss\n")
    pools: list[_AlwaysBrokenPool] = []

    def get_pool(_name: str = "search") -> _AlwaysBrokenPool:
        pools.append(_AlwaysBrokenPool())
        return pools[-1]

    monkeypatch.setattr(search_mod, "get_pool", get_pool)
    with pytest.raises(BrokenProcessPool):
        search_source(src, SearchQuery("hit"), parallel=True)
    assert len(pools) == 2 and all(pool.shut_down for pool in pools)


@pytest.mark.parametrize(
    ("text", "pattern", "expected"),
    [
        ("user from İstanbul\nistanbul\n", r"from istanbul", [0]),  # "İ" lower-cases to two characters
        ("FAıL here\nfail\nok\n", r"fail\b", [0, 1]),  # IGNORECASE equates "ı" and "i"; str.lower() does not
        ("ΣΥΝΔΕΣΗΣ\nok\n", "συνδεσησ", [0]),  # str.lower() turns a final "Σ" into "ς"
        ("x FOO Bar y\nfoo bar\nfoo x\n", r"foo (?:x|(?-i:Bar))", [0, 2]),  # scoped case-sensitive group
    ],
)
def test_case_insensitive_regex_matches_like_ignorecase(
    tmp_path: Path, text: str, pattern: str, expected: list[int]
) -> None:
    """Through the block search (shared lower/fold caches) the prefilter must agree with the plain regex scan."""
    src = make_source(tmp_path, text.encode())
    query = SearchQuery(pattern, regex=True)
    assert matching_lines(text.rstrip("\n"), query.compile(), 0) == expected
    assert search_source(src, query, parallel=False).tolist() == expected
