"""Regex literal prefilter: extraction and parity with full regex scans."""

from __future__ import annotations

import pytest

from loglens.core.highlight import HighlightRule, style_line
from loglens.core.search import SearchQuery, matching_lines


def test_literal_prefilter_extraction() -> None:
    import re

    from loglens.core.regex_tools import has_cased_literals, literal_prefilter

    i = re.IGNORECASE
    assert literal_prefilter(r"(?<![\w-])(ERROR|ERR|EROR|FAIL(ED|URE)?)\b|Exception\b", i) == (
        "eror",
        "err",
        "exception",
        "fail",
    )  # "error" dropped: contains "err"
    assert literal_prefilter(r"(WARN|WARNING|WRN)\b", i) == ("warn", "wrn")
    assert literal_prefilter(r"in \d{4,} ms", 0) == ("in ",)
    assert literal_prefilter(r"\d+ ms", 0) == (" ms",)
    assert literal_prefilter(r"\d+ s", 0) is None  # " s" too short to be selective
    assert literal_prefilter(r"timeout after \d+ seconds", 0) == ("timeout after ",)
    assert literal_prefilter(r"(foo)?barbaz", 0) == ("barbaz",)  # optional group must not be required
    assert literal_prefilter(r"a.b", 0) is None
    assert not has_cased_literals(r" 5\d\d \d+$")
    assert has_cased_literals(r"\d+ ms")
    assert has_cased_literals(r"[A-F]+")


@pytest.mark.parametrize(
    "pattern",
    [
        r"(ERROR|FAIL(ED)?)\b",
        r"Exception\b",
        r"timeout after \d+",
        r"^\d{6} Error",
        r"line$",
        r"(?i)DEADLOCK",
        r"err(or)?:\s+\w+",
        r"\bpay\w+ failed",
    ],
)
@pytest.mark.parametrize("case_sensitive", [True, False])
def test_prefiltered_equals_full_regex(pattern: str, case_sensitive: bool) -> None:

    words = [
        "Error",
        "ERROR:",
        "error: disk",
        "failed",
        "FAILED",
        "Exception",
        "TimeoutException",
        "timeout after 30",
        "deadlock",
        "Deadlock",
        "payment failed",
        "pay failed",
        "ok",
        "line",
        "liner",
        "err:  x",
    ]
    text = "\n".join(f"{i:06d} {words[i % len(words)]} {words[(i * 7) % len(words)]} line" for i in range(3000))
    q = SearchQuery(pattern, regex=True, case_sensitive=case_sensitive)
    assert q.matching(text, 5) == matching_lines(text, q.compile(), 5)


@pytest.mark.parametrize(
    ("pattern", "text", "expected"),
    [
        # a scoped case-sensitive group inside a branch: the regex must run on the original text, not the lowered one
        (r"foo (?:x|(?-i:Bar))", "x FOO Bar y\nfoo bar\nfoo x", [0, 2]),
        # "İ" lower-cases to two characters: offsets in text.lower() no longer match the text
        (r"İstanbul\b", "user from İstanbul\nISTANBUL\nistanbul\nx", [0, 1, 2]),
        (r"from istanbul", "user from İstanbul\nok", [0]),
        # IGNORECASE equivalences str.lower() does not know: ı/i, ſ/s, ς/σ, µ/μ
        (r"fail(ed)?\b", "FAıL here\nfailed\nok", [0, 1]),
        (r"faıl(ed)?\b", "FAIL here\nfailed\nok", [0, 1]),
        (r"ſtatus \d+", "STATUS 500\nok", [0]),
        ("συνδεσησ", "ΣΥΝΔΕΣΗΣ\nok", [0]),
        (r"\d+ µs\b", "took 15 Μs\nok", [0]),
    ],
)
def test_case_insensitive_prefilter_equals_full_regex(pattern: str, text: str, expected: list[int]) -> None:
    q = SearchQuery(pattern, regex=True)
    assert matching_lines(text, q.compile(), 0) == expected
    assert q.matching(text, 0) == expected


def test_backreference_is_case_insensitive() -> None:
    from loglens.core.regex_tools import has_cased_literals

    assert has_cased_literals(r"(\w)\1")
    assert SearchQuery(r"(\w)\1", regex=True).matching("Aa\nab\nBB", 0) == [0, 2]


def test_case_fold_keeps_length_and_merges_ignorecase_equivalents() -> None:
    from loglens.core.regex_tools import case_fold

    assert case_fold("Plain ASCII") == "plain ascii"
    for a, b in [("ı", "I"), ("ſ", "s"), ("ς", "Σ"), ("µ", "Μ")]:
        assert case_fold(a) == case_fold(b), (a, b)
        assert len(case_fold(a)) == 1


def test_rule_roundtrip_and_bad_regex() -> None:
    r = HighlightRule("bad", "(", regex=True)
    assert r.compiled() is None
    assert style_line([r], "anything").bg is None
    assert HighlightRule.from_dict(r.to_dict()) == r
