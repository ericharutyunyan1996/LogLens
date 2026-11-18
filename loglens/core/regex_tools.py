"""Regex analysis used to speed up searching.

``literal_prefilter`` finds a small set of plain strings such that *every* match of the regex contains at least one
of them. Searching for those strings with ``str.find`` is far faster than running the regex engine over every
character, so we only run the real regex on the (few) candidate lines.

For case-insensitive patterns the literals are looked for in :func:`case_fold`-ed text, but the regex itself always
runs on the original text (lower-casing is not equivalent to ``re.IGNORECASE``: scoped ``(?-i:...)`` groups, "İ").
"""

from __future__ import annotations

import importlib
import re
from collections.abc import Iterator
from functools import lru_cache
from typing import Any

try:  # CPython 3.11+
    import re._constants as _c
    import re._parser as _p
except ImportError:  # pragma: no cover - other interpreters: no optimisation
    _c = _p = None

MIN_LITERAL_LEN = 3
MAX_ALTERNATIVES = 24


def _fold_table() -> dict[int, int]:
    """Map every character ``re.IGNORECASE`` equates with another one beyond ``str.lower`` to one representative.

    IGNORECASE also treats e.g. "ı"/"i", "ſ"/"s", "ς"/"σ" and "µ"/"μ" as equal; ``str.lower`` keeps them apart.
    The representative is what ``str.lower`` makes of the class's capital letter ("i", "s", "σ", "μ").
    """
    try:  # the equivalence classes CPython's regex engine uses (generated from the Unicode database)
        extra: dict[int, tuple[int, ...]] = importlib.import_module("re._casefix")._EXTRA_CASES
    except (ImportError, AttributeError):  # pragma: no cover - other interpreters
        return {}
    table: dict[int, int] = {}
    for code, others in extra.items():
        members = sorted({chr(code), *map(chr, others)})
        stable = [m for m in members if m.upper().lower() == m]
        canonical = (stable or members)[0]
        table.update({ord(m): ord(canonical) for m in members if m != canonical})
    return table


_FOLD_TABLE = _fold_table()
_FOLD_CHARS = tuple(chr(code) for code in _FOLD_TABLE)


def fold_lowered(lowered: str) -> str:
    """:func:`case_fold` for text that is already ``str.lower()``-ed (ASCII text is returned as is, in O(1))."""
    if lowered.isascii() or not any(ch in lowered for ch in _FOLD_CHARS):
        return lowered
    return lowered.translate(_FOLD_TABLE)


def case_fold(text: str) -> str:
    """``text`` lower-cased so that characters ``re.IGNORECASE`` treats as equal become the same character."""
    return fold_lowered(text.lower())


def _parse(pattern: str, flags: int) -> Any:
    if _p is None:
        return None
    try:
        return _p.parse(pattern, flags)
    except (re.error, ValueError, TypeError, OverflowError, RecursionError):  # invalid: reported elsewhere
        return None


def _walk(node: Any) -> Iterator[tuple[Any, Any]]:
    if _p is not None and isinstance(node, _p.SubPattern):
        node = node.data
    if isinstance(node, list):
        for item in node:
            yield from _walk(item)
    elif isinstance(node, tuple):
        if len(node) == 2 and isinstance(node[0], _c._NamedIntConstant):
            yield node
            yield from _walk(node[1])
        else:
            for x in node:
                yield from _walk(x)


def _cased(ch: str) -> bool:
    return ch.lower() != ch.upper()


@lru_cache(maxsize=256)
def has_cased_literals(pattern: str, flags: int = 0) -> bool:
    """True if case-insensitivity could change what the pattern matches."""
    tree = _parse(pattern, flags)
    if tree is None:
        return True
    try:
        return any(_case_matters(op, av) for op, av in _walk(tree))
    except RecursionError:  # absurdly nested: assume it matters
        return True


def _case_matters(op: Any, av: Any) -> bool:
    if op is _c.GROUPREF:  # a backreference repeats captured text: "(\w)\1" must match "Aa" case-insensitively
        return True
    if op in (_c.LITERAL, _c.NOT_LITERAL):
        return _cased(chr(av))
    if op is _c.RANGE:
        lo, hi = av
        return any(_cased(chr(c)) for c in range(lo, min(hi, lo + 512) + 1))
    return False


def _score(cands: list[str] | None) -> tuple[int, int]:
    if not cands:
        return (-1, 0)
    return (min(len(x) for x in cands), -len(cands))


def _alternatives(items: Any) -> list[str] | None:
    """Best literal set for a sequence: every match of the sequence contains one of the returned strings."""
    best: list[str] | None = None
    run: list[str] = []

    def consider(cands: list[str] | None) -> None:
        nonlocal best
        if cands and len(cands) <= MAX_ALTERNATIVES and _score(cands) > _score(best):
            best = cands

    def flush() -> None:
        if run:
            consider(["".join(run)])
            run.clear()

    for op, av in items:
        if op is _c.LITERAL:
            run.append(chr(av))
            continue
        prefix = "".join(run)
        flush()
        if op is _c.SUBPATTERN:
            _group, add_flags, del_flags, sub = av
            if (add_flags | del_flags) & re.IGNORECASE:
                return None  # local case flag change: be safe, no prefilter
            consider(_alternatives(sub))
        elif op is getattr(_c, "ATOMIC_GROUP", None):
            consider(_alternatives(av))
        elif op is _c.BRANCH:
            branches = [_alternatives(b) for b in av[1]]
            if branches and all(branches):
                consider(sorted({x for b in branches for x in b}))  # type: ignore[union-attr]
            # The parser factors a shared prefix out of alternatives ("WARN|WRN" -> "W" + (ARN|RN));
            # glue it back onto each branch's leading literal ("WARN", "WRN").
            if prefix:
                leads = []
                for branch in av[1]:
                    lead = []
                    for bop, bav in branch:
                        if bop is not _c.LITERAL:
                            break
                        lead.append(chr(bav))
                    leads.append(prefix + "".join(lead))
                consider(sorted(set(leads)))
        elif op in (_c.MAX_REPEAT, _c.MIN_REPEAT, getattr(_c, "POSSESSIVE_REPEAT", _c.MAX_REPEAT)):
            lo, _hi, item = av
            if lo >= 1:
                consider(_alternatives(item))
    flush()
    return best


@lru_cache(maxsize=256)
def literal_prefilter(pattern: str, flags: int = 0) -> tuple[str, ...] | None:
    """Literals that every match contains (:func:`case_fold`-ed if IGNORECASE), or None if no useful set exists."""
    tree = _parse(pattern, flags)
    if tree is None:
        return None
    if tree.state.flags & re.IGNORECASE and not flags & re.IGNORECASE:
        flags |= re.IGNORECASE  # inline (?i)
    try:
        cands = _alternatives(list(tree))
    except RecursionError:  # absurdly nested: no prefilter
        return None
    if not cands or min(len(x) for x in cands) < MIN_LITERAL_LEN or any("\n" in x for x in cands):
        return None
    if flags & re.IGNORECASE:
        if any(len(x.lower()) != len(x) for x in cands):
            return None  # "İ" lower-cases to two characters, yet IGNORECASE matches it against a plain "i"
        cands = sorted({case_fold(x) for x in cands})
    # drop literals that contain another literal from the set (the shorter one already finds those lines)
    return tuple(x for x in cands if not any(y != x and y in x for y in cands))


def matching_lines_prefiltered(
    text: str,
    pattern: re.Pattern[str],
    literals: tuple[str, ...] | list[str],
    line0: int,
    *,
    haystack: str | None = None,
) -> list[int]:
    """Line numbers of lines matching ``pattern``, checking only lines that contain one of ``literals``.

    ``haystack`` is where the literals are looked for when that is not ``text`` itself: for IGNORECASE patterns pass
    ``case_fold(text)`` (literals from :func:`literal_prefilter` are folded the same way). It must be exactly as long
    as ``text`` so offsets coincide; the regex always runs on the original ``text``.
    """
    if haystack is not None and len(haystack) != len(text):
        raise ValueError("haystack must have the same length as text")
    starts: set[int] = set()
    hay = text if haystack is None else haystack
    find, rfind = hay.find, hay.rfind
    for lit in literals:
        pos = 0
        while True:
            s = find(lit, pos)
            if s < 0:
                break
            starts.add(rfind("\n", 0, s) + 1)
            nl = find("\n", s)
            if nl < 0:
                break
            pos = nl + 1
    out: list[int] = []
    line, last = line0, 0
    count, search, find_nl = text.count, pattern.search, text.find
    n = len(text)
    for ls in sorted(starts):
        line += count("\n", last, ls)
        last = ls
        le = find_nl("\n", ls)
        if search(text, ls, n if le < 0 else le):
            out.append(line)
    return out
