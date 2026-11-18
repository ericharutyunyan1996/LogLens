"""Highlighter rules: regex → colours, applied to visible lines only.

Colours are strings Qt understands: "#RRGGBB" or "#AARRGGBB" (alpha first). Background tints use alpha so the same
rule looks right on light and dark themes.

Rules run on every painted line, so a pattern that can take exponential time (catastrophic backtracking, e.g.
``(\\w+\\s?)+:``) would freeze the UI: :func:`backtracking_risk` detects such patterns statically and a rule using one
is inactive (``compiled()`` is None). Packs and the knowledge base use the same check to reject them on import.
"""

from __future__ import annotations

import re
import re._constants as _sre
import re._parser as _sre_parser
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from typing import Any

# ---- catastrophic backtracking -------------------------------------------------------------------------------------
# A repeat inside a repeated group ("nested quantifier") makes the engine try every way of splitting the text between
# the iterations when a line almost matches — exponential time — unless every choice inside the group is decided by
# the next character: "one more iteration" vs "go on", and the alternatives of a branch, must start with different
# characters. Character sets are bit masks over a sample alphabet (Latin-1 plus a few characters of other scripts) and
# one bit per class (digit, other word character, space, rest) for the characters outside it, so the check errs on
# the side of rejecting.
NESTED_REPEAT_LIMIT = 4  # an enclosing repeat of at most this many iterations stays polynomial (``(\d{1,3}\.){3}``)
RISK_CACHE = 2_048  # checked patterns remembered (knowledge-base entries are re-read from SQLite on every listing)
_SAMPLE = "".join(map(chr, range(256))) + "\u0100\u0101\u0141\u0142\u0416\u0436\u03a9\u03c9\u4e2d\u0663\u2003\u3000"
_INDEX = {char: index for index, char in enumerate(_SAMPLE)}
_SAMPLED = (1 << len(_SAMPLE)) - 1
_OTHER_DIGIT = 1 << len(_SAMPLE)  # characters outside the sample, by class
_OTHER_WORD = _OTHER_DIGIT << 1  # (word characters that are not digits)
_OTHER_SPACE = _OTHER_DIGIT << 2
_OTHER_REST = _OTHER_DIGIT << 3
_OTHERS = _OTHER_DIGIT | _OTHER_WORD | _OTHER_SPACE | _OTHER_REST
_ALL = _SAMPLED | _OTHERS
_DIGIT, _WORD = re.compile(r"\d"), re.compile(r"\w")
_SPACES_BEYOND = tuple(code for code in range(256, 0x3001) if chr(code).isspace())  # \s past Latin-1 (all ≤ U+3000)
_REPEATS = (_sre.MAX_REPEAT, _sre.MIN_REPEAT, _sre.POSSESSIVE_REPEAT)
_ZERO_WIDTH = (_sre.AT, _sre.ASSERT, _sre.ASSERT_NOT)
_ENCLOSING = (*_REPEATS, _sre.SUBPATTERN, _sre.ASSERT, _sre.ASSERT_NOT)  # nodes whose last field is a sub-sequence
_RISK_MESSAGE = (
    "can take exponential time on some lines: parts of a repeated group can match the same text in more than one way "
    "(like (\\w+\\s?)+). Make the parts exclusive (e.g. (\\w+\\s)+), or use a possessive quantifier (\\w++) or an "
    "atomic group (?>…)"
)


def _category(regex: str, others: int) -> tuple[int, int]:
    """(characters of a class escape, the out-of-sample class bits it covers completely)."""
    test = re.compile(regex)
    return sum(1 << index for index, char in enumerate(_SAMPLE) if test.fullmatch(char)) | others, others


_CATEGORIES = {
    _sre.CATEGORY_DIGIT: _category(r"\d", _OTHER_DIGIT),
    _sre.CATEGORY_NOT_DIGIT: _category(r"\D", _OTHERS & ~_OTHER_DIGIT),
    _sre.CATEGORY_SPACE: _category(r"\s", _OTHER_SPACE),
    _sre.CATEGORY_NOT_SPACE: _category(r"\S", _OTHERS & ~_OTHER_SPACE),
    _sre.CATEGORY_WORD: _category(r"\w", _OTHER_DIGIT | _OTHER_WORD),
    _sre.CATEGORY_NOT_WORD: _category(r"\W", _OTHER_SPACE | _OTHER_REST),
}


def _class_bit(char: str) -> int:
    """The out-of-sample class bit of ``char``."""
    if char.isspace():
        return _OTHER_SPACE
    if _DIGIT.fullmatch(char):
        return _OTHER_DIGIT
    return _OTHER_WORD if _WORD.fullmatch(char) else _OTHER_REST


_CASE_PARTNERS = [
    sum(1 << _INDEX[other] for other in {char, char.lower(), char.upper(), char.swapcase()} if other in _INDEX)
    for char in _SAMPLE
]


def _children(op: Any, av: Any) -> list[Sequence[Any]] | None:
    """Sub-sequences of a parsed node (None for nodes without any)."""
    if op in _ENCLOSING:  # (min, max, body) / (group, add flags, del flags, body) / (direction, body)
        return [av[-1]]
    if op is _sre.ATOMIC_GROUP:
        return [av]
    if op is _sre.BRANCH:
        return list(av[1])
    if op is _sre.GROUPREF_EXISTS:
        return [av[1], av[2] or []]
    return None


def _uses_ignore_case(sequence: Sequence[Any]) -> bool:
    for op, av in sequence:
        if op is _sre.SUBPATTERN and av[1] & re.IGNORECASE:
            return True
        if any(_uses_ignore_case(child) for child in _children(op, av) or ()):
            return True
    return False


class _BacktrackingCheck:
    """First-character sets over a parsed pattern (``re._parser`` tree) and the nested-choice ambiguity check."""

    def __init__(self, *, ignore_case: bool) -> None:
        self._ignore_case = ignore_case

    def _char(self, code: int) -> int:
        char = chr(code)
        index = _INDEX.get(char)
        if index is None:
            return _class_bit(char)
        return _CASE_PARTNERS[index] if self._ignore_case else 1 << index

    def _range(self, low: int, high: int) -> int:
        bits = 0
        for code in (*range(low, min(high, 255) + 1), *(ord(c) for c in _SAMPLE[256:] if low <= ord(c) <= high)):
            bits |= self._char(code)
        if high > 255:  # past Latin-1: assume any class but space, unless the range holds a space character
            bits |= _OTHERS & ~_OTHER_SPACE
            bits |= _OTHER_SPACE if any(low <= code <= high for code in _SPACES_BEYOND) else 0
        return bits

    def _set(self, items: Sequence[tuple[Any, Any]]) -> int:
        bits, covered, negate = 0, 0, False
        for op, av in items:
            if op is _sre.NEGATE:
                negate = True
            elif op is _sre.LITERAL:
                bits |= self._char(av)
            elif op is _sre.RANGE:
                bits |= self._range(*av)
            else:  # CATEGORY; an unknown one may be any character
                category_bits, category_covers = _CATEGORIES.get(av, (_ALL, 0))
                bits, covered = bits | category_bits, covered | category_covers
        return ((_SAMPLED & ~bits) | (_OTHERS & ~covered)) if negate else bits

    def _single(self, op: Any, av: Any) -> int | None:
        """Characters of a one-character node (None for other nodes)."""
        if op is _sre.LITERAL:
            return self._char(av)
        if op is _sre.NOT_LITERAL:
            return (_SAMPLED & ~self._char(av)) | _OTHERS
        if op is _sre.ANY:
            return _ALL
        if op is _sre.IN:
            return self._set(av)
        return None

    def first(self, sequence: Sequence[Any]) -> tuple[int, bool]:
        """(characters a match of ``sequence`` can start with, whether it can match the empty string)."""
        bits = 0
        for op, av in sequence:
            node_bits, nullable = self._first_of(op, av)
            bits |= node_bits
            if not nullable:
                return bits, False
        return bits, True

    def _first_of(self, op: Any, av: Any) -> tuple[int, bool]:
        if op in _ZERO_WIDTH:
            return 0, True
        single = self._single(op, av)
        if single is not None:
            return single, False
        children = _children(op, av)
        if children is None or (op in _REPEATS and not av[1]):  # back-references, unknown nodes; x{0}
            return (_ALL, True) if children is None else (0, True)
        firsts = [self.first(child) for child in children]
        bits = 0
        for child_bits, _nullable in firsts:
            bits |= child_bits
        return bits, any(nullable for _bits, nullable in firsts) or (op in _REPEATS and av[0] == 0)

    def ambiguous(self, sequence: Sequence[Any], follow: int, depth: int) -> bool:
        """True if ``sequence`` — followed by characters ``follow``, inside ``depth`` repeated groups — has a choice
        whose options can start with the same character."""
        follows: list[int] = []
        rest_bits, rest_nullable = 0, True
        for op, av in reversed(sequence):
            follows.append(rest_bits | (follow if rest_nullable else 0))
            bits, nullable = self._first_of(op, av)
            rest_bits, rest_nullable = bits | (rest_bits if nullable else 0), rest_nullable and nullable
        follows.reverse()
        return any(
            self._node_ambiguous(op, av, after, depth) for (op, av), after in zip(sequence, follows, strict=True)
        )

    def _node_ambiguous(self, op: Any, av: Any, follow: int, depth: int) -> bool:
        children = _children(op, av)
        if children is None:
            return False
        if op in _REPEATS:
            low, high, body = av
            body_bits, _nullable = self.first(body)
            possessive = op is _sre.POSSESSIVE_REPEAT  # never gives an iteration back: no choice to revisit
            if depth and not possessive and low != high and body_bits & follow:
                return True  # "one more iteration" and "go on" can start alike, inside a repeated group
            inner = depth + (0 if possessive or high <= NESTED_REPEAT_LIMIT else 1)
            return self.ambiguous(body, (body_bits | follow) if high > 1 else follow, inner)
        if op is _sre.BRANCH or op is _sre.GROUPREF_EXISTS:
            if depth and self._overlapping(children, follow):
                return True
        elif op in (_sre.ASSERT, _sre.ASSERT_NOT):
            follow = 0  # a look-around's content is not followed by the rest of the pattern
        return any(self.ambiguous(child, follow, depth) for child in children)

    def _overlapping(self, branches: Sequence[Sequence[Any]], follow: int) -> bool:
        seen = 0
        for branch in branches:
            bits, nullable = self.first(branch)
            starts = bits | (follow if nullable else 0)
            if starts & seen:
                return True
            seen |= starts
        return False


@lru_cache(maxsize=RISK_CACHE)
def backtracking_risk(pattern: str, flags: int = 0) -> str | None:
    """Why ``pattern`` could take exponential time on some lines (catastrophic backtracking), or None if it can't.

    A conservative static check: a repeat or alternation inside a repeated group (of more than
    :data:`NESTED_REPEAT_LIMIT` iterations) whose choices can start with the same character is reported, even when
    the rest of the pattern would happen to rule the ambiguity out.
    """
    try:
        parsed = _sre_parser.parse(pattern, flags)
        ignore_case = bool(parsed.state.flags & re.IGNORECASE) or _uses_ignore_case(parsed)
        risky = _BacktrackingCheck(ignore_case=ignore_case).ambiguous(parsed, 0, 0)
    except RecursionError:
        return "is nested too deeply to be checked"
    except (re.error, OverflowError, ValueError) as exc:
        return f"is not a valid regular expression: {exc}"
    return _RISK_MESSAGE if risky else None


def compile_safely(pattern: str, flags: int = 0) -> re.Pattern[str] | str:
    """``pattern`` compiled, or a readable reason it can't be used (invalid, or see :func:`backtracking_risk`).

    The reason completes a sentence starting with the pattern, e.g. "pattern '(' is not a valid regular expression".
    """
    try:
        compiled = re.compile(pattern, flags)
    except re.error as exc:
        return f"is not a valid regular expression: {exc}"
    except (OverflowError, RecursionError, ValueError) as exc:  # a{4294967296}; groups nested thousands deep
        return f"is not a valid regular expression: {exc or type(exc).__name__}"
    return backtracking_risk(pattern, flags) or compiled


@dataclass
class HighlightRule:
    name: str
    pattern: str
    regex: bool = True
    case_sensitive: bool = False
    fg: str | None = None
    bg: str | None = None
    whole_line: bool = True  # colour the whole line, or only the matched text
    scrollbar_mark: bool = False  # also show matching lines as marks on the scrollbar
    level_filter: bool = False  # offer as a one-click level chip in the filter panel
    enabled: bool = True
    # (pattern, regex, case_sensitive) → the compiled pattern or why it can't be used; redone when those change
    _compiled: tuple[tuple[object, bool, bool], re.Pattern[str] | str] | None = field(
        default=None, init=False, repr=False, compare=False
    )

    def _compile(self) -> re.Pattern[str] | str:
        key: tuple[object, bool, bool] = (self.pattern, self.regex, self.case_sensitive)
        if self._compiled is None or self._compiled[0] != key:
            pattern: object = self.pattern  # from_dict takes any JSON value
            if isinstance(pattern, str):
                flags = 0 if self.case_sensitive else re.IGNORECASE
                result = compile_safely(pattern if self.regex else re.escape(pattern), flags)
            else:
                result = "is not text"
            self._compiled = (key, result)
        return self._compiled[1]

    def compiled(self) -> re.Pattern[str] | None:
        """The rule's regex; None when it is invalid or could take exponential time (the rule is then inactive)."""
        result = self._compile()
        return result if isinstance(result, re.Pattern) else None

    def problem(self) -> str | None:
        """Why the pattern can't be used (completes "pattern …", see :func:`compile_safely`), None if it is fine."""
        result = self._compile()
        return result if isinstance(result, str) else None

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("_compiled", None)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> HighlightRule:
        known = {k: v for k, v in d.items() if k in cls.__dataclass_fields__ and not k.startswith("_")}
        return cls(**known)


@dataclass
class LineStyle:
    fg: str | None = None
    bg: str | None = None
    spans: list[tuple[int, int, str | None, str | None]] = field(default_factory=list)  # (start, end, fg, bg)


# A level word counts as a *level* (not prose like "is not critical") when it is
#   - written in capitals as a token:            ERROR, [FTL], |FATAL|
#   - the value of a level field:                level=error, "@l":"Error", "severity": "warning"
#   - a capitalised word in the record header:   2018-07-21 11:17:26, Error  DISM ...
#   - a Microsoft.Extensions.Logging prefix:     fail: / crit: / warn:
_TOKEN = r"(?<![\w-])"
_LEVEL_FIELD = r"""(?:level|Level|LEVEL|severity|Severity|lvl|@l|LogLevel|loglevel)["']?\s?[:=]\s?["']?"""
# Capitalised level directly after a leading timestamp (optionally a [thread] token / delimiter), i.e. in the
# record header — "2018-07-21 11:17:26, Error", "…18:38:29.3712|Warn|", "…10:15:02,123 [14] Error". Prose that
# merely starts early ("sto: {Reflect Critical Driver Package}") has no timestamp before it and does not match.
_HEADER = r"^[\d\-/.:,TZ+ ]{8,40}(?:[AP]M)?[\s,|;]*(?:\[[^\]]{0,24}\]\s*)?[|,;]?\s*"


def _level_rule(caps: str, words: str, mel_prefix: str) -> str:
    """Regex for one severity: CAPS tokens | level field | capitalised header word | MEL prefix."""
    return (
        rf"{_TOKEN}(?:{caps})\b|{_LEVEL_FIELD}(?:{words}|{words.title()}|{caps})\b|{_HEADER}(?:{words.title()})\b"
        rf"|^(?:{mel_prefix}): "
    )


def default_rules() -> list[HighlightRule]:
    """Built-in highlighters, in priority order (the first matching whole-line rule colours the line)."""
    return [
        HighlightRule(
            "Fatal / Critical",
            _level_rule("FATAL|FTL|CRITICAL|CRIT|EMERG|ALERT", "fatal|critical", "crit"),
            case_sensitive=True,
            bg="#5AE0204A",
            scrollbar_mark=True,
            level_filter=True,
        ),
        HighlightRule(
            "Error",
            _level_rule("ERROR|ERR|EROR|FAILED|FAILURE|FAIL", "error|failed|failure", "fail")
            + r"|[A-Za-z]Exception\b|^Exception\b",
            case_sensitive=True,
            bg="#40F04040",
            scrollbar_mark=True,
            level_filter=True,
        ),
        HighlightRule(
            "Stack trace",
            r"^\s+(at|bei|à|в)\s+\S|^\s+File \"|^Traceback \(most recent|^Caused by:|^\s*---> |--- End of",
            fg="#C05050",
        ),
        HighlightRule(
            "Warning",
            _level_rule("WARNING|WARN|WRN", "warning|warn", "warn"),
            case_sensitive=True,
            bg="#40F0B400",
            scrollbar_mark=True,
            level_filter=True,
        ),
        HighlightRule("HTTP 5xx (W3C)", r" 5\d\d \d+ \d+ \d+$", bg="#40F04040", scrollbar_mark=True, level_filter=True),
        HighlightRule("HTTP 4xx (W3C)", r" 4\d\d \d+ \d+ \d+$", bg="#30F0B400"),
        HighlightRule(
            "Debug / Trace",
            _level_rule("DEBUG|DBG|TRACE|TRC|VERBOSE|VRB", "debug|trace|verbose", "dbug|trce"),
            case_sensitive=True,
            fg="#8A8A8A",
            level_filter=True,
        ),
        # Prose such as "an error occurred" / "connection failed": visible, but not counted as an issue.
        HighlightRule(
            "Problem words",
            r"\b(?:errors?|failed|failure|exception|fatal|timed out|denied)\b",
            fg="#C0504D",
            whole_line=False,
        ),
        HighlightRule(
            "GUID", r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", fg="#B05FD0", whole_line=False
        ),
        HighlightRule("Hex code", r"\b0x[0-9a-f]{4,16}\b", fg="#D2691E", whole_line=False),
        HighlightRule("IPv4", r"\b(?:\d{1,3}\.){3}\d{1,3}\b", fg="#2E8BC0", whole_line=False),
    ]


def style_line(rules: list[HighlightRule], text: str) -> LineStyle:
    """First matching whole-line rule wins (rule order = priority); all span rules apply."""
    style = LineStyle()
    whole_done = False
    for rule in rules:
        if not rule.enabled:
            continue
        pat = rule.compiled()
        if pat is None:
            continue
        if rule.whole_line:
            if not whole_done and pat.search(text):
                style.fg, style.bg = rule.fg, rule.bg
                whole_done = True
        else:
            for m in pat.finditer(text):
                if m.end() > m.start():
                    style.spans.append((m.start(), m.end(), rule.fg, rule.bg))
    return style
