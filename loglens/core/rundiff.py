"""Side-by-side comparison of two runs (a good run and a bad run): an aligned, line-by-line diff.

Lines are compared by their *shape*: timestamps, numbers, ids and other variable parts are masked first, so two runs
of the same program line up even though every value differs. Equal stretches are folded away and what is only in one
run (or changed) stands out, with the line numbers on both sides to jump to.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from difflib import SequenceMatcher

from .patterns import mask_variables

MAX_LINES = 30_000  # per run; a longer one is compared by its first lines (and says so)
CONTEXT = 2  # equal lines kept around a difference
MIN_ROW_CHARS = 1


@dataclass(frozen=True, slots=True)
class DiffRow:
    kind: str  # "same" | "changed" | "only_a" | "only_b" | "gap"
    a_line: int | None = None  # 0-based
    a_text: str = ""
    b_line: int | None = None
    b_text: str = ""
    skipped: int = 0  # for "gap": equal lines folded away


@dataclass(slots=True)
class RunDiff:
    rows: list[DiffRow]
    same: int = 0
    changed: int = 0
    only_a: int = 0
    only_b: int = 0
    truncated: bool = False

    @property
    def identical(self) -> bool:
        return not (self.changed or self.only_a or self.only_b)


def _sample(lines: Iterable[tuple[int, str]]) -> tuple[list[tuple[int, str, str]], bool]:
    out: list[tuple[int, str, str]] = []
    for number, text in lines:
        if len(out) >= MAX_LINES:
            return out, True
        key = mask_variables(text)
        if len(key) >= MIN_ROW_CHARS:
            out.append((number, text, key))
    return out, False


def diff_runs(a: Iterable[tuple[int, str]], b: Iterable[tuple[int, str]], *, context: int = CONTEXT) -> RunDiff:
    """Align run ``a`` ("good") with run ``b`` ("bad") and describe what differs."""
    left, cut_a = _sample(a)
    right, cut_b = _sample(b)
    matcher = SequenceMatcher(None, [k for _n, _t, k in left], [k for _n, _t, k in right], autojunk=False)
    result = RunDiff([], truncated=cut_a or cut_b)
    raw: list[DiffRow] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for i, j in zip(range(i1, i2), range(j1, j2), strict=True):
                raw.append(DiffRow("same", left[i][0], left[i][1], right[j][0], right[j][1]))
            result.same += i2 - i1
        elif tag == "replace":
            span = max(i2 - i1, j2 - j1)
            for k in range(span):
                has_a, has_b = i1 + k < i2, j1 + k < j2
                kind = "changed" if has_a and has_b else ("only_a" if has_a else "only_b")
                row = DiffRow(
                    kind,
                    left[i1 + k][0] if has_a else None,
                    left[i1 + k][1] if has_a else "",
                    right[j1 + k][0] if has_b else None,
                    right[j1 + k][1] if has_b else "",
                )
                raw.append(row)
                setattr(result, kind, getattr(result, kind) + 1)
        elif tag == "delete":
            raw.extend(DiffRow("only_a", left[i][0], left[i][1]) for i in range(i1, i2))
            result.only_a += i2 - i1
        else:  # insert
            raw.extend(DiffRow("only_b", None, "", right[j][0], right[j][1]) for j in range(j1, j2))
            result.only_b += j2 - j1
    result.rows = list(_fold(raw, context))
    return result


def _fold(rows: list[DiffRow], context: int) -> Iterator[DiffRow]:
    """Keep ``context`` equal lines around a difference; a longer equal stretch becomes one "gap" row."""
    keep = [False] * len(rows)
    for index, row in enumerate(rows):
        if row.kind != "same":
            for near in range(max(0, index - context), min(len(rows), index + context + 1)):
                keep[near] = True
    skipped = 0
    for index, row in enumerate(rows):
        if keep[index]:
            if skipped:
                yield DiffRow("gap", skipped=skipped)
                skipped = 0
            yield row
        else:
            skipped += 1
    if skipped:
        yield DiffRow("gap", skipped=skipped)
