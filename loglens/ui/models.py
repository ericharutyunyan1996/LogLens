"""Row models for LogView: the whole file, or the filtered subset of its lines (optionally with context)."""

from __future__ import annotations

from typing import Protocol

import numpy as np

from ..core.filters import ContextRows, with_context
from ..core.records import RecordLayout
from ..core.secrets import SecretMasker, has_secrets, mask
from ..core.text_source import MAX_DISPLAY_LINE_BYTES, TextLogSource


class LineModel(Protocol):
    def row_count(self) -> int: ...
    def file_line(self, row: int) -> int: ...
    def row_for_line(self, line: int) -> int: ...
    def texts(self, first: int, count: int) -> list[str]: ...
    def full_text(self, row: int) -> str: ...
    def max_chars(self) -> int: ...
    def max_file_line(self) -> int: ...
    def is_hit(self, row: int) -> bool: ...
    def gap_before(self, row: int) -> bool: ...


MASK_LOOKBACK_LINES = 60  # lines read above a window so a private key that began above it is still masked


def masked(texts: list[str], preceding: list[str] | None = None) -> list[str]:
    """``texts`` (consecutive lines) with secrets replaced; ``preceding`` lines only establish whether the window
    starts inside a private key block that is logged line by line."""
    masker = SecretMasker()
    if preceding:
        masker.mask_lines(preceding)
    return masker.mask_lines(texts)


def _mask_one(text: str) -> str:
    return mask(text) if has_secrets(text) else text


class SourceLines:
    """Every line of the file; row == file line."""

    def __init__(self, source: TextLogSource, *, mask_secrets: bool = False) -> None:
        self.source = source
        self.mask_secrets = mask_secrets

    def row_count(self) -> int:
        return self.source.line_count()

    def file_line(self, row: int) -> int:
        return row

    def row_for_line(self, line: int) -> int:
        return line

    def texts(self, first: int, count: int) -> list[str]:
        texts = self.source.get_lines(first, count)
        if not self.mask_secrets:
            return texts
        start = max(first - MASK_LOOKBACK_LINES, 0)
        return masked(texts, self.source.get_lines(start, first - start))

    def full_text(self, row: int) -> str:
        text = self.source.get_full_line(row)
        if not self.mask_secrets:
            return text
        start = max(row - MASK_LOOKBACK_LINES, 0)
        return masked([text], self.source.get_lines(start, row - start))[0]

    def max_chars(self) -> int:
        return min(self.source.max_line_chars, MAX_DISPLAY_LINE_BYTES + 64)

    def max_file_line(self) -> int:
        return self.row_count()

    def is_hit(self, row: int) -> bool:
        return True

    def gap_before(self, row: int) -> bool:
        return False


class FilteredLines:
    """Matching lines of a filter, optionally with context lines and/or their whole multi-line records (dimmed)."""

    def __init__(
        self,
        source: TextLogSource,
        hits: np.ndarray | None = None,
        context: int = 0,
        *,
        records: RecordLayout | None = None,
    ) -> None:
        self.source = source
        self._hits = hits if hits is not None else np.empty(0, dtype=np.int64)
        self._context = context
        self._records = records
        self.mask_secrets = False
        self._rows = with_context(self._hits, context, context, source.line_count(), records=records)

    # ---- configuration -------------------------------------------------------------------------------------------
    def set_hits(self, hits: np.ndarray) -> None:
        self._hits = hits
        self._rebuild()

    def set_context(self, lines: int) -> None:
        self._context = max(lines, 0)
        self._rebuild()

    def set_records(self, records: RecordLayout | None) -> None:
        """Show whole records around every match (None = matching lines only)."""
        self._records = records
        self._rebuild()

    def _rebuild(self) -> None:
        total = self.source.line_count()
        self._rows = with_context(self._hits, self._context, self._context, total, records=self._records)

    @property
    def rows(self) -> ContextRows:
        return self._rows

    @property
    def hits(self) -> np.ndarray:
        return self._hits

    # ---- LineModel -----------------------------------------------------------------------------------------------
    def row_count(self) -> int:
        return len(self._rows.lines)

    def file_line(self, row: int) -> int:
        return int(self._rows.lines[row])

    def row_for_line(self, line: int) -> int:
        """Row of the line at or just before ``line``."""
        if not len(self._rows.lines):
            return 0
        return max(int(np.searchsorted(self._rows.lines, line, side="right")) - 1, 0)

    def texts(self, first: int, count: int) -> list[str]:
        texts = self.source.get_lines_at(self._rows.lines[first : first + count])
        return [_mask_one(t) for t in texts] if self.mask_secrets else texts

    def full_text(self, row: int) -> str:
        text = self.source.get_full_line(int(self._rows.lines[row]))
        return mask(text) if self.mask_secrets else text

    def max_chars(self) -> int:
        return min(self.source.max_line_chars, MAX_DISPLAY_LINE_BYTES + 64)

    def max_file_line(self) -> int:
        return self.source.line_count()

    def is_hit(self, row: int) -> bool:
        return bool(self._rows.is_hit[row])

    def gap_before(self, row: int) -> bool:
        return bool(self._rows.gap_before[row])
