"""A text log file exposed as numbered lines, with change detection for tail/follow mode."""

from __future__ import annotations

import enum
import os
import threading
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

import numpy as np

from .encoding import EncodingInfo, detect_encoding, for_codec
from .fileio import FileIdentity, file_identity, open_shared
from .line_index import IndexSnapshot, LineIndex

SAMPLE_BYTES = 64 * 1024
MAX_DISPLAY_LINE_BYTES = 64 * 1024  # longer lines are clipped for display (search still sees the full line)
BLOCK_READ_LIMIT = 8 * 1024 * 1024
# Shorter samples can't tell encodings apart (BOMs are up to 3 bytes, BOM-less UTF-16 needs two code units), and a
# sample without a newline may be the first line still being written: the guess is re-checked as the file grows.
MIN_DETECT_BYTES = 4
# Bytes compared at the start of the file and just before the indexed end, to tell "appended to" from "truncated and
# rewritten past the old size" (same file id, bigger size) between two polls. Log lines start with timestamps, so a
# rewrite virtually always changes them.
FINGERPRINT_BYTES = 64


class Change(enum.Enum):
    NONE = "none"
    GROWN = "grown"
    RESET = "reset"  # truncated, replaced, rotated or rewritten (or the encoding guess changed): re-index from scratch
    MISSING = "missing"


@dataclass(frozen=True, slots=True)
class _Fingerprint:
    """What the indexed bytes [0, end) looked like: their start and their end."""

    end: int
    head: bytes = b""
    tail: bytes = b""


def _read_fingerprint(f: BinaryIO, end: int) -> _Fingerprint:
    f.seek(0)
    head = f.read(min(end, FINGERPRINT_BYTES))
    tail_start = max(end - FINGERPRINT_BYTES, 0)
    f.seek(tail_start)
    return _Fingerprint(end, head, f.read(end - tail_start))


def _detection_settled(sample: bytes) -> bool:
    """True once ``sample`` is enough to trust the detected encoding for good."""
    return len(sample) >= SAMPLE_BYTES or (len(sample) >= MIN_DETECT_BYTES and b"\n" in sample)


class TextLogSource:
    def __init__(self, path: str | os.PathLike[str], codec: str | None = None) -> None:
        self.path = Path(path)
        with open_shared(self.path) as f:
            sample = f.read(SAMPLE_BYTES)
        self.forced_codec = codec
        self.encoding: EncodingInfo = for_codec(codec, sample) if codec else detect_encoding(sample)
        self.identity: FileIdentity = file_identity(self.path)
        self.index = LineIndex(self.encoding)
        self._io_lock = threading.Lock()
        self._fingerprint = _Fingerprint(0)
        self._encoding_settled = codec is not None or _detection_settled(sample)

    # ---- indexing ------------------------------------------------------------------------------------------------
    def build_index(
        self,
        cancel: threading.Event | None = None,
        progress: Callable[[int, int], None] | None = None,
    ) -> bool:
        """Index everything currently in the file. Safe to call again later to index appended data."""
        with open_shared(self.path) as f:
            size = os.fstat(f.fileno()).st_size
            completed = self.index.scan(f, size, cancel, progress)
            self._fingerprint = _read_fingerprint(f, self.index.scanned)
            return completed

    def check_change(self) -> Change:
        try:
            ident = file_identity(self.path)
        except FileNotFoundError:
            return Change.MISSING
        except OSError:
            return Change.NONE  # transient (locked by rotation in progress, etc.)
        if not ident.same_file(self.identity) or ident.size < self.index.scanned:
            return Change.RESET
        if ident.size == self.index.scanned:
            return Change.NONE
        try:
            rewritten = self._rewritten_or_misdetected()
        except OSError:
            return Change.NONE  # transient, as above: the next poll looks again
        return Change.RESET if rewritten else Change.GROWN

    def _rewritten_or_misdetected(self) -> bool:
        """The file grew: were the bytes already indexed rewritten, or did the encoding guess turn out wrong?"""
        fingerprint = self._fingerprint
        with open_shared(self.path) as f:
            if _read_fingerprint(f, fingerprint.end) != fingerprint:
                return True
            if self._encoding_settled:
                return False
            f.seek(0)
            sample = f.read(SAMPLE_BYTES)
        if detect_encoding(sample) != self.encoding:
            return True  # e.g. created empty (guessed UTF-8), then UTF-16 with a BOM was written
        self._encoding_settled = _detection_settled(sample)
        return False

    def reset(self) -> None:
        """Forget the index (file was truncated/replaced). Call build_index() afterwards.

        All or nothing: if the new file can't be read yet (e.g. still locked by the rotation) the OSError propagates
        and the source is left unchanged, so the next :meth:`check_change` reports RESET again.
        """
        identity = file_identity(self.path)
        encoding, settled = self.encoding, self._encoding_settled
        if self.forced_codec is None:
            with open_shared(self.path) as f:
                sample = f.read(SAMPLE_BYTES)
            encoding, settled = detect_encoding(sample), _detection_settled(sample)
        index = LineIndex(encoding)
        self.identity, self.encoding, self.index = identity, encoding, index
        self._fingerprint, self._encoding_settled = _Fingerprint(0), settled

    # ---- reading -------------------------------------------------------------------------------------------------
    def snapshot(self) -> IndexSnapshot:
        return self.index.snapshot()

    def line_count(self) -> int:
        return self.index.line_count()

    @property
    def max_line_chars(self) -> int:
        return self.index.max_line_bytes // self.encoding.unit

    def _decode(self, data: bytes) -> str:
        text = data.decode(self.encoding.codec, errors="replace")
        return text[:-1] if text.endswith("\r") else text

    def get_lines(self, first: int, count: int, snap: IndexSnapshot | None = None) -> list[str]:
        """Decoded lines [first, first+count) for display; very long lines are clipped."""
        snap = snap or self.snapshot()
        starts, ends = snap.spans(first, count)
        if not len(starts):
            return []
        lengths = ends - starts
        out: list[str] = []
        with self._io_lock, open_shared(self.path) as f:
            block_start, block_end = int(starts[0]), int(ends[-1])
            if block_end - block_start <= BLOCK_READ_LIMIT and int(lengths.max()) <= MAX_DISPLAY_LINE_BYTES:
                f.seek(block_start)
                block = f.read(block_end - block_start)
                for s, e in zip(starts.tolist(), ends.tolist(), strict=True):
                    out.append(self._decode(block[s - block_start : e - block_start]))
            else:
                for s, e in zip(starts.tolist(), ends.tolist(), strict=True):
                    out.append(self._read_clipped(f, s, e))
        return out

    def _read_clipped(self, f: BinaryIO, start: int, end: int) -> str:
        length = end - start
        clipped = length > MAX_DISPLAY_LINE_BYTES
        if clipped:
            length = MAX_DISPLAY_LINE_BYTES - MAX_DISPLAY_LINE_BYTES % self.encoding.unit
        f.seek(start)
        text = self._decode(f.read(length))
        if clipped:
            text += f"  …[line clipped, {(end - start) // 1024:,} KiB total]"
        return text

    def get_lines_at(self, lines: Iterable[int] | np.ndarray, snap: IndexSnapshot | None = None) -> list[str]:
        """Decoded text of arbitrary (sorted or not) line numbers, one file open for all of them."""
        snap = snap or self.snapshot()
        n = snap.line_count
        out: list[str] = []
        with self._io_lock, open_shared(self.path) as f:
            for line in lines:
                i = int(line)
                out.append(self._read_clipped(f, snap.line_start(i), snap.line_end(i)) if 0 <= i < n else "")
        return out

    def get_line(self, i: int) -> str:
        lines = self.get_lines(i, 1)
        return lines[0] if lines else ""

    def get_full_line(self, i: int, max_bytes: int = 32 * 1024 * 1024) -> str:
        """The complete line without the display clip (for the details pane / copy), capped at ``max_bytes``."""
        snap = self.snapshot()
        if not 0 <= i < snap.line_count:
            return ""
        start, end = snap.line_start(i), snap.line_end(i)
        length = min(end - start, max_bytes - max_bytes % self.encoding.unit)
        with open_shared(self.path) as f:
            f.seek(start)
            return self._decode(f.read(length))

    def iter_blocks(
        self,
        first: int = 0,
        last: int | None = None,
        block_bytes: int = 1024 * 1024,
        snap: IndexSnapshot | None = None,
    ) -> Iterator[tuple[int, int, str]]:
        """Yield (first_line, line_count, text) for consecutive line-aligned blocks.

        ``text`` holds the lines joined by "\\n" (CRLF normalised), without a trailing newline.
        """
        snap = snap or self.snapshot()
        last = snap.line_count if last is None else min(last, snap.line_count)
        line = first
        with open_shared(self.path) as f:
            while line < last:
                start_b = snap.line_start(line)
                j = int(np.searchsorted(snap.ends, start_b + block_bytes, side="left"))
                nxt = min(max(line + 1, j), last)
                end_b = snap.line_end(nxt - 1)
                f.seek(start_b)
                data = f.read(end_b - start_b)
                text = data.decode(self.encoding.codec, errors="replace").replace("\r\n", "\n")
                if text.endswith("\r"):
                    text = text[:-1]
                yield line, nxt - line, text
                line = nxt
