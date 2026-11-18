"""Incremental newline index for (very) large text files.

We store the byte offset of every newline code unit in a growable numpy int64 array. Line *i* spans
``[start(i), end(i))`` where ``end(i)`` is the newline position (exclusive) and ``start(i)`` is just after the previous
newline. Text after the last newline is a *partial* line (still being written, or a file without trailing newline);
it is visible as the last line.

The index is filled by one writer thread (scan) and read by the UI thread. Readers take a consistent snapshot under a
lock; the writer never mutates entries that are already published, so a snapshot stays valid without copying.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import BinaryIO

import numpy as np

from .encoding import EncodingInfo

SCAN_CHUNK = 8 * 1024 * 1024


@dataclass(frozen=True)
class IndexSnapshot:
    ends: np.ndarray  # newline offsets, length == n_complete
    scanned: int  # bytes [0, scanned) are indexed
    bom_len: int
    unit: int

    @property
    def n_complete(self) -> int:
        return len(self.ends)

    def _partial_start(self) -> int:
        return int(self.ends[-1]) + self.unit if len(self.ends) else self.bom_len

    @property
    def line_count(self) -> int:
        return len(self.ends) + (1 if self.scanned > self._partial_start() else 0)

    def line_start(self, i: int) -> int:
        return self.bom_len if i == 0 else int(self.ends[i - 1]) + self.unit

    def line_end(self, i: int) -> int:
        return int(self.ends[i]) if i < len(self.ends) else self.scanned

    def spans(self, first: int, count: int) -> tuple[np.ndarray, np.ndarray]:
        """Vectorised (starts, ends) for lines [first, first+count), clamped to line_count."""
        last = min(first + count, self.line_count)
        if last <= first:
            empty = np.empty(0, dtype=np.int64)
            return empty, empty
        idx = np.arange(first, last, dtype=np.int64)
        starts = np.full(len(idx), self.bom_len, dtype=np.int64)
        has_prev = idx > 0
        starts[has_prev] = self.ends[idx[has_prev] - 1] + self.unit
        ends = np.full(len(idx), self.scanned, dtype=np.int64)
        complete = idx < len(self.ends)
        ends[complete] = self.ends[idx[complete]]
        return starts, ends

    def line_of_offset(self, offset: int) -> int:
        """Line containing byte ``offset`` (a newline belongs to the line it terminates)."""
        return int(np.searchsorted(self.ends, offset, side="left"))


class LineIndex:
    def __init__(self, encoding: EncodingInfo) -> None:
        self.encoding = encoding
        self._lock = threading.Lock()
        self._buf = np.empty(4096, dtype=np.int64)
        self._n = 0
        self._scanned = encoding.bom_len
        self.max_line_bytes = 0

    # ---- reading -------------------------------------------------------------------------------------------------
    def snapshot(self) -> IndexSnapshot:
        with self._lock:
            return IndexSnapshot(self._buf[: self._n], self._scanned, self.encoding.bom_len, self.encoding.unit)

    @property
    def scanned(self) -> int:
        return self._scanned

    def line_count(self) -> int:
        return self.snapshot().line_count

    # ---- writing (single writer thread) --------------------------------------------------------------------------
    def _find_newlines(self, data: bytes) -> np.ndarray:
        if self.encoding.unit == 1:
            return np.flatnonzero(np.frombuffer(data, dtype=np.uint8) == 0x0A)
        dtype = "<u2" if self.encoding.codec.endswith("le") else ">u2"
        return np.flatnonzero(np.frombuffer(data, dtype=dtype) == 0x000A) * 2

    def _publish(self, positions: np.ndarray, new_scanned: int) -> None:
        count = len(positions)
        if count:
            prev_end = int(self._buf[self._n - 1]) + self.encoding.unit if self._n else self.encoding.bom_len
            # positions[k] - (positions[k-1] + unit) == length of line k without its newline
            lengths = np.diff(positions, prepend=prev_end - self.encoding.unit) - self.encoding.unit
            self.max_line_bytes = max(self.max_line_bytes, int(lengths.max()))
        with self._lock:
            if self._n + count > len(self._buf):
                new_cap = max(len(self._buf) * 2, self._n + count + 4096)
                buf = np.empty(new_cap, dtype=np.int64)
                buf[: self._n] = self._buf[: self._n]
                self._buf = buf  # old snapshots keep referencing the old buffer: still valid
            self._buf[self._n : self._n + count] = positions
            self._n += count
            self._scanned = new_scanned
        # The partial line (after the last newline) also counts towards the widest line.
        partial = new_scanned - (int(self._buf[self._n - 1]) + self.encoding.unit if self._n else self.encoding.bom_len)
        self.max_line_bytes = max(self.max_line_bytes, partial)

    def scan(
        self,
        f: BinaryIO,
        upto: int,
        cancel: threading.Event | None = None,
        progress: Callable[[int, int], None] | None = None,
        chunk: int = SCAN_CHUNK,
    ) -> bool:
        """Index bytes [scanned, upto). Returns False if cancelled."""
        unit = self.encoding.unit
        pos = self._scanned
        f.seek(pos)
        while pos < upto:
            want = min(chunk, upto - pos)
            want -= want % unit
            if want <= 0:
                break
            data = f.read(want)
            if len(data) % unit:
                data = data[: len(data) - len(data) % unit]
            if not data:
                break  # file shrank under us; caller's next change-check will notice
            self._publish(self._find_newlines(data) + pos, pos + len(data))
            pos += len(data)
            if progress:
                progress(pos, upto)
            if cancel is not None and cancel.is_set():
                return False
        return True
