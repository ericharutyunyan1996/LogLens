"""Run an analysis (HTTP statistics, transactions, patterns, …) over a document's lines in the background.

An analyzer is any function ``(lines: Iterable[(line number, text)]) -> result``; the runner feeds it the whole file
or a subset (e.g. the current filter's matches) in chunks, reports progress and supports cancellation.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass

import numpy as np
from PySide6.QtCore import QObject, Signal

from ..core.text_source import TextLogSource
from .jobs import JobSlot, start_worker

ANALYZE_MAX_LINES = 2_000_000  # beyond this the analysis covers the first lines only (and says so)
CHUNK_LINES = 20_000
Analyzer = Callable[[Iterable[tuple[int, str]]], object]
Progress = Callable[[int, int], None]
Task = Callable[[threading.Event, Progress], object]  # free-form job (e.g. reads two sources); may raise cancelled


class AnalysisCancelledError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class AnalysisScope:
    """Which lines an analysis covers: all lines (``lines`` is None) or the given sorted line numbers."""

    lines: np.ndarray | None = None
    description: str = "whole file"

    def count(self, total: int) -> int:
        return min(len(self.lines) if self.lines is not None else total, ANALYZE_MAX_LINES)


def iter_lines(
    source: TextLogSource,
    scope: AnalysisScope,
    *,
    cancel: threading.Event | None = None,
    progress: Callable[[int, int], None] | None = None,
) -> Iterator[tuple[int, str]]:
    """(line number, text) for the scope, chunked; raises AnalysisCancelledError when ``cancel`` is set."""
    total = scope.count(source.line_count())
    done = 0
    while done < total:
        if cancel is not None and cancel.is_set():
            raise AnalysisCancelledError
        size = min(CHUNK_LINES, total - done)
        if scope.lines is None:
            numbers: Iterable[int] = range(done, done + size)
            texts = source.get_lines(done, size)
        else:
            chunk = scope.lines[done : done + size]
            numbers, texts = chunk.tolist(), source.get_lines_at(chunk)
        yield from zip(numbers, texts, strict=False)
        done += size
        if progress is not None:
            progress(done, total)


class _Signals(QObject):
    progress = Signal(int, int, int)  # generation, done, total
    finished = Signal(int, object)
    failed = Signal(int, str)


class AnalysisRunner(QObject):
    """One analysis at a time per runner; starting a new one cancels the previous."""

    progress = Signal(int, int)
    finished = Signal(object)
    failed = Signal(str)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._job = JobSlot()
        self._signals = _Signals(self)
        self._signals.progress.connect(self._on_progress)
        self._signals.finished.connect(self._on_finished)
        self._signals.failed.connect(self._on_failed)

    def run(self, source: TextLogSource, scope: AnalysisScope, analyzer: Analyzer) -> None:
        self.run_task(lambda cancel, report: analyzer(iter_lines(source, scope, cancel=cancel, progress=report)))

    def run_task(self, task: Task) -> None:
        generation, cancel = self._job.begin()
        signals = self._signals

        def work() -> None:
            def report(done: int, total: int) -> None:
                signals.progress.emit(generation, done, total)

            try:
                result = task(cancel, report)
            except AnalysisCancelledError:
                return
            except Exception as exc:
                signals.failed.emit(generation, f"Analysis failed: {exc}")
                raise
            signals.finished.emit(generation, result)

        start_worker("analysis", work)

    def cancel(self) -> None:
        self._job.cancel()

    def _on_progress(self, generation: int, done: int, total: int) -> None:
        if self._job.is_current(generation):
            self.progress.emit(done, total)

    def _on_finished(self, generation: int, result: object) -> None:
        if self._job.is_current(generation):
            self.finished.emit(result)

    def _on_failed(self, generation: int, message: str) -> None:
        if self._job.is_current(generation):
            self.failed.emit(message)
