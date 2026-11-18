"""Live-watch services: alert rules over lines appended to open logs, and folders whose newest file is followed."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

from PySide6.QtCore import QObject, QTimer, Signal

from ..core.search import search_multi
from ..core.watch import (
    KIND_NEW_PATTERN,
    NEW_PATTERN_BASELINE_LINES,
    Alert,
    AlertEvaluator,
    AlertRule,
    NewPatternDetector,
    WatchProfile,
    newest_file,
)
from .jobs import start_worker
from .log_document import LogDocument

log = logging.getLogger(__name__)
MAX_ALERT_LINES_PER_BATCH = 100_000  # matching line numbers fed per rule per batch (texts only for the last one)
FOLDER_POLL_MS = 2_000


@dataclass
class _Batch:
    """What a worker found in one range of newly completed lines."""

    matches: list[list[tuple[int, str]]] = field(default_factory=list)  # per match rule: (line, text) pairs
    new_patterns: list[tuple[int, str]] = field(default_factory=list)


class AlertMonitor(QObject):
    """Runs the enabled alert rules over every batch of lines that became complete in the watched documents.

    The searching (and new-pattern clustering) runs on a worker, one batch per document at a time; ranges that
    arrive meanwhile are merged and processed next, so no line is skipped and none is evaluated twice.
    """

    alertFired = Signal(object, object)  # Alert, LogDocument
    _baselineReady = Signal(object, object)  # document key (id(), may exceed 32 bits), NewPatternDetector
    _batchDone = Signal(object, object)  # document key, _Batch | None

    def __init__(self, rules: list[AlertRule], parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._rules = list(rules)
        self._watched: dict[int, tuple[LogDocument, AlertEvaluator]] = {}
        self._detectors: dict[int, NewPatternDetector | None] = {}  # None while the baseline is being learned
        self._quiet_until: dict[int, float] = {}
        self._busy: set[int] = set()
        self._pending: dict[int, tuple[int, int]] = {}
        self._baselineReady.connect(self._on_baseline)
        self._batchDone.connect(self._on_batch)

    @property
    def active_rules(self) -> list[AlertRule]:
        return [r for r in self._rules if r.enabled]

    def set_rules(self, rules: list[AlertRule]) -> None:
        self._rules = list(rules)
        if self._new_pattern_rule() is None:
            self._detectors.clear()
        for key, (document, _old) in list(self._watched.items()):
            self._watched[key] = (document, AlertEvaluator(self._rules, document.title))

    def watch(self, document: LogDocument) -> None:
        key = id(document)
        if key in self._watched:
            return
        self._watched[key] = (document, AlertEvaluator(self._rules, document.title))
        document.linesAppendedRange.connect(lambda first, end, d=document: self._on_appended(d, first, end))
        document.destroyed.connect(lambda _obj=None, k=key: self._forget(k))

    def unwatch(self, document: LogDocument) -> None:
        self._forget(id(document))

    def _forget(self, key: int) -> None:
        for table in (self._watched, self._detectors, self._pending, self._quiet_until):
            table.pop(key, None)
        self._busy.discard(key)

    def _new_pattern_rule(self) -> AlertRule | None:
        return next((r for r in self._rules if r.enabled and r.kind == KIND_NEW_PATTERN), None)

    def _learn_baseline(self, document: LogDocument, first: int) -> None:
        """Learn what the log already says (in the background); new-pattern alerts start once that is known."""
        key = id(document)
        self._detectors[key] = None
        source, ready = document.source, self._baselineReady
        start = max(first - NEW_PATTERN_BASELINE_LINES, 0)

        def work() -> None:
            lines = source.get_lines(start, first - start)
            ready.emit(key, NewPatternDetector(zip(range(start, first), lines, strict=False)))

        start_worker("new-pattern-baseline", work)

    def _on_baseline(self, key: int, detector: NewPatternDetector) -> None:
        if key in self._detectors:
            self._detectors[key] = detector

    def _on_appended(self, document: LogDocument, first: int, end: int) -> None:
        key = id(document)
        if key not in self._watched or end <= first:
            return
        if self._new_pattern_rule() is not None and key not in self._detectors:
            self._learn_baseline(document, first)
        if key in self._busy:  # merge with what is waiting; processed when the running batch is done
            low, high = self._pending.get(key, (first, end))
            self._pending[key] = (min(low, first), max(high, end))
            return
        self._start_batch(document, first, end)

    def _start_batch(self, document: LogDocument, first: int, end: int) -> None:
        key = id(document)
        evaluator = self._watched[key][1]
        queries = [r.query for r in evaluator.rules]
        detector = self._detectors.get(key) if self._new_pattern_rule() is not None else None
        if not queries and detector is None:
            return
        self._busy.add(key)
        source, done = document.source, self._batchDone

        def work() -> None:
            batch = _Batch()
            try:
                for hits in search_multi(source, queries, first, end) if queries else []:
                    numbers = [int(i) for i in hits[-MAX_ALERT_LINES_PER_BATCH:]]
                    last_text = source.get_line(numbers[-1]) if numbers else ""
                    batch.matches.append(
                        [(n, "") for n in numbers[:-1]] + ([(numbers[-1], last_text)] if numbers else [])
                    )
                if detector is not None:
                    texts = source.get_lines(first, end - first)
                    batch.new_patterns = detector.feed(zip(range(first, end), texts, strict=False))
            except OSError as exc:
                log.info("alert check skipped, %s changed while reading: %s", source.path, exc)
                done.emit(key, None)
                return
            except Exception:
                log.exception("alert check failed")
                done.emit(key, None)
                return
            done.emit(key, batch)

        start_worker("alerts", work)

    def _on_batch(self, key: int, batch: _Batch | None) -> None:
        self._busy.discard(key)
        entry = self._watched.get(key)
        if entry is None:
            return
        document, evaluator = entry
        if batch is not None:
            now = time.monotonic()
            if batch.matches:
                for alert in evaluator.feed(now, batch.matches):
                    self.alertFired.emit(alert, document)
            rule = self._new_pattern_rule()
            new = batch.new_patterns
            if rule is not None and new and now >= self._quiet_until.get(key, 0.0):
                self._quiet_until[key] = now + rule.cooldown_s
                self.alertFired.emit(Alert(rule, document.title, len(new), new[0][0], new[-1][0], new[-1][1]), document)
        pending = self._pending.pop(key, None)
        if pending is not None:
            self._start_batch(document, *pending)

    @staticmethod
    def describe(alert: Alert) -> str:
        if alert.rule.kind == KIND_NEW_PATTERN:
            what = f"{alert.count} new kinds of message" if alert.count > 1 else "a new kind of message"
            return f"{alert.rule.name}: {what} in {alert.source}\n{alert.sample[:200]}"
        count = f"{alert.count:,} matches" if alert.count > 1 else "a match"
        return f"{alert.rule.name}: {count} in {alert.source}\n{alert.sample[:200]}"


class FolderWatcher(QObject):
    """Polls a folder (off the UI thread) and reports when a newer matching file appears."""

    newestChanged = Signal(str)
    _found = Signal(str)

    def __init__(self, profile: WatchProfile, current: Path | None, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.profile = profile
        self.current = current
        self._busy = False
        self._found.connect(self._on_found)
        self._timer = QTimer(self)
        self._timer.setInterval(FOLDER_POLL_MS)
        self._timer.timeout.connect(self.poll)
        self._timer.start()

    def stop(self) -> None:
        self._timer.stop()

    def poll(self) -> None:
        if self._busy:
            return
        self._busy = True
        profile, found = self.profile, self._found

        def work() -> None:
            try:
                newest = newest_file(profile.folder, profile.pattern, recursive=profile.recursive)
            except OSError as exc:
                log.warning("watching %s failed: %s", profile.folder, exc)
                newest = None
            found.emit(str(newest) if newest else "")

        start_worker("folder-watch", work)

    def _on_found(self, path: str) -> None:
        self._busy = False
        if path and (self.current is None or Path(path) != self.current):
            self.current = Path(path)
            self.newestChanged.emit(path)
