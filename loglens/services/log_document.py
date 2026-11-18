"""LogDocument — one open log file and all its non-visual state.

Owns the :class:`TextLogSource`, background indexing, tail/rotation polling, the current search and its hits,
scrollbar-mark rule results, multi-line record layout, the log's clock (time zone / shift) and bookmarks. Emits Qt
signals; contains no widgets, so it is testable headlessly and reusable by any view (tab, timeline, CLI-driven UI…).

Threading: heavy work runs on worker threads (and the search process pools). Workers never touch document state;
they emit queued signals tagged with a job generation, and the handlers (running on the owner's thread) drop
results from superseded jobs via :class:`JobSlot`.

Live growth: every result set (filter hits, record starts, scrollbar marks) knows the line count it is complete up
to (``_covered``). A full background job covers the lines that existed when it started; growth is indexed and
searched by a *tail job* on a worker, for every result set that is not being recomputed, from where that set's
coverage ends. When a full job finishes, a tail job catches it up. A file that is truncated, replaced or reappears
gets a fresh :class:`TextLogSource` and everything is recomputed.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
from PySide6.QtCore import QObject, QTimer, Signal

from ..core import navigation
from ..core.filters import FilterSpec, FilterTerm
from ..core.formats import ALL_FORMATS, Detection, LogFormat, detect_format
from ..core.highlight import HighlightRule
from ..core.histogram import Histogram, build_histogram
from ..core.records import (
    RecordLayout,
    compact_lines,
    line_at_time,
    line_range_for,
    record_start_query,
    time_bounds,
)
from ..core.search import SearchQuery, search_multi
from ..core.text_source import Change, TextLogSource
from ..core.timeparse import LineClock, infer_day_first
from .jobs import JobSlot, start_worker

log = logging.getLogger(__name__)

TAIL_INTERVAL_MS = 1000
FILTER, RECORDS, MARKS = "filter", "records", "marks"  # result sets kept up to date while the file grows
HITS_FLUSH_MS = 150  # coalesce partial search results into view updates at most this often
PROGRESS_INTERVAL_S = 0.1
HISTOGRAM_DEBOUNCE_MS = 400  # coalesce bursts of changes (marks, hits, tail growth) into one recomputation
HISTOGRAM_TAIL_MS = 5000  # while a file grows, refresh its histogram at most this often
_EMPTY = np.empty(0, dtype=np.int64)
_NO_RECORDS = RecordLayout(None, None)
MAX_RECORD_TEXT_LINES = 500  # lines of one record handed to the Inspector / AI
FORMAT_SAMPLE_LINES = 2_000  # first lines used to detect the format (headers / directives live at the top)


@dataclass(frozen=True, slots=True)
class MarkSummary:
    """Result of one scrollbar-mark rule, for status displays."""

    rule_index: int
    name: str
    count: int
    color: str


class _WorkerSignals(QObject):
    """Queued signals used by worker threads to report back (generation-tagged)."""

    indexProgress = Signal(int, object, object)  # generation, bytes done, bytes total (Python ints: files exceed 2 GiB)
    indexDone = Signal(int, bool)  # generation, completed
    indexFailed = Signal(int, str)  # generation, message
    searchFailed = Signal(int, str)  # generation, message
    tailDone = Signal(int, object)  # generation, _Tail | None
    searchPartial = Signal(int, object, int, int)  # generation, hits, lines done, lines total
    searchDone = Signal(int, float)  # generation, seconds
    marksDone = Signal(int, object)  # generation, list[np.ndarray]
    # generation, RecordLayout, SearchQuery | None, Detection, day_first (bool | None)
    recordsDone = Signal(int, object, object, object, object)
    histogramDone = Signal(int, object)  # generation, Histogram | None


class LogDocument(QObject):
    # content
    contentReset = Signal()  # source replaced (reload, truncation, rotation): views must rebind their models
    indexProgress = Signal(object, object)  # bytes done, bytes total (Python ints, no 32-bit overflow)
    indexFinished = Signal()
    indexFailed = Signal(str)  # the file could not be read
    linesAppended = Signal()  # tail growth
    linesAppendedRange = Signal(int, int)  # [first, end) of lines that became complete (alerts): each line once
    stateChanged = Signal()  # missing / size / encoding info changed
    # search
    searchQueued = Signal()  # waiting for indexing to finish
    searchProgress = Signal(int, int)  # lines done, lines total
    hitsChanged = Signal()
    searchFinished = Signal(int, float)  # hit count, seconds
    searchFailed = Signal(str)
    # annotations
    marksChanged = Signal()
    bookmarksChanged = Signal()
    recordsChanged = Signal()  # multi-line record layout detected / extended
    clockChanged = Signal()
    formatChanged = Signal()  # detected or chosen log format
    histogramChanged = Signal()

    def __init__(
        self, path: str | Path, rules: list[HighlightRule], codec: str | None = None, parent: QObject | None = None
    ) -> None:
        super().__init__(parent)
        self.path = str(Path(path))
        self._source = TextLogSource(self.path, codec)
        self._rules = rules
        self._filter: FilterSpec | None = None
        self._hits = _EMPTY
        self._hit_chunks: list[np.ndarray] = []
        self._rule_marks: list[np.ndarray] = []
        self._bookmarks: set[int] = set()
        self._indexing = False
        self._missing = False
        self._pending_filter: FilterSpec | None = None
        self._records = _NO_RECORDS
        self._record_query: SearchQuery | None = None
        self._clock = LineClock()
        self._clock_chosen = False  # the user set zone / shift: detection no longer changes them
        self._day_first: bool | None = None  # the file's day/month order for numeric dates (None = per line)
        self._detection: Detection | None = None
        self._format: LogFormat | None = None  # chosen by the user (None = use the detected one)
        self._extra_formats: list[LogFormat] = []  # the user's custom formats, tried before the built-in ones
        self._index_job, self._search_job, self._marks_job = JobSlot(), JobSlot(), JobSlot()
        self._records_job, self._histogram_job, self._tail_job = JobSlot(), JobSlot(), JobSlot()
        self._covered: dict[str, int] = dict.fromkeys((FILTER, RECORDS, MARKS), 0)  # lines each result set covers
        self._running: dict[str, int] = {}  # result sets being recomputed by a full job -> line count it covers
        self._tailing = False
        self._histogram: Histogram | None = None
        self._histogram_wanted = False

        self._signals = _WorkerSignals(self)
        self._signals.indexProgress.connect(self._on_index_progress)
        self._signals.indexDone.connect(self._on_index_done)
        self._signals.searchPartial.connect(self._on_search_partial)
        self._signals.searchDone.connect(self._on_search_done)
        self._signals.marksDone.connect(self._on_marks_done)
        self._signals.recordsDone.connect(self._on_records_done)
        self._signals.histogramDone.connect(self._on_histogram_done)
        self._signals.tailDone.connect(self._on_tail_done)
        self._signals.indexFailed.connect(self._on_index_failed)
        self._signals.searchFailed.connect(self._on_search_failed)

        self._hits_timer = QTimer(self)
        self._hits_timer.setSingleShot(True)
        self._hits_timer.setInterval(HITS_FLUSH_MS)
        self._hits_timer.timeout.connect(self._flush_hits)
        self._histogram_timer = QTimer(self)
        self._histogram_timer.setSingleShot(True)
        self._histogram_timer.setInterval(HISTOGRAM_DEBOUNCE_MS)
        self._histogram_timer.timeout.connect(self._start_histogram)
        for signal in (self.marksChanged, self.recordsChanged, self.clockChanged, self.searchFinished):
            signal.connect(self._schedule_histogram)
        self._tail_timer = QTimer(self)
        self._tail_timer.setInterval(TAIL_INTERVAL_MS)
        self._tail_timer.timeout.connect(self.check_file)

    # ---- lifecycle -----------------------------------------------------------------------------------------------
    def start(self) -> None:
        """Begin indexing and polling the file for changes."""
        self._start_indexing()
        self._tail_timer.start()

    def close(self) -> None:
        self._tail_timer.stop()
        self._histogram_timer.stop()
        for job in self._jobs():
            job.cancel()

    def _jobs(self) -> tuple[JobSlot, ...]:
        return (self._index_job, self._search_job, self._marks_job, self._records_job, self._histogram_job,
                self._tail_job)  # fmt: skip

    def reload(self, codec: str | None = None) -> None:
        """Re-open from scratch, optionally with a different encoding (``""`` = auto-detect)."""
        self._source = TextLogSource(self.path, codec if codec is not None else self._source.forced_codec)
        self._restart_after_reset()

    # ---- read-only state -----------------------------------------------------------------------------------------
    @property
    def source(self) -> TextLogSource:
        return self._source

    @property
    def title(self) -> str:
        return Path(self.path).name

    @property
    def is_indexing(self) -> bool:
        return self._indexing

    @property
    def is_missing(self) -> bool:
        return self._missing

    @property
    def filter_spec(self) -> FilterSpec | None:
        """The active filter (None when no search/filter is applied)."""
        return self._filter

    @property
    def hits(self) -> np.ndarray:
        return self._hits

    @property
    def bookmarks(self) -> frozenset[int]:
        return frozenset(self._bookmarks)

    def has_bookmark(self, line: int) -> bool:
        return line in self._bookmarks

    def bookmark_array(self) -> np.ndarray:
        return np.fromiter(sorted(self._bookmarks), dtype=np.int64, count=len(self._bookmarks))

    def mark_rules(self) -> list[HighlightRule]:
        """Enabled, valid rules that produce scrollbar marks, in rule order."""
        return [r for r in self._rules if r.enabled and r.scrollbar_mark and r.compiled() is not None]

    def rule_marks(self) -> list[np.ndarray]:
        """Matching line numbers per :meth:`mark_rules` entry (empty until computed)."""
        return list(self._rule_marks)

    def level_rules(self) -> list[HighlightRule]:
        """Rules offered as one-click level filters."""
        return [r for r in self._rules if r.enabled and r.level_filter and r.compiled() is not None]

    def level_count(self, rule: HighlightRule) -> int | None:
        """Number of lines for a level rule if already known (from scrollbar marks), else None."""
        for mark_rule, rows in zip(self.mark_rules(), self._rule_marks, strict=False):
            if mark_rule.name == rule.name:
                return len(rows)
        return None

    # ---- records & time ------------------------------------------------------------------------------------------
    @property
    def records(self) -> RecordLayout:
        """Where multi-line records start (``multi_line`` is False until detected, or for one-line-per-entry logs)."""
        return self._records

    def record_range(self, line: int) -> tuple[int, int]:
        """[start, end) of the record containing ``line`` (just the line for single-line logs)."""
        return self._records.record_of(line, self._source.line_count())

    def record_text(self, line: int) -> str:
        """Full text of the record containing ``line`` (capped at MAX_RECORD_TEXT_LINES lines)."""
        start, end = self.record_range(line)
        end = min(end, start + MAX_RECORD_TEXT_LINES)
        if end - start <= 1:
            return self._source.get_full_line(line)
        return "\n".join(self._source.get_full_line(i) for i in range(start, end))

    # ---- format --------------------------------------------------------------------------------------------------
    @property
    def detection(self) -> Detection | None:
        return self._detection

    @property
    def log_format(self) -> LogFormat | None:
        """The format in use: the user's choice, else the detected one (None until detection ran)."""
        if self._format is not None:
            return self._format
        return self._detection.format if self._detection is not None else None

    @property
    def format_chosen(self) -> bool:
        return self._format is not None

    def set_format(self, fmt: LogFormat | None) -> None:
        """Override the detected format (None = back to detection)."""
        self._format = fmt
        self.formatChanged.emit()
        self._apply_clock(self._file_clock())

    def set_extra_formats(self, formats: list[LogFormat]) -> None:
        self._extra_formats = list(formats)

    def format_candidates(self) -> list[LogFormat]:
        """The user's custom formats, then the built-in catalog."""
        return [*self._extra_formats, *ALL_FORMATS]

    def detect_again(self) -> None:
        """Re-run format detection (e.g. after a custom format was added)."""
        if not self._indexing:
            self._start_records()

    def format_context(self, count: int = 200) -> list[str]:
        """First lines of the file: header row / directives that stateful formats need to parse later lines."""
        return self._source.get_lines(0, min(count, self._source.line_count()))

    @property
    def clock(self) -> LineClock:
        return self._clock

    @property
    def clock_chosen(self) -> bool:
        """The user corrected this log's clock (otherwise it is the file's own: format zone, day/month order)."""
        return self._clock_chosen

    def set_clock(self, clock: LineClock) -> None:
        """The user's correction: zone for times without offset, clock shift (the file's day/month order is kept)."""
        self._clock_chosen = True
        self._apply_clock(replace(clock, day_first=self._day_first))

    def _file_clock(self) -> LineClock:
        """The clock the file implies: UTC for formats that always log UTC (W3C / IIS), else local time."""
        if self._clock_chosen:
            return replace(self._clock, day_first=self._day_first)
        fmt = self.log_format
        return LineClock(UTC if fmt is not None and fmt.times_utc else None, day_first=self._day_first)

    def _apply_clock(self, clock: LineClock) -> None:
        if clock != self._clock:
            self._clock = clock
            self.clockChanged.emit()
            if self._filter is not None and self._filter.time_range is not None:
                self.run_filter(self._filter)

    def line_time(self, text: str) -> datetime | None:
        return self._clock(text)

    def line_at_time(self, moment: datetime) -> int:
        """First line at or after ``moment`` (O(log n) reads; assumes time grows through the file)."""
        line = line_at_time(self._source, moment, self._records.starts, self._clock)
        return max(min(line, self._source.line_count() - 1), 0)

    def time_bounds(self) -> tuple[datetime | None, datetime | None]:
        return time_bounds(self._source, self._clock)

    # ---- histogram -----------------------------------------------------------------------------------------------
    @property
    def histogram(self) -> Histogram | None:
        """Latest timeline histogram (None until computed, or when the log has no timestamps)."""
        return self._histogram

    def enable_histogram(self, wanted: bool) -> None:
        """Compute histograms only while a view shows them."""
        self._histogram_wanted = wanted
        if wanted:
            self._schedule_histogram()

    def _schedule_histogram(self, *_args: object) -> None:
        if self._histogram_wanted and not self._indexing and not self._histogram_timer.isActive():
            self._histogram_timer.start(HISTOGRAM_DEBOUNCE_MS)

    def _start_histogram(self) -> None:
        generation, cancel = self._histogram_job.begin()
        source, signals, clock = self._source, self._signals, self._clock
        starts = self._records.starts
        series = {summary.name: rows for summary, rows in zip(self.mark_summaries(), self._rule_marks, strict=False)}
        if self._filter is not None:
            series["Matches"] = self._hits

        def work() -> None:
            try:
                first, last = time_bounds(source, clock)
                histogram = None
                if first is not None and last is not None and last >= first:
                    histogram = build_histogram(source, (first, last), starts=starts, time_of=clock, series=series)
            except OSError as exc:  # rotated / replaced while reading: the next file check re-reads it
                log.info("histogram skipped, %s changed while reading: %s", source.path, exc)
                return
            except Exception:
                log.exception("histogram failed")
                return
            if not cancel.is_set():
                signals.histogramDone.emit(generation, histogram)

        start_worker("histogram", work)

    def _on_histogram_done(self, generation: int, histogram: Histogram | None) -> None:
        if self._histogram_job.is_current(generation):
            self._histogram = histogram
            self.histogramChanged.emit()

    def mark_summaries(self) -> list[MarkSummary]:
        return [
            MarkSummary(i, rule.name, len(rows), rule.bg or rule.fg or "#E5484D")
            for i, (rule, rows) in enumerate(zip(self.mark_rules(), self._rule_marks, strict=False))
        ]

    # ---- navigation (pure lookups; the caller moves the view) ----------------------------------------------------
    def next_hit(self, current: int, forward: bool = True) -> int | None:
        return navigation.step(self._hits, current, forward)

    def next_mark(self, current: int, rule_index: int | None = None, forward: bool = True) -> int | None:
        arrays = self._rule_marks if rule_index is None else self._rule_marks[rule_index : rule_index + 1]
        return navigation.step_any(arrays, current, forward)

    def next_bookmark(self, current: int, forward: bool = True) -> int | None:
        return navigation.step(self.bookmark_array(), current, forward)

    # ---- mutations -----------------------------------------------------------------------------------------------
    def set_rules(self, rules: list[HighlightRule]) -> None:
        self._rules = rules
        self._start_marks()

    def toggle_bookmarks(self, lines: Iterable[int]) -> None:
        """Add the lines as bookmarks, or remove them if they are all bookmarked already."""
        lines = list(lines)
        if lines and all(line in self._bookmarks for line in lines):
            self._bookmarks.difference_update(lines)
        else:
            self._bookmarks.update(lines)
        self.bookmarksChanged.emit()

    def run_search(self, query: SearchQuery) -> str | None:
        """Convenience: a filter with a single include term."""
        return self.run_filter(FilterSpec((FilterTerm(query),)))

    def run_filter(self, spec: FilterSpec) -> str | None:
        """Start filtering; returns a validation error message instead of starting if a term is invalid."""
        error = spec.validate()
        if error:
            return error
        self._cancel_search()
        if spec.is_empty:
            self.clear_search()
            return None
        self._filter = spec
        self._set_hits(_EMPTY)
        if self._indexing:
            self._pending_filter = spec
            self.searchQueued.emit()
            return None
        generation, cancel = self._search_job.begin()
        end = self._source.line_count()  # this job covers the lines that exist now; growth is caught up after
        self._running[FILTER] = end
        source, signals, clock, starts = self._source, self._signals, self._clock, self._records.starts

        def work() -> None:
            started = time.perf_counter()
            block_start = 0

            def on_partial(hits: list[np.ndarray], done: int, total: int) -> None:
                nonlocal block_start
                combined = spec.combine(hits, first + block_start, done - block_start)
                block_start = done
                signals.searchPartial.emit(generation, combined, done, total)

            try:
                first, last = _line_window(source, spec, starts, clock)
                last = min(last, end)
                if spec.queries():
                    search_multi(source, spec.queries(), first, last, cancel=cancel, on_partial=on_partial)
                elif last > first:  # time range only: every line inside it
                    signals.searchPartial.emit(generation, np.arange(first, last, dtype=np.int64), 1, 1)
            except OSError as exc:  # rotated / replaced mid-search: the reset re-runs the search
                log.info("search interrupted, %s changed while reading: %s", source.path, exc)
                signals.searchFailed.emit(generation, "The file changed while searching — searching again.")
                return
            except Exception as exc:
                log.exception("search failed")
                signals.searchFailed.emit(generation, f"Search failed: {exc}")
                return
            if not cancel.is_set():
                signals.searchDone.emit(generation, time.perf_counter() - started)

        start_worker("search", work)
        return None

    def _cancel_search(self) -> None:
        self._search_job.cancel()
        self._hits_timer.stop()
        self._hit_chunks = []
        self._running.pop(FILTER, None)

    def clear_search(self) -> None:
        self._cancel_search()
        self._pending_filter = None
        self._filter = None
        self._set_hits(_EMPTY)

    # ---- indexing ------------------------------------------------------------------------------------------------
    def _start_indexing(self) -> None:
        generation, cancel = self._index_job.begin()
        self._indexing = True
        source, signals = self._source, self._signals

        def work() -> None:
            last_emit = 0.0
            completed = False

            def progress(done: int, total: int) -> None:
                nonlocal last_emit
                now = time.monotonic()
                if now - last_emit >= PROGRESS_INTERVAL_S:
                    last_emit = now
                    signals.indexProgress.emit(generation, done, total)

            try:
                completed = source.build_index(cancel, progress)
            except OSError as exc:
                signals.indexFailed.emit(generation, f"Cannot read the file: {exc}")
            except Exception as exc:  # e.g. MemoryError on a gigantic file: never leave the document "indexing"
                log.exception("indexing failed")
                signals.indexFailed.emit(generation, f"Indexing failed: {exc}")
            finally:
                signals.indexDone.emit(generation, completed)

        start_worker("index", work)

    def _on_index_progress(self, generation: int, done: int, total: int) -> None:
        if self._index_job.is_current(generation):
            self.indexProgress.emit(done, total)

    def _on_index_failed(self, generation: int, message: str) -> None:
        if self._index_job.is_current(generation):
            self.indexFailed.emit(message)

    def _on_index_done(self, generation: int, _completed: bool) -> None:
        if not self._index_job.is_current(generation):
            return
        self._indexing = False
        self.indexFinished.emit()
        self.stateChanged.emit()
        self._start_marks()
        if self._record_query is None and not self._records.multi_line:
            self._start_records()
        if self._pending_filter is not None:
            spec, self._pending_filter = self._pending_filter, None
            self.run_filter(spec)

    def _restart_after_reset(self) -> None:
        """The source was replaced: drop every result and in-flight job, then index and recompute everything."""
        for job in self._jobs():
            job.cancel()
        self._hits_timer.stop()
        self._hit_chunks = []
        self._tailing = False
        self._running.clear()
        self._covered = dict.fromkeys(self._covered, 0)
        self._pending_filter = self._filter
        self._set_hits(_EMPTY)
        self._rule_marks = []
        self._records, self._record_query = _NO_RECORDS, None
        self._histogram = None
        self.contentReset.emit()
        self._start_indexing()
        self.stateChanged.emit()

    # ---- tail / rotation -----------------------------------------------------------------------------------------
    def check_file(self) -> None:
        """Poll the file: pick up appended lines, re-index after truncation/rotation, track disappearance."""
        if self._indexing or self._tailing:
            return
        try:
            change = self._source.check_change()
        except OSError as exc:  # e.g. the rotated file is briefly locked: try again on the next poll
            log.info("could not check %s: %s", self.path, exc)
            return
        if change is Change.MISSING:
            if not self._missing:
                self._missing = True
                self.stateChanged.emit()
            return
        if self._missing:
            self._missing = False
            change = Change.RESET
        if change is Change.RESET:
            self._replace_source()
        elif change is Change.GROWN:
            self._start_tail()

    def _replace_source(self) -> None:
        """Truncated / rotated / replaced: a fresh source, so running workers keep reading the old one consistently."""
        log.info("%s was truncated or replaced; re-indexing", self.path)
        try:
            fresh = TextLogSource(self.path, self._source.forced_codec)
        except OSError as exc:  # not readable yet (being created / locked): next poll retries
            log.info("could not reopen %s: %s", self.path, exc)
            return
        self._source = fresh
        self._restart_after_reset()

    def _tail_plan(self) -> list[tuple[str, int, list[SearchQuery]]]:
        """(result set, first line to search, queries) for every result set that must follow the growth."""
        plan: list[tuple[str, int, list[SearchQuery]]] = []
        if self._filter is not None and FILTER not in self._running and self._pending_filter is None:
            plan.append((FILTER, max(self._covered[FILTER] - 1, 0), self._filter.queries()))
        if self._record_query is not None and self._records.starts is not None and RECORDS not in self._running:
            plan.append((RECORDS, max(self._covered[RECORDS] - 1, 0), [self._record_query]))
        rules = self.mark_rules()
        if rules and len(self._rule_marks) == len(rules) and MARKS not in self._running:
            plan.append((MARKS, max(self._covered[MARKS] - 1, 0), [_rule_query(r) for r in rules]))
        return plan

    def _start_tail(self) -> None:
        """Index the growth and search it for every result set, on a worker (any amount of growth)."""
        generation, cancel = self._tail_job.begin()
        self._tailing = True
        source, signals, clock, starts = self._source, self._signals, self._clock, self._records.starts
        plan, spec = self._tail_plan(), self._filter
        old = source.snapshot()

        def work() -> None:
            try:
                source.build_index(cancel)
                snap = source.snapshot()
                tail = _Tail(spec, old.line_count, old.n_complete, snap.line_count, snap.n_complete)
                first = min((start for _kind, start, _q in plan), default=snap.line_count)
                queries = [q for _kind, _start, kind_queries in plan for q in kind_queries]
                results = search_multi(source, queries, first, snap.line_count, cancel=cancel) if queries else []
                offset = 0
                for kind, start, kind_queries in plan:
                    hits = [h[h >= start] for h in results[offset : offset + len(kind_queries)]]
                    offset += len(kind_queries)
                    tail.results[kind] = (start, hits)
                if spec is not None and spec.time_range is not None and not spec.time_range.is_open:
                    tail.window = _line_window(source, spec, starts, clock)
            except OSError as exc:
                log.info("tail skipped, %s changed while reading: %s", source.path, exc)
                signals.tailDone.emit(generation, None)
                return
            except Exception:
                log.exception("tail update failed")
                signals.tailDone.emit(generation, None)
                return
            signals.tailDone.emit(generation, None if cancel.is_set() else tail)

        start_worker("tail", work)

    def _on_tail_done(self, generation: int, tail: _Tail | None) -> None:
        if not self._tail_job.is_current(generation):
            return
        self._tailing = False
        if tail is None:
            return
        new_count = tail.line_count
        self._merge_filter_tail(tail)
        if RECORDS in tail.results and self._records.starts is not None:
            start, (new_starts,) = tail.results[RECORDS]
            old = self._records.starts
            self._records = RecordLayout(
                self._records.pattern_name, compact_lines(np.concatenate([old[old < start], new_starts]))
            )
            self._covered[RECORDS] = new_count
            self.recordsChanged.emit()
        if MARKS in tail.results and len(self._rule_marks) == len(tail.results[MARKS][1]):
            start, new_marks = tail.results[MARKS]
            self._rule_marks = [np.concatenate([old[old < start], new])
                                for old, new in zip(self._rule_marks, new_marks, strict=True)]  # fmt: skip
            self._covered[MARKS] = new_count
            self.marksChanged.emit()
        if new_count != tail.old_count:
            self.linesAppended.emit()
        if tail.n_complete > tail.old_complete:
            self.linesAppendedRange.emit(tail.old_complete, tail.n_complete)
        self.stateChanged.emit()
        if self._histogram_wanted and not self._histogram_timer.isActive():
            self._histogram_timer.start(HISTOGRAM_TAIL_MS)
        self._catch_up()

    def _merge_filter_tail(self, tail: _Tail) -> None:
        if FILTER not in tail.results or self._filter is None or tail.spec is not self._filter:
            return  # the filter changed meanwhile: its own job covers the new lines
        start, hits = tail.results[FILTER]
        spec, new_count = self._filter, tail.line_count
        new_hits = spec.combine(hits, start, new_count - start) if hits else np.arange(start, new_count, dtype=np.int64)
        if tail.window is not None:  # time range: keep only the new lines inside it
            low, high = tail.window
            new_hits = new_hits[(new_hits >= low) & (new_hits < high)]
        self._set_hits(np.concatenate([self._hits[self._hits < start], new_hits]))
        self._covered[FILTER] = new_count

    def _catch_up(self) -> None:
        """Start a tail job if a result set lags behind the file (e.g. its full job finished after growth)."""
        if self._indexing or self._tailing:
            return
        count = self._source.line_count()
        if any(self._covered[kind] < count for kind, _start, _q in self._tail_plan()):
            self._start_tail()

    def _job_finished(self, kind: str) -> None:
        end = self._running.pop(kind, None)
        if end is not None:
            self._covered[kind] = end
        self._catch_up()

    # ---- search results ------------------------------------------------------------------------------------------
    def _on_search_partial(self, generation: int, hits: np.ndarray, done: int, total: int) -> None:
        if not self._search_job.is_current(generation):
            return
        if len(hits):
            self._hit_chunks.append(hits)
            if not self._hits_timer.isActive():
                self._hits_timer.start()
        self.searchProgress.emit(done, total)

    def _flush_hits(self) -> None:
        if self._hit_chunks:
            self._set_hits(np.concatenate([self._hits, *self._hit_chunks]))
            self._hit_chunks = []

    def _on_search_done(self, generation: int, seconds: float) -> None:
        if not self._search_job.is_current(generation):
            return
        self._hits_timer.stop()
        self._flush_hits()
        self.searchFinished.emit(len(self._hits), seconds)
        self._job_finished(FILTER)

    def _on_search_failed(self, generation: int, message: str) -> None:
        if self._search_job.is_current(generation):
            self._hits_timer.stop()
            self._flush_hits()
            self._running.pop(FILTER, None)
            self.searchFailed.emit(message)

    def _set_hits(self, hits: np.ndarray) -> None:
        self._hits = hits
        self.hitsChanged.emit()

    # ---- scrollbar marks -----------------------------------------------------------------------------------------
    def _start_marks(self) -> None:
        self._marks_job.cancel()
        self._running.pop(MARKS, None)
        self._rule_marks = []
        rules = self.mark_rules()
        if not rules or self._indexing:
            self.marksChanged.emit()
            return
        generation, cancel = self._marks_job.begin()
        queries = [_rule_query(r) for r in rules]
        source, signals = self._source, self._signals
        end = source.line_count()
        self._running[MARKS] = end

        def work() -> None:
            try:
                results = search_multi(source, queries, 0, end, cancel=cancel, pool="background")
            except OSError as exc:  # rotated / replaced while reading: the next file check re-reads it
                log.info("marks skipped, %s changed while reading: %s", source.path, exc)
                return
            if not cancel.is_set():
                signals.marksDone.emit(generation, results)

        start_worker("marks", work)

    def _on_marks_done(self, generation: int, results: list[np.ndarray]) -> None:
        if self._marks_job.is_current(generation):
            self._rule_marks = results
            self.marksChanged.emit()
            self._job_finished(MARKS)

    # ---- multi-line records --------------------------------------------------------------------------------------
    def _start_records(self) -> None:
        generation, cancel = self._records_job.begin()
        source, signals = self._source, self._signals
        candidates, filename = [*self._extra_formats, *ALL_FORMATS], self.title
        end = source.line_count()
        self._running[RECORDS] = end

        def work() -> None:
            try:
                sample = source.get_lines(0, min(FORMAT_SAMPLE_LINES, source.line_count()))
                detection = detect_format(sample, filename=filename, candidates=candidates)
                day_first = infer_day_first(sample)
                name, query = record_start_query(source)
                found = search_multi(source, [query], 0, end, cancel=cancel, pool="background")[0] if query else None
                starts = compact_lines(found) if found is not None else None
            except OSError as exc:  # rotated / replaced while reading: the next file check re-reads it
                log.info("record detection skipped, %s changed while reading: %s", source.path, exc)
                return
            except Exception:
                log.exception("record detection failed")
                return
            if not cancel.is_set():
                signals.recordsDone.emit(generation, RecordLayout(name, starts), query, detection, day_first)

        start_worker("records", work)

    def _on_records_done(
        self,
        generation: int,
        layout: RecordLayout,
        query: SearchQuery | None,
        detection: Detection,
        day_first: bool | None,
    ) -> None:
        if self._records_job.is_current(generation):
            self._records, self._record_query = layout, query
            self._detection, self._day_first = detection, day_first
            self.recordsChanged.emit()
            self.formatChanged.emit()
            self._apply_clock(self._file_clock())
            self._job_finished(RECORDS)


@dataclass
class _Tail:
    """What a tail job found: line counts before/after and new hits per result set (from a start line)."""

    spec: FilterSpec | None  # the filter the job searched for (stale when the user changed it meanwhile)
    old_count: int
    old_complete: int
    line_count: int
    n_complete: int
    results: dict[str, tuple[int, list[np.ndarray]]] = field(default_factory=dict)
    window: tuple[int, int] | None = None  # the filter's time range as lines, when it has one


def _line_window(
    source: TextLogSource, spec: FilterSpec, starts: np.ndarray | None, clock: LineClock
) -> tuple[int, int]:
    """Lines [first, last) a filter searches: the whole file, or the lines inside its time range."""
    window = spec.time_range
    if window is None or window.is_open:
        return 0, source.line_count()
    return line_range_for(source, window.start, window.end, starts=starts, time_of=clock)


def _rule_query(rule: HighlightRule) -> SearchQuery:
    return SearchQuery(rule.pattern, regex=rule.regex, case_sensitive=rule.case_sensitive)
