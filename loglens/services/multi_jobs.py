"""Jobs spanning several open logs: merge them into one timeline, and search all of them at once."""

from __future__ import annotations

import logging
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import QObject, Signal

from ..core.bundles import BundleError, BundleFile, extract_zip, list_log_files
from ..core.search import SearchQuery, search_multi
from ..core.text_source import TextLogSource
from ..core.timeline import TimelineSource, write_timeline
from ..core.winevent.reader import EventLogError, EventQuery, merge_timeline, read_events
from .jobs import JobSlot, start_worker

log = logging.getLogger(__name__)
TIMELINE_EVENT_CHANNELS = ("Application", "System")
TIMELINE_EVENT_LEVELS = (1, 2, 3)  # critical, error, warning
TIMELINE_MAX_EVENTS = 20_000
MAX_HITS_PER_LOG = 2_000  # results listed per log in "find in all logs" (the count stays exact)


class TimelineBuilder(QObject):
    progress = Signal(int)  # lines written
    finished = Signal(str, bool)  # path, truncated
    failed = Signal(str)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._cancel = threading.Event()

    def cancel(self) -> None:
        self._cancel.set()

    def build(
        self,
        sources: Sequence[TimelineSource],
        target: Path,
        *,
        events_window: tuple[datetime, datetime] | None = None,
    ) -> None:
        self._cancel = cancel = threading.Event()
        items = list(sources)

        def work() -> None:
            try:
                if events_window is not None:
                    events_source = _windows_events(events_window, target.with_suffix(".events.log"), cancel)
                    if events_source is not None:
                        items.append(TimelineSource("Windows", events_source))
                written, truncated = write_timeline(items, target, cancel=cancel, progress=self.progress.emit)
            except OSError as exc:
                self.failed.emit(f"Could not write the timeline: {exc}")
                return
            except Exception as exc:  # job boundary: report it, or the progress dialog would stay open forever
                log.exception("timeline %s failed", target)
                self.failed.emit(f"Could not build the timeline: {exc}")
                return
            if not cancel.is_set():
                self.finished.emit(str(target), truncated)
            log.info("timeline %s: %d lines", target, written)

        start_worker("timeline", work)


def _windows_events(window: tuple[datetime, datetime], target: Path, cancel: threading.Event) -> TextLogSource | None:
    """Errors/warnings Windows logged in ``window``, written as a log so they merge like any other source."""
    streams = []
    for channel in TIMELINE_EVENT_CHANNELS:
        query = EventQuery(channel, since=window[0], until=window[1], levels=TIMELINE_EVENT_LEVELS,
                           max_events=TIMELINE_MAX_EVENTS, newest_first=False)  # fmt: skip
        try:
            streams.append(list(read_events(query, cancel)))
        except EventLogError as exc:
            log.warning("timeline: %s", exc)
    events = merge_timeline(streams)
    if not events:
        return None
    events.sort(key=lambda e: e.time_created)
    target.write_text("".join(e.to_line() + "\n" for e in events), encoding="utf-8")
    source = TextLogSource(target)
    source.build_index()
    return source


@dataclass(frozen=True)
class LogHits:
    label: str
    key: object  # the caller's handle for the log (e.g. its document)
    total: int
    lines: list[tuple[int, str]]  # (line, text) of the first MAX_HITS_PER_LOG matches
    error: str = ""  # why this log could not be searched (then total is 0 and lines is empty)


class MultiSearch(QObject):
    """Search several logs with one query; results arrive per log, and ``done`` always follows."""

    found = Signal(object)  # LogHits (one per log, also for a log that could not be searched)
    done = Signal(int)  # logs searched successfully
    _found = Signal(int, object)
    _done = Signal(int, int)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._job = JobSlot()
        self._found.connect(
            lambda generation, hits: self.found.emit(hits) if self._job.is_current(generation) else None
        )
        self._done.connect(lambda generation, n: self.done.emit(n) if self._job.is_current(generation) else None)

    def search(self, logs: Sequence[tuple[str, object, TextLogSource]], query: SearchQuery) -> None:
        generation, cancel = self._job.begin()
        found, done = self._found, self._done

        def work() -> None:
            searched = 0
            try:
                for label, key, source in logs:
                    if cancel.is_set():
                        return
                    hits = _search_log(label, key, source, query, cancel)
                    if not hits.error:
                        searched += 1
                    found.emit(generation, hits)
            finally:  # the dialog waits for this: emit it even if something unexpected went wrong
                done.emit(generation, searched)

        start_worker("multi-search", work)


def _search_log(label: str, key: object, source: TextLogSource, query: SearchQuery, cancel: threading.Event) -> LogHits:
    """Hits of ``query`` in one log; a log that can't be searched yields a LogHits with ``error`` set."""
    try:
        hits = search_multi(source, [query], cancel=cancel)[0]
        shown = hits[:MAX_HITS_PER_LOG]
        texts = source.get_lines_at(shown)
    except OSError as exc:  # deleted, locked, network share gone, ...
        log.warning("find in all logs: cannot read %s: %s", label, exc)
        return LogHits(label, key, 0, [], error=f"Cannot read the file: {exc}")
    except Exception as exc:  # job boundary per log (e.g. the search pool broke twice): the other logs still run
        log.exception("find in all logs: searching %s failed", label)
        return LogHits(label, key, 0, [], error=f"Search failed: {exc}")
    return LogHits(label, key, len(hits), list(zip(shown.tolist(), texts, strict=True)))


class BundleLoader(QObject):
    """Lists the log files of a folder, or extracts a zip first (off the UI thread)."""

    loaded = Signal(str, object)  # bundle title, list[BundleFile]
    failed = Signal(str)

    def load(self, path: Path, extract_to: Path) -> None:
        def work() -> None:
            try:
                folder = path
                if path.is_file():
                    extract_zip(path, extract_to)
                    folder = extract_to
                files: list[BundleFile] = list_log_files(folder)
            except BundleError as exc:
                self.failed.emit(str(exc))
                return
            except Exception as exc:  # job boundary: report it, or the progress dialog would stay open forever
                log.exception("loading bundle %s failed", path)
                self.failed.emit(f"Could not open {path.name}: {exc}")
                return
            self.loaded.emit(path.name, files)

        start_worker("bundle", work)
