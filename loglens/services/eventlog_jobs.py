"""Background jobs for Windows Event Logs: export channels to a log file, find events around a moment."""

from __future__ import annotations

import logging
import os
import threading
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path

from PySide6.QtCore import QObject, QTimer, Signal

from ..core.fileio import open_shared
from ..core.winevent.models import EventRecord, record_from_line
from ..core.winevent.reader import EventLogError, EventQuery, ServerUnavailableError, merge_timeline, read_events
from .jobs import JobSlot, start_worker

log = logging.getLogger(__name__)
RELATED_CHANNELS = ("Application", "System")
RELATED_LEVELS = (1, 2, 3)  # critical, error, warning
RELATED_MAX_EVENTS = 500
FOLLOW_INTERVAL_MS = 3_000  # how often a followed event log is polled for new events
FOLLOW_BATCH = 5_000  # new events read per channel per poll
# Event lines keep milliseconds (and event-log queries compare milliseconds): a time read back from a line, or a
# query's start, may be up to this much earlier than the event itself.
LINE_TIME_RESOLUTION = timedelta(milliseconds=1)
TAIL_BLOCK_BYTES = 64 * 1024  # the end of an export is read backwards in blocks of this size
EventReader = Callable[[EventQuery], Iterable[EventRecord]]
EventKey = tuple[str, str, int]  # (server, channel, record id): record ids repeat from server to server
MAX_PARALLEL_SOURCES = 6  # this computer and servers are read side by side, at most this many at once
PollResult = tuple[list[EventRecord], list[str], dict[EventKey, datetime] | None]


class EventLogExporter(QObject):
    """Reads one or more channels/files and writes them as one time-ordered log file (one event per line)."""

    progress = Signal(str, int)  # channel, events read so far
    finished = Signal(str, object)  # output path, list of warnings (channels that failed)
    failed = Signal(str)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._cancel = threading.Event()
        # When the last export() started reading (aware). Events logged after this may be missing from the export:
        # pass it to EventLogFollower(since=...) so following picks up exactly where the export began.
        self.started_at: datetime | None = None

    def cancel(self) -> None:
        self._cancel.set()

    def export(self, queries: Sequence[EventQuery], target: Path) -> None:
        self._cancel = cancel = threading.Event()
        self.started_at = datetime.now().astimezone()

        def work() -> None:
            try:
                self._export(queries, target, cancel)
            except Exception as exc:  # job boundary: report it, or the progress dialog would stay open forever
                log.exception("event log export to %s failed", target)
                self.failed.emit(f"Could not read the event logs: {exc}")

        start_worker("eventlog-export", work)

    def _export(self, queries: Sequence[EventQuery], target: Path, cancel: threading.Event) -> None:
        """Worker thread: read every query (each server on its own thread), then write the merged timeline."""
        groups: dict[str, list[EventQuery]] = {}
        for query in queries:
            groups.setdefault(_source(query), []).append(query)

        def read_group(group: list[EventQuery]) -> tuple[list[list[EventRecord]], list[str]]:
            out: list[list[EventRecord]] = []
            problems: list[str] = []
            for query in group:
                label = f"{query.server.name}: {query.channel}" if query.server is not None else query.channel

                def report(count: int, label: str = label) -> None:
                    self.progress.emit(label, count)

                try:
                    out.append(list(read_events(query, cancel, progress=report)))
                except (
                    ServerUnavailableError
                ) as exc:  # the whole server is out of reach: do not retry its other channels
                    problems.append(str(exc))
                    break
                except EventLogError as exc:
                    problems.append(str(exc))
                if cancel.is_set():
                    break
            return out, problems

        streams: list[list[EventRecord]] = []
        warnings: list[str] = []
        with ThreadPoolExecutor(max_workers=max(1, min(len(groups), MAX_PARALLEL_SOURCES))) as pool:
            for read, problems in pool.map(read_group, groups.values()):
                streams.extend(read)
                warnings.extend(problems)
        if cancel.is_set():
            return
        if not streams:
            self.failed.emit("; ".join(warnings) or "No events could be read.")
            return
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("w", encoding="utf-8", newline="\n") as out:
                for event in merge_timeline(streams):
                    out.write(event.to_line() + "\n")
        except OSError as exc:
            self.failed.emit(f"Could not write {target}: {exc}")
            return
        self.finished.emit(str(target), warnings)


def _source(query: EventQuery) -> str:
    """Which machine a query reads from ("" = this computer): the unit of parallelism and of "this one is down"."""
    return query.server.name if query.server is not None else ""


class EventLogFollower(QObject):
    """Keeps an exported event-log file growing: polls the channels for newer events and appends them in time order.

    The log tab follows the file like any other growing log, so new Windows events show up live (with search,
    filters, alerts and the knowledge base) without opening Event Viewer.
    """

    appended = Signal(int)  # events appended in one poll
    failed = Signal(str)

    def __init__(
        self,
        queries: Sequence[EventQuery],
        target: Path,
        parent: QObject | None = None,
        *,
        reader: EventReader = read_events,
        since: datetime | None = None,
    ) -> None:
        """``since`` (aware, default now): poll for events from this moment on. Pass the export's
        :attr:`EventLogExporter.started_at` so events logged while the export ran are not lost; the ones the export
        did write are recognised in ``target`` on the first poll and not appended twice.
        """
        super().__init__(parent)
        self._reader = reader
        start = since if since is not None else datetime.now().astimezone()
        self._queries = [replace(q, since=start, until=None, newest_first=False, max_events=FOLLOW_BATCH)
                         for q in queries if not q.is_file]  # fmt: skip
        self._target = target
        # Events already in the file that the next query (from its ``since`` on, inclusive) can return again.
        self._seen: dict[EventKey, datetime] = {}
        self._seeded = False  # the first poll first learns which events from ``start`` on the export already wrote
        self._busy = False
        self._done = _FollowSignals(self)
        self._done.polled.connect(self._on_polled)
        self._timer = QTimer(self)
        self._timer.setInterval(FOLLOW_INTERVAL_MS)
        self._timer.timeout.connect(self.poll)

    @property
    def target(self) -> Path:
        return self._target

    @property
    def active(self) -> bool:
        return self._timer.isActive()

    @property
    def busy(self) -> bool:
        """A poll is running (a new poll request is skipped meanwhile)."""
        return self._busy

    def start(self) -> None:
        if self._queries:
            self._timer.start()

    def stop(self) -> None:
        self._timer.stop()

    def poll(self) -> None:
        if self._busy:
            return
        self._busy = True
        queries, seen, target, signals = list(self._queries), set(self._seen), self._target, self._done
        reader = self._reader
        seed_since = None if self._seeded or not queries else queries[0].since

        def work() -> None:
            try:
                result = _poll_once(queries, reader, target, seen, seed_since)
            except Exception as exc:  # job boundary: a stuck "busy" flag would stop following for good
                log.exception("event log follow poll failed")
                result = [], [f"Polling failed: {exc}"], None
            signals.polled.emit(*result)

        start_worker("eventlog-follow", work)

    def _on_polled(
        self, events: list[EventRecord], warnings: list[str], written: dict[EventKey, datetime] | None
    ) -> None:
        self._busy = False
        if written is not None:
            self._seen.update(written)
            self._seeded = True
        if warnings:
            self.failed.emit("; ".join(warnings))
        if not events:
            return
        self._seen.update({(e.server, e.channel, e.record_id): e.time_created for e in events})
        newest = max(e.time_created for e in events)
        # The next query starts at ``newest`` (inclusive, millisecond precision): only events from then on come back.
        cutoff = newest - LINE_TIME_RESOLUTION
        self._seen = {key: moment for key, moment in self._seen.items() if moment >= cutoff}
        self._queries = [replace(q, since=newest) for q in self._queries]
        self.appended.emit(len(events))


def _poll_once(
    queries: Sequence[EventQuery],
    reader: EventReader,
    target: Path,
    seen: set[EventKey],
    seed_since: datetime | None,
) -> PollResult:
    """Worker side of one poll: append the new events to ``target``.

    Returns (events appended, warnings, events found already written in ``target`` from ``seed_since`` on — None
    when ``seed_since`` is None).
    """
    written: dict[EventKey, datetime] | None = None
    if seed_since is not None:
        try:
            written = _written_since(target, seed_since)
        except OSError as exc:
            return [], [f"Could not read {target}: {exc}"], None
        seen = seen | written.keys()
    streams: list[list[EventRecord]] = []
    warnings: list[str] = []
    down: set[str] = set()  # servers that could not be connected to: not asked again for their other channels
    for query in queries:
        if _source(query) in down:
            continue
        try:
            streams.append([e for e in reader(query) if (e.server, e.channel, e.record_id) not in seen])
        except ServerUnavailableError as exc:
            warnings.append(str(exc))
            down.add(_source(query))
        except EventLogError as exc:
            warnings.append(str(exc))
    events = merge_timeline(streams)
    try:
        if events:
            with target.open("a", encoding="utf-8", newline="\n") as out:
                out.writelines(event.to_line() + "\n" for event in events)
    except OSError as exc:
        warnings.append(f"Could not write {target}: {exc}")
        events = []
    return events, warnings, written


def _written_since(target: Path, since: datetime) -> dict[EventKey, datetime]:
    """The events ``target`` already holds from ``since`` on. The file is time-ordered, so only its end is read."""
    found: dict[EventKey, datetime] = {}
    cutoff = since - LINE_TIME_RESOLUTION
    with open_shared(target) as f:
        end = f.seek(0, os.SEEK_END)
        carry = b""
        while end > 0:
            start = max(end - TAIL_BLOCK_BYTES, 0)
            f.seek(start)
            lines = (f.read(end - start) + carry).split(b"\n")
            carry = lines.pop(0) if start > 0 else b""  # may be cut off: completed by the next (earlier) block
            for raw in reversed(lines):
                record = record_from_line(raw.decode("utf-8", errors="replace").rstrip("\r"))
                if record is None:
                    continue
                if record.time_created < cutoff:
                    return found
                found[record.server, record.channel, record.record_id] = record.time_created
            end = start
    return found


class _FollowSignals(QObject):
    polled = Signal(object, object, object)  # list[EventRecord], list[str], dict[EventKey, datetime] | None


class RelatedEventsFinder(QObject):
    """Errors/warnings Windows logged within ±N minutes of a moment (Application + System by default)."""

    found = Signal(object, object)  # list[EventRecord], list[str] warnings
    failed = Signal(str)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._job = JobSlot()
        self._signals = _FinderSignals(self)
        self._signals.done.connect(self._on_done)

    def find(self, moment: datetime, minutes: int, channels: Sequence[str] = RELATED_CHANNELS) -> None:
        generation, cancel = self._job.begin()
        since, until = moment - timedelta(minutes=minutes), moment + timedelta(minutes=minutes)
        signals = self._signals

        def work() -> None:
            streams: list[list[EventRecord]] = []
            warnings: list[str] = []
            for channel in channels:
                query = EventQuery(
                    channel, since=since, until=until, levels=RELATED_LEVELS, max_events=RELATED_MAX_EVENTS
                )
                try:
                    streams.append(list(read_events(query, cancel)))
                except EventLogError as exc:
                    warnings.append(str(exc))
            signals.done.emit(generation, merge_timeline(streams), warnings)

        start_worker("related-events", work)

    def _on_done(self, generation: int, events: list[EventRecord], warnings: list[str]) -> None:
        if self._job.is_current(generation):
            self.found.emit(events, warnings)


class _FinderSignals(QObject):
    done = Signal(int, object, object)  # generation, events, warnings
