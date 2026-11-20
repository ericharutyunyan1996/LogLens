"""Query Windows event channels or .evtx files through the Windows Event Log API (pywin32)."""

from __future__ import annotations

import logging
import sys
import threading
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Any

from . import remote
from .models import EventRecord, parse_event_xml
from .remote import ServerError, ServerProfile

if sys.platform == "win32":
    import pywintypes
    import win32evtlog

log = logging.getLogger(__name__)

COMMON_CHANNELS = ("Application", "System", "Security", "Setup")
BATCH = 128
ERROR_ACCESS_DENIED = 5
ERROR_NOT_FOUND_CODES = {2, 15007}  # file / channel not found
MESSAGE_FORMAT_FAILURES = (OSError,) if sys.platform != "win32" else (pywintypes.error, OSError)


class EventLogError(Exception):
    """User-presentable failure (access denied, channel not found, …)."""


class ServerUnavailableError(EventLogError):
    """A remote server could not be connected to: its other channels would fail the same way, so callers skip them."""


@dataclass(frozen=True, slots=True)
class EventQuery:
    """What to read. Levels use Windows numbers (1 Critical, 2 Error, 3 Warning, 4 Information, 5 Verbose)."""

    channel: str = "Application"  # channel name, or a path to an .evtx file when ``is_file``
    is_file: bool = False
    since: datetime | None = None  # aware datetimes
    until: datetime | None = None
    levels: tuple[int, ...] = ()
    max_events: int = 20_000
    newest_first: bool = True
    server: ServerProfile | None = None  # read another Windows server's log (None = this computer)

    def xpath(self) -> str:
        conditions = []
        if self.levels:
            levels = set(self.levels)
            if 4 in levels:
                levels.add(0)  # "LogAlways" events are shown as Information
            conditions.append("(" + " or ".join(f"Level={lv}" for lv in sorted(levels)) + ")")
        if self.since is not None:
            conditions.append(f"TimeCreated[@SystemTime>='{_xpath_time(self.since)}']")
        if self.until is not None:
            conditions.append(f"TimeCreated[@SystemTime<='{_xpath_time(self.until)}']")
        return f"*[System[{' and '.join(conditions)}]]" if conditions else "*"


def _xpath_time(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class _MessageFormatter:
    """EvtFormatMessage with a per-provider metadata cache (opening publisher metadata is the slow part)."""

    def __init__(self, session: object | None = None) -> None:
        self._session: Any = session  # a remote session: message templates come from that server
        self._metadata: dict[str, object | None] = {}

    def format(self, provider: str, handle: object) -> str:
        if provider not in self._metadata:
            try:
                self._metadata[provider] = win32evtlog.EvtOpenPublisherMetadata(provider, self._session)
            except MESSAGE_FORMAT_FAILURES:
                self._metadata[provider] = None
        metadata = self._metadata[provider]
        if metadata is None:
            return ""
        try:
            return str(win32evtlog.EvtFormatMessage(metadata, handle, win32evtlog.EvtFormatMessageEvent) or "")
        except MESSAGE_FORMAT_FAILURES:
            return ""  # message template missing (e.g. .evtx from another machine): fall back to event data


def read_events(
    query: EventQuery,
    cancel: threading.Event | None = None,
    progress: Callable[[int], None] | None = None,
) -> Iterator[EventRecord]:
    """Yield events matching ``query`` (newest first by default)."""
    if sys.platform != "win32":  # pragma: no cover - Windows product
        raise EventLogError("Windows Event Logs are only available on Windows")
    flags = win32evtlog.EvtQueryFilePath if query.is_file else win32evtlog.EvtQueryChannelPath
    flags |= win32evtlog.EvtQueryReverseDirection if query.newest_first else win32evtlog.EvtQueryForwardDirection
    session = None
    if query.server is not None:
        try:
            session = remote.connect(query.server)
        except ServerError as exc:
            raise ServerUnavailableError(f"{query.server.name}: {exc}") from exc
    try:
        result = win32evtlog.EvtQuery(query.channel, flags, query.xpath(), session)
    except pywintypes.error as exc:
        raise _friendly(exc, query.channel, query.server) from exc
    formatter = _MessageFormatter(session)
    server_name = query.server.name if query.server is not None else ""
    count = 0
    while count < query.max_events:
        if cancel is not None and cancel.is_set():
            return
        try:
            handles = win32evtlog.EvtNext(result, min(BATCH, query.max_events - count))
        except pywintypes.error as exc:
            raise _friendly(exc, query.channel, query.server) from exc
        if not handles:
            return
        for handle in handles:
            xml = win32evtlog.EvtRender(handle, win32evtlog.EvtRenderEventXml)
            try:
                record = parse_event_xml(xml)
            except (ValueError, SyntaxError):
                log.debug("skipping unparsable event in %s", query.channel)
                continue
            message = formatter.format(record.provider, handle).strip()
            record = replace(record, message=message) if message else record
            yield replace(record, server=server_name) if server_name else record
            count += 1
        if progress is not None:
            progress(count)


def _friendly(exc: Exception, channel: str, server: ServerProfile | None = None) -> EventLogError:
    code = getattr(exc, "winerror", None)
    if server is not None:  # a remote read: say which server and what to change there
        failure = remote.explain(code, server, f"({channel}) {getattr(exc, 'strerror', exc)}")
        return EventLogError(f"{server.name}: {failure}")
    if code == ERROR_ACCESS_DENIED:
        return EventLogError(f"Access denied to '{channel}' — this log needs LogLens to run as administrator.")
    if code in ERROR_NOT_FOUND_CODES:
        return EventLogError(f"'{channel}' was not found.")
    return EventLogError(f"Cannot read '{channel}': {getattr(exc, 'strerror', exc)}")


def list_channels(server: ServerProfile | None = None) -> list[str]:
    """All event channels registered on this machine, or on ``server`` (sorted, common ones first)."""
    if sys.platform != "win32":  # pragma: no cover
        return []
    if server is not None:
        try:
            return remote.list_channels(server)
        except ServerError as exc:
            raise EventLogError(f"{server.name}: {exc}") from exc
    names: list[str] = []
    enumerator = win32evtlog.EvtOpenChannelEnum()
    while True:
        name = win32evtlog.EvtNextChannelPath(enumerator)
        if name is None:
            break
        names.append(name)
    rest = sorted((n for n in names if n not in COMMON_CHANNELS), key=str.lower)
    return [c for c in COMMON_CHANNELS if c in names] + rest


def merge_timeline(streams: Sequence[list[EventRecord]]) -> list[EventRecord]:
    """Combine several channels into one timeline (oldest first, like a log file)."""
    merged = [event for stream in streams for event in stream]
    merged.sort(key=lambda e: (e.time_created, e.record_id))
    return merged
