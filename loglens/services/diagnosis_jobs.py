"""Diagnose this computer: read the relevant Windows event logs for a period, run the recipes and coverage checks."""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from PySide6.QtCore import QObject, Signal

from ..core.diagnose import DiagnosisFinding, channels_needed, coverage_warnings, run_all
from ..core.winevent.models import EventRecord
from ..core.winevent.reader import EventLogError, EventQuery, ServerUnavailableError, read_events
from ..core.winevent.remote import ServerProfile
from ..core.winevent.wer import WerReport, find_reports, read_report
from .jobs import JobSlot, start_worker

log = logging.getLogger(__name__)
DIAGNOSE_MAX_EVENTS = 50_000  # per channel; recipes need information events too (boots, installs, service states)
MAX_WER_REPORTS = 200
EventReader = Callable[[EventQuery], Iterable[EventRecord]]


@dataclass(frozen=True)
class DiagnosisResult:
    start: datetime
    end: datetime
    findings: list[DiagnosisFinding]
    warnings: list[str]
    events_read: dict[str, int] = field(default_factory=dict)
    crash_reports: list[WerReport] = field(default_factory=list)


def diagnose(
    start: datetime, end: datetime, *, reader: EventReader = read_events, server: ServerProfile | None = None
) -> DiagnosisResult:
    """Read the channels the recipes need for [start, end] (of this computer, or of ``server``), run them, and collect
    coverage warnings."""
    by_channel: dict[str, list[EventRecord]] = {}
    errors: dict[str, str] = {}
    truncated = []
    for channel in channels_needed():
        query = EventQuery(channel, since=start, until=end, max_events=DIAGNOSE_MAX_EVENTS, server=server)
        try:
            events = list(reader(query))
        except (
            ServerUnavailableError
        ) as exc:  # the server cannot be reached at all: its other channels would fail alike
            errors[channel] = str(exc)
            break
        except EventLogError as exc:
            errors[channel] = str(exc)
            continue
        by_channel[channel] = events
        if len(events) >= DIAGNOSE_MAX_EVENTS:
            truncated.append(channel)
    findings = run_all(e for events in by_channel.values() for e in events)
    warnings = coverage_warnings(by_channel, start, end, errors, truncated_channels=truncated)
    reports = []
    # crash reports are files on this computer: a remote server's are not read
    for path in find_reports(since=start)[:MAX_WER_REPORTS] if server is None else []:
        try:
            reports.append(read_report(path))
        except (OSError, ValueError) as exc:
            log.debug("skipping WER report %s: %s", path, exc)
    return DiagnosisResult(start, end, findings, warnings, {c: len(e) for c, e in by_channel.items()}, reports)


class DiagnosisRunner(QObject):
    finished = Signal(object)  # DiagnosisResult
    failed = Signal(str)
    _done = Signal(int, object)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._job = JobSlot()
        self._done.connect(self._on_done)

    def run(self, hours: float, server: ServerProfile | None = None) -> None:
        generation, _cancel = self._job.begin()
        end = datetime.now().astimezone()
        start = end - timedelta(hours=hours)
        done = self._done

        def work() -> None:
            try:
                result: object = diagnose(start, end, server=server)
            except Exception as exc:
                log.exception("diagnosis failed")
                result = f"Diagnosis failed: {exc}"
            done.emit(generation, result)

        start_worker("diagnose", work)

    def _on_done(self, generation: int, result: object) -> None:
        if not self._job.is_current(generation):
            return
        if isinstance(result, DiagnosisResult):
            self.finished.emit(result)
        else:
            self.failed.emit(str(result))
