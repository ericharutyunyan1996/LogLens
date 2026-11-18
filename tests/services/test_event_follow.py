"""Following a Windows event log: new events are appended once, in time order (fake reader, no real event log)."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from PySide6.QtWidgets import QApplication

from loglens.core.winevent.models import EventRecord
from loglens.core.winevent.reader import EventQuery
from loglens.services import eventlog_jobs
from loglens.services.eventlog_jobs import EventLogExporter, EventLogFollower


def test_follower_appends_new_events_once(qapp: QApplication, wait_for: Callable[..., None], tmp_path: Path) -> None:
    base = datetime.now(UTC) + timedelta(seconds=5)
    log: list[EventRecord] = []

    def reader(query: EventQuery) -> Iterable[EventRecord]:
        assert query.since is not None and not query.newest_first
        return [e for e in log if e.channel == query.channel and e.time_created >= query.since]

    target = tmp_path / "events.log"
    target.write_text("", encoding="utf-8")
    follower = EventLogFollower([EventQuery("System"), EventQuery("Application")], target, reader=reader)
    counts: list[int] = []
    follower.appended.connect(counts.append)

    log.append(EventRecord("System", "Service Control Manager", 7036, 4, base, record_id=1, message="started"))
    log.append(EventRecord("Application", "Application Error", 1000, 2, base, record_id=7, message="crash"))
    follower.poll()
    wait_for(lambda: counts == [2])
    follower.poll()  # nothing new (the two events at the same moment are not appended again)
    wait_for(lambda: not follower.busy)
    log.append(EventRecord("System", "Kernel-Power", 41, 1, base + timedelta(seconds=1), record_id=2, message="x"))
    follower.poll()
    wait_for(lambda: len(counts) == 2)
    lines = target.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3 and "Kernel-Power" in lines[-1]


def test_follower_picks_up_events_logged_while_the_export_ran(
    qapp: QApplication, wait_for: Callable[..., None], tmp_path: Path
) -> None:
    started = datetime.now(UTC) - timedelta(minutes=1)  # the export began reading a minute ago
    old = EventRecord("System", "Disk", 7, 3, started - timedelta(seconds=10), record_id=1, message="before")
    exported = EventRecord("System", "Disk", 7, 3, started + timedelta(seconds=1), record_id=2, message="in export")
    missed = EventRecord("Application", "App", 1000, 2, started + timedelta(seconds=2), record_id=9, message="missed")
    log = [old, exported, missed]

    def reader(query: EventQuery) -> Iterable[EventRecord]:
        assert query.since is not None
        return [e for e in log if e.channel == query.channel and e.time_created >= query.since]

    target = tmp_path / "events.log"
    target.write_text(old.to_line() + "\n" + exported.to_line() + "\n", encoding="utf-8")  # what the export wrote
    queries = [EventQuery("System"), EventQuery("Application")]
    follower = EventLogFollower(queries, target, reader=reader, since=started)
    counts: list[int] = []
    follower.appended.connect(counts.append)

    follower.poll()
    wait_for(lambda: counts == [1])  # only the event the export missed; the exported one is not appended twice
    follower.poll()
    wait_for(lambda: not follower.busy)
    assert counts == [1]
    lines = target.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3 and "missed" in lines[-1]


def test_exporter_records_its_start_and_reports_unexpected_errors(
    qapp: QApplication, wait_for: Callable[..., None], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken_reader(*_args: object, **_kwargs: object) -> Iterable[EventRecord]:
        raise ValueError("boom")

    monkeypatch.setattr(eventlog_jobs, "read_events", broken_reader)
    exporter = EventLogExporter()
    failures: list[str] = []
    exporter.failed.connect(failures.append)
    before = datetime.now(UTC)
    assert exporter.started_at is None
    exporter.export([EventQuery("System")], tmp_path / "export.log")
    wait_for(lambda: failures)  # the progress dialog closes on "failed"
    assert "boom" in failures[0]
    assert exporter.started_at is not None and exporter.started_at.tzinfo is not None
    assert before <= exporter.started_at <= datetime.now(UTC)
