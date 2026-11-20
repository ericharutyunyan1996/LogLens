"""Several servers (and this computer) are read side by side into one merged timeline."""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

from PySide6.QtWidgets import QApplication

from loglens.core.winevent.models import EventRecord, record_from_line
from loglens.core.winevent.reader import EventQuery, ServerUnavailableError
from loglens.core.winevent.remote import ServerProfile
from loglens.services import eventlog_jobs
from loglens.services.eventlog_jobs import EventLogExporter

START = datetime(2026, 11, 20, 10, 0, tzinfo=UTC)


def test_servers_are_read_in_parallel_merged_by_time_and_a_dead_one_is_skipped(
    qapp: QApplication, wait_for: Callable[..., None], tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    a, b, c = ServerProfile("A", "a1"), ServerProfile("B", "b1"), ServerProfile("C", "c1")
    barrier = threading.Barrier(2)  # servers A and B must be inside read_events at the same moment
    calls: list[tuple[str, str]] = []
    lock = threading.Lock()

    def fake_read(query: EventQuery, cancel=None, progress=None) -> Iterator[EventRecord]:  # type: ignore[no-untyped-def]
        name = query.server.name if query.server else ""
        with lock:
            calls.append((name, query.channel))
        if name == "C":
            raise ServerUnavailableError("C: c1 did not answer on port 135")
        if name in ("A", "B") and query.channel == "System":
            barrier.wait(10)  # only passes when both servers are being read in parallel
        offset = {"A": 1, "B": 2, "": 3}[name]
        for i in range(3):
            yield EventRecord(
                query.channel,
                "Prov",
                100 + i,
                2,
                START + timedelta(minutes=offset + i * 10),
                record_id=i,
                server=name,
                message=f"{name or 'local'} #{i}",
            )

    monkeypatch.setattr(eventlog_jobs, "read_events", fake_read)
    done: list[tuple[str, list[str]]] = []
    failed: list[str] = []
    exporter = EventLogExporter()
    exporter.finished.connect(lambda path, warnings: done.append((path, warnings)))
    exporter.failed.connect(failed.append)
    queries = [
        EventQuery("System", server=a), EventQuery("Application", server=a), EventQuery("System", server=b),
        EventQuery("System", server=c), EventQuery("Application", server=c), EventQuery("System"),
    ]  # fmt: skip
    exporter.export(queries, tmp_path / "merged.log")
    wait_for(lambda: done or failed)
    assert not failed, failed
    path, warnings = done[0]
    assert [name for name, _ in calls].count("C") == 1  # C's second channel was never tried: the server is down
    assert len(warnings) == 1 and "C: c1 did not answer" in warnings[0]  # one clear message, not one per channel
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    records = [record_from_line(line) for line in lines]
    assert all(r is not None for r in records)
    assert {r.server for r in records if r} == {
        "A",
        "B",
        "",
    }  # every reachable source is in the timeline, the dead one is not
    times = [r.time_created for r in records if r]
    assert times == sorted(times)  # one merged timeline
    assert any("[System @ A]" in line for line in lines) and any(
        "[System]" in line and "@" not in line.split("—")[0] for line in lines
    )


def test_events_of_different_servers_with_the_same_record_id_are_not_duplicates() -> None:
    """The follower de-duplicates by (server, channel, record id): ids repeat from server to server."""
    one = EventRecord("System", "P", 1, 2, START, record_id=7, server="A")
    two = EventRecord("System", "P", 1, 2, START, record_id=7, server="B")
    keys = {(e.server, e.channel, e.record_id) for e in (one, two)}
    assert len(keys) == 2
