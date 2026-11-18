"""Live growth vs background jobs (review findings): hits stay sorted and complete, alerts see every completed
line once, marks have no gaps, cleared/reset results never come back, indexing errors never leave a stuck state."""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterator
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np
import pytest
from PySide6.QtWidgets import QApplication

from loglens.core.filters import FilterSpec, FilterTerm, TimeRange
from loglens.core.highlight import default_rules
from loglens.core.search import SearchQuery, shutdown_pool
from loglens.core.watch import Alert, AlertRule
from loglens.services import log_document
from loglens.services.log_document import LogDocument
from loglens.services.watch_service import AlertMonitor

LINES = [f"2026-11-13 10:{i // 60:02d}:{i % 60:02d}.000 [1] {'ERROR' if i % 50 == 0 else 'INFO '} Svc - m {i}"
         for i in range(400)]  # fmt: skip


@pytest.fixture
def log_file(tmp_path: Path) -> Path:
    path = tmp_path / "live.log"
    path.write_text("\n".join(LINES) + "\n", encoding="utf-8")
    return path


@pytest.fixture
def gate(monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable[[Callable[..., bool]], threading.Event]]:
    """Hold the first search_multi call matching a predicate until the returned event is set."""
    real = log_document.search_multi
    gates: list[tuple[Callable[..., bool], threading.Event, list[bool]]] = []

    def wrapped(*args: object, **kwargs: object) -> list[np.ndarray]:
        for predicate, event, used in gates:
            if not used and predicate(*args, **kwargs):
                used.append(True)
                event.wait(10)
        return real(*args, **kwargs)  # type: ignore[arg-type] - same signature, forwarded

    monkeypatch.setattr(log_document, "search_multi", wrapped)

    def add(predicate: Callable[..., bool]) -> threading.Event:
        event = threading.Event()
        gates.append((predicate, event, []))
        return event

    yield add


def _append(path: Path, text: str) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(text)


def _start(qapp: QApplication, wait_for: Callable[..., None], path: Path) -> LogDocument:
    doc = LogDocument(path, default_rules())
    doc.start()
    wait_for(lambda: not doc.is_indexing and bool(doc.mark_summaries()))
    return doc


def test_growth_during_a_running_search_keeps_hits_sorted_and_complete(
    qapp: QApplication, wait_for: Callable[..., None], log_file: Path, gate: Callable[..., threading.Event]
) -> None:
    doc = _start(qapp, wait_for, log_file)
    release = gate(lambda *a, **k: k.get("on_partial") is not None)  # the filter job, not the tail job
    finished: list[int] = []
    doc.searchFinished.connect(lambda n, _s: finished.append(n))
    doc.run_search(SearchQuery("ERROR"))
    _append(log_file, "2026-11-13 11:00:00.000 [1] ERROR Svc - grown while searching\n")
    doc.check_file()
    wait_for(lambda: doc.source.line_count() == 401)  # tail job ran while the search was held
    release.set()
    wait_for(lambda: bool(finished) and len(doc.hits) == 9)
    hits = doc.hits.tolist()
    assert hits == sorted(set(hits)) and hits[-1] == 400
    doc.close()
    shutdown_pool()


def test_marks_have_no_gap_when_the_file_grows_during_the_marks_job(
    qapp: QApplication, wait_for: Callable[..., None], log_file: Path, gate: Callable[..., threading.Event]
) -> None:
    release = gate(lambda *a, **k: k.get("pool") == "background" and len(a[1]) > 1)  # the marks job
    doc = LogDocument(log_file, default_rules())
    doc.start()
    wait_for(lambda: not doc.is_indexing)
    _append(log_file, "2026-11-13 11:00:00.000 [1] ERROR Svc - grown during marks\n")
    doc.check_file()
    wait_for(lambda: doc.source.line_count() == 401)
    release.set()
    wait_for(lambda: {s.name: s.count for s in doc.mark_summaries()}.get("Error") == 9)
    doc.close()
    shutdown_pool()


def test_alert_sees_a_line_completed_across_two_polls(
    qapp: QApplication, wait_for: Callable[..., None], log_file: Path
) -> None:
    doc = _start(qapp, wait_for, log_file)
    monitor = AlertMonitor([AlertRule("db", SearchQuery("Database down"))])
    fired: list[Alert] = []
    monitor.alertFired.connect(lambda alert, _d: fired.append(alert))
    monitor.watch(doc)
    _append(log_file, "2026-11-13 11:00:00.000 [1] ERROR Svc - Datab")  # a buffered writer flushed half a line
    doc.check_file()
    wait_for(lambda: doc.source.line_count() == 401)
    _append(log_file, "ase down\n")
    doc.check_file()
    wait_for(lambda: len(fired) == 1)
    assert "Database down" in fired[0].sample
    doc.close()
    shutdown_pool()


def test_open_time_range_follows_growth_without_emptying_the_hits(
    qapp: QApplication, wait_for: Callable[..., None], log_file: Path
) -> None:
    doc = _start(qapp, wait_for, log_file)
    start = datetime(2026, 11, 13, 10, 5).astimezone()
    finished: list[int] = []
    doc.searchFinished.connect(lambda n, _s: finished.append(n))
    doc.run_filter(FilterSpec((FilterTerm(SearchQuery("ERROR")),), time_range=TimeRange(start, None)))
    wait_for(lambda: bool(finished))
    before = len(doc.hits)
    sizes: list[int] = []
    doc.hitsChanged.connect(lambda: sizes.append(len(doc.hits)))
    _append(log_file, (datetime(2026, 11, 13, 11, 0) + timedelta()).strftime("%Y-%m-%d %H:%M:%S.000") +
            " [1] ERROR Svc - inside the open range\n")  # fmt: skip
    doc.check_file()
    wait_for(lambda: len(doc.hits) == before + 1)
    assert 0 not in sizes  # never flickers to empty
    doc.close()
    shutdown_pool()


def test_cleared_search_results_do_not_come_back(
    qapp: QApplication, wait_for: Callable[..., None], log_file: Path, gate: Callable[..., threading.Event]
) -> None:
    doc = _start(qapp, wait_for, log_file)
    release = gate(lambda *a, **k: k.get("on_partial") is not None)
    doc.run_search(SearchQuery("ERROR"))
    doc.clear_search()
    release.set()
    for _ in range(30):
        qapp.processEvents()
        threading.Event().wait(0.02)
    assert len(doc.hits) == 0 and doc.filter_spec is None
    doc.close()
    shutdown_pool()


def test_indexing_error_never_leaves_the_document_stuck(
    qapp: QApplication, wait_for: Callable[..., None], log_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    doc = LogDocument(log_file, default_rules())

    def explode(*_args: object, **_kwargs: object) -> bool:
        raise MemoryError("simulated")

    monkeypatch.setattr(doc.source, "build_index", explode)
    errors: list[str] = []
    doc.indexFailed.connect(errors.append)
    doc.start()
    wait_for(lambda: not doc.is_indexing)
    assert errors and "simulated" in errors[0]
    doc.close()
