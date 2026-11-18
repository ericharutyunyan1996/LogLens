"""LogDocument without any widgets: indexing, search, marks, bookmarks, tail, truncation."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest
from PySide6.QtWidgets import QApplication

from loglens.core.highlight import default_rules
from loglens.core.search import SearchQuery, shutdown_pool
from loglens.services.log_document import LogDocument


@pytest.fixture
def log_file(tmp_path: Path) -> Path:
    lines = [
        f"2026-11-13 10:00:{i % 60:02d}.000 [1] {'ERROR' if i % 100 == 0 else 'INFO '} Svc - message {i}"
        for i in range(1000)
    ]
    path = tmp_path / "doc.log"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def test_index_search_marks_bookmarks(qapp: QApplication, wait_for: Callable[..., None], log_file: Path) -> None:
    doc = LogDocument(log_file, default_rules())
    finished: list[int] = []
    doc.searchFinished.connect(lambda count, _s: finished.append(count))
    doc.start()
    wait_for(lambda: not doc.is_indexing and any(s.count for s in doc.mark_summaries()))
    assert doc.source.line_count() == 1000
    assert {s.name: s.count for s in doc.mark_summaries()}["Error"] == 10

    assert doc.run_search(SearchQuery("(", regex=True)) is not None  # invalid regex is reported, not started
    assert doc.run_search(SearchQuery("error")) is None
    wait_for(lambda: bool(finished))
    assert finished == [10] and doc.hits.tolist() == list(range(0, 1000, 100))
    assert doc.next_hit(0) == 100 and doc.next_hit(0, forward=False) == 900

    doc.toggle_bookmarks([5, 7])
    assert doc.bookmarks == {5, 7} and doc.next_bookmark(5) == 7
    doc.toggle_bookmarks([5, 7])
    assert doc.bookmarks == frozenset()
    doc.close()
    shutdown_pool()


def test_tail_and_truncation(qapp: QApplication, wait_for: Callable[..., None], log_file: Path) -> None:
    doc = LogDocument(log_file, default_rules())
    resets: list[bool] = []
    doc.contentReset.connect(lambda: resets.append(True))
    doc.start()
    wait_for(lambda: not doc.is_indexing)
    doc.run_search(SearchQuery("ERROR"))
    wait_for(lambda: len(doc.hits) == 10)

    with log_file.open("a", encoding="utf-8") as f:
        f.write("2026-11-13 11:00:00.000 [1] ERROR Svc - appended\n")
    doc.check_file()  # growth is indexed and searched by a tail job on a worker
    wait_for(lambda: doc.source.line_count() == 1001 and len(doc.hits) == 11)
    assert doc.hits.tolist() == sorted(set(doc.hits.tolist()))

    log_file.write_text("2026-11-13 12:00:00.000 [1] ERROR Svc - new file\n", encoding="utf-8")
    doc.check_file()
    assert resets == [True]
    wait_for(lambda: not doc.is_indexing and len(doc.hits) == 1)  # search re-runs after re-indexing
    assert doc.source.line_count() == 1
    doc.close()
    shutdown_pool()
