"""Jobs over several logs: one bad log must not sink "find in all logs", and failures always reach the dialog."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest
from PySide6.QtWidgets import QApplication

from loglens.core.search import SearchQuery
from loglens.services import multi_jobs
from loglens.services.multi_jobs import BundleLoader, LogHits, MultiSearch, TimelineBuilder
from tests.helpers import make_source


def test_multi_search_reports_an_unreadable_log_and_finishes(
    qapp: QApplication, wait_for: Callable[..., None], tmp_path: Path
) -> None:
    gone = make_source(tmp_path, b"error one\nok\n", "gone.log")
    good = make_source(tmp_path, b"ok\nerror two\nerror three\n", "good.log")
    gone.path.unlink()  # closed or rotated away after it was opened
    search = MultiSearch()
    found: list[LogHits] = []
    done: list[int] = []
    search.found.connect(found.append)
    search.done.connect(done.append)

    search.search([("gone", 1, gone), ("good", 2, good)], SearchQuery("error"))
    wait_for(lambda: done)

    assert done == [1]  # logs searched successfully
    assert [hits.label for hits in found] == ["gone", "good"]
    assert found[0].error and found[0].total == 0 and found[0].lines == []
    assert found[1].error == ""
    assert found[1].total == 2 and [line for line, _text in found[1].lines] == [1, 2]


def _boom(*_args: object, **_kwargs: object) -> None:
    raise ValueError("boom")


def test_timeline_reports_unexpected_errors(
    qapp: QApplication, wait_for: Callable[..., None], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(multi_jobs, "write_timeline", _boom)
    builder = TimelineBuilder()
    failures: list[str] = []
    builder.failed.connect(failures.append)
    builder.build([], tmp_path / "timeline.log")
    wait_for(lambda: failures)  # the progress dialog closes on "failed"
    assert "boom" in failures[0]


def test_bundle_loader_reports_unexpected_errors(
    qapp: QApplication, wait_for: Callable[..., None], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(multi_jobs, "list_log_files", _boom)
    loader = BundleLoader()
    failures: list[str] = []
    loader.failed.connect(failures.append)
    loader.load(tmp_path, tmp_path / "extracted")
    wait_for(lambda: failures)
    assert "boom" in failures[0]
