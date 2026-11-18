"""Working across open logs: find in all of them, and merge them into one timeline."""

from __future__ import annotations

import zipfile
from collections.abc import Callable
from pathlib import Path

import pytest
from PySide6.QtWidgets import QApplication

from loglens.core.search import shutdown_pool
from loglens.settings import Settings
from loglens.ui.bundle_dialog import BundleDialog
from loglens.ui.main_window import MainWindow
from loglens.ui.multi_dialogs import TimelineDialog


@pytest.fixture
def window(qapp: QApplication, wait_for: Callable[..., None], tmp_path: Path):
    first, second = tmp_path / "api.log", tmp_path / "worker.log"
    first.write_text("2026-11-13 10:00:00,000 INFO api up\n2026-11-13 10:00:04,000 ERROR api timeout\n", "utf-8")
    second.write_text("2026-11-13 10:00:02,000 INFO worker up\n2026-11-13 10:00:03,000 ERROR worker timeout\n", "utf-8")
    win = MainWindow(Settings())
    win.show()
    for path in (first, second):
        win.open_file(str(path))
    wait_for(lambda: all(not t.document.is_indexing for t in win.all_tabs()))
    yield win
    win.close()
    shutdown_pool()


def test_find_in_all_logs(window, wait_for: Callable[..., None]) -> None:
    window.find_in_all()
    dialog = window._find_all
    dialog.query.setText("timeout")
    dialog.run()
    wait_for(lambda: dialog.results.topLevelItemCount() == 2)
    worker = next(
        dialog.results.topLevelItem(i) for i in range(2) if dialog.results.topLevelItem(i).text(0) == "worker.log"
    )
    dialog._jump(worker.child(0), 0)
    assert window.current_tab().document.title == "worker.log" and window.current_tab().main_view.current_row() == 1


def test_merge_into_timeline(window, wait_for: Callable[..., None], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(TimelineDialog, "exec", lambda self: (self.events.setChecked(False), 1)[1])
    window.build_timeline()
    wait_for(lambda: window.current_tab().document.title.startswith("Timeline"))
    tab = window.current_tab()
    wait_for(lambda: not tab.document.is_indexing and tab.document.source.line_count() == 4)
    lines = tab.document.source.get_lines(0, 4)
    assert [line.split("›")[0].split("‹")[1] for line in lines] == ["api.log", "worker.log", "worker.log", "api.log"]


def test_live_dashboard_and_services(window, monkeypatch: pytest.MonkeyPatch) -> None:
    states = {"Spooler": "Running"}
    monkeypatch.setattr("loglens.ui.dashboard.service_states", lambda names: {n: states.get(n, "?") for n in names})
    monkeypatch.setattr("loglens.ui.watch_controller.service_states", lambda names: {n: states[n] for n in names})
    notes: list[str] = []
    monkeypatch.setattr(window.watch, "notify", lambda title, text: notes.append(f"{title}: {text}"))
    window.open_dashboard()
    board = window._dashboard
    assert board.logs.topLevelItemCount() == 2
    window.watch.set_watched_services(["Spooler"])
    board.refresh()
    assert board.services_tree.topLevelItem(0).text(1) == "Running"
    window.watch._poll_services()
    states["Spooler"] = "Stopped"
    window.watch._poll_services()
    assert notes and "Running → Stopped" in notes[0]
    window.watch.set_watched_services([])


def test_open_zip_bundle(
    window, wait_for: Callable[..., None], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    bundle = tmp_path / "support.zip"
    with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("node1/app.log", "2026-11-13 10:00:00,000 INFO node1 up\n")
        z.writestr("node2/app.log.1", "2026-11-13 10:00:01,000 INFO node2 up\n")
        z.writestr("readme.pdf", b"%PDF")
    monkeypatch.setattr(BundleDialog, "exec", lambda self: (self.merge.setChecked(False), 1)[1])
    before = len(window.all_tabs())
    window.open_file(str(bundle))
    wait_for(lambda: len(window.all_tabs()) == before + 2)
    assert {t.document.title for t in window.all_tabs()[-2:]} == {"app.log", "app.log.1"}
