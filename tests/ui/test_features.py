"""Event log export, knowledge-base explanations in the Inspector, related events, paste, editable AI preview."""

from __future__ import annotations

import sys
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from PySide6.QtCore import QEvent
from PySide6.QtWidgets import QApplication, QMessageBox, QToolButton

from loglens.core.ai.explain import build_request
from loglens.core.ai.redaction import Redactor
from loglens.core.filters import FilterMode
from loglens.core.search import SearchQuery, shutdown_pool
from loglens.core.winevent.models import EVENT_LINE, EventRecord
from loglens.core.winevent.reader import EventQuery
from loglens.services.eventlog_jobs import EventLogExporter
from loglens.settings import Settings
from loglens.ui.ai_dialogs import AIPreviewDialog
from loglens.ui.inspector import TAB_WINDOWS
from loglens.ui.main_window import MainWindow
from loglens.ui.report_dialog import ReportDialog

LINES = [
    "2026-11-13 10:00:00,000 [1] INFO  Svc - started",
    "2026-11-13 10:00:01,000 [1] ERROR Svc - Transaction (Process ID 61) was deadlocked on lock resources",
    "2026-11-13 10:00:02,000 [1] ERROR Svc - Faulting module crashed with 0xc0000005",
]


@pytest.fixture
def window(qapp: QApplication, wait_for: Callable[..., None], tmp_path: Path):
    log = tmp_path / "app.log"
    log.write_text("\n".join(LINES) + "\n", encoding="utf-8")
    win = MainWindow(Settings())
    win.resize(1200, 800)
    win.show()
    win.open_file(str(log))
    tab = win.current_tab()
    assert tab is not None
    wait_for(lambda: not tab.document.is_indexing)
    yield win, tab
    win.close()
    shutdown_pool()


def test_inspector_explains_lines_from_knowledge_base(window) -> None:
    _win, tab = window
    tab.main_view.go_to_row(1)
    details = tab.inspector.details.toPlainText()
    assert "What this means" in details and "SQL Server deadlock (error 1205)" in details and "Retry" in details
    tab.main_view.go_to_row(2)
    assert "access violation" in tab.inspector.details.toPlainText()


def test_related_events_listed_and_explained(window) -> None:
    _win, tab = window
    tab.main_view.go_to_row(1)
    event = EventRecord(
        "System", "Service Control Manager", 7031, 2, datetime(2026, 11, 13, 6, 0, 2, tzinfo=UTC),
        message="The Shop service terminated unexpectedly.",
    )  # fmt: skip
    tab.inspector.show_related([event], [], "within ±5 min of 10:00:01")
    assert tab.inspector.tabs.currentIndex() == TAB_WINDOWS
    item = tab.inspector.related.topLevelItem(0)
    assert item is not None and item.text(4) == "A service terminated unexpectedly"
    assert "Restart" in tab.inspector.related_details.toPlainText() or "crash" in (
        tab.inspector.related_details.toPlainText()
    )


def test_related_events_need_a_timestamp(window, tmp_path: Path, wait_for: Callable[..., None]) -> None:
    win, _tab = window
    plain = tmp_path / "plain.log"
    plain.write_text("no timestamp here\n", encoding="utf-8")
    win.open_file(str(plain))
    tab = win.current_tab()
    wait_for(lambda: not tab.document.is_indexing and tab.document.source.line_count() == 1)
    tab.main_view.go_to_row(0)
    tab.find_related_events(5)
    assert "no timestamp" in tab.inspector.related_status.text()


def test_filter_chip_menu_survives_count_updates(window, wait_for: Callable[..., None]) -> None:
    """Regression: level counts refresh while a log grows; that must not destroy an open chip menu."""
    _win, tab = window
    panel = tab.filter_panel
    wait_for(lambda: bool(tab.document.mark_summaries()) and bool(panel._levels))
    panel.edit.setText("deadlocked")
    panel.pin_current(FilterMode.NONE)
    QApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)  # drop chips replaced earlier
    chip = next(w for w in panel.findChildren(QToolButton) if w.objectName() == "filterChip")
    levels = [replace(option, count=(option.count or 0) + 1) for option in panel._levels]
    panel.set_levels(levels)  # what a tail update does
    QApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)  # a rebuilt chip would be deleted here
    QApplication.processEvents()
    assert chip in panel.findChildren(QToolButton) and not chip.isHidden()
    assert any(f"{levels[0].count:,}" in b.text() for b in panel._level_buttons)
    remove = next(a for a in chip.menu().actions() if a.text() == "Remove")
    remove.trigger()
    assert not panel._pinned and panel.spec().is_empty


def test_multiline_paste_becomes_any_of_filters(window, wait_for: Callable[..., None]) -> None:
    _win, tab = window
    tab.filter_panel.add_any_terms(["deadlocked", "0xc0000005"])
    spec = tab.filter_panel.spec()
    assert [t.mode for t in spec.terms] == [FilterMode.ANY, FilterMode.ANY]
    wait_for(lambda: tab.document.hits.tolist() == [1, 2])


def test_web_search_query_from_selection(window) -> None:
    _win, tab = window
    tab.main_view.go_to_row(2)
    assert tab.selected_texts() == [LINES[2]]


def test_ai_preview_sends_the_edited_text(qapp: QApplication) -> None:
    request = build_request("a.log", [(0, "ERROR secret-project failed"), (1, "next")], [0], Redactor([]))
    dialog = AIPreviewDialog(request, "claude-opus-5-5")
    assert dialog.edited_text() == request.user_text
    dialog.text.setPlainText(request.user_text.replace("secret-project", "<removed>"))
    assert "secret-project" not in dialog.edited_text() and "edited" in dialog.counter.text()
    dialog.text.setPlainText("   ")
    assert not dialog.send_button.isEnabled()  # nothing to send


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Event Log")
def test_export_local_event_log(qapp: QApplication, wait_for: Callable[..., None], tmp_path: Path) -> None:
    exporter = EventLogExporter()
    results: list[tuple[str, list[str]]] = []
    exporter.finished.connect(lambda path, warnings: results.append((path, warnings)))
    exporter.failed.connect(lambda message: results.append(("", [message])))
    target = tmp_path / "events.log"
    exporter.export([EventQuery("Application", max_events=25), EventQuery("No-Such-Channel/xyz", max_events=5)],
                    target)  # fmt: skip
    wait_for(lambda: bool(results), timeout=60)
    path, warnings = results[0]
    assert path == str(target) and any("No-Such-Channel" in w for w in warnings)
    lines = target.read_text(encoding="utf-8").splitlines()
    assert 0 < len(lines) <= 25 and all(EVENT_LINE.match(line) for line in lines)


def test_web_search_dialog_parts_toggle(qapp: QApplication) -> None:
    from loglens.core.websearch import query_parts
    from loglens.ui.web_search_dialog import WebSearchDialog

    lines = [
        "ERROR System.Net.WebException: The remote server returned an error: (502) Bad Gateway.",
        "HResult 0x80072ee2",
    ]
    dialog = WebSearchDialog(query_parts(lines), "Bing")
    assert [t.text() for t in dialog.toggles] == ["WebException", "Message", "0x80072ee2"]
    assert dialog.query_text().startswith('System.Net.WebException "The remote server')
    dialog.exact.setChecked(False)
    assert '"' not in dialog.query_text()
    dialog.toggles[1].setChecked(False)  # drop the message
    assert dialog.query_text() == "System.Net.WebException 0x80072ee2"
    assert "words" in dialog.counter.text() and dialog.chosen_engine() == "Bing"


def test_inspector_clear(window) -> None:
    _win, tab = window
    tab.main_view.go_to_row(1)
    assert tab.inspector.details.toPlainText()
    tab.inspector.clear()
    assert not tab.inspector.details.toPlainText() and not tab.inspector.raw.toPlainText()


def test_whole_records_and_record_inspector(window, tmp_path: Path, wait_for: Callable[..., None]) -> None:
    win, _tab = window
    log = tmp_path / "records.log"
    lines = []
    for i in range(20):
        lines.append(f"2026-11-13 10:00:{i:02d},000 [1] {'ERROR' if i == 5 else 'INFO '} Svc - step {i}")
        if i == 5:
            lines += ["System.InvalidOperationException: boom", "   at Svc.Run()"]
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    win.open_file(str(log))
    tab = win.current_tab()
    wait_for(lambda: tab.document.records.multi_line)
    assert not tab.filter_panel.whole_records.isHidden()

    tab.main_view.go_to_row(6)  # a stack-trace line: the Inspector shows the whole record
    assert "Lines 6–8" in tab.inspector.details.toPlainText()
    assert "InvalidOperationException" in tab.inspector.raw.toPlainText()
    assert tab.selected_texts()[0].endswith("step 5")

    tab.run_search(SearchQuery("ERROR"))
    wait_for(lambda: len(tab.document.hits) == 1)
    tab.filter_panel.whole_records.setChecked(True)
    assert tab.shown_lines().tolist() == [5, 6, 7]


def test_saved_filter_round_trip(window, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    win, tab = window
    panel = tab.filter_panel
    panel.edit.setText("deadlocked")
    panel.pin_current(FilterMode.ALL)
    monkeypatch.setattr("loglens.ui.packs_controller.QInputDialog.getText", lambda *_a, **_k: ("Deadlocks", True))
    win.packs.save_current(panel)
    assert [f.name for f in win.settings.saved_filters()] == ["Deadlocks"]

    panel.clear()
    assert panel.spec().is_empty
    panel.apply_saved(win.settings.saved_filters()[0])
    assert [t.query.pattern for t in panel.spec().terms] == ["deadlocked"]

    target = tmp_path / "team.loglens.json"
    monkeypatch.setattr("loglens.ui.packs_controller.QFileDialog.getSaveFileName", lambda *_a, **_k: (str(target), ""))
    monkeypatch.setattr("loglens.ui.packs_controller.QMessageBox.information", lambda *_a, **_k: None)
    win.packs.export_pack()
    win.packs.delete("Deadlocks")
    assert win.settings.saved_filters() == []
    monkeypatch.setattr("loglens.ui.packs_controller.QFileDialog.getOpenFileName", lambda *_a, **_k: (str(target), ""))
    monkeypatch.setattr(
        "loglens.ui.packs_controller.QMessageBox.question", lambda *_a, **_k: QMessageBox.StandardButton.No
    )
    win.packs.import_pack()
    assert [f.name for f in win.settings.saved_filters()] == ["Deadlocks"]


def test_incident_report_dialog(window, wait_for: Callable[..., None]) -> None:
    _win, tab = window
    wait_for(lambda: bool(tab.document.mark_summaries()))
    tab.document.toggle_bookmarks([1])
    tab.main_view.go_to_row(2)
    dialog = ReportDialog(tab)
    dialog.context.setValue(1)
    report = dialog.build()
    assert [e.line for e in report.evidence] == [2]  # bookmark 2 and selection 3 merge into one context block
    assert "deadlocked" in report.evidence[0].text and "0xc0000005" in report.evidence[0].text
    assert any(f.title for f in report.evidence[0].findings)
    assert report.counts and report.time_span.startswith("2026-11-13")
