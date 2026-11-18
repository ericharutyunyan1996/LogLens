"""Knowledge-base editing, secret masking, the analysis window and alert rules — end to end in the main window."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest
from PySide6.QtCore import QPoint, Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication

from loglens.core.kb import KBEntry
from loglens.core.search import shutdown_pool
from loglens.settings import Settings
from loglens.ui.kb_dialog import KnowledgeDialog
from loglens.ui.kb_entry_dialog import KBEntryDialog
from loglens.ui.main_window import MainWindow
from loglens.ui.watch_dialogs import AlertRulesDialog

TOKEN = "Zx9" + "Kq7Lm2Np4Rs6Tu8Vw0Yb1Cd3Ef5Gh"  # synthetic, high-entropy
LINES = [
    "2026-11-13 10:00:00,000 [1] INFO  Web - GET /api/orders/1001 responded 200 in 12 ms",
    "2026-11-13 10:00:01,000 [1] INFO  Web - GET /api/orders/1002 responded 200 in 30 ms",
    "2026-11-13 10:00:02,000 [1] ERROR Web - POST /api/orders responded 500 in 950 ms",
    "2026-11-13 10:00:03,000 [1] ERROR Sync - Widget pipeline stalled on stage 7",
    f"2026-11-13 10:00:04,000 [1] DEBUG Auth - calling api with client_secret={TOKEN}",
]


@pytest.fixture
def window(qapp: QApplication, wait_for: Callable[..., None], tmp_path: Path):
    log = tmp_path / "web.log"
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


def test_unexplained_error_is_queued_and_can_be_taught(window, monkeypatch: pytest.MonkeyPatch) -> None:
    win, tab = window
    tab.main_view.go_to_row(3)  # an error nothing explains
    queued = [u.sample for u in win.knowledge.unknowns()]
    assert any("pipeline stalled" in sample for sample in queued)

    def fake_exec(dialog: KBEntryDialog) -> int:
        dialog.title.setText("Pipeline stall")
        dialog.explanation.setPlainText("A processing stage stopped making progress.")
        assert "✔" in dialog.match_result.text()  # the suggested pattern matches the line it came from
        return 1

    monkeypatch.setattr(KBEntryDialog, "exec", fake_exec)
    tab.teach_knowledge_base()
    assert not any("pipeline stalled" in u.sample for u in win.knowledge.unknowns())
    tab.main_view.go_to_row(3)
    assert "Pipeline stall" in tab.inspector.details.toPlainText()
    assert "Your knowledge base" in tab.inspector.details.toPlainText()

    dialog = KnowledgeDialog(win.knowledge, win)
    assert dialog.entries.topLevelItemCount() == 1
    dialog.search.setText("progress")
    assert dialog.entries.topLevelItemCount() == 1


def test_secrets_warned_and_masked(window) -> None:
    win, tab = window
    tab.main_view.go_to_row(4)
    assert "Secret in log" in tab.inspector.details.toPlainText()
    assert TOKEN in tab.inspector.raw.toPlainText()
    win.act_mask.trigger()
    assert TOKEN not in tab.inspector.raw.toPlainText()
    assert TOKEN not in tab.main_view.current_text()
    win.act_mask.trigger()
    assert TOKEN in tab.main_view.current_text()


def test_http_analysis_window(window, wait_for: Callable[..., None]) -> None:
    win, tab = window
    win.analyze("http")
    analysis = win._analysis[id(tab)]
    page = analysis.pages["http"]
    page.run()
    wait_for(lambda: page.endpoints.topLevelItemCount() > 0)
    endpoints = {page.endpoints.topLevelItem(i).text(0) for i in range(page.endpoints.topLevelItemCount())}
    assert "GET /api/orders/{id}" in endpoints and "3 requests" in page.status.text()
    item = page.slowest.topLevelItem(0)
    assert item is not None and item.text(0) == "950.0"
    page.jump(item)
    assert tab.main_view.current_row() == 2


def test_select_characters_within_a_line(window, qapp: QApplication) -> None:
    _win, tab = window
    view = tab.main_view
    qapp.processEvents()
    view.repaint()
    y_top = view.painted_rows()[0][0]
    y = y_top + view._lh // 2
    start = LINES[0].index("GET")

    def x(column: int) -> int:
        return int(view._text_x0() + column * view._cw)

    QTest.mousePress(view.viewport(), Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier, QPoint(x(start), y))
    QTest.mouseMove(view.viewport(), QPoint(x(start + len("GET /api/orders/1001")), y))
    QTest.mouseRelease(view.viewport(), Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier, QPoint(x(0), y))
    assert view.selected_text() == "GET /api/orders/1001"
    view.copy_selection()
    assert QGuiApplication.clipboard().text() == "GET /api/orders/1001"
    QTest.keyClick(view, Qt.Key.Key_Down)  # moving on clears the partial selection
    assert view.selected_text() == ""


def test_alert_rules_dialog_round_trip(qapp: QApplication) -> None:
    settings = Settings()
    dialog = AlertRulesDialog(settings.alert_rules(), False)
    dialog._add()
    rules = dialog.rules()
    assert len(rules) == len(settings.alert_rules()) + 1 and rules[-1].enabled
    entry = KBEntry(id="x", title="t", explanation="e")
    editor = KBEntryDialog(entry, "some line")
    with pytest.raises(ValueError, match="pattern"):
        editor.entry()  # no event source or pattern: LogLens could never show it


def test_patterns_and_compare_pages(window, wait_for: Callable[..., None]) -> None:
    win, tab = window
    win.analyze("patterns")
    analysis = win._analysis[id(tab)]
    page = analysis.pages["patterns"]
    page.run()
    wait_for(lambda: page.tree.topLevelItemCount() > 0)
    templates = [page.tree.topLevelItem(i).text(2) for i in range(page.tree.topLevelItemCount())]
    assert any("responded" in t for t in templates)
    page.tree.setCurrentItem(page.tree.topLevelItem(0))
    page._filter_selected()
    wait_for(lambda: len(tab.document.hits) > 0)

    tab.main_view.go_to_row(3)
    compare = analysis.pages["compare"]
    compare.refresh_scope()
    compare.run()
    wait_for(lambda: "new" in compare.status.text())
    assert compare.new.topLevelItemCount() >= 1
