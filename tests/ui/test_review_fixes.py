"""Fixes from the UI review: dashboard refresh, SQL off the UI thread, the analysis window acting on its own tab,
secret masking everywhere, input validation, unhandled exceptions, UI-thread feedback and theme switches."""

from __future__ import annotations

import json
import logging
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pytest
from PySide6.QtCore import QEvent, Qt
from PySide6.QtWidgets import QApplication, QDialog, QFileDialog, QMessageBox, QWidget

from loglens import app as app_module
from loglens.core.ai.config import AIConfig, Provider
from loglens.core.formats import format_by_name
from loglens.core.search import shutdown_pool
from loglens.core.winevent.models import EventRecord
from loglens.core.winevent.reader import EventQuery
from loglens.services.ai_service import AIService
from loglens.services.diagnosis_jobs import diagnose
from loglens.services.knowledge_service import KnowledgeService
from loglens.services.multi_jobs import LogHits
from loglens.settings import Settings
from loglens.ui.ai_dialogs import AISettingsDialog
from loglens.ui.analysis_window import AnalysisWindow
from loglens.ui.columns_view import ColumnsModel
from loglens.ui.dashboard import DashboardWindow
from loglens.ui.detail_render import LIGHT
from loglens.ui.diagnose_dialog import DiagnoseDialog
from loglens.ui.eventlog_dialog import EventLogDialog
from loglens.ui.inspector import Inspector
from loglens.ui.kb_dialog import KnowledgeDialog
from loglens.ui.main_window import MainWindow
from loglens.ui.multi_dialogs import FindAllDialog
from loglens.ui.packs_controller import PacksController
from loglens.ui.report_dialog import ReportDialog
from loglens.ui.time_dialogs import TimeRangeDialog
from loglens.ui.watch_dialogs import WatchFolderDialog

TOKEN = "Zx9" + "Kq7Lm2Np4Rs6Tu8Vw0Yb1Cd3Ef5Gh"  # synthetic, high-entropy
ACCEPTED = QDialog.DialogCode.Accepted.value
SHOP = [
    "2026-11-13 10:00:00,000 [1] INFO  Shop.Orders - order 1 placed",
    "2026-11-13 10:00:01,000 [2] ERROR Shop.Payments - card declined",
    "System.InvalidOperationException: declined",
    "2026-11-13 10:00:02,000 [1] INFO  Shop.Orders - order 2 placed",
    "2026-11-13 10:00:03,000 [3] WARN  Shop.Stock - low stock",
]
OTHER = ["2026-11-13 10:00:02,000 [1] INFO  Worker - worker up", "2026-11-13 10:00:03,000 [1] ERROR Worker - timeout"]


def _settle(qapp: QApplication, seconds: float = 0.3) -> None:
    """Process events for a while (to let late results arrive, if any would)."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        qapp.processEvents()
        time.sleep(0.01)


@pytest.fixture
def window(qapp: QApplication, wait_for: Callable[..., None], tmp_path: Path):
    shop_log, other_log = tmp_path / "shop.log", tmp_path / "other.log"
    shop_log.write_text("\n".join(SHOP) + "\n", encoding="utf-8")
    other_log.write_text("\n".join(OTHER) + "\n", encoding="utf-8")
    win = MainWindow(Settings())
    win.show()
    for path in (shop_log, other_log):
        win.open_file(str(path))
    shop, other = win.all_tabs()
    wait_for(lambda: all(not t.document.is_indexing for t in (shop, other)) and shop.document.log_format is not None)
    yield win, shop, other
    win.close()
    shutdown_pool()


# ---- 1. dashboard ---------------------------------------------------------------------------------------------------
class _Source:
    def __init__(self, lines: list[str]) -> None:
        self.lines = lines

    def line_count(self) -> int:
        return len(self.lines)

    def get_line(self, index: int) -> str:
        return self.lines[index]


def _fake_tab(title: str, lines: list[str]) -> SimpleNamespace:
    errors = np.array([i for i, line in enumerate(lines) if "ERROR" in line], dtype=np.int64)
    document = SimpleNamespace(
        title=title,
        is_missing=False,
        source=_Source(lines),
        mark_summaries=lambda: [SimpleNamespace(name="Error", count=len(errors))],
        rule_marks=lambda: [errors],
    )
    return SimpleNamespace(document=document, follow=False)


def test_dashboard_keeps_rows_and_selection_and_polls_only_while_visible(
    qapp: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("loglens.ui.dashboard.service_states", lambda names: dict.fromkeys(names, "Running"))
    tabs = [_fake_tab("a.log", ["INFO up", "ERROR down"]), _fake_tab("b.log", ["INFO up"])]
    services = ["Spooler", "W32Time"]

    def set_services(names: list[str]) -> None:
        services[:] = names

    board = DashboardWindow(lambda: list(tabs), lambda _tab: None, lambda: list(services), set_services)
    assert not board.is_polling
    board.show()
    assert board.is_polling and board.logs.topLevelItemCount() == 2
    board.logs.setCurrentItem(board.logs.topLevelItem(0))
    board.services_tree.setCurrentItem(board.services_tree.topLevelItem(1))
    board.refresh()  # what the timer does every 2 s
    current = board.logs.currentItem()
    assert current is not None and current.text(0) == "a.log"
    board._remove_service()  # "Remove" still knows which service is selected after a refresh
    assert services == ["Spooler"] and board.services_tree.topLevelItemCount() == 1
    tabs.pop(0)
    board.refresh()
    assert [board.logs.topLevelItem(i).text(0) for i in range(board.logs.topLevelItemCount())] == ["b.log"]
    board.reject()  # Esc only hides the window: it must stop polling
    assert not board.isVisible() and not board.is_polling
    board.show()
    assert board.is_polling
    board.close()
    assert not board.is_polling


def test_dashboard_masks_secrets_in_latest_problem(qapp: QApplication, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("loglens.ui.dashboard.service_states", lambda names: {})
    tab = _fake_tab("a.log", [f"ERROR login failed for client_secret={TOKEN}"])
    masking = [True]
    board = DashboardWindow(
        lambda: [tab], lambda _tab: None, list, lambda _names: None, mask_secrets=lambda: masking[0]
    )
    board.refresh()
    assert "client_secret=" in board.logs.topLevelItem(0).text(5) and TOKEN not in board.logs.topLevelItem(0).text(5)
    masking[0] = False
    board.refresh()
    assert TOKEN in board.logs.topLevelItem(0).text(5)


# ---- 2. SQL page ----------------------------------------------------------------------------------------------------
def test_sql_query_runs_off_the_ui_thread_and_can_be_cancelled(
    window, qapp: QApplication, wait_for: Callable[..., None]
) -> None:
    win, shop, _other = window
    analysis = AnalysisWindow(shop, win, others=win.all_tabs)
    sql = analysis.pages["sql"]
    sql.run()
    wait_for(lambda: sql.table.rowCount() > 0 and not sql.query_busy)  # records loaded, default query shown
    sql.query.setPlainText("WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM n) SELECT count(*) FROM n")
    sql.run_query()  # never ends by itself: it must not block the UI thread
    assert sql.query_busy and "Running" in sql.status.text() and not sql.run_query_button.isEnabled()
    assert not sql.cancel_query_button.isHidden()
    sql.cancel_query()
    assert not sql.query_busy and sql.run_query_button.isEnabled() and sql.cancel_query_button.isHidden()
    _settle(qapp)
    assert sql.status.text() == "Query cancelled."  # the interrupted query's late result was dropped
    sql.query.setPlainText("SELECT count(*) AS n FROM log")
    sql.run_query()
    wait_for(lambda: not sql.query_busy)
    header = sql.table.horizontalHeaderItem(0)
    assert header is not None and header.text() == "n" and sql.table.item(0, 0).text() == "4"
    analysis.shutdown()


# ---- 3. analysis window ---------------------------------------------------------------------------------------------
def test_analysis_window_brings_its_tab_forward_and_filters_once(window, wait_for: Callable[..., None]) -> None:
    win, shop, other = window
    analysis = AnalysisWindow(shop, win, others=win.all_tabs, show_tab=win.tabs.setCurrentWidget)
    win.tabs.setCurrentWidget(other)
    analysis._jump(3)
    assert win.current_tab() is shop and shop.main_view.current_row() == 3

    win.tabs.setCurrentWidget(other)
    panel = shop.filter_panel
    panel.edit.setText("order (")  # old text, not a valid regex: it must not be searched as one
    specs: list[object] = []
    panel.specChanged.connect(specs.append)
    analysis._filter(r"order \d placed")
    assert win.current_tab() is shop
    assert len(specs) == 1  # one search, with the new pattern as a regex
    query = specs[0].terms[-1].query
    assert query.pattern == r"order \d placed" and query.regex
    wait_for(lambda: len(shop.document.hits) == 2)


def test_analysis_scopes_refresh_when_the_window_is_shown_again(window, wait_for: Callable[..., None]) -> None:
    win, shop, other = window
    analysis = AnalysisWindow(shop, win, others=win.all_tabs)
    analysis.show()
    patterns, compare = analysis.pages["patterns"], analysis.pages["compare"]
    assert patterns.scope.count() == 1 and compare.scope.count() == 2
    analysis.hide()
    shop.filter_panel.set_text("placed")
    shop.filter_panel.apply()
    wait_for(lambda: len(shop.document.hits) == 2)
    win.close_tab(win.tabs.indexOf(other))
    analysis.show()
    assert patterns.scope.count() == 2 and patterns.scope.currentText() == "Current filter (2 lines)"
    assert compare.scope.count() == 1  # the closed log is no longer offered as a baseline
    patterns.scope.setCurrentIndex(0)  # the user's choice survives the next refresh
    analysis.hide()
    analysis.show()
    assert patterns.scope.currentIndex() == 0
    analysis.close()


def test_analysis_page_cancel_and_window_shutdown(window, qapp: QApplication) -> None:
    win, shop, _other = window
    analysis = AnalysisWindow(shop, win, others=win.all_tabs)
    patterns = analysis.pages["patterns"]
    patterns.run()
    assert patterns.busy and not patterns.cancel_button.isHidden() and not patterns.run_button.isEnabled()
    patterns.cancel_button.click()
    assert not patterns.busy and patterns.cancel_button.isHidden() and patterns.run_button.isEnabled()
    assert patterns.status.text() == "Cancelled."
    _settle(qapp)
    assert patterns.tree.topLevelItemCount() == 0  # the cancelled run's result was dropped
    for key in ("patterns", "http", "sql"):
        analysis.pages[key].run()
    assert any(page.busy for page in analysis.pages.values())
    analysis.shutdown()
    assert not any(page.busy for page in analysis.pages.values())


# ---- 4. secret masking ----------------------------------------------------------------------------------------------
def test_columns_model_masks_secrets(qapp: QApplication) -> None:
    fmt = format_by_name("json")
    assert fmt is not None
    record = {
        "time": "2026-11-13T10:00:00Z",
        "level": "Info",
        "message": f"api client_secret={TOKEN}",
        "password": TOKEN,
    }
    model = ColumnsModel(_Source([json.dumps(record), f"continuation token={TOKEN}"]), fmt, [])

    def row_text(row: int) -> str:
        return " ".join(str(model.data(model.index(row, c))) for c in range(model.columnCount()))

    assert TOKEN in row_text(0) and TOKEN in row_text(1)
    changed: list[object] = []
    model.dataChanged.connect(lambda *args: changed.append(args))
    model.mask_secrets = True
    assert changed and TOKEN not in row_text(0) and TOKEN not in row_text(1)
    assert "client_secret=" in row_text(0)  # key names stay readable
    model.mask_secrets = False
    assert TOKEN in row_text(0)


def test_find_in_all_masks_secrets(qapp: QApplication) -> None:
    masking = [True]
    dialog = FindAllDialog(list, lambda _tab, _line: None, mask_secrets=lambda: masking[0])
    hits = LogHits("a.log", 1, 1, [(0, f"connect with client_secret={TOKEN}")])
    dialog._add(hits)
    assert TOKEN not in dialog.results.topLevelItem(0).child(0).text(1)
    masking[0] = False
    dialog._add(hits)
    assert TOKEN in dialog.results.topLevelItem(1).child(0).text(1)


# ---- 5. input validation --------------------------------------------------------------------------------------------
def test_time_range_refuses_from_after_to(qapp: QApplication) -> None:
    last = datetime(2026, 11, 13, 12, 0, tzinfo=UTC).astimezone()
    dialog = TimeRangeDialog((last - timedelta(hours=2), last))
    dialog.start.setDateTime(dialog.end.dateTime().addSecs(60))
    dialog.accept()
    assert dialog.result() != ACCEPTED and not dialog.error.isHidden() and "later" in dialog.error.text()
    dialog.start.setDateTime(dialog.end.dateTime().addSecs(-60))
    assert dialog.error.isHidden()
    dialog.accept()
    assert dialog.result() == ACCEPTED and dialog.time_range() is not None


def test_event_log_dialog_needs_a_level(qapp: QApplication) -> None:
    dialog = EventLogDialog()
    for box in dialog.levels.values():
        box.setChecked(False)
    dialog.accept()
    assert dialog.result() != ACCEPTED and "level" in dialog.error.text()
    dialog.levels[2].setChecked(True)
    dialog.accept()
    assert dialog.result() == ACCEPTED and {q.levels for q in dialog.queries()} == {(2,)}


def test_event_log_channel_listing_shows_a_wait_cursor(qapp: QApplication, monkeypatch: pytest.MonkeyPatch) -> None:
    shapes: list[object] = []

    def fake_list_channels(_server=None) -> list[str]:
        cursor = QApplication.overrideCursor()
        shapes.append(cursor.shape() if cursor is not None else None)
        return ["Application", "Custom/Operational"]

    monkeypatch.setattr("loglens.ui.eventlog_dialog.list_channels", fake_list_channels)
    dialog = EventLogDialog()
    dialog.channel_filter.setText("custom")
    assert shapes == [Qt.CursorShape.WaitCursor] and QApplication.overrideCursor() is None


def test_watch_folder_must_exist(qapp: QApplication, tmp_path: Path) -> None:
    dialog = WatchFolderDialog(str(tmp_path / "missing"))
    dialog._accept()
    assert dialog.result() != ACCEPTED and "not found" in dialog.error.text()
    dialog.folder.setText(str(tmp_path))
    dialog._accept()
    assert dialog.result() == ACCEPTED


def test_knowledge_queue_button_says_restore_for_dismissed_lines(qapp: QApplication, tmp_path: Path) -> None:
    service = KnowledgeService(tmp_path / "knowledge.db")
    service.store.record_unknown("2026-11-13 10:00:00 ERROR Sync - widget pipeline stalled on stage 7")
    signature = service.unknowns()[0].signature
    service.dismiss(signature)
    dialog = KnowledgeDialog(service)
    assert dialog.queue.topLevelItemCount() == 0
    dialog.show_dismissed.setChecked(True)
    dialog.queue.setCurrentItem(dialog.queue.topLevelItem(0))
    assert dialog.dismiss_button.text() == "Restore"
    dialog.dismiss_button.click()
    assert [u.signature for u in service.unknowns()] == [signature]  # restored, as the button said
    dialog.queue.setCurrentItem(dialog.queue.topLevelItem(0))
    assert dialog.dismiss_button.text() == "Dismiss"
    service.close()


def test_pack_that_is_not_utf8_is_reported(qapp: QApplication, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pack = tmp_path / "team.loglens.json"
    pack.write_bytes(b"\xff\xfe{\x00}")
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *_args: (str(pack), ""))
    warnings: list[str] = []
    monkeypatch.setattr(QMessageBox, "warning", lambda _parent, _title, text, *_args: warnings.append(text))
    host = QWidget()
    PacksController(Settings(), host).import_pack()
    assert len(warnings) == 1 and "UTF-8" in warnings[0]


# ---- 6. unhandled exceptions ----------------------------------------------------------------------------------------
def test_unhandled_exception_is_logged_and_shown_once(qapp: QApplication, caplog: pytest.LogCaptureFixture) -> None:
    try:
        raise ValueError("boom")
    except ValueError as exc:
        error = exc
    with caplog.at_level(logging.CRITICAL, logger="loglens.app"):
        box = app_module.handle_exception(ValueError, error, error.__traceback__)
    assert box is not None and box.isVisible() and "boom" in box.text()
    assert any(r.message == "Unhandled exception" and r.exc_info for r in caplog.records)
    assert app_module.handle_exception(KeyError, KeyError("again"), None) is None  # one message box at a time
    box.close()
    second = app_module.handle_exception(KeyError, KeyError("later"), None)
    assert second is not None
    second.close()


def test_exception_hook_survives_a_failing_report(
    qapp: QApplication, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*_args: object) -> None:
        raise RuntimeError("no screen")

    monkeypatch.setattr(app_module, "_show_error", broken)
    with caplog.at_level(logging.ERROR, logger="loglens.app"):
        assert app_module.handle_exception(ValueError, ValueError("boom"), None) is None
    assert any("Could not show" in r.message for r in caplog.records)


def test_thread_exceptions_are_logged(caplog: pytest.LogCaptureFixture) -> None:
    saved = sys.excepthook, threading.excepthook
    try:
        app_module.install_exception_hooks()
        assert sys.excepthook is app_module.handle_exception
        assert threading.excepthook is app_module.handle_thread_exception
    finally:
        sys.excepthook, threading.excepthook = saved
    worker = threading.Thread(name="loglens-test-worker")
    error = RuntimeError("worker broke")
    with caplog.at_level(logging.CRITICAL, logger="loglens.app"):
        app_module.handle_thread_exception(threading.ExceptHookArgs((RuntimeError, error, None, worker)))
    assert any("loglens-test-worker" in r.getMessage() and r.exc_info for r in caplog.records)


# ---- 7. UI-thread blocking and lifetimes ----------------------------------------------------------------------------
def test_ai_settings_lists_models_in_the_background_and_lets_go_of_the_service(
    qapp: QApplication, wait_for: Callable[..., None], monkeypatch: pytest.MonkeyPatch
) -> None:
    release = threading.Event()

    def slow_list_models(_config: AIConfig) -> list[str]:
        release.wait(10)
        return ["llama3.1", "qwen2.5"]

    monkeypatch.setattr("loglens.ui.ai_dialogs.list_models", slow_list_models)
    service = AIService()
    dialog = AISettingsDialog(AIConfig(enabled=True, provider=Provider.LOCAL), service)
    dialog.refresh_local_models()  # returns at once
    assert dialog.test_result.text() == "Listing models…" and not dialog.refresh_models_button.isEnabled()
    release.set()
    wait_for(lambda: dialog.local_model.count() == 2)
    assert "2 models" in dialog.test_result.text() and dialog.refresh_models_button.isEnabled()
    dialog.done(0)
    service.connectionTested.emit(True, "answer for a closed dialog", False)
    assert "closed dialog" not in dialog.test_result.text()  # no longer connected to the long-lived service


def test_report_is_built_under_a_wait_cursor(window, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _win, shop, _other = window
    target = tmp_path / "report.md"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *_args: (str(target), ""))
    shapes: list[object] = []
    build = ReportDialog.build

    def recording_build(self: ReportDialog) -> object:
        cursor = QApplication.overrideCursor()
        shapes.append(cursor.shape() if cursor is not None else None)
        return build(self)

    monkeypatch.setattr(ReportDialog, "build", recording_build)
    dialog = ReportDialog(shop)
    dialog._save()
    assert shapes == [Qt.CursorShape.WaitCursor] and QApplication.overrideCursor() is None and target.is_file()


# ---- 8. theme -------------------------------------------------------------------------------------------------------
def _crash_events(query: EventQuery) -> list[EventRecord]:
    if query.channel != "Application":
        return []
    now = datetime.now(UTC)
    crash = {"AppName": "shop.exe", "ModuleName": "ucrtbase.dll", "ExceptionCode": "0xc0000409"}
    return [
        EventRecord("Application", "Application Error", 1000, 2, now - timedelta(minutes=m), record_id=m, data=crash,
                    message="Faulting application name: shop.exe, faulting module name: ucrtbase.dll")
        for m in (5, 30, 50)
    ]  # fmt: skip


def test_diagnosis_details_follow_a_theme_switch(
    qapp: QApplication, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = datetime.now(UTC)
    result = diagnose(now - timedelta(hours=2), now, reader=_crash_events)
    dialog = DiagnoseDialog(KnowledgeService(tmp_path / "knowledge.db"), lambda _lines, _title: None, lambda _p: None)
    dialog._show(result)
    assert "#123456" not in dialog.details.toHtml()
    monkeypatch.setattr(Inspector, "palette_for_theme", staticmethod(lambda: replace(LIGHT, muted="#123456")))
    QApplication.sendEvent(dialog, QEvent(QEvent.Type.PaletteChange))
    assert "#123456" in dialog.details.toHtml()


# ---- summary and unusual pages --------------------------------------------------------------------------------------
def test_summary_and_unusual_pages_run_and_link_to_lines(window, wait_for: Callable[..., None]) -> None:
    win, shop, _other = window
    analysis = AnalysisWindow(shop, win, others=win.all_tabs, show_tab=win.tabs.setCurrentWidget)
    summary, unusual = analysis.pages["summary"], analysis.pages["unusual"]
    summary.run()
    wait_for(lambda: bool(summary.view.toPlainText()))
    assert "What to look at first" in summary.view.toPlainText() and "lines" in summary.status.text()
    assert summary.markdown().startswith("# ")
    jumped: list[int] = []
    summary.lineRequested.connect(jumped.append)
    from PySide6.QtCore import QUrl

    summary._link(QUrl("line:///2"))
    assert jumped == [2]
    unusual.run()
    wait_for(lambda: not unusual.busy)
    assert unusual.status.text()
    analysis.shutdown()


# ---- charts page ----------------------------------------------------------------------------------------------------
def test_charts_page_draws_counts_and_values(window, wait_for: Callable[..., None], qapp: QApplication) -> None:
    from loglens.core.charts import ChartSpec

    win, shop, _other = window
    analysis = AnalysisWindow(shop, win, others=win.all_tabs)
    page = analysis.pages["charts"]
    page.run()  # counting every line
    wait_for(lambda: page.chart_view.data is not None)
    assert page.chart_view.data.samples == 4
    page.set_spec(ChartSpec(source="regex", pattern="", aggregate="avg"))
    page.run()  # a regex chart without a pattern is explained, not run
    assert "pattern" in page.status.text().lower()
    page.resize(700, 500)
    assert not page.chart_view.grab().isNull()
    analysis.shutdown()


# ---- trace dialog ---------------------------------------------------------------------------------------------------
def test_trace_dialog_follows_an_id_across_open_logs(window, wait_for: Callable[..., None]) -> None:
    from loglens.ui.trace_dialog import TraceDialog, candidate_ids

    win, shop, _other = window
    assert candidate_ids(["x traceId=abc123def456 y"]) == ["abc123def456"]
    jumped: list[tuple[object, int]] = []
    dialog = TraceDialog(win.all_tabs, lambda tab, line: jumped.append((tab, line)), "order", None, win)
    dialog.run()  # "order" appears in two lines of the shop log only
    wait_for(lambda: dialog.trace is not None)
    trace = dialog.trace
    assert trace is not None and len(trace.lanes) == 1 and trace.event_count == 2
    assert dialog.events.topLevelItemCount() == 2 and "2 events" in dialog.status.text()
    dialog.events.itemDoubleClicked.emit(dialog.events.topLevelItem(0), 0)
    assert jumped and jumped[0][0] is shop
    dialog.id_box.setCurrentText("zzz-not-there")
    dialog.trace = None
    dialog.run()
    wait_for(lambda: dialog.trace is not None)
    assert "not found" in dialog.status.text()
    dialog.search.deleteLater()


# ---- compare two runs -------------------------------------------------------------------------------------------------
def test_rundiff_dialog_compares_two_open_logs(window, wait_for: Callable[..., None]) -> None:
    from loglens.ui.rundiff_dialog import RunDiffDialog

    win, shop, other = window
    shown: list[tuple[object, int]] = []
    dialog = RunDiffDialog(win.all_tabs, lambda tab, line: shown.append((tab, line)), win)
    dialog.good.setCurrentIndex(dialog.good.findData(shop))
    dialog.bad.setCurrentIndex(dialog.bad.findData(other))
    dialog.run()
    wait_for(lambda: dialog.diff is not None)
    diff = dialog.diff
    assert diff is not None and not diff.identical
    assert dialog.tree.topLevelItemCount() >= 1 and "only in" in dialog.status.text()
    first = next(
        i
        for i in range(dialog.tree.topLevelItemCount())
        if dialog.tree.topLevelItem(i).data(0, Qt.ItemDataRole.UserRole)
    )
    dialog._jump(dialog.tree.topLevelItem(first), 1)
    assert shown
    dialog.good.setCurrentIndex(dialog.bad.currentIndex())
    dialog.run()
    assert "different" in dialog.status.text()
