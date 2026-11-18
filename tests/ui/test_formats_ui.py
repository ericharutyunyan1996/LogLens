"""Format detection in the tab, columns view, custom formats, and the Fields / SQL analysis pages."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from loglens.core.search import shutdown_pool
from loglens.settings import Settings
from loglens.ui.format_dialog import FormatDialog
from loglens.ui.main_window import MainWindow

LINES = [
    "2026-11-13 10:00:00,000 [1] INFO  Shop.Orders - order 1 placed",
    "2026-11-13 10:00:01,000 [2] ERROR Shop.Payments - card declined",
    "System.InvalidOperationException: declined",
    "2026-11-13 10:00:02,000 [1] INFO  Shop.Orders - order 2 placed",
    "2026-11-13 10:00:03,000 [3] WARN  Shop.Stock - low stock",
]
PIPES = ["10:00:00|Info|orders|placed", "10:00:01|Error|payments|declined", "10:00:02|Info|orders|placed again"]


@pytest.fixture
def window(qapp: QApplication, wait_for: Callable[..., None], tmp_path: Path):
    log = tmp_path / "shop.log"
    log.write_text("\n".join(LINES) + "\n", encoding="utf-8")
    win = MainWindow(Settings())
    win.show()
    win.open_file(str(log))
    tab = win.current_tab()
    wait_for(lambda: tab.document.log_format is not None)
    yield win, tab
    win.close()
    shutdown_pool()


def test_detected_format_and_columns(window, wait_for: Callable[..., None]) -> None:
    win, tab = window
    assert "▾" in tab.format_chip.text()
    win.act_columns.trigger()
    assert tab.columns_visible and win.act_columns.isChecked()
    model = tab.columns.model()
    headers = [model.headerData(c, Qt.Orientation.Horizontal) for c in range(model.columnCount())]
    assert len(headers) >= 3 and model.rowCount() == len(LINES)
    assert "card declined" in " ".join(str(model.data(model.index(1, c))) for c in range(model.columnCount()))
    tab.columns.select_row(4)
    tab.columns.currentRowChanged.emit(4)
    assert tab.main_view.current_row() == 4  # the Inspector follows the table
    win.act_columns.trigger()
    assert not tab.columns_visible


def test_custom_format(window, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, wait_for: Callable[..., None]) -> None:
    win, _tab = window
    log = tmp_path / "pipes.log"
    log.write_text("\n".join(PIPES) + "\n", encoding="utf-8")
    win.open_file(str(log))
    tab = win.current_tab()
    wait_for(lambda: tab.document.log_format is not None)

    def fake_exec(dialog: FormatDialog) -> int:
        dialog.name.setText("Pipes")
        dialog.kind.setCurrentIndex(1)  # regex
        dialog.pattern.setPlainText(r"^(?P<time>[\d:]+)\|(?P<level>\w+)\|(?P<area>\w+)\|(?P<message>.*)$")
        assert "3 of 3 records parsed" in dialog.status.text()
        return 1

    monkeypatch.setattr(FormatDialog, "exec", fake_exec)
    win.new_custom_format(tab)
    assert tab.document.log_format is not None and tab.document.log_format.display_name == "Pipes"
    assert [f.name for f in win.settings.custom_formats()] == ["Pipes"]
    model = tab.columns.model()
    assert [model.headerData(c, Qt.Orientation.Horizontal) for c in range(model.columnCount())] == [
        "time",
        "level",
        "area",
        "message",
    ]
    win.delete_custom_format("Pipes")
    assert win.settings.custom_formats() == []


def test_fields_and_sql_pages(window, wait_for: Callable[..., None]) -> None:
    win, tab = window
    win.analyze("fields")
    analysis = win._analysis[id(tab)]
    fields = analysis.pages["fields"]
    fields.run()
    wait_for(lambda: fields.fields.count() > 0)
    assert "4 records" in fields.status.text()
    sql = analysis.pages["sql"]
    sql.run()
    wait_for(lambda: sql.table.rowCount() > 0)
    levels = {sql.table.item(r, 0).text(): sql.table.item(r, 1).text() for r in range(sql.table.rowCount())}
    assert levels == {"Info": "2", "Error": "1", "Warning": "1"}
    sql.query.setPlainText("SELECT _line, _message FROM log WHERE _level = 'Error'")
    sql.run_query()  # runs on a worker thread
    wait_for(lambda: not sql.query_busy)
    sql._jump_row(sql.table.item(0, 1))
    assert tab.main_view.current_row() == 1
