"""Headless end-to-end test of the real main window (Qt offscreen platform)."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from PySide6.QtWidgets import QApplication

from loglens.core.filters import FilterMode
from loglens.core.search import SearchQuery, shutdown_pool
from loglens.settings import Settings
from loglens.ui.main_window import MainWindow

SCREEN_DIR = Path(__file__).resolve().parents[2] / "samples" / "generated" / "screens"


def test_open_search_navigate_wrap_details_follow(
    qapp: QApplication, wait_for: Callable[..., None], tmp_path: Path
) -> None:
    log = tmp_path / "app.log"
    lines = []
    for i in range(5000):
        level = "ERROR" if i % 250 == 0 else ("WARN " if i % 97 == 0 else "INFO ")
        lines.append(
            f"2026-11-13 10:{i // 60 % 60:02d}:{i % 60:02d}.000 [{i % 9:>4}] {level} Svc - message {i} "
            f"id=6f1c2e7a-0d3b-4c1e-9a55-{i:012d} code=0xc0000005"
        )
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    win = MainWindow(Settings())
    win.resize(700, 800)  # narrow, so long lines wrap in the wrap-mode check
    win.show()
    win.open_file(str(log))
    tab = win.current_tab()
    assert tab is not None
    wait_for(lambda: not tab.document.is_indexing)
    assert tab.document.source.line_count() == 5000
    wait_for(
        lambda: len(tab.document.mark_summaries()) > 1 and tab.document.mark_summaries()[1].count > 0
    )  # Error rule marks computed
    assert {s.name: s.count for s in tab.document.mark_summaries()}["Error"] == 20

    tab.run_search(SearchQuery("error"))
    wait_for(lambda: len(tab.document.hits) == 20)
    tab.next_match()
    assert tab.main_view.current_row() == 0
    tab.next_match()
    assert tab.main_view.current_row() == 250
    tab.toggle_bookmark()
    assert 250 in tab.document.bookmarks

    SCREEN_DIR.mkdir(parents=True, exist_ok=True)
    win.grab().save(str(SCREEN_DIR / "main_search.png"))

    # next/previous issue navigation over the scrollbar-mark rules
    tab.main_view.go_to_row(0)
    assert tab.next_marked(None, True)
    assert tab.main_view.current_row() == 97  # first WARN (errors are at 0, 250, ...)
    assert tab.next_marked(None, False)
    assert tab.main_view.current_row() == 0
    assert tab.next_marked(1, True)  # rule index 1 = Error only
    assert tab.main_view.current_row() == 250

    # word wrap: a very long line occupies several visual rows, clicks map back to the right line
    tab.set_wrap(True)
    tab.main_view.go_to_row(0)
    tab.main_view.viewport().repaint()
    painted = tab.main_view.painted_rows()
    rows = [r for _, r, _ in painted]
    assert rows == sorted(rows) and len(set(rows)) < len(rows)  # line 0 wraps (it is longer than the view)
    y_second_segment = painted[1][0]
    assert tab.main_view.row_at(y_second_segment + 1) == painted[1][1]
    tab.set_wrap(False)

    # the inspector shows the selected line: header (line, timestamp, level), decoded fields, raw text
    tab.set_inspector_visible(True)
    tab.main_view.go_to_row(250)
    details = tab.inspector.details.toPlainText()
    assert "Line 251" in details and "2026-11-13 10:04:10.000" in details and "Error" in details
    assert "id = 6f1c2e7a" in details or "code" in details  # key=value fields decoded
    assert "message 250" in tab.inspector.raw.toPlainText()
    assert not tab.inspector.explain_btn.isEnabled()  # AI is off by default

    # filter panel: level chip + pinned exclude + context lines
    panel = tab.filter_panel
    panel.clear()
    assert panel.level_names() == ["Fatal", "Error", "Warning", "HTTP 5xx (W3C)", "Debug"]
    panel.select_levels({"Error"})
    wait_for(lambda: len(tab.document.hits) == 20)
    panel.edit.setText("message 250 ")  # trailing space: must not also exclude "message 2500"
    panel.pin_current(FilterMode.NONE)
    wait_for(lambda: len(tab.document.hits) == 19)
    assert 250 not in tab.document.hits.tolist()
    panel.context.setValue(1)
    assert tab.filtered_view.model().row_count() == 19 * 3 - 1  # line 0 has no line before it
    panel.clear()
    assert tab.results_stack.currentWidget() is tab.empty_hint
    tab.run_search(SearchQuery("error"))
    wait_for(lambda: len(tab.document.hits) == 20)

    # follow mode picks up appended lines (tail) and scrolls to the end, keeping the user's selected line
    selected = tab.main_view.current_row()
    tab.set_follow(True)
    with log.open("a", encoding="utf-8") as f:
        f.write("2026-11-13 11:00:00.000 [   1] ERROR Svc - appended failure\n")
    tab.document.check_file()
    wait_for(lambda: tab.document.source.line_count() == 5001 and len(tab.document.hits) == 21)
    bar = tab.main_view.verticalScrollBar()
    assert bar.value() == bar.maximum()
    assert tab.main_view.current_row() == selected  # bookmarks / copy / AI still act on the line the user chose

    win.close()
    shutdown_pool()
