"""Regressions from the UI review: highlighter round trip, Ctrl+C in the Inspector, one AI request across tabs,
Inspector stable while a log grows, no Ctrl+Alt+letter shortcuts."""

from __future__ import annotations

import threading
from collections.abc import Callable
from pathlib import Path

import pytest
from PySide6.QtGui import QGuiApplication, QKeySequence, QTextCursor
from PySide6.QtWidgets import QApplication

from loglens.core.ai.config import AIConfig, Provider
from loglens.core.ai.explain import Explanation
from loglens.core.highlight import default_rules
from loglens.core.search import shutdown_pool
from loglens.settings import Settings
from loglens.ui.highlighter_dialog import HighlighterDialog
from loglens.ui.main_window import MainWindow

LINES = [
    "2026-11-13 10:00:00,000 [1] INFO  Svc - started",
    "2026-11-13 10:00:01,000 [1] ERROR Svc - widget pipeline stalled on stage 7",
    "System.InvalidOperationException: stalled",
    "   at Svc.Run()",
]


@pytest.fixture
def window(qapp: QApplication, wait_for: Callable[..., None], tmp_path: Path):
    settings = Settings()
    settings.set_ai_config(AIConfig(enabled=True, provider=Provider.LOCAL, local_model="fake",
                                    preview_before_send=False))  # fmt: skip
    win = MainWindow(settings)
    win.show()
    for name in ("a.log", "b.log"):
        path = tmp_path / name
        path.write_text("\n".join(LINES) + "\n", encoding="utf-8")
        win.open_file(str(path))
    wait_for(lambda: all(not t.document.is_indexing for t in win.all_tabs()))
    yield win
    win.close()
    shutdown_pool()


def test_highlighter_dialog_keeps_level_chips(qapp: QApplication) -> None:
    rules = default_rules()
    before = [r.name for r in rules if r.level_filter]
    dialog = HighlighterDialog(rules)
    assert [r.name for r in dialog.rules() if r.level_filter] == before and before  # OK without edits changes nothing


def test_ctrl_c_copies_the_inspector_selection(window, wait_for: Callable[..., None]) -> None:
    tab = window.current_tab()
    tab.main_view.go_to_row(1)
    raw = tab.inspector.raw
    tab.inspector.tabs.setCurrentWidget(raw)
    raw.setFocus()
    wait_for(lambda: QApplication.focusWidget() is raw)
    cursor = raw.textCursor()
    cursor.movePosition(QTextCursor.MoveOperation.Start)
    cursor.movePosition(QTextCursor.MoveOperation.Right, QTextCursor.MoveMode.KeepAnchor, 10)
    raw.setTextCursor(cursor)
    window.act_copy.trigger()
    assert QGuiApplication.clipboard().text() == "2026-11-13"
    assert window.act_copy.shortcut() == QKeySequence(QKeySequence.StandardKey.Copy)


class _Slow:
    compatibility_used = False

    def __init__(self, release: threading.Event) -> None:
        self.release = release

    def explain(self, request, progress=None, cancel=None):
        self.release.wait(5)
        return Explanation("ok", "info", False, "", (), (), "", "low")

    def test_connection(self) -> str:
        return "fake"


def test_second_ai_request_releases_the_first_tab(window, wait_for: Callable[..., None]) -> None:
    release = threading.Event()
    window.ai.service._factory = lambda _c, _k: _Slow(release)
    first, second = window.all_tabs()
    for tab in (first, second):
        tab.main_view.go_to_row(1)
    window.ai.explain(first)
    assert not first.inspector.explain_btn.isEnabled()
    window.ai.explain(second)
    assert first.inspector.explain_btn.isEnabled() and "newer request" in first.inspector.ai_status.text()
    release.set()
    wait_for(lambda: "ok" in second.inspector.ai_result.toPlainText())
    window.close_tab(window.tabs.indexOf(second))  # closing a tab mid-request must not leave the status busy
    assert not window.statusBar().currentMessage().startswith("AI: Preparing")


def test_inspector_survives_tail_growth(window, wait_for: Callable[..., None], tmp_path: Path) -> None:
    tab = window.current_tab()
    tab.main_view.go_to_row(2)  # inside the multi-line record
    wait_for(lambda: tab.document.records.multi_line)
    tab.main_view.go_to_row(2)
    queued = sum(u.count for u in window.knowledge.unknowns())
    browser = tab.inspector.details
    cursor = browser.textCursor()
    cursor.select(QTextCursor.SelectionType.Document)
    browser.setTextCursor(cursor)
    for i in range(3):  # the log grows: records/marks refresh, the Inspector must not re-render
        with (tmp_path / "b.log").open("a", encoding="utf-8") as f:
            f.write(f"2026-11-13 10:00:0{2 + i},000 [1] INFO  Svc - more\n")
        count = tab.document.source.line_count()
        tab.document.check_file()
        wait_for(lambda c=count: tab.document.source.line_count() == c + 1)
    assert browser.textCursor().hasSelection()
    assert sum(u.count for u in window.knowledge.unknowns()) == queued


def test_no_ctrl_alt_letter_shortcuts(window) -> None:
    from PySide6.QtGui import QAction

    shortcuts = [a.shortcut().toString() for a in window.findChildren(QAction) if not a.shortcut().isEmpty()]
    assert not [s for s in shortcuts if s.startswith("Ctrl+Alt+") and len(s) == len("Ctrl+Alt+X")]


def test_view_masks_a_private_key_logged_line_by_line(tmp_path: Path) -> None:
    import base64
    import random

    from loglens.core.text_source import TextLogSource
    from loglens.ui.models import SourceLines

    rng = random.Random(7)
    body = [base64.b64encode(bytes(rng.randrange(256) for _ in range(48))).decode() for _ in range(5)]
    lines = ["2026-11-13 10:00:00 INFO dumping config", "-----BEGIN RSA PRIVATE KEY-----", *body,
             "-----END RSA PRIVATE KEY-----", "2026-11-13 10:00:01 INFO done"]  # fmt: skip
    path = tmp_path / "key.log"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    source = TextLogSource(path)
    source.build_index()
    model = SourceLines(source, mask_secrets=True)
    window = model.texts(4, 3)  # starts in the middle of the key: the lines above establish the state
    assert not any(chunk in " ".join(window) for chunk in body[2:5])
    assert body[0] not in model.full_text(2)
    assert model.texts(8, 1) == ["2026-11-13 10:00:01 INFO done"]


def test_highlighter_dialog_refuses_a_pattern_that_could_freeze(
    qapp: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    from PySide6.QtWidgets import QMessageBox

    from loglens.core.highlight import HighlightRule
    from loglens.ui.highlighter_dialog import HighlighterDialog

    warnings: list[str] = []
    monkeypatch.setattr(QMessageBox, "warning", lambda *args: warnings.append(args[2]))
    dialog = HighlighterDialog([HighlightRule("ok", "ERROR"), HighlightRule("slow", "(a+)+$")])
    dialog.accept()
    assert dialog.result() == 0 and warnings and "slow" in warnings[0]
    dialog.table.removeRow(1)
    dialog.accept()
    assert dialog.result() == 1
