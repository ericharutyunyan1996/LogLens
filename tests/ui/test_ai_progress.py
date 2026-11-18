"""'Explain with AI' shows what is happening while it waits, and can be cancelled."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from pathlib import Path

import pytest
from PySide6.QtWidgets import QApplication

from loglens.core.ai.config import AIConfig, Provider
from loglens.core.ai.explain import ExplainRequest, Explanation
from loglens.core.search import shutdown_pool
from loglens.settings import Settings
from loglens.ui.main_window import MainWindow

ANSWER = Explanation("Looks like a timeout.", "warning", False, "", (), (), "", "medium", model="fake (local)")


class SlowProvider:
    compatibility_used = False

    def __init__(self, release: threading.Event) -> None:
        self.release = release

    def explain(self, request: ExplainRequest, progress=None, cancel=None) -> Explanation:
        if progress is not None:
            progress("Receiving the answer from fake… 12 words")
        self.release.wait(10)
        return ANSWER

    def test_connection(self) -> str:
        return "fake"


@pytest.fixture
def window(qapp: QApplication, wait_for: Callable[..., None], tmp_path: Path):
    log = tmp_path / "app.log"
    log.write_text("2026-11-13 10:00:00,000 ERROR Svc - request timed out\n", encoding="utf-8")
    settings = Settings()
    settings.set_ai_config(AIConfig(enabled=True, provider=Provider.LOCAL, local_model="fake",
                                    preview_before_send=False))  # fmt: skip
    win = MainWindow(settings)
    win.show()
    win.open_file(str(log))
    tab = win.current_tab()
    wait_for(lambda: not tab.document.is_indexing)
    tab.main_view.go_to_row(0)
    yield win, tab
    win.close()
    shutdown_pool()


def test_progress_is_visible_then_answer(window, wait_for: Callable[..., None]) -> None:
    win, tab = window
    release = threading.Event()
    win.ai.service._factory = lambda _config, _key: SlowProvider(release)
    win.act_inspector.trigger()  # hide the Inspector: asking the AI must bring it back
    assert not tab.inspector.isVisible()
    win.ai.explain(tab)
    inspector = tab.inspector
    wait_for(lambda: "Receiving the answer" in inspector.ai_status.text())
    assert inspector.isVisible() and not inspector.ai_progress.isHidden() and not inspector.cancel_ai_btn.isHidden()
    assert not inspector.explain_btn.isEnabled() and "AI:" in win.statusBar().currentMessage()
    time.sleep(1.1)
    wait_for(lambda: " s" in inspector.ai_status.text())  # elapsed seconds tick
    release.set()
    wait_for(lambda: "Looks like a timeout" in inspector.ai_result.toPlainText())
    assert inspector.ai_progress.isHidden() and inspector.explain_btn.isEnabled()
    assert "answer received" in win.statusBar().currentMessage()


def test_cancel(window, wait_for: Callable[..., None]) -> None:
    win, tab = window
    release = threading.Event()
    win.ai.service._factory = lambda _config, _key: SlowProvider(release)
    win.ai.explain(tab)
    wait_for(lambda: "Receiving" in tab.inspector.ai_status.text())
    tab.inspector.cancel_ai_btn.click()
    assert "Cancelled" in tab.inspector.ai_status.text() and tab.inspector.cancel_ai_btn.isHidden()
    release.set()
    time.sleep(0.2)
    QApplication.processEvents()
    assert "Looks like" not in tab.inspector.ai_result.toPlainText()  # the late answer is dropped


def test_settings_show_local_fields(window) -> None:
    from loglens.ui.ai_dialogs import AISettingsDialog

    win, _tab = window
    dialog = AISettingsDialog(win.ai.config(), win.ai.service, win)
    dialog.show()
    assert dialog.local_url.isVisible() and not dialog.model.isVisible() and not dialog.compatibility.isVisible()
    assert dialog.config().provider is Provider.LOCAL and dialog.config().local_model == "fake"
    dialog.provider.setCurrentIndex(dialog.provider.findData(Provider.API_KEY.value))
    assert dialog.model.isVisible() and not dialog.local_url.isVisible()
    dialog.close()
