"""Render LogLens screens with the native Windows platform, off-screen (never shown), for visual review.

python tools/screenshots.py  ->  samples/generated/screens/*.png
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "samples" / "generated" / "screens"
SAMPLES = ROOT / "samples" / "generated"

os.environ["APPDATA"] = tempfile.mkdtemp()  # never touch the real settings

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from loglens.core.ai.config import AIConfig
from loglens.core.ai.explain import Cause, Explanation
from loglens.core.filters import FilterMode
from loglens.core.search import SearchQuery, shutdown_pool
from loglens.core.winevent.reader import EventQuery
from loglens.services.eventlog_jobs import EventLogExporter
from loglens.settings import Settings
from loglens.ui.ai_dialogs import AISettingsDialog
from loglens.ui.log_tab import LogTab
from loglens.ui.main_window import MainWindow
from loglens.ui.theme import apply_theme

# Hand-written answer used only to review the AI tab layout — not model output.
SAMPLE_ANSWER = Explanation(
    summary="Report generation took 19 s, almost four times the 5 s threshold.",
    severity="warning",
    is_likely_noise=False,
    what_happened="ReportWorker finished report 4365 in 19,176 ms while other requests stayed fast.",
    probable_causes=(
        Cause("A large report or a slow database query inside the report job", "high", (56,)),
        Cause("Contention with concurrent order processing", "low", (54, 55, 57)),
    ),
    next_steps=("Check the report's row count and query plan", "Compare with earlier runs of report 4365"),
    missing_information="Database timings for the report query.",
    confidence="medium",
    model="sample (layout preview)",
)


def pump(app: QApplication, condition: Callable[[], object] = lambda: True, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        app.processEvents()
        if condition():
            break
        time.sleep(0.01)
    for _ in range(5):
        app.processEvents()


def open_tab(app: QApplication, win: MainWindow, name: str) -> LogTab:
    win.open_file(str(SAMPLES / name) if not Path(name).is_absolute() else name)
    tab = win.current_tab()
    assert tab is not None
    pump(app, lambda: not tab.document.is_indexing and any(s.count for s in tab.document.mark_summaries()))
    return tab


def shoot_main(app: QApplication, win: MainWindow, theme: str) -> None:
    tab = open_tab(app, win, "app_small.log")
    tab.run_search(SearchQuery("payment"))
    pump(app, lambda: len(tab.document.hits) > 0)
    tab.next_marked(None, True)
    tab.next_marked(None, True)
    pump(app)
    win.refresh_status()
    win.grab().save(str(OUT / f"main_{theme}.png"))
    tab.inspector.show_ai_result(SAMPLE_ANSWER)
    pump(app)
    win.grab().save(str(OUT / f"ai_tab_{theme}.png"))


def shoot_filters(app: QApplication, win: MainWindow, theme: str) -> None:
    tab = open_tab(app, win, "app.json")
    panel = tab.filter_panel
    panel.select_levels({"Warning"})
    panel.edit.setText("CacheManager")
    panel.pin_current(FilterMode.NONE)
    panel.context.setValue(1)
    pump(app, lambda: len(tab.document.hits) > 0)
    tab.next_marked(None, True)
    tab.next_marked(None, True)
    pump(app)
    win.grab().save(str(OUT / f"json_filters_inspector_{theme}.png"))


def shoot_event_logs(app: QApplication, win: MainWindow, theme: str) -> None:
    """Real Application + System events of this machine (last 24 h, errors/warnings), explained."""
    exporter = EventLogExporter()
    result: list[str] = []
    exporter.finished.connect(lambda path, _warnings: result.append(path))
    exporter.failed.connect(lambda message: result.append(""))
    since = datetime.now().astimezone() - timedelta(days=1)
    target = OUT / f"events_{theme}.log"
    exporter.export([EventQuery(c, since=since, levels=(1, 2, 3), max_events=2000) for c in ("Application", "System")],
                    target)  # fmt: skip
    pump(app, lambda: bool(result), timeout=60)
    if not result or not result[0]:
        return
    tab = open_tab(app, win, str(target))
    tab.next_marked(None, True)
    tab.find_related_events(5)
    pump(app, lambda: tab.inspector.related.topLevelItemCount() > 0, timeout=20)
    win.grab().save(str(OUT / f"events_windows_tab_{theme}.png"))
    tab.inspector.tabs.setCurrentIndex(0)
    pump(app)
    win.grab().save(str(OUT / f"events_details_{theme}.png"))


def shoot_ai_settings(app: QApplication, win: MainWindow, theme: str) -> None:
    dialog = AISettingsDialog(AIConfig(enabled=True), win.ai.service, win)
    dialog.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen, True)
    dialog.show()
    pump(app)
    dialog.grab().save(str(OUT / f"ai_settings_{theme}.png"))
    dialog.close()


def main() -> None:
    app = QApplication([])
    OUT.mkdir(parents=True, exist_ok=True)
    recent = [str(SAMPLES / n) for n in ("app_small.log", "u_ex261113.log", "app.json")]
    for theme in ("light", "dark"):
        apply_theme(app, theme)
        pump(app)
        win = MainWindow(Settings(theme=theme, recent_files=recent))
        win.refresh_theme()
        win.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen, True)  # real platform, never visible
        win.resize(1400, 860)
        win.show()
        pump(app)
        win.grab().save(str(OUT / f"welcome_{theme}.png"))
        shoot_main(app, win, theme)
        shoot_filters(app, win, theme)
        shoot_event_logs(app, win, theme)
        shoot_ai_settings(app, win, theme)
        win.close()
        pump(app)
    shutdown_pool()
    print("screens written to", OUT)


if __name__ == "__main__":
    main()
