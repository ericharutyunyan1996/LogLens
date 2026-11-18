"""Drive the REAL LogLens window through every feature, with captions, and report pass/fail per step.

    .venv\\Scripts\\python.exe tools\\demo.py [--record out.mp4] [--fast] [--no-ai]

The window is shown on screen (not off-screen); steps use the same actions/menus/dialogs the user does. Settings live in a
temporary APPDATA (the AI section points at a local Ollama), so your own settings and knowledge base are untouched.
With --record, ffmpeg (gdigrab) captures the window's screen area for the whole run. A JSON report is written next to it.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
SAMPLES = ROOT / "samples" / "generated"
_REAL_APPDATA = os.environ.get("APPDATA", "")
# Temp files live under a neutral folder, so no Windows user name ever appears on screen (paths in tab headers).
DEMO_TMP = Path(os.environ.get("LOGLENS_DEMO_TMP", r"C:\LogLensDemo"))
DEMO_TMP.mkdir(parents=True, exist_ok=True)
tempfile.tempdir = str(DEMO_TMP)
os.environ["APPDATA"] = tempfile.mkdtemp(prefix="loglens-demo-")
os.environ["LOCALAPPDATA"] = os.environ["APPDATA"]

from PySide6.QtCore import QPoint, Qt, QTimer
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QDialog, QInputDialog, QFileDialog, QLabel, QPushButton, QWidget

from loglens.core.ai.config import AIConfig, Provider
from loglens.core.filters import FilterMode
from loglens.core.highlight import HighlightRule
from loglens.core.search import SearchQuery, shutdown_pool
from loglens.settings import Settings
from loglens.ui.main_window import MainWindow
from loglens.ui.theme import apply_theme
from loglens.ui.time_dialogs import _to_qt
from tools.demo_narration import INTRO, NARRATION, OUTRO

OLLAMA_MODEL = os.environ.get("LOGLENS_DEMO_MODEL", "qwen2.5:7b")

VOICE_DIR = TTS_HOME = Path(os.environ.get("LOGLENS_TTS_HOME", Path.home() / ".loglens-demo"))


def make_voice(texts: dict[str, str]) -> dict[str, float]:
    """Synthesize every narration line with Piper (offline neural TTS); returns {key: seconds}."""
    import wave

    out = Path(tempfile.mkdtemp(prefix="loglens-voice-"))
    keys = {f"c{i:03d}": key for i, key in enumerate(texts)}
    (out / "texts.json").write_text(json.dumps({n: texts[k] for n, k in keys.items()}), encoding="utf-8")
    python = TTS_HOME / "tts-venv" / "Scripts" / "python.exe"
    subprocess.run([str(python), str(ROOT / "tools" / "_tts.py"), str(TTS_HOME / "voices" / "en_US-ryan-high.onnx"),
                    str(out / "texts.json"), str(out)], check=True)  # fmt: skip
    clips = {}
    for name, key in keys.items():
        with wave.open(str(out / f"{name}.wav")) as w:
            clips[key] = w.getnframes() / w.getframerate()
    VOICE_FILES.update({key: out / f"{name}.wav" for name, key in keys.items()})
    return clips


VOICE_FILES: dict[str, Path] = {}


def mix_voice(video: Path, cues: list[tuple[str, float]], clips: dict[str, float]) -> None:
    """Lay each narration clip over the recording at the moment it was cued, then mux into the same mp4."""
    inputs, filters, labels = [], [], []
    for i, (key, at) in enumerate(cues):
        inputs += ["-i", str(VOICE_FILES[key])]
        ms = int(at * 1000)
        filters.append(f"[{i + 1}:a]adelay={ms}|{ms}[a{i}]")
        labels.append(f"[a{i}]")
    graph = ";".join(filters) + f";{''.join(labels)}amix=inputs={len(labels)}:normalize=0,volume=1.6[voice]"
    target = video.with_name(video.stem + "-voice" + video.suffix)
    subprocess.run(["ffmpeg", "-y", "-i", str(video), *inputs, "-filter_complex", graph, "-map", "0:v", "-map", "[voice]",
                    "-c:v", "copy", "-c:a", "aac", "-b:a", "160k", "-shortest", str(target)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # fmt: skip
    print("narrated video:", target)


# step title -> (what to capture, file name): "main" = the main window, otherwise a window class name
SHOTS: dict[str, tuple[str, str]] = {
    "Welcome page with recent files": ("main", "welcome"),
    "Switch theme: dark": ("main", "welcome-dark"),
    "Open a log: format detected, levels and timeline strip": ("main", "open-log"),
    "Search for 'payment' (live highlight of matches)": ("main", "search"),
    "Filter by level: warnings and errors only": ("main", "filter-levels"),
    "Pin filters as chips: must match / must not match": ("main", "filter-chips"),
    "Columns view: parsed fields as a table": ("main", "columns-view"),
    "Open a JSON-lines log: Inspector decodes the payload": ("main", "json-inspector"),
    "Analyze: message patterns": ("AnalysisWindow", "analyze-patterns"),
    "Analyze: field value counts": ("AnalysisWindow", "analyze-fields"),
    "Analyze: SQL over parsed records": ("AnalysisWindow", "analyze-sql"),
    "Analyze: request / response pairs": ("AnalysisWindow", "analyze-transactions"),
    "Analyze: HTTP request statistics (IIS log)": ("AnalysisWindow", "analyze-http"),
    "Merge open logs into one timeline": ("main", "merged-timeline"),
    "Windows events around the selected line": ("main", "windows-events"),
    "AI: answer shown in the Inspector": ("main", "ai-answer"),
}


class Demo:
    def __init__(self, app: QApplication, win: MainWindow, fast: bool) -> None:
        self.app, self.win, self.fast = app, win, fast
        self.results: list[dict] = []
        self.clips: dict[str, float] = {}  # narration key -> seconds of speech
        self.cues: list[tuple[str, float]] = []  # (key, seconds since the recording started)
        self.t0 = time.monotonic()
        self.dwell = 0.0  # extra seconds on every screen
        self.shots: Path | None = None  # folder for README screenshots (--shots)
        self.gap = 0.0  # pause after the narration of each step
        self.errors: list[str] = []
        sys.excepthook = lambda et, ev, tb: (self.errors.append("".join(traceback.format_exception(et, ev, tb))),
                                             traceback.print_exception(et, ev, tb))  # fmt: skip
        self.caption = QLabel(win)
        self.caption.setStyleSheet(
            "background: rgba(20,24,33,225); color: white; font: 600 15pt 'Segoe UI'; padding: 10px 18px;"
            "border-radius: 10px;"
        )
        self.caption.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)

    # ---- plumbing ------------------------------------------------------------------------------------------------
    def pump(self, seconds: float = 0.0, until: Callable[[], object] | None = None, timeout: float = 20.0) -> bool:
        end = time.monotonic() + (timeout if until else seconds * (0.25 if self.fast else 1))
        while time.monotonic() < end:
            self.app.processEvents()
            if until and until():
                self.pump(0.15)
                return True
            time.sleep(0.01)
        return until is None

    def type_into(self, edit: QWidget, text: str, enter: bool = True) -> None:
        """Type like a person (one key at a time, visible on screen) and press Enter."""
        edit.setFocus()
        edit.clear()
        for ch in text:
            QTest.keyClick(edit, ch)
            self.pump(0.07)
        if enter:
            self.pump(0.3)
            QTest.keyClick(edit, Qt.Key.Key_Return)

    def shot(self, name: str, widget: QWidget | None = None) -> None:
        """Save a PNG of the window (or another widget) for the README; only with --shots."""
        if self.shots is None:
            return
        self.caption.hide()  # captions belong in the video, not in README screenshots
        self.pump(0.4)
        (widget or self.win).grab().save(str(self.shots / f"{name}.png"))
        self.caption.show()

    def say(self, text: str) -> None:
        self.caption.setText(text)
        self.caption.adjustSize()
        w = self.win.width()
        self.caption.move(max((w - self.caption.width()) // 2, 8), self.win.height() - self.caption.height() - 46)
        self.caption.raise_()
        self.caption.show()
        self.pump(0.5)

    def speak(self, key: str) -> float:
        """Cue the narration of ``key`` now (mixed into the video afterwards); returns how long it lasts."""
        if key in self.clips:
            self.cues.append((key, time.monotonic() - self.t0))
        return self.clips.get(key, 0.0)

    def step(self, title: str, fn: Callable[[], object], hold: float = 1.5) -> None:
        started = time.monotonic()
        speech = self.speak(title)
        self.say(title)
        before = len(self.errors)
        try:
            fn()
            self.pump(hold + self.dwell)  # time to look at the result
            self.pump(max(speech + 0.4 - (time.monotonic() - started), 0.0))  # let the voice finish
            self.pump(self.gap)  # a breath between features
            if self.shots is not None and title in SHOTS:
                kind, name = SHOTS[title]
                target = next((w for w in self.app.topLevelWidgets() if type(w).__name__ == kind and w.isVisible()), None) if kind != "main" else None
                self.shot(name, target)
            if len(self.errors) > before:
                raise RuntimeError("unhandled exception in the app: " + self.errors[-1].strip().splitlines()[-1])
            left = self.app.activeModalWidget()
            if left is not None:
                name = type(left).__name__
                self.close_modals()
                raise RuntimeError(f"a dialog was left open: {name}")
            self.results.append({"step": title, "ok": True, "seconds": round(time.monotonic() - started, 1)})
            print(f"  ok   {title}", flush=True)
        except Exception as exc:  # noqa: BLE001 - a demo step must never stop the run
            self.results.append({"step": title, "ok": False, "error": repr(exc), "trace": traceback.format_exc()})
            print(f"  FAIL {title}: {exc!r}", flush=True)
            self.close_modals()

    def close_modals(self) -> None:
        for _ in range(5):
            w = self.app.activeModalWidget()
            if w is None:
                break
            w.reject()
            self.pump(0.1)

    def modal(self, trigger: Callable[[], object], handler: Callable[[QWidget], object] | None = None,
              hold: float = 1.5, wait: Callable[[QWidget], object] | None = None, accept: bool = False) -> None:  # fmt: skip
        """Run ``trigger`` (opens a modal dialog and blocks), let ``handler`` act on it, then accept it."""
        problems: list[str] = []

        def act() -> None:
            w = self.app.activeModalWidget()
            if w is None:
                QTimer.singleShot(150, act)
                return
            try:
                self.pump(hold)
                if handler:
                    handler(w)
                if wait:
                    wait(w)
                self.pump(hold)
            except Exception as exc:  # noqa: BLE001
                problems.append(repr(exc))
            finally:
                (w.accept if accept and isinstance(w, QDialog) else w.reject if isinstance(w, QDialog) else w.close)()

        QTimer.singleShot(300, act)
        trigger()
        if problems:
            raise RuntimeError(problems[0])

    def tab(self):
        tab = self.win.current_tab()
        assert tab is not None, "no tab open"
        return tab

    def open(self, name: str):
        path = Path(name) if Path(name).is_absolute() else SAMPLES / name
        self.win.open_file(str(path))
        self.pump(until=lambda: (t := self.win.current_tab()) is not None and t.document.path.lower() == str(path).lower()
                  and not t.document.is_indexing)  # fmt: skip
        return self.tab()

    def window_of(self, cls_name: str, timeout: float = 15.0):
        found: list[QWidget] = []

        def check() -> bool:
            for w in self.app.topLevelWidgets():
                if type(w).__name__ == cls_name and w.isVisible():
                    found.append(w)
                    return True
            return False

        self.pump(until=check, timeout=timeout)
        assert found, f"{cls_name} did not open"
        return found[0]

    def close_windows(self, *names: str) -> None:
        for w in list(self.app.topLevelWidgets()):
            if type(w).__name__ in names and w.isVisible():
                w.close()
        self.pump(0.3)


# ====================================================================================================================
def run(d: Demo, with_ai: bool) -> None:
    win, app = d.win, d.app
    S = d.step

    def tog(action, on: bool) -> None:
        """Flip a checkable menu action the way a click does (setChecked alone would not run its handler)."""
        if action.isChecked() != on:
            action.trigger()

    # ---- 1. start screen, themes --------------------------------------------------------------------------------
    S("Welcome page with recent files", lambda: d.pump(1.0))
    S("Switch theme: dark", lambda: win._set_theme(next(a for a in win.theme_group.actions() if a.data() == "dark")), 1.2)
    S("Switch theme: light", lambda: win._set_theme(next(a for a in win.theme_group.actions() if a.data() == "light")), 1.2)

    # ---- 2. open + format detection ------------------------------------------------------------------------------
    S("Open a log: format detected, levels and timeline strip", lambda: d.open("app_small.log"), 2.0)

    def search() -> None:
        tab = d.tab()
        d.type_into(tab.filter_panel.edit, "payment")
        assert d.pump(until=lambda: len(tab.document.hits) > 0, timeout=15), "search found nothing"

    S("Search for 'payment' (live highlight of matches)", search, 2.0)
    S("Jump to next match", lambda: win.act_next.trigger(), 1.0)
    S("Jump to previous match", lambda: win.act_prev.trigger(), 1.0)
    S("Find all matches as results list", lambda: d.tab().run_search(SearchQuery("payment")), 1.5)

    def levels() -> None:
        panel = d.tab().filter_panel
        panel.edit.setText("")
        panel.select_levels({"Warning", "Error"})
        assert d.pump(until=lambda: len(d.tab().document.hits) > 0, timeout=15), 'no level matches'

    S("Filter by level: warnings and errors only", levels, 2.0)
    S("Next issue (error/warning navigation)", lambda: win.act_next_issue.trigger(), 1.0)
    S("Previous issue", lambda: win.act_prev_issue.trigger(), 1.0)

    def pin() -> None:
        panel = d.tab().filter_panel
        panel.select_levels(set())
        d.type_into(panel.edit, "CacheManager", enter=False)
        d.pump(1.0)
        panel.pin_current(FilterMode.ALL)  # becomes a chip: line MUST match
        d.pump(1.2)
        d.type_into(panel.edit, "miss", enter=False)
        d.pump(0.8)
        panel.pin_current(FilterMode.NONE)  # a second chip: line must NOT match
        assert d.pump(until=lambda: len(d.tab().document.hits) > 0, timeout=15), 'pinned filters matched nothing'
        assert len(panel._pinned) == 2

    S("Pin filters as chips: must match / must not match", pin, 2.5)

    def ctx() -> None:
        d.tab().filter_panel.context.setValue(2)
        d.pump(1.0)

    S("Show 2 context lines around each match", ctx, 1.8)
    S("Clear filters", lambda: (d.tab().filter_panel.clear(), d.tab().clear_search()), 1.2)

    # ---- 3. navigation (every dialog is really used and confirmed, and the effect is checked) ---------------------
    S("Bookmark a line", lambda: win.act_bookmark.trigger(), 0.8)
    S("Next bookmark", lambda: win.act_next_bm.trigger(), 0.8)

    def goto_line() -> None:
        def fill(w: QWidget) -> None:
            w.setIntValue(120)
            d.pump(1.5)

        d.modal(win.act_goto.trigger, fill, accept=True)
        assert d.tab().main_view.current_row() == 119, d.tab().main_view.current_row()

    S("Go to line…", goto_line, 1.0)

    def goto_time() -> None:
        tab = d.tab()
        first, last = tab.document.time_bounds()
        row_before = tab.main_view.current_row()

        def fill(w: QWidget) -> None:
            w.edit.setDateTime(_to_qt(first + (last - first) * 0.8))
            d.pump(1.5)

        d.modal(win.act_goto_time.trigger, fill, accept=True)
        assert tab.main_view.current_row() != row_before, "go to time did not move"

    S("Go to time…", goto_time, 1.0)

    def time_range() -> None:
        tab = d.tab()
        first, last = tab.document.time_bounds()
        span = last - first
        total = len(tab.shown_lines()) or tab.document.source.line_count()

        def fill(w: QWidget) -> None:
            w.use_start.setChecked(True)
            w.start.setDateTime(_to_qt(first + span * 0.4))
            w.use_end.setChecked(True)
            w.end.setDateTime(_to_qt(first + span * 0.6))
            d.pump(2.0)

        d.modal(win.act_time_range.trigger, fill, accept=True)
        d.pump(until=lambda: tab.filter_panel.time_range is not None, timeout=10)
        d.pump(2.5)
        assert tab.filter_panel.time_range is not None
        assert len(tab.shown_lines()) < total, "the time range did not narrow the lines"
        tab.filter_panel.set_time_range(None)

    S("Time range filter…", time_range, 1.0)

    def clock() -> None:
        def fill(w: QWidget) -> None:
            w.utc.setChecked(True)
            d.pump(2.0)

        d.modal(win.act_clock.trigger, fill, accept=True)

    S("Clock / timezone settings…", clock, 1.0)

    # ---- 4. view options -----------------------------------------------------------------------------------------
    S("Word wrap on", lambda: tog(win.act_wrap, True), 1.0)
    S("Word wrap off", lambda: tog(win.act_wrap, False), 0.6)
    S("Hide / show the Inspector", lambda: (tog(win.act_inspector, False), d.pump(0.8), tog(win.act_inspector, True)), 1.0)
    S("Hide / show the timeline strip", lambda: (tog(win.act_timeline, False), d.pump(0.8), tog(win.act_timeline, True)), 1.0)
    S("Columns view: parsed fields as a table", lambda: tog(win.act_columns, True), 2.0)
    S("Back to plain text view", lambda: tog(win.act_columns, False), 0.8)
    S("Zoom in / out", lambda: (win.act_zoom_in.trigger(), win.act_zoom_in.trigger(), d.pump(0.8), win.act_zoom_reset.trigger()), 1.0)

    def secrets() -> None:
        path = Path(tempfile.mkdtemp(prefix="loglens-secrets-")) / "secrets-demo.log"
        path.write_text(
            "2026-11-18 09:00:01 INFO  service started\n"
            "2026-11-18 09:00:02 DEBUG connecting with password=Sup3rS3cretPass! to db01\n"
            "2026-11-18 09:00:03 DEBUG Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkZW1vIn0.c2lnbmF0dXJlMTIzNDU2\n"
            "2026-11-18 09:00:04 INFO  using key AKIAIOSFODNN7EXAMPLE for the backup bucket\n"
            "2026-11-18 09:00:05 INFO  jdbc:sqlserver://db01;user=sa;password=Hunter2Hunter2\n"
            "2026-11-18 09:00:06 INFO  api_key=\"abcd1234efgh5678ijkl9012mnop3456\"\n",
            encoding="utf-8",
        )
        win.open_file(str(path))
        tab = d.tab()
        d.pump(until=lambda: not tab.document.is_indexing)
        d.pump(3.0)  # the viewer sees the secrets in clear text first
        tog(win.act_mask, True)
        d.pump(4.0)  # ...and now they are masked
        assert tab._mask_secrets, "secrets masking did not turn on"
        d.shot("mask-secrets")
        tog(win.act_mask, False)
        d.pump(1.5)

    S("Mask secrets toggle", secrets, 1.0)
    d.open("app_small.log")
    S("Encoding menu: reopen as another encoding", lambda: win._set_encoding(next(a for a in win.encoding_group.actions() if a.data() == "utf-8")), 1.2)

    def highlighters() -> None:
        def add_rule(w: QWidget) -> None:
            w._append(HighlightRule("Timeouts and failures", "timeout|failed|exception", bg="#66FF5555"))
            d.pump(2.0)

        d.modal(win.act_highlighters.trigger, add_rule, accept=True)
        d.pump(2.5)
        assert any(r.name == "Timeouts and failures" for r in win.rules), "highlight rule was not saved"

    S("Highlighters dialog (colour rules)", highlighters, 0.5)

    # ---- 5. structured logs, inspector ---------------------------------------------------------------------------
    def json_log() -> None:
        tab = d.open("app.json")
        tab.next_marked(None, True)
        d.pump(1.0)

    S("Open a JSON-lines log: Inspector decodes the payload", json_log, 2.5)
    S("Inspector: switch tabs", lambda: [d.tab().inspector.tabs.setCurrentIndex(i) or d.pump(0.8)
                                         for i in range(min(3, d.tab().inspector.tabs.count()))], 0.5)  # fmt: skip

    # ---- 6. analysis windows (each page really runs and must finish without an error) -----------------------------
    def analyze_page(key: str, settle: float = 2.5) -> None:
        win.analyze(key)
        window = d.window_of("AnalysisWindow")
        page = window.pages[key]
        d.pump(1.0)
        page.run_button.click()
        d.pump(0.3)
        d.pump(until=lambda: not page._busy, timeout=120)
        status = page.status.text()
        assert not status.startswith("⚠"), f"{key}: {status}"
        if key == "sql":
            page.run_query_button.click()
            d.pump(0.3)
            d.pump(until=lambda: not page._busy and not page.cancel_query_button.isVisible(), timeout=60)
            assert not page.status.text().startswith("⚠"), f"sql: {page.status.text()}"
        d.pump(settle)

    d.open("app_small.log")
    S("Analyze: message patterns", lambda: analyze_page("patterns"), 0.5)
    S("Analyze: field value counts", lambda: analyze_page("fields"), 0.5)
    S("Analyze: SQL over parsed records", lambda: analyze_page("sql"), 0.5)
    S("Analyze: compare (what changed?)", lambda: analyze_page("compare"), 0.5)
    S("Analyze: request / response pairs", lambda: analyze_page("transactions"), 0.5)
    d.close_windows("AnalysisWindow")
    d.open("u_ex261113.log")
    S("Analyze: HTTP request statistics (IIS log)", lambda: analyze_page("http", 3.5), 0.5)
    d.close_windows("AnalysisWindow")

    # ---- 7. copy, export, report, open dialogs (native file pickers are answered by the demo) ----------------------
    out_dir = Path(tempfile.mkdtemp(prefix="loglens-out-"))
    pick: dict[str, str] = {}

    def fake_save(*_a: object, **_k: object) -> tuple[str, str]:
        return pick["save"], ""

    def fake_open_many(*_a: object, **_k: object) -> tuple[list[str], str]:
        return [pick["open"]], ""

    QFileDialog.getSaveFileName = staticmethod(fake_save)  # type: ignore[method-assign]
    QFileDialog.getOpenFileNames = staticmethod(fake_open_many)  # type: ignore[method-assign]
    QFileDialog.getExistingDirectory = staticmethod(lambda *_a, **_k: pick["dir"])  # type: ignore[method-assign]
    QFileDialog.getOpenFileName = staticmethod(lambda *_a, **_k: (pick["file"], ""))  # type: ignore[method-assign]

    def open_via_dialog() -> None:
        pick["open"] = str(SAMPLES / "scenario.log")
        before = win.tabs.count()
        win.act_open.trigger()
        d.pump(until=lambda: win.tabs.count() > before, timeout=20)
        assert win.tabs.count() > before

    S("File > Open… (file picker)", open_via_dialog, 1.5)
    d.open("app_small.log")

    def export_lines() -> None:
        tab = d.tab()
        tab.filter_panel.select_levels({"Warning", "Error"})
        assert d.pump(until=lambda: len(tab.document.hits) > 0, timeout=15), "no warnings/errors to export"
        pick["save"] = str(out_dir / "filtered.csv")
        win.act_export.trigger()
        d.pump(until=lambda: Path(pick["save"]).exists() and tab._exporter is None, timeout=30)
        assert Path(pick["save"]).stat().st_size > 0, "export wrote nothing"
        tab.filter_panel.select_levels(set())
        tab.clear_search()

    S("Export the filtered lines to CSV", export_lines, 1.5)

    def copy_lines() -> None:
        tab = d.tab()
        tab.next_marked(None, True)
        win.act_copy.trigger()

    S("Copy lines to the clipboard", copy_lines, 1.0)

    def report_save() -> None:
        pick["save"] = str(out_dir / "report.html")

        def save(w: QWidget) -> None:
            next(b for b in w.findChildren(QPushButton) if b.text().startswith("Save")).click()

        d.modal(win.act_report.trigger, save, hold=2.0)
        assert Path(pick["save"]).exists() and Path(pick["save"]).stat().st_size > 200, "report not written"

    S("Incident report dialog", report_save, 1.0)

    def web_search() -> None:
        tab = d.tab()
        tab.next_marked(None, True)
        d.modal(lambda: win.search_web(tab), hold=2.0)

    S("Web search with a cleaned query", web_search, 0.5)

    def teach() -> None:
        tab = d.tab()
        tab.next_marked(None, True)

        def fill(w: QWidget) -> None:
            w.explanation.setPlainText("Demo entry: the cache miss ratio is high; check the cache size and TTL.")

        d.modal(tab.teach_knowledge_base, fill, hold=2.0, accept=True)

    S("Teach the knowledge base a new explanation", teach, 1.5)

    # ---- 8. tabs, merge, bundles, find all, dashboard ------------------------------------------------------------
    S("Switch between open tabs", lambda: (win.act_next_tab.trigger(), d.pump(0.8), win.act_prev_tab.trigger()), 1.0)
    def merge() -> None:
        d.open("app_utf16.log")
        before = win.tabs.count()

        def choose(w: QWidget) -> None:
            for i in range(w.list.count()):
                w.list.item(i).setCheckState(Qt.CheckState.Checked)
            w.events.setChecked(False)
            d.pump(1.5)

        d.modal(win.merge_open_logs, choose, hold=1.5, accept=True)
        d.pump(until=lambda: win.tabs.count() > before, timeout=60)
        assert win.tabs.count() > before, "merged timeline did not open"
        d.pump(until=lambda: not d.tab().document.is_indexing, timeout=60)

    S("Merge open logs into one timeline", merge, 1.5)

    def bundle() -> None:
        pick["dir"] = str(SAMPLES)
        before = win.tabs.count()

        def choose(w: QWidget) -> None:
            next(b for b in w.findChildren(QPushButton) if b.text().startswith("Folder")).click()

        d.modal(win.open_bundle_dialog, choose, hold=1.0)

        timer = QTimer(d.win)
        timer.setInterval(200)

        def poll() -> None:
            w = app.activeModalWidget()
            if w is not None and type(w).__name__ == "BundleDialog":
                timer.stop()
                d.pump(2.0)
                w.merge.setChecked(False)  # merging is its own step; here just open the selected logs
                w.accept()

        timer.timeout.connect(poll)
        timer.start()
        d.pump(until=lambda: win.tabs.count() > before, timeout=40)
        timer.stop()
        assert win.tabs.count() > before, "bundle opened nothing"

    S("Open a folder of logs (support bundle)", bundle, 1.5)
    def find_all() -> None:
        win.find_in_all()
        dlg = d.window_of("FindAllDialog")
        dlg.query.setText("payment")
        d.pump(0.8)
        dlg.run()
        d.pump(until=lambda: dlg.results.topLevelItemCount() > 0, timeout=30)
        d.pump(2.5)
        assert dlg.results.topLevelItemCount() > 0 and "matches" in dlg.status.text(), f"find all: {dlg.status.text()!r}"
        d.close_windows("FindAllDialog")

    S("Find in all open logs", find_all, 0.5)
    S("Dashboard (live overview)", lambda: (win.open_dashboard(), d.pump(2.5), d.close_windows("DashboardWindow")), 0.5)

    # ---- 9. live follow ------------------------------------------------------------------------------------------
    def live() -> None:
        path = out_dir / "live.log"
        path.write_text("".join(f"2026-11-18 10:00:{i:02d} INFO heartbeat {i}\n" for i in range(20)), encoding="utf-8")
        win.open_live(str(path))
        tab = d.tab()
        d.pump(until=lambda: not tab.document.is_indexing)
        start = tab.document.source.line_count()
        for i in range(20, 32):
            with path.open("a", encoding="utf-8") as f:
                f.write(f"2026-11-18 10:00:{i:02d} {'ERROR payment gateway timeout' if i == 28 else 'INFO heartbeat'} {i}\n")
            d.pump(0.5)
        d.pump(until=lambda: tab.document.source.line_count() > start, timeout=15)
        assert tab.document.source.line_count() > start, "live tail did not pick up new lines"

    S("Live tail: new lines appear as they are written", live, 1.0)

    def alerts() -> None:
        d.modal(win.watch.edit_alerts, hold=2.5)

    S("Alert rules for watched logs", alerts, 0.5)

    def watch_folder() -> None:
        d.modal(win.watch.watch_folder_dialog, hold=2.5)

    S("Watch a folder: always open the newest file", watch_folder, 0.5)

    # ---- 10. knowledge base, diagnosis, Windows event logs ------------------------------------------------------
    def kb() -> None:
        def look(w: QWidget) -> None:
            d.pump(1.5)
            from PySide6.QtWidgets import QTabWidget

            t = w.findChild(QTabWidget)
            if t is not None:
                for i in range(t.count()):
                    t.setCurrentIndex(i)
                    d.pump(1.5)

        d.modal(win.open_knowledge_base, look, hold=1.5)

    S("Knowledge base (offline explanations)", kb, 0.5)

    def diagnose() -> None:
        win.open_diagnosis()
        dlg = d.window_of("DiagnoseDialog")
        d.pump(1.0)
        dlg.run_button.click()
        d.pump(0.5)
        d.pump(until=lambda: dlg.run_button.isEnabled(), timeout=180)
        d.pump(4.0)
        d.close_windows("DiagnoseDialog")

    S("Diagnose this computer", diagnose, 0.5)

    def events() -> None:
        before = win.tabs.count()

        def choose(w: QWidget) -> None:
            for name in ("Application", "System"):
                for i in range(w.channels.count()):
                    item = w.channels.item(i)
                    if item.text().startswith(name):
                        item.setCheckState(Qt.CheckState.Checked)
            d.pump(1.5)

        d.modal(win.open_event_logs, choose, hold=1.5, accept=True)
        d.pump(until=lambda: win.tabs.count() > before, timeout=180)
        assert win.tabs.count() > before, "no event log tab opened"
        tab = d.tab()
        d.pump(until=lambda: not tab.document.is_indexing, timeout=60)

    S("Windows Event Logs: read Application and System into a searchable log", events, 2.0)

    def related() -> None:
        tab = d.tab()
        tab.next_marked(None, True)
        tab.find_related_events(5)
        d.pump(until=lambda: tab.inspector.related.topLevelItemCount() > 0, timeout=30)
        d.pump(2.0)

    S("Windows events around the selected line", related, 1.5)

    def evtx() -> None:
        target = out_dir / "system.evtx"
        subprocess.run(["wevtutil", "epl", "System", str(target), "/q:*[System[TimeCreated[timediff(@SystemTime) <= 172800000]]]", "/ow:true"], check=True)
        before = win.tabs.count()
        win.open_evtx(str(target))
        d.pump(until=lambda: win.tabs.count() > before, timeout=120)
        assert win.tabs.count() > before, "evtx did not open"
        d.pump(until=lambda: not d.tab().document.is_indexing, timeout=60)

    S("Open an exported .evtx file", evtx, 2.0)

    def follow_events() -> None:
        before = win.tabs.count()

        def choose(w: QWidget) -> None:
            for i in range(w.channels.count()):
                item = w.channels.item(i)
                item.setCheckState(Qt.CheckState.Checked if item.text().startswith("Application") else Qt.CheckState.Unchecked)
            w.follow.setChecked(True)
            d.pump(1.5)

        d.modal(win.open_event_logs, choose, hold=1.0, accept=True)
        d.pump(until=lambda: win.tabs.count() > before, timeout=120)
        assert win.tabs.count() > before, "followed event log did not open"
        d.pump(3.0)

    S("Follow Windows events live", follow_events, 1.5)
    S("Watch menu: follow files, alerts, services", lambda: (win.menuBar().actions()[5].menu().popup(win.mapToGlobal(QPoint(420, 30))),
                                                              d.pump(2.0), win.menuBar().actions()[5].menu().hide()), 0.5)  # fmt: skip
    S("About LogLens", lambda: d.modal(win.act_about.trigger, hold=2.0), 0.5)

    # ---- 10. AI with Ollama --------------------------------------------------------------------------------------
    if not with_ai:
        return
    d.open("app_small.log")

    def settings_dialog() -> None:
        state: dict[str, str] = {}

        def act(w: QWidget) -> None:
            button = next(b for b in w.findChildren(QPushButton) if b.text().startswith("Test connection"))
            button.click()
            d.pump(until=lambda: w.test_result.text() not in ("", "Testing…"), timeout=60)
            state["result"] = w.test_result.text()

        d.modal(win.act_ai_settings.trigger, act, hold=2.5)
        assert "qwen" in state.get("result", "") or "OK" in state.get("result", "") or "✓" in state.get("result", ""),             f"connection test said: {state.get('result')!r}"

    S("AI settings: provider = local Ollama, test connection", settings_dialog, 0.5)

    def explain() -> None:
        tab = d.tab()
        d.type_into(tab.filter_panel.edit, "ERROR")
        assert d.pump(until=lambda: len(tab.document.hits) > 0, timeout=15), "no ERROR lines found"
        tab.next_marked(None, True)
        d.pump(1.0)

        def send(w) -> None:
            d.pump(2.5)  # let the viewer read the redacted preview

        QTimer.singleShot(0, lambda: None)
        d.modal(lambda: win.act_explain.trigger(), send, hold=1.0, accept=True)
        d.speak('AI wait: line')
        d.pump(until=lambda: not win.ai.service.busy, timeout=300)
        inspector = tab.inspector
        assert inspector._explanation is not None and not inspector.ai_status.text().startswith("⚠"),             f"no answer: {inspector.ai_status.text()!r}"

    S("AI: explain the selected line (preview, then local model answer)", explain, 4.0)
    S("AI: answer shown in the Inspector", lambda: d.tab().inspector.tabs.setCurrentIndex(d.tab().inspector.tabs.count() - 1), 3.0)


    def explain_patterns() -> None:
        win.analyze("patterns")
        window = d.window_of("AnalysisWindow")
        d.pump(3.0)
        tab = d.tab()
        tab.inspector._explanation = None
        button = next(b for b in window.findChildren(QPushButton) if b.text().startswith("Explain these patterns"))
        window.pages['patterns'].run_button.click()
        d.pump(0.3)
        d.pump(until=lambda: bool(window.pages['patterns']._patterns), timeout=120)
        d.modal(button.click, lambda w: d.pump(2.5), hold=1.0, accept=True)
        d.speak('AI wait: patterns')
        d.pump(until=lambda: not win.ai.service.busy, timeout=300)
        assert tab.inspector._explanation is not None, f"no answer: {tab.inspector.ai_status.text()!r}"
        d.close_windows("AnalysisWindow")

    S("AI: explain the top patterns of the log", explain_patterns, 3.0)

    def save_answer() -> None:
        tab = d.tab()
        d.pump(until=lambda: tab.inspector.last_explanation is not None, timeout=5)
        if tab.inspector.last_explanation is None:  # the patterns answer belongs to the whole log: ask about one line
            tab.next_marked(None, True)
        assert tab.inspector.last_explanation is not None, "no AI answer to save"
        tab.inspector.save_answer_btn.setEnabled(True)
        d.modal(tab.save_answer_to_knowledge_base, lambda w: d.pump(2.0), hold=1.0, accept=True)

    S("AI: save the answer to your knowledge base", save_answer, 1.5)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--record", help="write an mp4 of the screen area of the window")
    parser.add_argument("--fast", action="store_true", help="shorter pauses (test run)")
    parser.add_argument("--no-ai", action="store_true")
    parser.add_argument("--speed", type=float, default=1.0, help="play the finished narrated video this much faster")
    parser.add_argument("--shots", help="folder to save README screenshots into")
    parser.add_argument("--no-voice", action="store_true", help="record without narration")
    args = parser.parse_args()

    app = QApplication([])
    ai = AIConfig(enabled=True, provider=Provider.LOCAL, local_api="ollama", local_url="http://localhost:11434",
                  local_model=OLLAMA_MODEL, preview_before_send=True)  # fmt: skip
    settings = Settings(theme="light", recent_files=[str(SAMPLES / n) for n in ("app_small.log", "u_ex261113.log", "app.json")])
    settings.set_ai_config(ai)
    apply_theme(app, "light")
    win = MainWindow(settings)
    win.refresh_theme()
    if args.record:
        win.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint, True)  # nothing else on screen may cover the capture
    win.resize(1500, 900)
    win.move(40, 40)
    win.show()
    d = Demo(app, win, args.fast)
    if args.shots:
        d.shots = Path(args.shots)
        d.shots.mkdir(parents=True, exist_ok=True)
    if args.record:  # a relaxed pace: one feature at a time, with time to read the screen
        d.dwell, d.gap = 0.2, 0.3
    if args.record and not args.no_voice:
        d.clips = make_voice(NARRATION)
    d.pump(1.5)

    recorder = None
    if args.record:
        geo = win.frameGeometry()
        dpr = win.devicePixelRatioF()
        x, y, w, h = (int(v * dpr) for v in (geo.x(), geo.y(), geo.width(), geo.height()))
        w, h = w - w % 2, h - h % 2
        recorder = subprocess.Popen(
            ["ffmpeg", "-y", "-f", "gdigrab", "-framerate", "20", "-offset_x", str(x), "-offset_y", str(y),
             "-video_size", f"{w}x{h}", "-i", "desktop", "-c:v", "libx264", "-preset", "veryfast", "-crf", "23",
             "-pix_fmt", "yuv420p", args.record],
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )  # fmt: skip
        out = Path(args.record)
        for _ in range(100):  # ffmpeg needs a moment before the first frame; the voice must start with the video
            if out.exists() and out.stat().st_size > 0:
                break
            time.sleep(0.1)
        d.t0 = time.monotonic()
        d.pump(1.0)
    try:
        d.say("LogLens: a tour of every feature")
        d.pump(max(d.speak(INTRO) + 0.5, 1.0))
        run(d, with_ai=not args.no_ai)
        d.say("LogLens — read, filter, understand and explain any log, locally.")
        d.pump(max(d.speak(OUTRO) + 1.0, 2.5))
    finally:
        if recorder is not None and recorder.stdin is not None:
            recorder.stdin.write(b"q")
            recorder.stdin.flush()
            recorder.wait(timeout=60)
            if d.clips:
                mix_voice(Path(args.record), d.cues, d.clips)
                if args.speed != 1.0:
                    narrated = Path(args.record).with_name(Path(args.record).stem + "-voice.mp4")
                    quick = narrated.with_name(narrated.stem + "-quick.mp4")
                    s = args.speed
                    subprocess.run(["ffmpeg", "-y", "-i", str(narrated), "-filter_complex",
                                    f"[0:v]setpts=PTS/{s}[v];[0:a]atempo={s}[a]", "-map", "[v]", "-map", "[a]",
                                    "-c:v", "libx264", "-preset", "medium", "-crf", "23", "-pix_fmt", "yuv420p",
                                    "-c:a", "aac", "-b:a", "160k", "-movflags", "+faststart", str(quick)],
                                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # fmt: skip
                    quick.replace(narrated)
        win.close()
        shutdown_pool()
    report = ROOT / "build" / "demo_report.json"
    report.parent.mkdir(exist_ok=True)
    report.write_text(json.dumps(d.results, indent=2), encoding="utf-8")
    failed = [r for r in d.results if not r["ok"]]
    print(f"\n{len(d.results) - len(failed)}/{len(d.results)} steps ok; report: {report}")
    shutil.rmtree(os.environ["APPDATA"], ignore_errors=True)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
