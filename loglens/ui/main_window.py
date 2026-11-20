"""Main window: tabs, menus, toolbar, status pills, drag & drop, recent files, welcome page."""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING

from PySide6.QtCore import QByteArray, QSize, Qt, QTimer
from PySide6.QtGui import (
    QAction,
    QActionGroup,
    QCloseEvent,
    QColor,
    QDragEnterEvent,
    QDropEvent,
    QGuiApplication,
    QIcon,
    QKeySequence,
)
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QProgressDialog,
    QStackedWidget,
    QTabWidget,
    QToolBar,
    QToolButton,
    QWidget,
)

from .. import APP_NAME, __version__
from ..core.bundles import BundleFile
from ..core.containers import LogSource
from ..core.elevation import elevation_is_safe, is_admin, relaunch_elevated
from ..core.encoding import KNOWN_ENCODINGS
from ..core.formats import FormatError, LogFormat
from ..core.highlight import HighlightRule
from ..core.incident import Incident
from ..core.plugins import Analyzer, PluginInfo, read_source, run_analyzer, scan
from ..core.plugins import Source as PluginSource
from ..core.timeline import TimelineSource
from ..core.websearch import query_parts
from ..core.winevent.reader import EventQuery
from ..paths import container_logs_dir, event_exports_dir, plugin_logs_dir, plugins_dir
from ..services.analysis_jobs import AnalysisScope, iter_lines
from ..services.container_jobs import ContainerStreamer, capture_path
from ..services.eventlog_jobs import EventLogExporter, EventLogFollower
from ..services.knowledge_service import KnowledgeService
from ..services.log_document import MarkSummary
from ..services.multi_jobs import BundleLoader, TimelineBuilder
from ..settings import Settings
from .ai_controller import AIController
from .analysis_window import AnalysisWindow
from .bundle_dialog import BundleDialog
from .eventlog_dialog import EventLogDialog
from .format_dialog import PREVIEW_LINES, FormatDialog
from .highlighter_dialog import HighlighterDialog
from .icons import dot_pixmap, logo_icon, logo_pixmap, themed_icon
from .incident_window import IncidentWindow
from .log_tab import LogTab
from .log_view import monospace_font
from .multi_dialogs import FindAllDialog, TimelineDialog
from .packs_controller import PacksController
from .payload_view import Background
from .qt_utils import copy_from_focused_text, exec_dialog
from .theme import THEMES, apply_theme, is_dark, style_sheet
from .watch_controller import WatchController
from .web_search_dialog import WebSearchDialog
from .welcome_page import WelcomePage

if TYPE_CHECKING:
    from .diagnose_dialog import DiagnoseDialog
    from .rundiff_dialog import RunDiffDialog

log = logging.getLogger(__name__)
LOG_FILTER = (
    "Log files (*.log *.txt *.out *.err *.json *.jsonl *.csv *.trace);;Windows event log files (*.evtx);;All files (*)"
)
# (page key, menu text, shortcut). No Ctrl+Alt+letter shortcuts anywhere: on Windows AltGr is Ctrl+Alt, and
# AltGr+letter types characters (@ € µ on German, ą ć ó on Polish layouts …) that a shortcut would swallow.
ANALYSIS_ACTIONS = (
    ("summary", "&Summary (what to look at first)…", "Ctrl+Shift+U"),
    ("unusual", "&Unusual (spikes, new messages)…", ""),
    ("charts", "C&harts (over time)…", "Ctrl+Shift+G"),
    ("patterns", "&Patterns…", "Ctrl+Shift+N"),
    ("compare", "&Compare (what changed?)…", ""),
    ("fields", "&Fields (value counts)…", ""),
    ("sql", "&SQL over records…", "Ctrl+Shift+Q"),
    ("script", "Scri&pt (Python)…", ""),
    ("http", "&HTTP requests…", "Ctrl+Shift+H"),
    ("transactions", "&Request / response pairs…", ""),
)
EVTX_MAX_EVENTS = 500_000  # events read from one .evtx file (newest first)


class MainWindow(QMainWindow):
    def __init__(self, settings: Settings) -> None:
        super().__init__()
        self.settings = settings
        self.setWindowTitle(APP_NAME)
        self.setWindowIcon(logo_icon())
        self.resize(1400, 900)
        self.setAcceptDrops(True)
        self.font_ = monospace_font(settings.font_family, settings.font_size)
        self.rules = settings.rules()

        self.tabs = QTabWidget(self)
        self.tabs.setTabsClosable(True)
        self.tabs.setMovable(True)
        self.tabs.setDocumentMode(True)
        self.tabs.tabCloseRequested.connect(self.close_tab)
        self.tabs.currentChanged.connect(self._on_tab_changed)
        self.welcome = WelcomePage(self)
        self.welcome.openRequested.connect(self.open_dialog)
        self.welcome.recentRequested.connect(self.open_file)
        self.stack = QStackedWidget(self)
        self.stack.addWidget(self.welcome)
        self.stack.addWidget(self.tabs)
        self.setCentralWidget(self.stack)

        self.status_pos = QLabel(self)
        self.statusBar().addWidget(self.status_pos)
        self.pill_box = QWidget(self)
        self.pill_layout = QHBoxLayout(self.pill_box)
        self.pill_layout.setContentsMargins(0, 0, 4, 0)
        self.pill_layout.setSpacing(2)
        self.statusBar().addPermanentWidget(self.pill_box)
        self._pills: list[QToolButton] = []

        self.ai = AIController(settings, self)
        self.ai.configChanged.connect(self._refresh_ai_state)
        self.ai.busyChanged.connect(self._on_ai_busy)
        self.packs = PacksController(settings, self)
        self.packs.rulesImported.connect(self.apply_rules)
        self._quitting = False
        self._ai_busy = False
        self._analysis: dict[int, AnalysisWindow] = {}
        self._event_followers: dict[str, EventLogFollower] = {}
        self._streamers: dict[str, ContainerStreamer] = {}
        self._diagnosis: DiagnoseDialog | None = None
        self._trace_dialog: QDialog | None = None
        self._rundiff: RunDiffDialog | None = None
        self._incident: IncidentWindow | None = None
        self._plugins: list[PluginInfo] = []
        self._plugin_job: Background | None = None
        self._find_all: FindAllDialog | None = None
        self._dashboard: QDialog | None = None
        self.knowledge = KnowledgeService(parent=self)
        self.knowledge.set_team_dir(settings.team_kb_dir, announce=False)
        self.reload_plugins()
        self.knowledge.teamChanged.connect(lambda path: setattr(self.settings, "team_kb_dir", path))
        self._told_about_tray = False
        self.watch = WatchController(settings, self)
        self._build_actions()
        self._build_menus()
        self._refresh_recent()
        self._restore_geometry()
        self._refresh_icons()
        QGuiApplication.styleHints().colorSchemeChanged.connect(lambda _scheme: self.refresh_theme())
        self._update_ui()

    # ---- actions & menus -----------------------------------------------------------------------------------------
    def _action(
        self,
        text: str,
        slot: Callable[..., object],
        shortcut: str | QKeySequence.StandardKey | None = None,
        *,
        checkable: bool = False,
        tip: str = "",
        icon: str = "",
    ) -> QAction:
        act = QAction(text, self)
        tip = tip or text.replace("&", "").rstrip("…")
        if shortcut is not None:
            sequence = QKeySequence(shortcut)
            act.setShortcut(sequence)
            act.setShortcutContext(Qt.ShortcutContext.WindowShortcut)
            tip += f"  ({sequence.toString(QKeySequence.SequenceFormat.NativeText)})"
        act.setCheckable(checkable)
        act.setToolTip(tip)
        act.setStatusTip(tip)
        if icon:
            act.setProperty("iconName", icon)
        act.triggered.connect(slot)
        return act

    def _build_actions(self) -> None:
        self._build_file_actions()
        self._build_navigation_actions()
        self._build_view_actions()

    def _build_file_actions(self) -> None:
        a = self._action
        self.act_open = a("&Open…", self.open_dialog, QKeySequence.StandardKey.Open, icon="open")
        self.act_events = a(
            "Open Windows &Event Logs…",
            self.open_event_logs,
            "Ctrl+Shift+O",
            tip="Read Application/System/… event logs or an .evtx file into a searchable, explained view",
            icon="events",
        )
        self.act_events.setIconText("Event Logs")
        self.act_containers = a(
            "&Containers && Kubernetes…",
            self.open_containers,
            tip="Read the logs of Docker containers and Kubernetes pods (uses your docker / kubectl)",
        )
        self.act_servers = a(
            "&Servers…",
            self.open_servers,
            tip="Other Windows servers whose Event Viewer logs LogLens can read (add, test, remove)",
        )
        self.act_bundle = a(
            "Open &folder or zip…",
            self.open_bundle_dialog,
            "Ctrl+Shift+D",
            tip="A support bundle or a folder of logs: pick files, open them, merge them into one timeline",
        )
        self.act_reload = a("&Reload", lambda: self._with_tab(lambda t: t.reload()), "F5", icon="reload")
        self.act_admin = a(
            "Restart as &administrator",
            self.restart_as_admin,
            tip="Needed for the Security event log and some protected log files; your open files are reopened",
        )
        safe, reason = elevation_is_safe()
        self.act_admin.setVisible(not is_admin())
        self.act_admin.setEnabled(safe)
        if not safe:
            self.act_admin.setToolTip(f"Not available: {reason}")
        self.act_report = a(
            "Incident &report…",
            lambda: self._with_tab(lambda t: t.report_dialog()),
            "Ctrl+Shift+P",
            tip="Markdown/HTML report: bookmarks, matches, AI answer, Windows events — optionally redacted",
        )
        self.act_merge = a(
            "&Merge into timeline…",
            self.merge_open_logs,
            tip="Merge open logs (and Windows errors of the same period) into one time-ordered view",
        )
        self.act_share_copy = a(
            "Save a &share-safe copy…",
            self.save_share_copy,
            tip="A copy of the whole log with secrets masked and people / machines replaced by consistent pseudonyms",
        )
        self.act_export = a(
            "&Export lines…",
            lambda: self._with_tab(lambda t: t.export_results()),
            tip="Save the filtered lines as text, CSV or JSON Lines",
        )
        self.act_close = a("&Close tab", lambda: self.close_tab(self.tabs.currentIndex()), "Ctrl+W")
        self.act_exit = a("E&xit", self.close, "Alt+F4")
        self.act_about = a(f"&About {APP_NAME}", self._about)
        self.act_next_tab = a("Next tab", lambda: self._cycle_tab(1), "Ctrl+Tab")
        self.act_prev_tab = a("Previous tab", lambda: self._cycle_tab(-1), "Ctrl+Shift+Tab")
        for act in (self.act_next_tab, self.act_prev_tab):
            self.addAction(act)

    def _build_navigation_actions(self) -> None:
        a, tab = self._action, self._with_tab
        self.act_copy = a("&Copy", self._copy, QKeySequence.StandardKey.Copy)
        self.act_find = a("&Find…", lambda: tab(lambda t: t.focus_search()), QKeySequence.StandardKey.Find, icon="find")
        self.act_find_all = a("Find in &all open logs…", self.find_in_all, "Ctrl+Shift+F")
        self.act_next = a("Find &next", lambda: tab(lambda t: t.next_match()), "F3")
        self.act_prev = a("Find &previous", lambda: tab(lambda t: t.prev_match()), "Shift+F3")
        self.act_next_issue = a(
            "Next &issue",
            lambda: tab(lambda t: t.next_marked(None, True)),
            "Ctrl+E",
            tip="Jump to the next error / warning",
            icon="error",
        )
        self.act_prev_issue = a("Previous issue", lambda: tab(lambda t: t.next_marked(None, False)), "Ctrl+Shift+E")
        self.act_goto = a("&Go to line…", lambda: tab(lambda t: t.go_to_line_dialog()), "Ctrl+G", icon="goto")
        self.act_goto_time = a(
            "Go to &time…",
            lambda: tab(lambda t: t.go_to_time_dialog()),
            "Ctrl+Shift+G",
            tip="Jump to the first line at or after a date and time",
        )
        self.act_time_range = a(
            "Filter by time &range…",
            lambda: tab(lambda t: t.time_range_dialog()),
            "Ctrl+Shift+R",
            tip="Only show lines between two times (combines with search terms and levels)",
        )
        self.act_clock = a(
            "Log &time zone…",
            lambda: tab(lambda t: t.clock_dialog()),
            tip="Which time zone this log's timestamps are in, and clock corrections",
        )
        self.act_bookmark = a("Toggle &bookmark", lambda: tab(lambda t: t.toggle_bookmark()), "Ctrl+B", icon="bookmark")
        self.act_next_bm = a("Next bookmark", lambda: tab(lambda t: t.next_bookmark(True)), "F2")
        self.act_prev_bm = a("Previous bookmark", lambda: tab(lambda t: t.next_bookmark(False)), "Shift+F2")

    def _build_view_actions(self) -> None:
        a = self._action
        self.act_follow = a(
            "&Follow",
            self._toggle_follow,
            "Ctrl+T",
            checkable=True,
            tip="Follow the end of the file as it grows (tail)",
            icon="follow",
        )
        self.act_wrap = a("&Word wrap", self._toggle_wrap, "Alt+Z", checkable=True)
        self.act_wrap.setChecked(self.settings.word_wrap)
        self.act_inspector = a(
            "&Inspector",
            self._toggle_inspector,
            "Ctrl+D",
            checkable=True,
            tip="Right-hand panel: the selected line decoded (JSON, XML, URLs, SQL, tokens…) and AI explanations",
        )
        self.act_inspector.setChecked(self.settings.show_inspector)
        self.act_timeline = a(
            "&Timeline",
            self._toggle_timeline,
            "Ctrl+Shift+L",
            checkable=True,
            tip="Activity-over-time strip above the log: click to jump, drag to filter a time range",
        )
        self.act_timeline.setChecked(self.settings.show_timeline)
        self.act_mask = a(
            "&Mask secrets",
            self._toggle_mask,
            "Ctrl+Shift+M",
            checkable=True,
            tip="Show passwords, tokens and keys as •••••• (for screen sharing and screenshots)",
        )
        self.act_mask.setChecked(self.settings.mask_secrets)
        self.act_columns = a(
            "&Columns view",
            lambda checked: self._with_tab(lambda t: t.set_columns_visible(checked)),
            "Ctrl+Shift+T",
            checkable=True,
            tip="Show the log as a table of parsed fields (the format chip in the header changes the format)",
        )
        self.act_highlighters = a("&Highlighters…", self.edit_highlighters, "Ctrl+H", icon="highlight")
        self.act_zoom_in = a("Zoom in", lambda: self._zoom(1), QKeySequence.StandardKey.ZoomIn)
        self.act_zoom_out = a("Zoom out", lambda: self._zoom(-1), QKeySequence.StandardKey.ZoomOut)
        self.act_zoom_reset = a("Reset zoom", lambda: self._zoom(0), "Ctrl+0")
        self.act_explain = a(
            "&Explain selected line…",
            lambda: self._with_tab(self.ai.explain),
            "Ctrl+Shift+A",
            tip="Ask the AI assistant what the selected line means (preview before sending)",
            icon="ai",
        )
        self.act_explain.setIconText("Ask AI")
        self.act_ai_settings = a("AI &settings…", self.ai.open_settings, tip="Provider, key, model, privacy")

    def _build_menus(self) -> None:
        mb = self.menuBar()
        m = mb.addMenu("&File")
        m.addAction(self.act_open)
        m.addAction(self.act_events)
        m.addAction(self.act_servers)
        m.addAction(self.act_containers)
        m.addAction(self.act_bundle)
        self.recent_menu = m.addMenu("Open &recent")
        m.addAction(self.act_reload)
        m.addSeparator()
        m.addAction(self.act_merge)
        m.addAction(self.act_export)
        m.addAction(self.act_share_copy)
        m.addAction(self.act_report)
        m.addSeparator()
        m.addAction(self.act_close)
        m.addSeparator()
        m.addAction(self.act_admin)
        m.addAction(self.act_exit)

        m = mb.addMenu("&Edit")
        for act in (
            self.act_copy,
            None,
            self.act_find,
            self.act_find_all,
            self.act_next,
            self.act_prev,
            None,
            self.act_next_issue,
            self.act_prev_issue,
            None,
            self.act_goto,
            self.act_goto_time,
            self.act_time_range,
            None,
            self.act_bookmark,
            self.act_next_bm,
            self.act_prev_bm,
        ):
            m.addSeparator() if act is None else m.addAction(act)

        m = mb.addMenu("&View")
        for act in (
            self.act_follow,
            self.act_wrap,
            self.act_inspector,
            self.act_timeline,
            self.act_columns,
            self.act_mask,
            None,
            self.act_highlighters,
        ):
            m.addSeparator() if act is None else m.addAction(act)
        m.addSeparator()
        theme_menu = m.addMenu("&Theme")
        self.theme_group = QActionGroup(self)
        for key, name in THEMES.items():
            act = theme_menu.addAction(name)
            act.setCheckable(True)
            act.setData(key)
            act.setChecked(key == self.settings.theme)
            self.theme_group.addAction(act)
        self.theme_group.triggered.connect(self._set_theme)
        enc = m.addMenu("&Encoding")
        self.encoding_group = QActionGroup(self)
        auto = enc.addAction("Auto-detect")
        auto.setCheckable(True)
        auto.setData("")
        self.encoding_group.addAction(auto)
        enc.addSeparator()
        for codec, name in KNOWN_ENCODINGS.items():
            act = enc.addAction(name)
            act.setCheckable(True)
            act.setData(codec)
            self.encoding_group.addAction(act)
        self.encoding_group.triggered.connect(self._set_encoding)
        m.addAction(self.act_clock)
        m.addSeparator()
        m.addAction(self.act_zoom_in)
        m.addAction(self.act_zoom_out)
        m.addAction(self.act_zoom_reset)
        self._build_tool_menus()
        self._build_toolbar()

    def _build_tool_menus(self) -> None:
        mb = self.menuBar()
        self.analyze_menu = mb.addMenu("A&nalyze")
        for key, text, shortcut in ANALYSIS_ACTIONS:
            act = self.analyze_menu.addAction(text, partial(self.analyze, key))
            if shortcut:
                act.setShortcut(shortcut)
        self.analyze_menu.addSeparator()
        kb = self.analyze_menu.addAction("&Knowledge base…", self.open_knowledge_base)
        kb.setShortcut("Ctrl+Shift+K")
        self.analyze_menu.addAction("&Diagnose a computer…", self.open_diagnosis)
        pin = self.analyze_menu.addAction("Add selected lines to the &incident", self.pin_to_incident)
        pin.setShortcut("Ctrl+Shift+I")
        self.analyze_menu.addAction("&Incident…", self.open_incident)
        self.analyze_menu.addAction("&Trace an id across logs…", self.open_trace, "Ctrl+Shift+T")
        self.analyze_menu.addAction("Compare two &runs side by side…", self.open_rundiff)
        self.plugin_menu = self.analyze_menu.addMenu("&Plugins")
        self.plugin_menu.aboutToShow.connect(self._fill_plugin_menu)
        ask = self.analyze_menu.addAction("&Ask in plain words…", self.ask_in_plain_words)
        ask.setShortcut("Ctrl+Shift+A")
        self.watch_menu = mb.addMenu("&Watch")
        self.watch_menu.aboutToShow.connect(lambda: self.watch.fill_menu(self.watch_menu))
        self.watch.fill_menu(self.watch_menu)

        m = mb.addMenu("&AI")
        m.addAction(self.act_explain)
        m.addSeparator()
        m.addAction(self.act_ai_settings)

        m = mb.addMenu("&Help")
        m.addAction(self.act_about)

    def _build_toolbar(self) -> None:
        tb = QToolBar("Main", self)
        tb.setObjectName("main_toolbar")
        tb.setMovable(False)
        tb.setIconSize(QSize(18, 18))
        tb.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        for act in (
            self.act_open,
            self.act_events,
            self.act_reload,
            None,
            self.act_find,
            self.act_next_issue,
            self.act_goto,
            self.act_bookmark,
            None,
            self.act_follow,
            self.act_highlighters,
            None,
            self.act_explain,
        ):
            tb.addSeparator() if act is None else tb.addAction(act)
        self.toolbar = tb
        self.addToolBar(tb)

    # ---- theming -------------------------------------------------------------------------------------------------
    def _refresh_icons(self) -> None:
        dark = is_dark()
        for act in self.findChildren(QAction):
            name = act.property("iconName")
            if name:
                act.setIcon(themed_icon(name, dark))
        for i in range(self.tabs.count()):
            tab = self.tabs.widget(i)
            if isinstance(tab, LogTab):
                tab.refresh_icons()
        self.welcome.refresh(self.settings.recent_files)

    def refresh_theme(self) -> None:
        app = QApplication.instance()
        if isinstance(app, QApplication):
            app.setStyleSheet(style_sheet(is_dark()))
        self._refresh_icons()
        self.refresh_status()

    def _set_theme(self, act: QAction) -> None:
        self.settings.theme = act.data()
        app = QApplication.instance()
        if isinstance(app, QApplication):
            apply_theme(app, self.settings.theme)
        QTimer.singleShot(50, self.refresh_theme)

    # ---- files ---------------------------------------------------------------------------------------------------
    def open_servers(self) -> None:
        from .servers_dialog import ServersDialog  # noqa: PLC0415 - dialog module only needed on demand

        ServersDialog(self.settings, self).exec()

    def open_containers(self) -> None:
        from .containers_dialog import ContainersDialog  # noqa: PLC0415 - dialog module only needed on demand

        dialog = ContainersDialog(self)
        if not exec_dialog(dialog):
            return
        for source in dialog.sources():
            self._stream_container(source)

    def _stream_container(self, source: LogSource) -> None:
        """Capture ``source``'s log stream into a file and open it (live while the process keeps running)."""
        target = capture_path(container_logs_dir(), source, f"{datetime.now():%Y%m%d-%H%M%S}")
        streamer = ContainerStreamer(source, target, self)
        key = str(target.resolve()).lower()
        self._streamers[key] = streamer
        streamer.failed.connect(lambda message: self._container_failed(source, message))
        if source.follow:
            streamer.started.connect(lambda: self.open_live(str(target)))
        else:
            streamer.ended.connect(lambda: self.open_file(str(target)))
        streamer.start()

    def _container_failed(self, source: LogSource, message: str) -> None:
        self.statusBar().showMessage(f"{source.title}: {message}", 15000)
        QMessageBox.warning(self, APP_NAME, f"{source.title}\n\n{message}")

    def open_event_logs(self) -> None:
        dialog = EventLogDialog(self, self.settings.servers())
        if not exec_dialog(dialog):
            return
        queries = dialog.queries()
        if not queries:
            QMessageBox.information(self, APP_NAME, "Choose at least one event log (or an .evtx file).")
            return
        self._export_events(queries, dialog.title(), follow=dialog.keep_following)

    def _follow_events(self, queries: list[EventQuery], target: Path, since: datetime | None = None) -> None:
        """Open the export live and keep appending new events to it while its tab is open.

        ``since``: when the export started reading — events logged while it ran are picked up, not lost.
        """
        follower = EventLogFollower(queries, target, self, since=since)
        follower.failed.connect(lambda message: self.statusBar().showMessage(f"Event log follow: {message}", 10000))
        self._event_followers[str(target.resolve()).lower()] = follower
        follower.start()
        self.open_live(str(target))

    def restart_as_admin(self, extra_paths: list[str] | None = None) -> None:
        """Relaunch elevated (UAC prompt) with the open files, then close this window."""
        paths = [t.document.path for t in self.all_tabs()] + list(extra_paths or [])
        safe, reason = elevation_is_safe()
        if not safe:
            QMessageBox.information(self, APP_NAME, f"LogLens can't restart as administrator here: {reason}")
            return
        if relaunch_elevated(paths):
            self.quit_app()
        else:
            self.statusBar().showMessage("Not restarted — administrator rights were not granted.", 8000)

    def _offer_elevation(self, message: str, problems: list[str], *, extra_path: str = "") -> None:
        needs_admin = not is_admin() and any(
            "administrator" in p.lower() or "access is denied" in p.lower() or "permission" in p.lower()
            for p in problems
        )
        if not needs_admin:
            QMessageBox.information(self, APP_NAME, message)
            return
        box = QMessageBox(
            QMessageBox.Icon.Warning, APP_NAME, message + "\n\nThis needs administrator rights.", parent=self
        )
        restart = box.addButton("Restart as administrator", QMessageBox.ButtonRole.AcceptRole)
        box.addButton(QMessageBox.StandardButton.Close)
        box.exec()
        if box.clickedButton() is restart:
            self.restart_as_admin([extra_path] if extra_path else None)

    def open_evtx(self, path: str) -> None:
        """An .evtx file (double-click, Open, drag & drop): read it into an explained, searchable log tab."""
        self._export_events([EventQuery(path, is_file=True, max_events=EVTX_MAX_EVENTS)], Path(path).stem)

    def _export_events(self, queries: list[EventQuery], title: str, *, follow: bool = False) -> None:
        target = event_exports_dir() / f"EventLog {title} {datetime.now():%Y%m%d-%H%M%S}.log"
        progress = QProgressDialog("Reading event logs…", "Cancel", 0, 0, self)
        progress.setWindowTitle("Windows Event Logs")
        progress.setMinimumDuration(300)
        exporter = EventLogExporter(self)
        exporter.progress.connect(lambda channel, n: progress.setLabelText(f"Reading {channel}: {n:,} events…"))
        progress.canceled.connect(exporter.cancel)

        def done(path: str, warnings: list[str]) -> None:
            progress.close()
            if follow:
                self._follow_events(queries, Path(path), since=exporter.started_at)
            else:
                self.open_file(path)
            if warnings:
                self._offer_elevation("Some logs could not be read:\n\n" + "\n".join(warnings), warnings)

        def failed(message: str) -> None:
            progress.close()
            QMessageBox.warning(self, APP_NAME, message)

        exporter.finished.connect(done)
        exporter.failed.connect(failed)
        exporter.export(queries, target)

    def search_web(self, tab: LogTab) -> None:
        lines = tab.selected_texts()
        if not lines:
            return
        dialog = WebSearchDialog(query_parts(lines), self.settings.web_search_engine, self)
        if exec_dialog(dialog):
            self.settings.web_search_engine = dialog.chosen_engine()

    def open_dialog(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(self, "Open log files", self.settings.last_dir, LOG_FILTER)
        for p in paths:
            self.open_file(p)

    def open_file(self, path: str, codec: str | None = None) -> None:
        path = str(Path(path).resolve())
        for i in range(self.tabs.count()):
            tab = self.tabs.widget(i)
            if isinstance(tab, LogTab) and tab.document.path.lower() == path.lower():
                self.tabs.setCurrentIndex(i)
                return
        if Path(path).is_dir() or Path(path).suffix.lower() == ".zip":
            self.open_bundle(path)
            return
        if Path(path).suffix.lower() == ".evtx":
            self.open_evtx(path)
            return
        try:
            tab = LogTab(
                path,
                self.rules,
                self.font_,
                follow=self.settings.follow_by_default,
                codec=codec,
                tab_width=self.settings.tab_width,
                context_lines=self.settings.context_lines,
                knowledge=self.knowledge,
            )
        except PermissionError as exc:
            self._offer_elevation(f"Cannot open {path}:\n{exc}", [str(exc)], extra_path=path)
            return
        except OSError as exc:
            QMessageBox.warning(self, APP_NAME, f"Cannot open {path}:\n{exc}")
            return
        tab.set_wrap(self.settings.word_wrap)
        tab.set_inspector_visible(self.settings.show_inspector)
        tab.set_histogram_visible(self.settings.show_timeline)
        if self.settings.mask_secrets:
            tab.set_mask_secrets(True)
        tab.statusChanged.connect(self.refresh_status)
        tab.inspector.explainRequested.connect(lambda t=tab: self.ai.explain(t))
        tab.inspector.cancelAiRequested.connect(self.ai.cancel)
        tab.inspector.aiSettingsRequested.connect(self.ai.open_settings)
        tab.inspector.webSearchRequested.connect(lambda t=tab: self.search_web(t))
        tab.filter_panel.contextChanged.connect(self._remember_context)
        self.packs.attach(tab.filter_panel)
        tab.document.set_extra_formats(self._custom_formats())
        tab.customFormatRequested.connect(lambda t=tab: self.new_custom_format(t))
        tab.customFormatDeleteRequested.connect(self.delete_custom_format)
        tab.columnsToggled.connect(self._sync_columns_action)
        self.watch.watch_document(tab.document)
        tab.inspector.set_ai_ready(*self.ai.readiness())
        idx = self.tabs.addTab(tab, tab.title)
        self.tabs.setTabToolTip(idx, path)
        self.tabs.setCurrentIndex(idx)
        self.settings.add_recent(path)
        self._refresh_recent()
        self._update_ui()
        tab.main_view.setFocus()

    def save_share_copy(self) -> None:
        """Write the current log as a copy that is safer to send to someone else."""
        from ..services.sharecopy_jobs import ShareCopyJob  # noqa: PLC0415 - only needed on demand
        from .sharecopy_dialog import ShareCopyDialog  # noqa: PLC0415

        tab = self.current_tab()
        if tab is None:
            return
        dialog = ShareCopyDialog(tab.document.title, self)
        if not exec_dialog(dialog):
            return
        stem = Path(tab.document.path)
        target, _ = QFileDialog.getSaveFileName(
            self,
            "Save the share-safe copy",
            str(stem.with_name(stem.stem + "-shareable.log")),
            "Log text (*.log *.txt)",
        )
        if not target:
            return
        mapping = Path(target).with_suffix(".replacements.csv") if dialog.mapping.isChecked() else None
        total = tab.document.source.line_count()
        progress = QProgressDialog("Writing the copy…", "Cancel", 0, max(total, 1), self)
        progress.setWindowTitle("Share-safe copy")
        progress.setMinimumDuration(500)
        job = ShareCopyJob(self)
        job.progress.connect(lambda done, _total: progress.setValue(done))
        progress.canceled.connect(job.cancel)

        def finished(path: str, counts: object) -> None:
            progress.close()
            replaced = ", ".join(f"{n} {kind}" for kind, n in dict(counts).items()) or "nothing to replace"  # type: ignore[call-overload]
            self.statusBar().showMessage(
                f"Saved {Path(path).name}: replaced {replaced}. Check it before sharing.", 15000
            )
            job.deleteLater()

        def failed(message: str) -> None:
            progress.close()
            QMessageBox.warning(self, APP_NAME, message)
            job.deleteLater()

        job.finished.connect(finished)
        job.failed.connect(failed)
        job.run(tab.document.source, Path(target), dialog.pseudonymizer(), mapping)

    def _incident_window(self) -> IncidentWindow:
        if self._incident is None:
            self._incident = IncidentWindow(Incident(), self.show_incident_line, self)
        return self._incident

    def open_incident(self) -> None:
        window = self._incident_window()
        window.show()
        window.raise_()
        window.activateWindow()

    def pin_to_incident(self) -> None:
        """Pin the selected lines of the current log to the incident (opens it so the user sees them land)."""
        tab = self.current_tab()
        if tab is None:
            return
        first, last = tab.selected_range()
        if first < 0:
            self.statusBar().showMessage("Select the lines to pin first.", 5000)
            return
        lines = [(n, tab.document.source.get_full_line(n)) for n in range(first, last + 1)]
        window = self._incident_window()
        added = window.pin(tab.document.title, tab.document.path, lines)
        self.statusBar().showMessage(f"Pinned {added} line{'s' if added != 1 else ''} to the incident.", 5000)
        self.open_incident()

    def show_incident_line(self, path: str, source: str, line: int) -> None:
        """Jump to a pinned line: switch to its tab, or open the file again when it was closed."""
        for tab in self.all_tabs():
            if (path and tab.document.path.lower() == path.lower()) or (not path and tab.document.title == source):
                self.show_line_in_tab(tab, line)
                return
        if path and Path(path).exists():
            self.open_file(path)
            opened = self.current_tab()
            if opened is not None:
                self.show_line_in_tab(opened, line)
        else:
            self.statusBar().showMessage(f"{source} is not open and its file was not found.", 8000)

    def reapply_formats(self) -> None:
        formats = self._custom_formats()
        self._for_each_tab(lambda t: t.document.set_extra_formats(formats))

    # ---- plugins ---------------------------------------------------------------------------------------------------
    def reload_plugins(self) -> list[PluginInfo]:
        self._plugins = scan(plugins_dir(), self.settings.plugin_enabled)
        return self._plugins

    def _fill_plugin_menu(self) -> None:
        menu = self.plugin_menu
        menu.clear()
        if not self._plugins:
            self.reload_plugins()
        tab = self.current_tab()
        analyzers = [(p, a) for p in self._plugins for a in p.analyzers]
        for plugin, analyzer in analyzers:
            action = menu.addAction(f"{analyzer.title}  ({plugin.title})", partial(self.run_plugin_analyzer, analyzer))
            action.setEnabled(tab is not None)
        sources = [(p, s) for p in self._plugins for s in p.sources]
        if sources:
            if analyzers:
                menu.addSeparator()
            for plugin, source in sources:
                menu.addAction(f"Open: {source.title}  ({plugin.title})", partial(self.open_plugin_source, source))
        if analyzers or sources:
            menu.addSeparator()
        menu.addAction("&Manage plugins…", self.open_plugins)

    def open_plugins(self) -> None:
        from .plugins_dialog import PluginsDialog  # noqa: PLC0415 - dialog module only needed on demand

        dialog = PluginsDialog(plugins_dir(), self.settings, self.reload_plugins, self)
        exec_dialog(dialog)
        self.reload_plugins()
        self.reapply_formats()

    def run_plugin_analyzer(self, analyzer: Analyzer) -> None:
        """Run a plugin's analyzer over the whole current log in the background and show its report."""
        from .plugins_dialog import ReportDialog  # noqa: PLC0415

        tab = self.current_tab()
        if tab is None:
            return
        source, title = tab.document.source, tab.document.title
        total = source.line_count()
        scope = AnalysisScope(None, "the whole log")
        self.statusBar().showMessage(f"Running {analyzer.title}…")

        def work() -> object:
            return run_analyzer(analyzer, (text for _n, text in iter_lines(source, scope)))

        def done(result: object) -> None:
            self.statusBar().clearMessage()
            text = str(result) if not isinstance(result, Exception) else f"The plugin failed: {result}"
            ReportDialog(f"{analyzer.title}: {title} ({total:,} lines)", text, self).show()

        self._plugin_job = Background(self, done)
        self._plugin_job.start(work)

    def open_plugin_source(self, source: PluginSource) -> None:
        """Read a plugin source in the background, write it to a file and open that as a live-less log tab."""
        self.statusBar().showMessage(f"Reading {source.title}…")

        def work() -> object:
            lines = read_source(source)
            safe = "".join(c if c.isalnum() or c in " -_" else "_" for c in source.title).strip() or "plugin"
            target = plugin_logs_dir() / f"{safe} {datetime.now():%Y%m%d-%H%M%S}.log"
            target.write_text("\n".join(lines) + "\n", encoding="utf-8")
            return str(target)

        def done(result: object) -> None:
            self.statusBar().clearMessage()
            if isinstance(result, str):
                self.open_file(result)
            else:
                QMessageBox.warning(self, APP_NAME, f"The source could not be read: {result}")

        self._plugin_job = Background(self, done)
        self._plugin_job.start(work)

    def open_rundiff(self) -> None:
        from .rundiff_dialog import RunDiffDialog  # noqa: PLC0415 - dialog module only needed on demand

        if self._rundiff is None:
            self._rundiff = RunDiffDialog(self.all_tabs, self.show_line_in_tab, self)
        self._rundiff.refresh()
        self._rundiff.show()
        self._rundiff.raise_()
        self._rundiff.activateWindow()

    def open_trace(self) -> None:
        """Follow the id on the selected line (or a typed one) through every open log."""
        from .trace_dialog import TraceDialog, candidate_ids  # noqa: PLC0415 - dialog module only needed on demand

        tab = self.current_tab()
        ids = candidate_ids(tab.selected_texts()) if tab is not None else []
        dialog = TraceDialog(self.all_tabs, self.show_line_in_tab, ids[0] if ids else "", ids, self)
        dialog.show()
        self._trace_dialog = dialog
        if ids:
            dialog.run()

    def show_line_in_tab(self, tab: LogTab, line: int) -> None:
        self.tabs.setCurrentWidget(tab)
        tab.main_view.go_to_row(line)
        tab.main_view.setFocus()

    def ask_in_plain_words(self) -> None:
        """A sentence becomes the current log's filter (levels, words to include / exclude, a time range)."""
        from ..core.packs import SavedFilter  # noqa: PLC0415
        from ..core.timeparse import parse_line_time  # noqa: PLC0415
        from .plain_search_dialog import PlainSearchDialog  # noqa: PLC0415 - dialog module only needed on demand

        tab = self.current_tab()
        if tab is None:
            return
        total = tab.document.source.line_count()
        last = next(
            (
                m
                for line in reversed(tab.document.source.get_lines(max(total - 50, 0), 50))
                if (m := parse_line_time(line))
            ),
            None,
        )
        dialog = PlainSearchDialog(last, self)
        if not exec_dialog(dialog):
            return
        query, panel = dialog.query, tab.filter_panel
        panel.set_time_range(query.time_range)
        panel.apply_saved(SavedFilter("Plain words", tuple(query.terms), tuple(query.levels)))

    def open_diagnosis(self) -> None:
        from .diagnose_dialog import DiagnoseDialog  # noqa: PLC0415 - dialog module only needed on demand

        if self._diagnosis is None:
            self._diagnosis = DiagnoseDialog(self.knowledge, self.open_lines, self.open_file, self)
        self._diagnosis.set_servers(self.settings.servers())
        self._diagnosis.show()
        self._diagnosis.raise_()
        self._diagnosis.activateWindow()

    def open_dashboard(self) -> None:
        from .dashboard import DashboardWindow  # noqa: PLC0415 - window module only needed on demand

        if self._dashboard is None:
            self._dashboard = DashboardWindow(
                self.all_tabs,
                self.tabs.setCurrentWidget,
                self.watch.watched_services,
                self.watch.set_watched_services,
                self,
                mask_secrets=lambda: self.settings.mask_secrets,
            )
        self._dashboard.show()
        self._dashboard.raise_()

    def find_in_all(self) -> None:
        if self._find_all is None:
            self._find_all = FindAllDialog(
                self.all_tabs,
                lambda tab, line: self.show_line(tab.document, line),
                self,
                mask_secrets=lambda: self.settings.mask_secrets,
            )
            tab = self.current_tab()
            if tab is not None:
                self._find_all.query.setText(tab.filter_panel.edit.text())
        self._find_all.show()
        self._find_all.raise_()
        self._find_all.query.setFocus()

    def open_bundle_dialog(self) -> None:
        box = QMessageBox(QMessageBox.Icon.Question, APP_NAME, "Open a folder of logs or a zip file?", parent=self)
        folder = box.addButton("Folder…", QMessageBox.ButtonRole.AcceptRole)
        archive = box.addButton("Zip file…", QMessageBox.ButtonRole.AcceptRole)
        box.addButton(QMessageBox.StandardButton.Cancel)
        box.exec()
        if box.clickedButton() is folder:
            path = QFileDialog.getExistingDirectory(self, "Folder of logs", self.settings.last_dir)
        elif box.clickedButton() is archive:
            path, _ = QFileDialog.getOpenFileName(self, "Zip of logs", self.settings.last_dir, "Zip files (*.zip)")
        else:
            return
        if path:
            self.open_bundle(path)

    def open_bundle(self, path: str) -> None:
        """List the logs of a folder or zip (zips are extracted safely first) and let the user pick what to open."""
        source = Path(path)
        target = event_exports_dir().parent / "bundles" / f"{source.stem} {datetime.now():%Y%m%d-%H%M%S}"
        loader = BundleLoader(self)
        self.statusBar().showMessage(f"Reading {source.name}…")

        def loaded(title: str, files: list[BundleFile]) -> None:
            self.statusBar().clearMessage()
            if not files:
                QMessageBox.information(self, APP_NAME, f"No log files found in {title}.")
                return
            dialog = BundleDialog(title, files, self)
            if not exec_dialog(dialog):
                return
            chosen = dialog.selected()
            for file in chosen:
                self.open_file(file)
            if dialog.merge.isChecked() and len(chosen) > 1:
                QTimer.singleShot(500, lambda: self.build_timeline(preselect=chosen))

        loader.loaded.connect(loaded)
        loader.failed.connect(lambda message: QMessageBox.warning(self, APP_NAME, message))
        loader.load(source, target)

    def merge_open_logs(self) -> None:
        self.build_timeline()

    def build_timeline(self, preselect: list[str] | None = None) -> None:
        tabs = self.all_tabs()
        if preselect:
            wanted = {str(Path(p).resolve()).lower() for p in preselect}
            tabs = [t for t in tabs if t.document.path.lower() in wanted] or tabs
        if not tabs:
            return
        dialog = TimelineDialog(tabs, self)
        if not exec_dialog(dialog) or not dialog.selected():
            return
        chosen = dialog.selected()
        sources = [TimelineSource(t.document.title, t.document.source, t.document.clock, t.document.records.starts)
                   for t in chosen]  # fmt: skip
        window = None
        if dialog.events.isChecked():
            bounds = [b for t in chosen for b in t.document.time_bounds() if b is not None]
            window = (min(bounds), max(bounds)) if bounds else None
        target = event_exports_dir() / f"Timeline {datetime.now():%Y%m%d-%H%M%S}.log"
        progress = QProgressDialog("Merging logs by time…", "Cancel", 0, 0, self)
        progress.setWindowTitle("Timeline")
        progress.setMinimumDuration(300)
        builder = TimelineBuilder(self)
        builder.progress.connect(lambda n: progress.setLabelText(f"Merging logs by time… {n:,} lines"))
        progress.canceled.connect(builder.cancel)

        def finished(path: str, truncated: bool) -> None:
            progress.close()
            self.open_file(path)
            if truncated:
                QMessageBox.information(self, APP_NAME, "The timeline was cut at 10 million lines.")

        def failed(message: str) -> None:
            progress.close()
            QMessageBox.warning(self, APP_NAME, message)

        builder.finished.connect(finished)
        builder.failed.connect(failed)
        builder.build(sources, target, events_window=window)

    def open_lines(self, lines: list[str], title: str) -> None:
        """Write ``lines`` to a new file in the exports folder and open it (evidence, selections, …)."""
        safe = "".join(c if c.isalnum() or c in " -_." else "_" for c in title)[:60].strip() or "lines"
        target = event_exports_dir() / f"{safe} {datetime.now():%Y%m%d-%H%M%S}.log"
        try:
            target.write_text("\n".join(lines) + "\n", encoding="utf-8")
        except OSError as exc:
            QMessageBox.warning(self, APP_NAME, f"Could not write {target}:\n{exc}")
            return
        self.open_file(str(target))

    def open_knowledge_base(self) -> None:
        from .kb_dialog import KnowledgeDialog  # noqa: PLC0415 - dialog module only needed on demand

        exec_dialog(KnowledgeDialog(self.knowledge, self))

    def analyze(self, page: str) -> None:
        """Open (or bring up) the analysis window of the current tab on ``page``."""
        tab = self.current_tab()
        if tab is None:
            return
        window = self._analysis.get(id(tab))
        if window is None:
            window = AnalysisWindow(tab, self, others=self.all_tabs, show_tab=self.tabs.setCurrentWidget)
            window.aggregateRequested.connect(
                lambda patterns, scope, t=tab: self.ai.explain_patterns(t, patterns, scope)
            )
            self._analysis[id(tab)] = window
        window.show_page(page)

    def close_tab(self, index: int) -> None:
        tab = self.tabs.widget(index)
        if isinstance(tab, LogTab):
            self.ai.forget(tab)
            follower = self._event_followers.pop(tab.document.path.lower(), None)
            if follower is not None:
                follower.stop()
                follower.deleteLater()
            streamer = self._streamers.pop(str(Path(tab.document.path).resolve()).lower(), None)
            if streamer is not None:
                streamer.stop()
                streamer.deleteLater()
            analysis = self._analysis.pop(id(tab), None)
            if analysis is not None:
                analysis.shutdown()  # cancel running analyses of the closing tab
                analysis.close()
                analysis.deleteLater()
            tab.close_tab()
        self.tabs.removeTab(index)
        if tab is not None:
            tab.deleteLater()
        self._update_ui()

    def current_tab(self) -> LogTab | None:
        tab = self.tabs.currentWidget()
        return tab if isinstance(tab, LogTab) else None

    def _with_tab(self, action: Callable[[LogTab], object]) -> None:
        """Run ``action`` on the current tab, if there is one."""
        tab = self.current_tab()
        if tab is not None:
            action(tab)

    def _refresh_recent(self) -> None:
        self.recent_menu.clear()
        for path in self.settings.recent_files:
            act = self.recent_menu.addAction(path)
            act.triggered.connect(lambda _=False, p=path: self.open_file(p))
        self.recent_menu.setEnabled(bool(self.settings.recent_files))
        self.welcome.refresh(self.settings.recent_files)

    # ---- drag & drop ---------------------------------------------------------------------------------------------
    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent) -> None:
        for url in event.mimeData().urls():
            if url.isLocalFile():
                self.open_file(url.toLocalFile())

    # ---- view actions --------------------------------------------------------------------------------------------
    def _copy(self) -> None:
        if copy_from_focused_text():
            return
        tab = self.current_tab()
        if tab is None:
            return
        view = tab.filtered_view if tab.filtered_view.hasFocus() else tab.main_view
        view.copy_selection()

    def _toggle_follow(self, checked: bool) -> None:
        tab = self.current_tab()
        if tab is not None:
            tab.set_follow(checked)

    def all_tabs(self) -> list[LogTab]:
        return [t for i in range(self.tabs.count()) if isinstance(t := self.tabs.widget(i), LogTab)]

    def _for_each_tab(self, fn: Callable[[LogTab], object]) -> None:
        for i in range(self.tabs.count()):
            tab = self.tabs.widget(i)
            if isinstance(tab, LogTab):
                fn(tab)

    def _toggle_wrap(self, checked: bool) -> None:
        self.settings.word_wrap = checked
        self._for_each_tab(lambda t: t.set_wrap(checked))

    def _toggle_inspector(self, checked: bool) -> None:
        self.settings.show_inspector = checked
        self._for_each_tab(lambda t: t.set_inspector_visible(checked))

    def _on_ai_busy(self, busy: bool, text: str) -> None:
        """Keep the request visible: status bar text, and the Inspector shown if it was hidden."""
        if busy and not self._ai_busy and not self.act_inspector.isChecked():
            self.act_inspector.trigger()  # once per request: the user may hide it again while waiting
        self._ai_busy = busy
        if text:
            self.statusBar().showMessage(text, 0 if busy else 8000)
        else:
            self.statusBar().clearMessage()

    def _sync_columns_action(self, visible: bool) -> None:
        tab = self.current_tab()
        if tab is not None and tab.columns_visible == visible:
            self.act_columns.setChecked(visible)

    def _custom_formats(self) -> list[LogFormat]:
        out = [fmt for plugin in self._plugins for fmt in plugin.formats]
        for custom in self.settings.custom_formats():
            try:
                out.append(custom.to_format())
            except FormatError as exc:
                log.warning("custom format %s unusable: %s", custom.name, exc)
        return out

    def new_custom_format(self, tab: LogTab) -> None:
        dialog = FormatDialog(tab.document.format_context(PREVIEW_LINES), parent=self)
        if not exec_dialog(dialog):
            return
        custom = dialog.custom_format()
        kept = [f for f in self.settings.custom_formats() if f.name != custom.name]
        self.settings.set_custom_formats([*kept, custom])
        self.settings.save()
        formats = self._custom_formats()
        self._for_each_tab(lambda t: t.document.set_extra_formats(formats))
        tab.document.set_format(custom.to_format())
        tab.set_columns_visible(True)

    def delete_custom_format(self, name: str) -> None:
        self.settings.set_custom_formats([f for f in self.settings.custom_formats() if f.name != name])
        self.settings.save()
        formats = self._custom_formats()
        for tab in self.all_tabs():
            tab.document.set_extra_formats(formats)
            current = tab.document.log_format
            if tab.document.format_chosen and current is not None and current.display_name == name:
                tab.document.set_format(None)
            tab.document.detect_again()

    def _toggle_mask(self, checked: bool) -> None:
        self.settings.mask_secrets = checked
        self._for_each_tab(lambda t: t.set_mask_secrets(checked))

    def _toggle_timeline(self, checked: bool) -> None:
        self.settings.show_timeline = checked
        self._for_each_tab(lambda t: t.set_histogram_visible(checked))

    def _remember_context(self, lines: int) -> None:
        self.settings.context_lines = lines

    def _refresh_ai_state(self) -> None:
        ready = self.ai.readiness()
        self._for_each_tab(lambda t: t.inspector.set_ai_ready(*ready))

    def edit_highlighters(self) -> None:
        dlg = HighlighterDialog(self.rules, self)
        if exec_dialog(dlg):
            self.apply_rules(dlg.rules())

    def apply_rules(self, rules: list[HighlightRule]) -> None:
        self.rules = rules
        self.settings.set_rules(self.rules)
        self.settings.save()
        self._for_each_tab(lambda t: t.set_rules(self.rules))

    def _set_encoding(self, act: QAction) -> None:
        tab = self.current_tab()
        if tab is not None:
            tab.reload(codec=act.data() or "")  # "" = auto-detect
            self._update_ui()

    def _zoom(self, delta: int) -> None:
        size = 10 if delta == 0 else max(6, min(32, self.settings.font_size + delta))
        self.settings.font_size = size
        self.font_ = monospace_font(self.settings.font_family, size)
        self._for_each_tab(lambda t: t.set_font(self.font_))

    def _cycle_tab(self, step: int) -> None:
        if self.tabs.count():
            self.tabs.setCurrentIndex((self.tabs.currentIndex() + step) % self.tabs.count())

    def _about(self) -> None:
        box = QMessageBox(self)
        box.setWindowTitle(f"About {APP_NAME}")
        box.setIconPixmap(logo_pixmap(72))
        box.setText(
            f"<h3>{APP_NAME} {__version__}</h3><p>Fast log viewer & analyzer for Windows with Event Log "
            "correlation, diagnosis and live watch.</p>"
        )
        box.exec()

    # ---- state ---------------------------------------------------------------------------------------------------
    def _on_tab_changed(self, _index: int) -> None:
        self._update_ui()

    def _update_ui(self) -> None:
        tab = self.current_tab()
        self.stack.setCurrentWidget(self.tabs if self.tabs.count() else self.welcome)
        for act in (
            self.act_reload,
            self.act_export,
            self.act_report,
            self.act_close,
            self.act_copy,
            self.act_find,
            self.act_next,
            self.act_prev,
            self.act_goto,
            self.act_goto_time,
            self.act_time_range,
            self.act_clock,
            self.act_bookmark,
            self.act_next_bm,
            self.act_prev_bm,
            self.act_follow,
            self.act_next_issue,
            self.act_prev_issue,
        ):
            act.setEnabled(tab is not None)
        self.act_follow.setChecked(bool(tab and tab.follow))
        self.act_columns.setChecked(bool(tab and tab.columns_visible))
        if tab is not None:
            want = tab.document.source.forced_codec or ""
            for act in self.encoding_group.actions():
                act.setChecked(act.data() == want)
            self.setWindowTitle(f"{tab.title} — {APP_NAME}")
        else:
            self.setWindowTitle(APP_NAME)
        self.refresh_status()

    def refresh_status(self) -> None:
        tab = self.current_tab()
        if tab is None:
            self.status_pos.setText("")
            self._set_pills([])
            return
        doc = tab.document
        row = tab.main_view.current_row()
        count = doc.source.line_count()
        position = f"Ln {row + 1:,} / {count:,}" if row >= 0 else f"{count:,} lines"
        bookmarks = len(doc.bookmarks)
        if bookmarks:
            position += f"   ·   {bookmarks} bookmark{'s' if bookmarks != 1 else ''}"
        self.status_pos.setText(position)
        self._set_pills([s for s in doc.mark_summaries() if s.count])

    def _set_pills(self, pills: list[MarkSummary]) -> None:
        while len(self._pills) < len(pills):
            b = QToolButton(self.pill_box)
            b.setObjectName("statusPill")
            b.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.clicked.connect(lambda _=False, btn=b: self._pill_clicked(btn))
            self.pill_layout.addWidget(b)
            self._pills.append(b)
        for b, summary in zip(self._pills, pills, strict=False):
            color = QColor(summary.color)
            color.setAlpha(255)
            b.setIcon(QIcon(dot_pixmap(color.name())))
            b.setText(f"{summary.count:,} {summary.name}")
            b.setToolTip(f"Jump to the next '{summary.name}' line (Shift+click: previous)")
            b.setProperty("ruleIndex", summary.rule_index)
            b.show()
        for b in self._pills[len(pills) :]:
            b.hide()

    def _pill_clicked(self, button: QToolButton) -> None:
        tab = self.current_tab()
        if tab is None:
            return
        forward = not (QGuiApplication.keyboardModifiers() & Qt.KeyboardModifier.ShiftModifier)
        tab.next_marked(button.property("ruleIndex"), forward)
        tab.main_view.setFocus()

    def _restore_geometry(self) -> None:
        if self.settings.window_geometry:
            self.restoreGeometry(QByteArray.fromBase64(self.settings.window_geometry.encode()))
        if self.settings.window_state:
            self.restoreState(QByteArray.fromBase64(self.settings.window_state.encode()))

    def quit_app(self) -> None:
        """Really quit (also when 'keep running in the notification area' is on)."""
        self._quitting = True
        self.close()

    def open_live(self, path: str) -> None:
        """Open ``path`` (or switch to it) and follow its end."""
        self.open_file(path)
        tab = self.current_tab()
        if tab is not None and Path(tab.document.path).resolve() == Path(path).resolve():
            tab.set_follow(True)
            self._update_ui()

    def show_line(self, document: object, line: int) -> None:
        """Bring the tab showing ``document`` to the front and select ``line``."""
        for i in range(self.tabs.count()):
            tab = self.tabs.widget(i)
            if isinstance(tab, LogTab) and tab.document is document:
                self.tabs.setCurrentIndex(i)
                tab.main_view.go_to_row(line)
                tab.main_view.setFocus()
                return

    def closeEvent(self, event: QCloseEvent) -> None:
        if self.watch.keeps_running and not self._quitting:
            event.ignore()
            self.hide()
            if not self._told_about_tray:
                self._told_about_tray = True
                self.watch.notify(APP_NAME, "Still watching your logs here. Right-click the icon → Quit to exit.")
            return
        if self.watch.tray is not None:
            self.watch.tray.hide()
        for streamer in self._streamers.values():
            streamer.stop()  # do not leave docker / kubectl processes running after the app closes
        self.settings.window_geometry = _to_base64(self.saveGeometry())
        self.settings.window_state = _to_base64(self.saveState())
        try:
            self.settings.save()
        except OSError as exc:
            log.warning("could not save settings: %s", exc)
        self._for_each_tab(lambda t: t.close_tab())
        super().closeEvent(event)

    def receive_files(self, paths: list[str]) -> None:
        """Files handed over by another launch (Explorer "Open with", double-click): open them and come to the front."""
        if self.isMinimized():
            self.showNormal()
        self.raise_()
        self.activateWindow()
        self.open_later(paths)

    def open_later(self, paths: list[str]) -> None:
        def open_all() -> None:
            for path in paths:
                self.open_file(path)

        QTimer.singleShot(0, open_all)


def _to_base64(data: QByteArray) -> str:
    return bytes(data.toBase64().data()).decode("ascii")
