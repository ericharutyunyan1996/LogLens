"""Inspector — right-hand panel for the selected line.

Tabs: Details (knowledge-base explanation + decoded payloads), Raw, Windows (events logged around the line's time),
AI (explanation on request). The panel only renders; the owning tab supplies data and handles the request signals.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, QUrl, Signal
from PySide6.QtGui import QColor, QFont, QGuiApplication
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTabWidget,
    QTextBrowser,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..core.ai.explain import Explanation
from ..core.kb import Finding
from ..core.payload_tree import COLLAPSE_CHARS
from ..core.payloads import MAX_ANALYZED_CHARS, Section, analyze
from ..core.secrets import find_secrets, has_secrets
from ..core.winevent.entities import extract
from ..core.winevent.models import EventRecord, record_from_line
from ..services.knowledge_service import KnowledgeService
from .detail_render import DARK, LIGHT, LineHeader, Palette, render_details, render_explanation, render_secrets
from .payload_view import PayloadStructure
from .theme import is_dark

DETAILS_PLACEHOLDER = "Select a line to inspect it — JSON, XML, URLs, SQL, tokens and fields are decoded here."
LEVEL_COLORS = {1: "#E0204A", 2: "#E5484D", 3: "#F5A524"}
TAB_DETAILS, TAB_RAW, TAB_WINDOWS, TAB_AI = range(4)


def _browser(parent: QWidget) -> QTextBrowser:
    browser = QTextBrowser(parent)
    browser.setOpenLinks(False)
    browser.setFrameShape(QTextBrowser.Shape.NoFrame)
    return browser


def _small_button(text: str, parent: QWidget) -> QPushButton:
    button = QPushButton(text, parent)
    button.setObjectName("smallButton")
    return button


class Inspector(QWidget):
    lineRequested = Signal(int)  # 0-based file line
    explainRequested = Signal()
    aiSettingsRequested = Signal()
    webSearchRequested = Signal()
    relatedRequested = Signal(int)  # minutes around the line's timestamp
    teachRequested = Signal()  # add the selected line to the user's knowledge base
    cancelAiRequested = Signal()
    saveAnswerRequested = Signal()  # keep the AI answer in the knowledge base

    def __init__(self, font: QFont, knowledge: KnowledgeService, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("inspector")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self._knowledge = knowledge
        self._sections: list[Section] = []
        self._raw = ""
        self._events: list[EventRecord] = []
        self._explanation: Explanation | None = None
        self._ai_ready_message = ""

        title = QLabel("Inspector", self)
        title.setObjectName("inspectorTitle")
        search = _small_button("Search web", self)
        search.setToolTip("Search the web for this error (you can edit the query first)")
        search.clicked.connect(self.webSearchRequested)
        copy_line = _small_button("Copy line", self)
        copy_line.clicked.connect(lambda: QGuiApplication.clipboard().setText(self._raw))
        teach = _small_button("Add to KB", self)
        teach.setToolTip("Explain this line in your own knowledge base, so LogLens recognises it next time")
        teach.clicked.connect(self.teachRequested)
        clear = _small_button("Clear", self)
        clear.setToolTip("Clear everything shown in the Inspector (details, Windows events, AI answer)")
        clear.clicked.connect(self.clear)
        head = QHBoxLayout()
        head.setContentsMargins(10, 8, 8, 4)
        head.addWidget(title)
        head.addStretch(1)
        head.addWidget(search)
        head.addWidget(copy_line)
        head.addWidget(teach)
        head.addWidget(clear)

        self.details = _browser(self)
        self.details.anchorClicked.connect(self._on_anchor)
        self.details.setPlaceholderText(DETAILS_PLACEHOLDER)
        self.raw = QPlainTextEdit(self)
        self.raw.setReadOnly(True)
        self.raw.setFrameShape(QPlainTextEdit.Shape.NoFrame)
        self.raw.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        self.tabs = QTabWidget(self)
        self.tabs.setDocumentMode(True)
        self.structure = PayloadStructure(self)  # JSON / XML too big to print: a collapsed, expandable tree
        self.details_split = QSplitter(Qt.Orientation.Vertical, self)
        self.details_split.addWidget(self.details)
        self.details_split.addWidget(self.structure)
        self.details_split.setSizes([260, 420])
        self.tabs.addTab(self.details_split, "Details")
        self.tabs.addTab(self.raw, "Raw")
        self.tabs.addTab(self._build_windows_tab(), "Windows")
        self.tabs.addTab(self._build_ai_tab(), "AI")
        self.set_font(font)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addLayout(head)
        layout.addWidget(self.tabs, 1)

    # ---- construction --------------------------------------------------------------------------------------------
    def _build_windows_tab(self) -> QWidget:
        page = QWidget(self)
        intro = QLabel("What did Windows log around this line's time? (Application + System errors and warnings)", page)
        intro.setWordWrap(True)
        intro.setObjectName("aiStatus")
        self.minutes = QSpinBox(page)
        self.minutes.setRange(1, 24 * 60)
        self.minutes.setValue(5)
        self.minutes.setSuffix(" min")
        self.minutes.setPrefix("± ")
        find = QPushButton("Find Windows events", page)
        find.setObjectName("primary")
        find.clicked.connect(lambda: self.relatedRequested.emit(self.minutes.value()))
        row = QHBoxLayout()
        row.addWidget(self.minutes)
        row.addWidget(find)
        row.addStretch(1)
        self.related_status = QLabel(page)
        self.related_status.setWordWrap(True)
        self.related_status.setObjectName("aiStatus")
        self.related = QTreeWidget(page)
        self.related.setHeaderLabels(["Time", "Level", "Source", "ID", "Meaning"])
        self.related.setRootIsDecorated(False)
        self.related.setUniformRowHeights(True)
        self.related.header().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.related.header().setStretchLastSection(True)
        self.related.currentItemChanged.connect(self._show_related_event)
        self.related_details = _browser(page)
        split = QSplitter(Qt.Orientation.Vertical, page)
        split.addWidget(self.related)
        split.addWidget(self.related_details)
        split.setSizes([200, 260])
        layout = QVBoxLayout(page)
        layout.setContentsMargins(10, 10, 10, 6)
        layout.addWidget(intro)
        layout.addLayout(row)
        layout.addWidget(self.related_status)
        layout.addWidget(split, 1)
        return page

    def _build_ai_tab(self) -> QWidget:
        page = QWidget(self)
        self.ai_status = QLabel(page)
        self.ai_status.setWordWrap(True)
        self.ai_status.setObjectName("aiStatus")
        self.explain_btn = QPushButton("Explain with AI", page)
        self.explain_btn.setObjectName("primary")
        self.explain_btn.setToolTip("Explain the selected line(s); you review and can edit what is sent")
        self.explain_btn.clicked.connect(self.explainRequested)
        settings = _small_button("AI settings…", page)
        settings.clicked.connect(self.aiSettingsRequested)
        self.save_answer_btn = _small_button("Save to knowledge base…", page)
        self.save_answer_btn.setToolTip("Review the answer and keep it, so it shows offline next time")
        self.save_answer_btn.clicked.connect(self.saveAnswerRequested)
        self.save_answer_btn.setEnabled(False)
        self.cancel_ai_btn = _small_button("Cancel", page)
        self.cancel_ai_btn.setToolTip("Stop waiting for this answer")
        self.cancel_ai_btn.clicked.connect(self.cancelAiRequested)
        self.cancel_ai_btn.hide()
        self.ai_progress = QProgressBar(page)
        self.ai_progress.setRange(0, 0)  # indeterminate: the provider gives no percentage
        self.ai_progress.setTextVisible(False)
        self.ai_progress.setMaximumHeight(6)
        self.ai_progress.hide()
        buttons = QHBoxLayout()
        buttons.addWidget(self.explain_btn)
        buttons.addWidget(self.cancel_ai_btn)
        buttons.addWidget(settings)
        buttons.addWidget(self.save_answer_btn)
        buttons.addStretch(1)
        self.ai_result = _browser(page)
        self.ai_result.anchorClicked.connect(self._on_anchor)
        layout = QVBoxLayout(page)
        layout.setContentsMargins(10, 10, 10, 6)
        layout.addWidget(self.ai_status)
        layout.addWidget(self.ai_progress)
        layout.addLayout(buttons)
        layout.addWidget(self.ai_result, 1)
        return page

    # ---- line details --------------------------------------------------------------------------------------------
    def set_font(self, font: QFont) -> None:
        self.raw.setFont(font)  # raw text: the log font; formatted views: UI font with monospace code blocks
        for browser in (self.details, self.ai_result, self.related_details):
            browser.document().setDefaultFont(QGuiApplication.font())

    @staticmethod
    def palette_for_theme() -> Palette:
        return DARK if is_dark() else LIGHT

    def show_line(self, header: LineHeader | None, text: str, findings: list[Finding] | None = None) -> None:
        self._raw = text
        self.raw.setPlainText(text)
        if header is None:
            self._sections = []
            self.details.clear()
            self.structure.clear()
            return
        record = record_from_line(text)
        facts = extract(record).items() if record is not None else None
        analysis = analyze(text)
        body, self._sections = render_details(
            header, analysis, self.palette_for_theme(), findings, facts, collapse_chars=COLLAPSE_CHARS
        )
        big = len(text) > MAX_ANALYZED_CHARS or any(
            s.kind in ("JSON", "XML") and len(s.body) > COLLAPSE_CHARS for s in self._sections
        )
        if big:
            self.structure.show_for(text)
        else:
            self.structure.clear()
        if has_secrets(text):
            body = render_secrets(find_secrets(text), self.palette_for_theme()) + body
        self.details.setHtml(body)

    def clear(self) -> None:
        """Empty every tab (the next selected line fills Details/Raw again)."""
        self.structure.clear()
        self._raw = ""
        self._sections = []
        self._events = []
        self._explanation = None
        self.save_answer_btn.setEnabled(False)
        for browser in (self.details, self.related_details, self.ai_result):
            browser.clear()
        self.raw.clear()
        self.related.clear()
        self.related_status.setText("")
        self.ai_status.setText(self._ai_ready_message)

    # ---- related Windows events ----------------------------------------------------------------------------------
    def show_related_busy(self, message: str) -> None:
        self.related.clear()
        self.related_details.clear()
        self.related_status.setText(message)
        self.tabs.setCurrentIndex(TAB_WINDOWS)

    def show_related_error(self, message: str) -> None:
        self.related_status.setText(f"⚠ {message}")
        self.tabs.setCurrentIndex(TAB_WINDOWS)

    def show_related(self, events: list[EventRecord], warnings: list[str], window: str) -> None:
        self._events = events
        self.related.clear()
        for index, event in enumerate(events):
            findings = self._knowledge.lookup_event(event.provider, event.event_id)
            meaning = findings[0].title if findings else " ".join(event.text().split())[:120]
            local = event.time_created.astimezone()
            item = QTreeWidgetItem(
                [local.strftime("%H:%M:%S"), event.level_name, event.provider, str(event.event_id), meaning]
            )
            item.setData(0, Qt.ItemDataRole.UserRole, index)
            color = LEVEL_COLORS.get(event.level)
            if color:
                item.setForeground(1, QColor(color))
            self.related.addTopLevelItem(item)
        notes = "  ·  ".join(warnings)
        summary = f"{len(events)} error/warning events {window}." if events else f"No errors or warnings {window}."
        self.related_status.setText(summary + (f"  ⚠ {notes}" if notes else ""))
        first = self.related.topLevelItem(0)
        if first is not None:
            self.related.setCurrentItem(first)
        self.tabs.setCurrentIndex(TAB_WINDOWS)

    def _show_related_event(self, item: QTreeWidgetItem | None, _previous: QTreeWidgetItem | None) -> None:
        if item is None:
            return
        event = self._events[int(item.data(0, Qt.ItemDataRole.UserRole))]
        line = event.to_line()
        local = event.time_created.astimezone()
        header = LineHeader(
            0,
            local.strftime("%Y-%m-%d %H:%M:%S"),
            event.level_name,
            LEVEL_COLORS.get(event.level, ""),
            title=f"{event.channel} · {event.provider} ({event.event_id})",
        )
        body, _sections = render_details(
            header, analyze(line), self.palette_for_theme(), self._knowledge.explain(line), extract(event).items()
        )
        self.related_details.setHtml(body)

    # ---- AI ------------------------------------------------------------------------------------------------------
    def set_ai_ready(self, ready: bool, message: str) -> None:
        self._ai_ready_message = message
        self.explain_btn.setEnabled(ready)
        self.ai_status.setText(message)

    def show_ai_busy(self, message: str) -> None:
        self.explain_btn.setEnabled(False)
        self.explain_btn.setText("Asking…")
        self.cancel_ai_btn.show()
        self.ai_progress.show()
        self.save_answer_btn.setEnabled(False)
        self.set_ai_progress(message)
        self.tabs.setCurrentIndex(TAB_AI)

    def set_ai_progress(self, message: str, elapsed_s: int | None = None) -> None:
        """Phase of the running request, e.g. "Waiting for the answer… · 12 s"."""
        suffix = f"  ·  {elapsed_s} s" if elapsed_s is not None else ""
        self.ai_status.setText(f"⏳ {message}{suffix}")
        palette = self.palette_for_theme()
        self.ai_result.setHtml(
            f'<p style="color:{palette.muted};margin-top:24px;" align="center">⏳<br>{message}{suffix}<br><br>'
            "The answer appears here. You can keep working meanwhile.</p>"
        )

    def _ai_idle(self) -> None:
        self.explain_btn.setEnabled(True)
        self.explain_btn.setText("Explain with AI")
        self.cancel_ai_btn.hide()
        self.ai_progress.hide()

    @property
    def last_explanation(self) -> Explanation | None:
        """The AI answer currently shown (for reports / saving to the knowledge base)."""
        return self._explanation

    @property
    def related_events(self) -> list[EventRecord]:
        return list(self._events)

    def show_ai_result(self, explanation: Explanation, subject: str = "") -> None:
        self._explanation = explanation
        self.save_answer_btn.setEnabled(True)
        self._ai_idle()
        self.ai_status.setText(f"Answer for {subject} — click a cited line to jump to it." if subject else "")
        self.ai_result.setHtml(render_explanation(explanation, self.palette_for_theme()))
        self.tabs.setCurrentIndex(TAB_AI)

    def refresh_theme(self) -> None:
        """Re-render HTML that carries theme colours (AI answer, Windows event details) after a light/dark switch."""
        if self._explanation is not None and not self.ai_result.toPlainText().startswith("⏳"):
            self.ai_result.setHtml(render_explanation(self._explanation, self.palette_for_theme()))
        current = self.related.currentItem()
        if current is not None:
            self._show_related_event(current, None)

    def show_ai_error(self, message: str) -> None:
        self._ai_idle()
        if self.ai_result.toPlainText().startswith("⏳"):
            self.ai_result.clear()
        self.ai_status.setText(f"⚠ {message}")
        self.tabs.setCurrentIndex(TAB_AI)

    # ---- links ---------------------------------------------------------------------------------------------------
    def _on_anchor(self, url: QUrl) -> None:
        scheme, _, value = url.toString().partition(":")
        if scheme == "copy" and value.isdigit() and int(value) < len(self._sections):
            QGuiApplication.clipboard().setText(self._sections[int(value)].body)
        elif scheme == "line" and value.isdigit():
            self.lineRequested.emit(int(value) - 1)
