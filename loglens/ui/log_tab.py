"""LogTab — the widget for one open log.

Layout: file header on top; left = main view over the filter panel and its results; right = Inspector.
All state and background work live in :class:`~loglens.services.log_document.LogDocument`; this class lays out
widgets, forwards user actions to the document and re-renders on its signals.
"""

from __future__ import annotations

from datetime import datetime
from functools import partial
from pathlib import Path

import numpy as np
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont, QGuiApplication
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QMenu,
    QMessageBox,
    QProgressBar,
    QProgressDialog,
    QSizePolicy,
    QSplitter,
    QStackedWidget,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from ..core.ansi import strip_ansi
from ..core.filters import FilterSpec, TimeRange
from ..core.highlight import HighlightRule
from ..core.kb import KnowledgeStoreError, entry_from_explanation, signature_of
from ..core.search import SearchQuery
from ..core.secrets import mask
from ..core.timestamps import find_timestamp
from ..core.units import human_size
from ..core.winevent.models import EventRecord
from ..services.eventlog_jobs import RelatedEventsFinder
from ..services.export_jobs import LineExporter
from ..services.knowledge_service import KnowledgeService
from ..services.log_document import LogDocument
from .columns_view import ColumnsModel, ColumnsView
from .detail_render import LineHeader
from .filter_panel import FilterPanel, LevelOption
from .histogram_view import HistogramView
from .icons import themed_icon
from .inspector import Inspector
from .kb_entry_dialog import KBEntryDialog
from .log_view import BOOKMARK_COLOR, SEARCH_BG, LogView
from .models import FilteredLines, SourceLines
from .qt_utils import exec_dialog
from .report_dialog import ReportDialog
from .theme import is_dark
from .time_dialogs import ClockDialog, GoToTimeDialog, TimeRangeDialog

MAX_BOOKMARK_SELECTION = 10_000
EXPORT_FILTERS = "Log text (*.log *.txt);;CSV — line, time, level, text (*.csv);;JSON Lines (*.jsonl *.json)"
MAX_COPY_LINES = 200_000
MAX_SELECTED_LINES = 50  # lines handed to web search / AI from a selection
EXPORT_CHUNK = 20_000
LIVE_SEARCH_MAX_BYTES = 50 * 1024 * 1024  # search-as-you-type only for files that search near-instantly
EMPTY_HINT = (
    "<p style='font-size:11pt;'><b>No filter yet</b></p>"
    "<p>Type in the search box and press <b>Enter</b> — or click a level such as <b>Error</b> above.<br>"
    "Use <b>+ Include</b> / <b>− Exclude</b> to pin several filters, and <b>Context</b> to see lines around matches."
    "</p>"
)


class LogTab(QWidget):
    statusChanged = Signal()
    customFormatRequested = Signal()  # the user wants to define a format for this log
    customFormatDeleteRequested = Signal(str)  # format name
    columnsToggled = Signal(bool)

    def __init__(
        self,
        path: str,
        rules: list[HighlightRule],
        font: QFont,
        *,
        follow: bool = False,
        codec: str | None = None,
        tab_width: int = 4,
        context_lines: int = 0,
        knowledge: KnowledgeService | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.knowledge = knowledge or KnowledgeService(parent=self)
        self.document = LogDocument(path, rules, codec, parent=self)
        self.follow = follow
        self._build_header()
        self._build_body(font, rules, tab_width, context_lines)
        self._connect()
        self.main_view.set_follow(follow)
        self.refresh_icons()
        self._update_info()
        self._refresh_levels()
        self.document.start()

    # ---- construction --------------------------------------------------------------------------------------------
    def _build_header(self) -> None:
        doc_path = self.document.path
        self.header = QWidget(self)
        self.header.setObjectName("fileHeader")
        self.header.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.file_icon = QLabel(self.header)
        name_label = QLabel(self.document.title, self.header)
        name_label.setObjectName("fileName")
        path_label = QLabel(str(Path(doc_path).parent), self.header)
        path_label.setObjectName("filePath")
        path_label.setToolTip(doc_path)
        path_label.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        path_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.chips: dict[str, QLabel] = {}
        for key in ("encoding", "size", "lines"):
            chip = QLabel(self.header)
            chip.setObjectName("chip")
            self.chips[key] = chip
        self.live_chip = QLabel("● LIVE", self.header)
        self.live_chip.setObjectName("liveChip")
        self.live_chip.setToolTip("Following the end of the file (Ctrl+T)")
        self.missing_chip = QLabel("File missing — waiting for it to reappear", self.header)
        self.format_chip = QToolButton(self.header)
        self.format_chip.setObjectName("formatChip")
        self.format_chip.setText("format…")
        self.format_chip.setToolTip("Log format: detected automatically — click to change it or show columns")
        self.format_chip.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.format_chip.setAutoRaise(True)
        self.format_chip.setMenu(QMenu(self.format_chip))
        self.format_chip.menu().aboutToShow.connect(self._fill_format_menu)
        self.missing_chip.setObjectName("warnChip")
        self.index_progress = QProgressBar(self.header)
        self.index_progress.setFixedWidth(150)
        self.index_progress.setMaximumHeight(14)
        self.index_progress.setFormat("indexing %p%")
        self.index_progress.hide()

        layout = QHBoxLayout(self.header)
        layout.setContentsMargins(10, 6, 10, 6)
        layout.setSpacing(8)
        for widget, stretch in (
            (self.file_icon, 0),
            (name_label, 0),
            (path_label, 1),
            (self.index_progress, 0),
            (self.missing_chip, 0),
            (self.live_chip, 0),
            (self.format_chip, 0),
        ):
            layout.addWidget(widget, stretch)
        for chip in self.chips.values():
            layout.addWidget(chip)

    def _build_body(self, font: QFont, rules: list[HighlightRule], tab_width: int, context_lines: int) -> None:
        self.main_view = LogView(self)
        self.filtered_view = LogView(self, show_word_click=False)
        for view in (self.main_view, self.filtered_view):
            view.set_font(font)
            view.set_rules(rules)
            view.set_tab_width(tab_width)
            view.set_bookmark_check(self.document.has_bookmark)
        self._context_lines = context_lines
        self._whole_records = False
        self._mask_secrets = False
        self._inspector_key: tuple[int, int, bool] | None = None
        self._exporter: LineExporter | None = None
        self._related_window = ""
        self._bind_models()

        self.filter_panel = FilterPanel(self)
        self.filter_panel.context.setValue(context_lines)
        self.empty_hint = QLabel(EMPTY_HINT, self)
        self.empty_hint.setObjectName("emptyHint")
        self.empty_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_hint.setWordWrap(True)
        self.results_stack = QStackedWidget(self)
        self.results_stack.addWidget(self.empty_hint)
        self.results_stack.addWidget(self.filtered_view)

        results = QWidget(self)
        results_layout = QVBoxLayout(results)
        results_layout.setContentsMargins(0, 0, 0, 0)
        results_layout.setSpacing(0)
        results_layout.addWidget(self.filter_panel)
        results_layout.addWidget(self.results_stack, 1)

        self.columns = ColumnsView(self)
        self.columns.set_font(font)
        self._columns_model: ColumnsModel | None = None
        self.main_stack = QStackedWidget(self)
        self.main_stack.addWidget(self.main_view)
        self.main_stack.addWidget(self.columns)
        self.v_splitter = QSplitter(Qt.Orientation.Vertical, self)
        self.v_splitter.addWidget(self.main_stack)
        self.v_splitter.addWidget(results)
        self.v_splitter.setStretchFactor(0, 3)
        self.v_splitter.setStretchFactor(1, 2)
        self.v_splitter.setSizes([560, 300])

        self.histogram = HistogramView(self)
        left = QWidget(self)
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(0)
        left_layout.addWidget(self.histogram)
        left_layout.addWidget(self.v_splitter, 1)

        self.inspector = Inspector(font, self.knowledge, self)
        self._related = RelatedEventsFinder(self)
        self.h_splitter = QSplitter(Qt.Orientation.Horizontal, self)
        self.h_splitter.addWidget(left)
        self.h_splitter.addWidget(self.inspector)
        self.h_splitter.setStretchFactor(0, 3)
        self.h_splitter.setStretchFactor(1, 1)
        self.h_splitter.setSizes([1000, 420])

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self.header)
        layout.addWidget(self.h_splitter, 1)

    def _bind_models(self) -> None:
        records = self.document.records if self._whole_records else None
        self._filtered_model = FilteredLines(
            self.document.source, self.document.hits, self._context_lines, records=records
        )
        self._filtered_model.mask_secrets = self._mask_secrets
        self._source_model = SourceLines(self.document.source, mask_secrets=self._mask_secrets)
        self.main_view.set_model(self._source_model)
        self.filtered_view.set_model(self._filtered_model)

    def _connect(self) -> None:
        doc, panel = self.document, self.filter_panel
        doc.contentReset.connect(self._bind_models)
        doc.indexProgress.connect(self._on_index_progress)
        doc.indexFinished.connect(self._on_index_finished)
        doc.indexFailed.connect(lambda message: panel.show_status(message, error=True))
        doc.linesAppended.connect(self.main_view.model_changed)
        doc.stateChanged.connect(self._update_info)
        doc.searchQueued.connect(lambda: panel.show_status("waiting for indexing…"))
        doc.searchProgress.connect(panel.show_progress)
        doc.hitsChanged.connect(self._on_hits_changed)
        doc.searchFinished.connect(self._on_search_finished)
        doc.searchFailed.connect(lambda message: panel.show_status(message, error=True))
        doc.marksChanged.connect(self._refresh_marks)
        doc.marksChanged.connect(self._refresh_levels)
        doc.bookmarksChanged.connect(self._on_bookmarks_changed)
        doc.recordsChanged.connect(self._on_records_changed)
        doc.formatChanged.connect(self._on_format_changed)
        doc.linesAppended.connect(self._grow_columns)
        self.columns.currentRowChanged.connect(lambda row: self.main_view.go_to_row(row, center=True))
        doc.histogramChanged.connect(self._on_histogram_changed)
        self.histogram.lineRequested.connect(self.main_view.go_to_row)
        self.histogram.rangeSelected.connect(lambda start, end: panel.set_time_range(TimeRange(start, end)))
        self.histogram.eventsRequested.connect(self._show_timeline_events)
        self.histogram.eventsClicked.connect(lambda events: self.inspector.show_related(events, [], "in this bin"))
        self._timeline_events = RelatedEventsFinder(self)
        self._timeline_events.found.connect(self._on_timeline_events)
        doc.clockChanged.connect(self.statusChanged)

        panel.specChanged.connect(self.apply_filter)
        panel.nextRequested.connect(self.next_match)
        panel.prevRequested.connect(self.prev_match)
        panel.contextChanged.connect(self._set_context)
        panel.copyRequested.connect(self.copy_results)
        panel.exportRequested.connect(self.export_results)
        panel.wholeRecordsChanged.connect(self._set_whole_records)
        panel.timeRangeRequested.connect(self.time_range_dialog)
        self.filtered_view.currentRowChanged.connect(self._on_filtered_row)
        self.filtered_view.rowActivated.connect(self._on_filtered_activated)
        self.main_view.currentRowChanged.connect(self._on_main_row)
        self.main_view.wordDoubleClicked.connect(panel.set_text)
        self.main_view.contextActionsRequested.connect(self._extend_context_menu)
        self.filtered_view.contextActionsRequested.connect(self._extend_context_menu)
        self.inspector.lineRequested.connect(self.main_view.go_to_row)
        self.inspector.teachRequested.connect(self.teach_knowledge_base)
        self.inspector.saveAnswerRequested.connect(self.save_answer_to_knowledge_base)
        self.knowledge.changed.connect(self._refresh_inspector)
        self.inspector.relatedRequested.connect(self.find_related_events)
        self._related.found.connect(self._on_related_found)

    # ---- appearance / settings -----------------------------------------------------------------------------------
    @property
    def title(self) -> str:
        return self.document.title

    def close_tab(self) -> None:
        self.document.close()

    def set_font(self, font: QFont) -> None:
        self.main_view.set_font(font)
        self.columns.set_font(font)
        self.filtered_view.set_font(font)
        self.inspector.set_font(font)

    def set_wrap(self, wrap: bool) -> None:
        self.main_view.set_wrap(wrap)
        self.filtered_view.set_wrap(wrap)

    # ---- format & columns ----------------------------------------------------------------------------------------
    @property
    def columns_visible(self) -> bool:
        return self.main_stack.currentWidget() is self.columns

    def set_columns_visible(self, visible: bool) -> None:
        """Show the log as a table of parsed fields (or as text again)."""
        if visible and not self._build_columns():
            visible = False
        self.main_stack.setCurrentWidget(self.columns if visible else self.main_view)
        if visible:
            self.columns.select_row(max(self.main_view.current_row(), 0))
            self.columns.setFocus()
        self.columnsToggled.emit(visible)

    def _build_columns(self) -> bool:
        fmt = self.document.log_format
        if fmt is None:
            self.filter_panel.show_status("The log's format is still being detected — try again in a moment.")
            return False
        self._columns_model = ColumnsModel(self.document.source, fmt, self.document.format_context())
        self._columns_model.mask_secrets = self._mask_secrets
        self.columns.set_columns_model(self._columns_model)
        return True

    def _grow_columns(self) -> None:
        if self._columns_model is not None and self.columns_visible:
            self._columns_model.grow()

    def _on_format_changed(self) -> None:
        fmt, detection = self.document.log_format, self.document.detection
        if fmt is None:
            return
        sure = f" · {detection.confidence:.0%}" if detection is not None and not self.document.format_chosen else ""
        self.format_chip.setText(f"{fmt.display_name}{sure}  ▾")
        if self.columns_visible:
            self._build_columns()

    def _fill_format_menu(self) -> None:
        menu = self.format_chip.menu()
        menu.clear()
        detection, current = self.document.detection, self.document.log_format
        if detection is not None:
            title = menu.addAction(f"Detected: {detection.format.display_name} ({detection.confidence:.0%})")
            title.setEnabled(False)
        columns = menu.addAction("Show as columns", lambda: self.set_columns_visible(not self.columns_visible))
        columns.setCheckable(True)
        columns.setChecked(self.columns_visible)
        menu.addSeparator()
        choose = menu.addMenu("Use format")
        for fmt in self.document.format_candidates():
            action = choose.addAction(fmt.display_name, partial(self.document.set_format, fmt))
            action.setCheckable(True)
            action.setChecked(current is not None and fmt.name == current.name)
        if self.document.format_chosen:
            menu.addAction("Back to the detected format", lambda: self.document.set_format(None))
        menu.addSeparator()
        menu.addAction("New custom format…", self.customFormatRequested.emit)
        custom = [f for f in self.document.format_candidates() if f.name.startswith("custom:")]
        if custom:
            delete = menu.addMenu("Delete custom format")
            for fmt in custom:
                delete.addAction(fmt.display_name, partial(self.customFormatDeleteRequested.emit, fmt.display_name))

    def set_mask_secrets(self, enabled: bool) -> None:
        """Show passwords, tokens and keys as •••••• in the views and the Inspector (e.g. while screen sharing)."""
        self._mask_secrets = enabled
        self._source_model.mask_secrets = enabled
        self._filtered_model.mask_secrets = enabled
        if self._columns_model is not None:
            self._columns_model.mask_secrets = enabled
        self.main_view.viewport().update()
        self.filtered_view.viewport().update()
        self._refresh_inspector()

    def set_histogram_visible(self, visible: bool) -> None:
        self.histogram.setVisible(visible)
        self.document.enable_histogram(visible)

    def _show_timeline_events(self, show: bool) -> None:
        """Mark Windows errors/warnings of the log's whole period on the timeline."""
        if not show:
            self.histogram.set_events([])
            return
        first, last = self.document.time_bounds()
        if first is None or last is None:
            self.filter_panel.show_status("This log has no timestamps to place Windows events against.")
            return
        middle = first + (last - first) / 2
        minutes = int((last - first).total_seconds() // 120) + 1
        self.filter_panel.show_status("Reading Windows errors and warnings for this period…")
        self._timeline_events.find(middle, minutes)

    def _on_timeline_events(self, events: list[EventRecord], warnings: list[str]) -> None:
        self.histogram.set_events(events)
        note = f" ({'; '.join(warnings)})" if warnings else ""
        self.filter_panel.show_status(f"{len(events)} Windows errors/warnings marked on the timeline{note}")

    def _on_histogram_changed(self) -> None:
        colors: dict[str, QColor] = {}
        for summary in self.document.mark_summaries():
            color = QColor(summary.color)
            color.setAlpha(230)
            colors[summary.name] = color
        colors["Matches"] = QColor(SEARCH_BG)
        self.histogram.set_histogram(self.document.histogram, colors)

    def set_inspector_visible(self, visible: bool) -> None:
        self.inspector.setVisible(visible)
        if visible:
            self._refresh_inspector()

    def refresh_icons(self) -> None:
        self.file_icon.setPixmap(themed_icon("file", is_dark()).pixmap(18, 18))
        self.filter_panel.refresh_icons()
        self._refresh_inspector()
        self.inspector.refresh_theme()

    def set_rules(self, rules: list[HighlightRule]) -> None:
        self.main_view.set_rules(rules)
        self.filtered_view.set_rules(rules)
        self.document.set_rules(rules)
        self._refresh_levels()

    def set_follow(self, follow: bool) -> None:
        self.follow = follow
        self.main_view.set_follow(follow)
        self._update_info()

    def reload(self, codec: str | None = None) -> None:
        self.document.reload(codec)

    def focus_search(self) -> None:
        self.filter_panel.focus()

    def go_to_line_dialog(self) -> None:
        count = self.document.source.line_count()
        if count == 0:
            return
        current = max(self.main_view.current_row(), 0) + 1
        line, ok = QInputDialog.getInt(self, "Go to line", f"Line number (1 – {count:,}):", current, 1, count)
        if ok:
            self.main_view.go_to_row(line - 1)
            self.main_view.setFocus()

    def report_dialog(self) -> None:
        dialog = ReportDialog(self, self)
        if exec_dialog(dialog):
            self.filter_panel.show_status(f"Report saved to {Path(dialog.saved_path).name}")

    def go_to_time_dialog(self) -> None:
        if self.document.source.line_count() == 0:
            return
        bounds = self.document.time_bounds()
        if bounds[0] is None:
            QMessageBox.information(self, "Go to time", "LogLens found no timestamps in this log.")
            return
        initial = self._current_time() or bounds[0]
        dialog = GoToTimeDialog(initial, bounds, self)
        if exec_dialog(dialog):
            self.main_view.go_to_row(self.document.line_at_time(dialog.moment()))
            self.main_view.setFocus()

    def time_range_dialog(self) -> None:
        bounds = self.document.time_bounds()
        if bounds[0] is None:
            QMessageBox.information(self, "Filter by time", "LogLens found no timestamps in this log.")
            return
        dialog = TimeRangeDialog(bounds, self.filter_panel.time_range, self._current_time(), self)
        if exec_dialog(dialog):
            self.filter_panel.set_time_range(dialog.time_range())

    def clock_dialog(self) -> None:
        dialog = ClockDialog(self.document.clock, self)
        if exec_dialog(dialog):
            self.document.set_clock(dialog.clock())

    def _current_time(self) -> datetime | None:
        row = self.main_view.current_row()
        if row < 0:
            return None
        start, _end = self.document.record_range(row)
        return self.document.line_time(self.document.source.get_line(start))

    # ---- filtering -----------------------------------------------------------------------------------------------
    def run_search(self, query: SearchQuery) -> None:
        """Programmatic quick search (single include term), e.g. from tools and tests."""
        self.filter_panel.edit.setText(query.pattern)
        self.filter_panel.regex.setChecked(query.regex)
        self.filter_panel.case.setChecked(query.case_sensitive)
        self.filter_panel.apply()

    def apply_filter(self, spec: FilterSpec) -> None:
        error = self.document.run_filter(spec)
        if error:
            self.filter_panel.show_status(error, error=True)
            return
        pattern = spec.highlight_pattern()
        self.main_view.set_search_pattern(pattern)
        self.filtered_view.set_search_pattern(pattern)
        self.results_stack.setCurrentWidget(self.empty_hint if spec.is_empty else self.filtered_view)
        if spec.is_empty:
            self.filter_panel.show_status("")
            self.filter_panel.show_progress(1, 1)
        elif not self.document.is_indexing:
            self.filter_panel.show_status("searching…")
        self.statusChanged.emit()

    def clear_search(self) -> None:
        self.filter_panel.clear()

    def next_match(self) -> None:
        self._go_to(self.document.next_hit(self.main_view.current_row(), forward=True))

    def prev_match(self) -> None:
        self._go_to(self.document.next_hit(self.main_view.current_row(), forward=False))

    def next_marked(self, rule_index: int | None = None, forward: bool = True) -> bool:
        """Jump to the next/previous line flagged by a scrollbar-mark rule (any rule if ``rule_index`` is None)."""
        return self._go_to(self.document.next_mark(self.main_view.current_row(), rule_index, forward))

    def _go_to(self, line: int | None) -> bool:
        if line is None:
            return False
        self.main_view.go_to_row(line)
        return True

    def _set_context(self, lines: int) -> None:
        self._context_lines = lines
        self._filtered_model.set_context(lines)
        self.filtered_view.model_changed()

    def _set_whole_records(self, whole: bool) -> None:
        self._whole_records = whole
        self._filtered_model.set_records(self.document.records if whole else None)
        self.filtered_view.model_changed()

    def _on_records_changed(self) -> None:
        self.filter_panel.set_records_available(self.document.records.multi_line)
        if self._whole_records:
            self._filtered_model.set_records(self.document.records)
            self.filtered_view.model_changed()
        self._update_inspector()

    def _on_hits_changed(self) -> None:
        self._filtered_model.set_hits(self.document.hits)
        self.filtered_view.model_changed()
        if self.document.filter_spec is not None and self.follow:
            self.filtered_view.scroll_to_end()
        self._refresh_marks()

    def _on_search_finished(self, count: int, seconds: float) -> None:
        self.filter_panel.show_progress(1, 1)
        text = f"{count:,} matching line{'s' if count != 1 else ''}  ·  {seconds:.2f} s"
        self.filter_panel.show_status(text if count else f"No lines match  ·  {seconds:.2f} s")

    def shown_lines(self) -> np.ndarray:
        """File lines shown in the results list (matches plus context / whole records)."""
        return self._filtered_model.rows.lines

    def copy_results(self) -> None:
        hits = self.shown_lines()[:MAX_COPY_LINES]
        if len(hits):
            texts = self.document.source.get_lines_at(hits)
            if self._mask_secrets:
                texts = [mask(t) for t in texts]
            QGuiApplication.clipboard().setText("\n".join(texts))
            self.filter_panel.show_status(f"Copied {len(hits):,} lines to the clipboard")

    def export_results(self) -> None:
        hits = self.shown_lines()
        if not len(hits) or self._exporter is not None:
            return
        default = str(Path(self.document.path).with_name(Path(self.document.path).stem + "-filtered.log"))
        target, chosen = QFileDialog.getSaveFileName(self, "Export lines", default, EXPORT_FILTERS)
        if not target:
            return
        progress = QProgressDialog("Exporting lines…", "Cancel", 0, len(hits), self)
        progress.setWindowTitle("Export")
        progress.setMinimumDuration(500)
        exporter = LineExporter(self)
        self._exporter = exporter
        exporter.progress.connect(lambda done, _total: progress.setValue(done))
        progress.canceled.connect(exporter.cancel)

        def finished(path: str, count: int) -> None:
            progress.close()
            self._exporter = None
            masked = " (secrets masked)" if self._mask_secrets else ""
            self.filter_panel.show_status(f"Exported {count:,} lines to {Path(path).name}{masked}")

        def failed(message: str) -> None:
            progress.close()
            self._exporter = None
            QMessageBox.warning(self, "Export", message)

        exporter.finished.connect(finished)
        exporter.failed.connect(failed)
        exporter.export(
            self.document.source,
            hits,
            Path(target),
            kind=_export_kind(target, chosen),
            time_of=self.document.line_time,
            level_of=lambda text: self._level_of(text)[0],
            mask_secrets=self._mask_secrets,
        )

    def selected_range(self, max_lines: int = MAX_SELECTED_LINES) -> tuple[int, int]:
        """First and last (inclusive) selected line in the main view, widened to whole multi-line records."""
        first, last = self.main_view.selected_rows()
        if first < 0:
            return -1, -1
        first = self.document.record_range(first)[0]
        last = self.document.record_range(last)[1] - 1
        return first, min(last, first + max_lines - 1)

    def selected_texts(self) -> list[str]:
        """Full text of the selected lines / records in the main view (at most MAX_SELECTED_LINES)."""
        first, last = self.selected_range()
        if first < 0:
            return []
        return [self.document.source.get_full_line(line) for line in range(first, last + 1)]

    # ---- Windows events around a line ------------------------------------------------------------------------------
    def find_related_events(self, minutes: int) -> None:
        if self.main_view.current_row() < 0:
            self.inspector.show_related_error("Select a line first.")
            return
        moment = self._current_time()
        if moment is None:
            self.inspector.show_related_error("This line has no timestamp LogLens can read.")
            return
        local = moment.astimezone()
        self._related_window = f"within ±{minutes} min of {local:%Y-%m-%d %H:%M:%S}"
        self.inspector.show_related_busy(f"Reading Application and System logs {self._related_window}…")
        self._related.find(moment, minutes)

    def _on_related_found(self, events: list[EventRecord], warnings: list[str]) -> None:
        self.inspector.show_related(events, warnings, self._related_window)

    # ---- levels --------------------------------------------------------------------------------------------------
    def _refresh_levels(self) -> None:
        options = []
        for rule in self.document.level_rules():
            query = SearchQuery(rule.pattern, regex=rule.regex, case_sensitive=rule.case_sensitive)
            short = rule.name.split(" / ")[0]
            options.append(LevelOption(short, rule.bg or rule.fg or "#8b949e", query, self.document.level_count(rule)))
        self.filter_panel.set_levels(options)

    def _level_of(self, text: str) -> tuple[str, str]:
        for rule in self.document.level_rules():
            pattern = rule.compiled()
            if pattern is not None and pattern.search(text):
                color = QColor(rule.bg or rule.fg or "#8b949e")
                color.setAlpha(255)
                return rule.name.split(" / ")[0], color.name()
        return "", ""

    # ---- bookmarks -----------------------------------------------------------------------------------------------
    def toggle_bookmark(self) -> None:
        view = self.filtered_view if self.filtered_view.hasFocus() else self.main_view
        first, last = view.selected_rows()
        model = view.model()
        if first < 0 or model is None:
            return
        last = min(last, first + MAX_BOOKMARK_SELECTION - 1)
        self.document.toggle_bookmarks(model.file_line(row) for row in range(first, last + 1))

    def next_bookmark(self, forward: bool = True) -> None:
        self._go_to(self.document.next_bookmark(self.main_view.current_row(), forward))

    def _on_bookmarks_changed(self) -> None:
        self.main_view.viewport().update()
        self.filtered_view.viewport().update()
        self._refresh_marks()
        self.statusChanged.emit()

    # ---- view synchronisation ------------------------------------------------------------------------------------
    def _on_filtered_row(self, row: int) -> None:
        self.main_view.go_to_row(self._filtered_model.file_line(row), center=True, emit=False)
        self._update_inspector(user=True)

    def _on_filtered_activated(self, row: int) -> None:
        self._on_filtered_row(row)
        self.main_view.setFocus()

    def _on_main_row(self, row: int) -> None:
        if self.columns_visible:
            self.columns.select_row(row)
        self._update_inspector(user=True)
        self.histogram.set_current_line(row)
        model = self._filtered_model
        if model.row_count():
            filtered_row = model.row_for_line(row)
            self.filtered_view.go_to_row(
                filtered_row, center=False, select=model.file_line(filtered_row) == row, emit=False
            )
        self.statusChanged.emit()

    def _refresh_inspector(self) -> None:
        """Re-render even if the same record is shown (theme, masking or knowledge changed)."""
        self._update_inspector(force=True)

    def _update_inspector(self, *, force: bool = False, user: bool = False) -> None:
        """Show the current record. Background refreshes (tail growth) skip re-rendering an unchanged record, so the
        user's selection and scroll position in the Inspector survive; only a user's selection queues unknowns."""
        if not self.inspector.isVisible():
            return
        row = self.main_view.current_row()
        if row < 0:
            self._inspector_key = None
            self.inspector.show_line(None, "")
            return
        start, end = self.document.record_range(row)
        key = (start, end, self._mask_secrets)
        if key == self._inspector_key and not force:
            return
        self._inspector_key = key
        text = self.document.record_text(row) if end - start > 1 else self.main_view.current_text()
        first_line = text.split("\n", 1)[0]
        stamp = find_timestamp(first_line)
        level, color = self._level_of(first_line)
        title = f"Lines {start + 1:,}–{end:,}  (one record)" if end - start > 1 else ""
        header = LineHeader(start + 1, stamp.text if stamp else "", level, color, title=title)
        text = strip_ansi(text)
        findings = self.knowledge.explain(text)
        self.inspector.show_line(header, mask(text) if self._mask_secrets else text, findings)
        if user:
            self.knowledge.note_unexplained(text, level, findings)

    # ---- knowledge base ------------------------------------------------------------------------------------------
    def teach_knowledge_base(self) -> None:
        first, _last = self.selected_range()
        if first < 0:
            return
        from .kb_dialog import KnowledgeDialog  # noqa: PLC0415 - dialog module only needed on demand

        line = self.document.source.get_full_line(first)
        if KnowledgeDialog(self.knowledge, self).edit_new(line, resolves=signature_of(line).key):
            self.filter_panel.show_status("Saved to your knowledge base — it now explains lines like this one")

    def save_answer_to_knowledge_base(self) -> None:
        explanation = self.inspector.last_explanation
        first, _last = self.selected_range()
        if explanation is None or first < 0:
            return
        line = self.document.source.get_full_line(first)
        try:
            entry = entry_from_explanation(
                line,
                explanation.summary[:120],
                explanation.what_happened or explanation.summary,
                [cause.cause for cause in explanation.probable_causes],
                explanation.next_steps,
                noise="benign" if explanation.is_likely_noise else "normal",
                taken_ids=self.knowledge.store.ids(),
            )
        except (ValueError, KnowledgeStoreError) as exc:
            QMessageBox.warning(self, "Knowledge base", f"Could not build an entry from this line: {exc}")
            return
        dialog = KBEntryDialog(entry, line, title="Save AI answer to the knowledge base", parent=self)
        if exec_dialog(dialog):
            try:
                self.knowledge.add(dialog.entry(), resolves=signature_of(line).key)
            except (KnowledgeStoreError, ValueError) as exc:
                QMessageBox.warning(self, "Knowledge base", str(exc))
                return
            self.filter_panel.show_status("AI answer saved to your knowledge base")

    def _extend_context_menu(self, menu: QMenu, row: int) -> None:
        menu.addSeparator()
        menu.addAction("Toggle bookmark\tCtrl+B", self.toggle_bookmark)
        menu.addAction("Explain with AI\tCtrl+Shift+A", self.inspector.explainRequested.emit)
        menu.addAction("Search the web…", self.inspector.webSearchRequested.emit)
        menu.addAction("Find Windows events around this time", lambda: self.find_related_events(5))
        if self.sender() is self.filtered_view:
            menu.addAction("Show in main view", lambda: self._on_filtered_activated(row))

    # ---- indexing & info -----------------------------------------------------------------------------------------
    def _on_index_progress(self, done: int, total: int) -> None:
        self.index_progress.show()
        self.index_progress.setMaximum(1000)  # per mille: byte counts can exceed QProgressBar's 32-bit range
        self.index_progress.setValue(int(1000 * done / total) if total else 0)
        self.main_view.model_changed()
        self._update_info()

    def _on_index_finished(self) -> None:
        self.index_progress.hide()
        self.main_view.model_changed()
        self.filter_panel.set_live(self.document.source.index.scanned <= LIVE_SEARCH_MAX_BYTES)

    def _refresh_marks(self) -> None:
        marks: list[tuple[np.ndarray, QColor]] = []
        for summary, rows in zip(self.document.mark_summaries(), self.document.rule_marks(), strict=False):
            color = QColor(summary.color)
            color.setAlpha(255)
            marks.append((rows, color))
        if len(self.document.hits):
            marks.append((self.document.hits, SEARCH_BG))
        if self.document.bookmarks:
            marks.append((self.document.bookmark_array(), BOOKMARK_COLOR))
        self.main_view.set_marks(marks)
        self.statusChanged.emit()

    def _update_info(self) -> None:
        source = self.document.source
        self.chips["encoding"].setText(source.encoding.display_name)
        self.chips["size"].setText(human_size(source.index.scanned))
        self.chips["lines"].setText(f"{source.line_count():,} lines")
        self.live_chip.setVisible(self.follow)
        self.missing_chip.setVisible(self.document.is_missing)
        self.statusChanged.emit()


def _export_kind(target: str, chosen_filter: str) -> str:
    suffix = Path(target).suffix.lower()
    if suffix == ".csv" or (suffix not in {".json", ".jsonl"} and chosen_filter.startswith("CSV")):
        return "csv"
    if suffix in {".json", ".jsonl"} or chosen_filter.startswith("JSON"):
        return "json"
    return "text"
