"""Shared parts of the Analyze window: the page base class (scope, run, progress) and sortable result tables."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QProgressBar,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..services.analysis_jobs import ANALYZE_MAX_LINES, AnalysisRunner, AnalysisScope, Analyzer

if TYPE_CHECKING:
    from .log_tab import LogTab

LINE_ROLE = Qt.ItemDataRole.UserRole
SORT_ROLE = Qt.ItemDataRole.UserRole + 1


class SortableItem(QTreeWidgetItem):
    """Tree row that sorts numerically on columns that carry a SORT_ROLE value."""

    def __lt__(self, other: QTreeWidgetItem) -> bool:
        tree = self.treeWidget()
        column = tree.sortColumn() if tree is not None else 0
        mine, theirs = self.data(column, SORT_ROLE), other.data(column, SORT_ROLE)
        if mine is not None and theirs is not None:
            return bool(mine < theirs)
        return self.text(column).lower() < other.text(column).lower()


def make_row(values: Sequence[object], line: int | None = None) -> SortableItem:
    item = SortableItem([format_value(v) for v in values])
    for column, value in enumerate(values):
        if isinstance(value, int | float) and not isinstance(value, bool):
            item.setData(column, SORT_ROLE, value)
            item.setTextAlignment(column, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        elif value is None:
            item.setData(column, SORT_ROLE, -1.0)
    if line is not None:
        item.setData(0, LINE_ROLE, line)
    return item


def format_value(value: object) -> str:
    if value is None:
        return "—"
    if isinstance(value, float):
        return f"{value:,.1f}"
    if isinstance(value, int) and not isinstance(value, bool):
        return f"{value:,}"
    return str(value)


def make_tree(headers: Sequence[str], parent: QWidget) -> QTreeWidget:
    tree = QTreeWidget(parent)
    tree.setHeaderLabels(list(headers))
    tree.setRootIsDecorated(False)
    tree.setUniformRowHeights(True)
    tree.setSortingEnabled(True)
    tree.header().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
    tree.header().setStretchLastSection(True)
    return tree


def fill_tree(tree: QTreeWidget, rows: list[SortableItem]) -> None:
    tree.setSortingEnabled(False)
    tree.clear()
    tree.addTopLevelItems(rows)
    tree.setSortingEnabled(True)


class AnalysisPage(QWidget):
    lineRequested = Signal(int)
    filterRequested = Signal(str)  # a regex to filter the log with
    bookmarksRequested = Signal(list)  # list[int] lines to bookmark
    title = ""
    intro = ""

    def __init__(self, tab: LogTab, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.tab = tab
        self.runner = AnalysisRunner(self)
        self.runner.progress.connect(self._on_progress)
        self.runner.finished.connect(self._on_finished)
        intro = QLabel(self.intro, self)
        intro.setObjectName("dialogNote")
        intro.setWordWrap(True)
        self.scope = QComboBox(self)
        self.run_button = QPushButton("Analyze", self)
        self.run_button.setObjectName("primary")
        self.run_button.clicked.connect(self.run)
        self.cancel_button = QPushButton("Cancel", self)
        self.cancel_button.setToolTip("Stop the running analysis")
        self.cancel_button.clicked.connect(self.cancel)
        self.cancel_button.hide()
        self.progress = QProgressBar(self)
        self.progress.setMaximumWidth(160)
        self.progress.setTextVisible(False)
        self.progress.hide()
        self.status = QLabel(self)
        self.status.setObjectName("aiStatus")
        self.status.setWordWrap(True)
        self.runner.failed.connect(self._on_failed)
        self._busy = False
        top = QHBoxLayout()
        top.addWidget(QLabel("Lines:", self))
        top.addWidget(self.scope)
        top.addWidget(self.run_button)
        top.addWidget(self.cancel_button)
        top.addWidget(self.progress)
        top.addStretch(1)
        self.body = QVBoxLayout()
        layout = QVBoxLayout(self)
        layout.addWidget(intro)
        layout.addLayout(top)
        layout.addWidget(self.status)
        layout.addLayout(self.body, 1)
        self.refresh_scope()

    # ---- scope & running -----------------------------------------------------------------------------------------
    def refresh_scope(self) -> None:
        """Re-read the scope choices (line count, current filter); a choice the user made between them is kept."""
        kept = self.scope.currentIndex() if self.scope.count() > 1 else None
        self.scope.clear()
        total = self.tab.document.source.line_count()
        self.scope.addItem(f"Whole file ({total:,} lines)", AnalysisScope(None, "the whole file"))
        hits = self.tab.document.hits
        if self.tab.document.filter_spec is not None and len(hits):
            self.scope.addItem(f"Current filter ({len(hits):,} lines)", AnalysisScope(hits, "the current filter"))
            self.scope.setCurrentIndex(0 if kept == 0 else 1)

    @property
    def busy(self) -> bool:
        """Whether an analysis of this page is running."""
        return self._busy

    def set_busy(self, busy: bool, status: str = "") -> None:
        """Switch between running (progress, Cancel) and idle (Analyze enabled); ``status`` replaces the status."""
        self._busy = busy
        self.run_button.setEnabled(not busy)
        self.cancel_button.setVisible(busy)
        self.progress.setVisible(busy)
        if busy:
            self.progress.setRange(0, 0)  # busy indicator until the first progress report
        if status:
            self.status.setText(status)

    def run(self) -> None:
        scope: AnalysisScope = self.scope.currentData()
        total = scope.count(self.tab.document.source.line_count())
        capped = " (first 2,000,000 lines)" if total >= ANALYZE_MAX_LINES else ""
        self.set_busy(True, f"Analyzing {scope.description}{capped}…")
        self.runner.run(self.tab.document.source, scope, self.analyzer())

    def cancel(self) -> None:
        """Stop the running analysis (its late result is dropped) and reset the page."""
        self.runner.cancel()
        if self._busy:
            self.set_busy(False, "Cancelled.")

    def _on_progress(self, done: int, total: int) -> None:
        self.progress.setRange(0, max(total, 1))
        self.progress.setValue(done)

    def _on_finished(self, result: object) -> None:
        self.set_busy(False)
        self.show_result(result)

    def _on_failed(self, message: str) -> None:
        self.set_busy(False, f"⚠ {message}")

    def jump(self, item: QTreeWidgetItem | None) -> None:
        line = item.data(0, LINE_ROLE) if item is not None else None
        if line is not None:
            self.lineRequested.emit(int(line))

    # ---- per page ------------------------------------------------------------------------------------------------
    def analyzer(self) -> Analyzer:
        raise NotImplementedError

    def show_result(self, result: object) -> None:
        raise NotImplementedError
