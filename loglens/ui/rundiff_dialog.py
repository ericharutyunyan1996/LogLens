"""Compare two runs side by side: pick a good and a bad log, see what only one of them did."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..core.rundiff import DiffRow, RunDiff, diff_runs
from ..services.analysis_jobs import AnalysisScope, iter_lines
from .payload_view import Background

if TYPE_CHECKING:
    from .log_tab import LogTab

KIND_COLORS = {"changed": "#F0B400", "only_a": "#D9534F", "only_b": "#4CAF50"}
LINE_ROLE = Qt.ItemDataRole.UserRole


def _scope(tab: LogTab, filtered: bool) -> AnalysisScope:
    hits = tab.document.hits
    if filtered and tab.document.filter_spec is not None and len(hits):
        return AnalysisScope(hits, "the current filter")
    return AnalysisScope(None, "the whole log")


class RunDiffDialog(QDialog):
    def __init__(
        self,
        tabs: Callable[[], list[LogTab]],
        show: Callable[[LogTab, int], None],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Compare two runs side by side")
        self.setWindowFlag(Qt.WindowType.WindowMaximizeButtonHint, True)
        self.resize(1180, 680)
        self._tabs, self._show = tabs, show
        self._left: LogTab | None = None
        self._right: LogTab | None = None
        self.diff: RunDiff | None = None
        self._worker = Background(self, self._finished)
        intro = QLabel(
            "Pick a good run and a bad run (two open logs). Timestamps, numbers and ids are ignored when lines are "
            "matched up, so only real differences show: red = only in the good run, green = only in the bad run, "
            "yellow = changed. Double-click a row to jump to the line.",
            self,
        )
        intro.setWordWrap(True)
        intro.setObjectName("dialogNote")
        self.good = QComboBox(self)
        self.bad = QComboBox(self)
        self.filtered = QCheckBox("Only the lines each log's current filter shows", self)
        self.go = QPushButton("Compare", self)
        self.go.setObjectName("primary")
        self.go.clicked.connect(self.run)
        row = QHBoxLayout()
        row.addWidget(QLabel("Good run:", self))
        row.addWidget(self.good, 1)
        row.addWidget(QLabel("Bad run:", self))
        row.addWidget(self.bad, 1)
        row.addWidget(self.go)
        self.status = QLabel(self)
        self.status.setObjectName("aiStatus")
        self.status.setWordWrap(True)
        self.tree = QTreeWidget(self)
        self.tree.setHeaderLabels(["Line", "Good run", "Line", "Bad run"])
        self.tree.setRootIsDecorated(False)
        self.tree.setUniformRowHeights(True)
        self.tree.header().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.tree.setColumnWidth(0, 60)
        self.tree.setColumnWidth(1, 480)
        self.tree.setColumnWidth(2, 60)
        self.tree.itemDoubleClicked.connect(self._jump)
        layout = QVBoxLayout(self)
        layout.addWidget(intro)
        layout.addLayout(row)
        layout.addWidget(self.filtered)
        layout.addWidget(self.status)
        layout.addWidget(self.tree, 1)
        self.refresh()

    def refresh(self) -> None:
        """Re-read the open logs (called when the dialog is shown)."""
        tabs = self._tabs()
        keep = (self.good.currentText(), self.bad.currentText())
        for box in (self.good, self.bad):
            box.clear()
            for tab in tabs:
                box.addItem(tab.document.title, tab)
        if len(tabs) >= 2:
            self.good.setCurrentIndex(max(0, self.good.findText(keep[0])))
            second = self.bad.findText(keep[1])
            self.bad.setCurrentIndex(second if second >= 0 and second != self.good.currentIndex() else 1)

    def run(self) -> None:
        left, right = self.good.currentData(), self.bad.currentData()
        if left is None or right is None:
            self.status.setText("Open two logs first.")
            return
        if left is right:
            self.status.setText("Choose two different logs.")
            return
        self._left, self._right = left, right
        filtered = self.filtered.isChecked()
        scopes = (_scope(left, filtered), _scope(right, filtered))
        self.go.setEnabled(False)
        self.status.setText("Comparing…")

        def work() -> object:
            return diff_runs(iter_lines(left.document.source, scopes[0]), iter_lines(right.document.source, scopes[1]))

        self._worker.start(work)

    def _finished(self, result: object) -> None:
        self.go.setEnabled(True)
        if isinstance(result, Exception):
            self.status.setText(f"⚠ {result}")
            return
        assert isinstance(result, RunDiff)
        self.show_diff(result)

    def show_diff(self, diff: RunDiff) -> None:
        self.diff = diff
        self.tree.clear()
        for row in diff.rows:
            self.tree.addTopLevelItem(self._item(row))
        cut = " The runs are long: only their first lines were compared." if diff.truncated else ""
        if diff.identical:
            self.status.setText(f"<b>No difference</b> in shape: {diff.same:,} lines match.{cut}")
        else:
            self.status.setText(
                f"<b>{diff.only_a:,} only in the good run, {diff.only_b:,} only in the bad run, {diff.changed:,} "
                f"changed</b>; {diff.same:,} lines match.{cut}"
            )

    def _item(self, row: DiffRow) -> QTreeWidgetItem:
        if row.kind == "gap":
            item = QTreeWidgetItem(["", f"… {row.skipped:,} matching lines …", "", ""])
            item.setForeground(1, QBrush(QColor("#8A8A8A")))
            return item
        item = QTreeWidgetItem(
            [
                str(row.a_line + 1) if row.a_line is not None else "",
                row.a_text.strip(),
                str(row.b_line + 1) if row.b_line is not None else "",
                row.b_text.strip(),
            ]
        )
        item.setData(0, LINE_ROLE, (row.a_line, row.b_line))
        color = KIND_COLORS.get(row.kind)
        if color:
            tint = QColor(color)
            tint.setAlpha(60)
            for column in range(4):
                item.setBackground(column, QBrush(tint))
        return item

    def _jump(self, item: QTreeWidgetItem, column: int) -> None:
        lines = item.data(0, LINE_ROLE)
        if not lines:
            return
        a_line, b_line = lines
        use_right = column >= 2 and b_line is not None
        tab = self._right if use_right else self._left
        line = b_line if use_right else a_line
        if tab is not None and line is not None:
            self._show(tab, line)
