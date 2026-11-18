"""Dialogs that work across open logs: merge them into one timeline, and find a text in all of them."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QToolButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..core.search import SearchQuery
from ..core.secrets import has_secrets, mask
from ..services.multi_jobs import LogHits, MultiSearch

if TYPE_CHECKING:
    from .log_tab import LogTab

TAB_ROLE = Qt.ItemDataRole.UserRole
LINE_ROLE = Qt.ItemDataRole.UserRole + 1
MAX_TEXT_CHARS = 500  # of a listed line


class TimelineDialog(QDialog):
    """Choose which open logs to merge (and whether to add Windows errors for the same period)."""

    def __init__(self, tabs: list[LogTab], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Merge into one timeline")
        self._tabs = tabs
        self.list = QListWidget(self)
        for index, tab in enumerate(tabs):
            item = QListWidgetItem(f"{tab.document.title}   —   {tab.document.clock.describe()}", self.list)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Checked)
            item.setData(TAB_ROLE, index)
        self.events = QCheckBox("Add Windows errors and warnings (Application, System) from the same period", self)
        self.events.setChecked(True)
        note = QLabel(
            "Records are merged by their real time; each log's time zone (View → Log time zone) is honoured. Every "
            "line starts with a common timestamp and ‹the log's name›, and multi-line records stay together.",
            self,
        )
        note.setObjectName("dialogNote")
        note.setWordWrap(True)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel, self)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Logs to merge:", self))
        layout.addWidget(self.list, 1)
        layout.addWidget(self.events)
        layout.addWidget(note)
        layout.addWidget(buttons)

    def selected(self) -> list[LogTab]:
        return [
            self._tabs[int(self.list.item(row).data(TAB_ROLE))]
            for row in range(self.list.count())
            if self.list.item(row).checkState() == Qt.CheckState.Checked
        ]


class FindAllDialog(QDialog):
    """Search every open log at once; double-click a result to jump to it.

    ``mask_secrets`` (when given and true at the time results arrive) masks secret values in the listed lines.
    """

    def __init__(
        self,
        tabs: Callable[[], list[LogTab]],
        show: Callable[[LogTab, int], None],
        parent: QWidget | None = None,
        *,
        mask_secrets: Callable[[], bool] | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Find in all open logs")
        self.resize(980, 560)
        self._tabs = tabs
        self._show = show
        self._mask_secrets = mask_secrets
        self._by_key: dict[int, LogTab] = {}
        self._listed = 0
        self.search = MultiSearch(self)
        self.search.found.connect(self._add)
        self.search.done.connect(self._finished)
        self.query = QLineEdit(self)
        self.query.setPlaceholderText("Text or regular expression to find in every open log…")
        self.query.returnPressed.connect(self.run)
        self.regex = QToolButton(self)
        self.regex.setText(".*")
        self.regex.setCheckable(True)
        self.regex.setToolTip("Regular expression")
        self.case = QToolButton(self)
        self.case.setText("Aa")
        self.case.setCheckable(True)
        self.case.setToolTip("Match case")
        go = QPushButton("Find", self)
        go.setObjectName("primary")
        go.clicked.connect(self.run)
        row = QHBoxLayout()
        row.addWidget(self.query, 1)
        row.addWidget(self.regex)
        row.addWidget(self.case)
        row.addWidget(go)
        self.status = QLabel(self)
        self.status.setObjectName("aiStatus")
        self.results = QTreeWidget(self)
        self.results.setHeaderLabels(["Log / line", "Text"])
        self.results.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.results.itemDoubleClicked.connect(self._jump)
        layout = QVBoxLayout(self)
        layout.addLayout(row)
        layout.addWidget(self.status)
        layout.addWidget(self.results, 1)

    def run(self) -> None:
        text = self.query.text()
        if not text:
            return
        query = SearchQuery(text, regex=self.regex.isChecked(), case_sensitive=self.case.isChecked())
        error = query.validate()
        if error:
            self.status.setText(f"⚠ {error}")
            return
        tabs = self._tabs()
        self._by_key = {id(tab): tab for tab in tabs}
        self.results.clear()
        self._listed = 0
        self.status.setText("Searching…")
        self.search.search([(tab.document.title, id(tab), tab.document.source) for tab in tabs], query)

    def _add(self, hits: LogHits) -> None:
        if hits.error:  # the log could not be searched (e.g. deleted or locked): say so instead of skipping it
            self.results.addTopLevelItem(QTreeWidgetItem([hits.label, f"⚠ {hits.error}"]))
            return
        if not hits.total:
            return
        shown = f" (first {len(hits.lines):,})" if hits.total > len(hits.lines) else ""
        parent = QTreeWidgetItem([f"{hits.label}", f"{hits.total:,} matches{shown}"])
        hide = self._mask_secrets is not None and self._mask_secrets()
        for line, text in hits.lines:
            # mask before truncating: a cut-off secret might no longer be recognised
            shown_text = mask(text) if hide and has_secrets(text) else text
            child = QTreeWidgetItem([f"{line + 1:,}", shown_text[:MAX_TEXT_CHARS]])
            child.setData(0, TAB_ROLE, hits.key)
            child.setData(0, LINE_ROLE, line)
            parent.addChild(child)
        self.results.addTopLevelItem(parent)
        parent.setExpanded(self.results.topLevelItemCount() <= 3)
        self._listed += len(hits.lines)
        self.status.setText(f"{self._listed:,} matches listed in {self.results.topLevelItemCount()} logs")

    def _finished(self, searched: int) -> None:
        if not self._listed:
            self.status.setText(f"No matches in {searched} logs")
        else:
            self.status.setText(f"{self.status.text()}  ·  searched {searched} logs")

    def _jump(self, item: QTreeWidgetItem, _column: int) -> None:
        tab = self._by_key.get(item.data(0, TAB_ROLE))
        line = item.data(0, LINE_ROLE)
        if tab is not None and line is not None:
            self._show(tab, int(line))
