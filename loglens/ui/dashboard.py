"""Live dashboard: every open log at a glance (growth, issues, last problem) plus the state of chosen services.

Rows are updated in place (keyed by tab / service name) so selection and scroll position survive a refresh; the
refresh timer only runs while the window is visible.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor, QHideEvent, QShowEvent
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QSplitter,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..core.secrets import mask
from ..core.service_status import list_services, service_states

if TYPE_CHECKING:
    from .log_tab import LogTab

REFRESH_MS = 2_000
IDLE_AFTER_S = 60  # a followed log that hasn't grown for this long is shown as idle
MAX_PROBLEM_CHARS = 200
PROBLEM_WORDS = ("error", "critical", "fatal")
KEY_ROLE = Qt.ItemDataRole.UserRole  # tab id (logs) or service name (services)
STATE_COLORS = {"Running": "#30A46C", "Stopped": "#E5484D", "Not installed": "#8b949e"}
GREW_COLOR = "#E5484D"  # the Errors cell of a log whose problem count just went up
PROBLEMS_COLUMN = 4


def _sync_rows(tree: QTreeWidget, rows: Sequence[tuple[object, list[str]]]) -> dict[object, QTreeWidgetItem]:
    """Make ``tree``'s top-level rows match ``rows`` ((key, texts) in display order) without rebuilding it.

    Rows whose key is gone are removed, new keys are inserted at their position, existing rows only get changed
    texts — so the current item, selection and scroll position survive. Returns the items by key.
    """
    wanted = {key for key, _texts in rows}
    for index in reversed(range(tree.topLevelItemCount())):
        item = tree.topLevelItem(index)
        if item is not None and item.data(0, KEY_ROLE) not in wanted:
            tree.takeTopLevelItem(index)
    existing: dict[object, QTreeWidgetItem] = {}
    for index in range(tree.topLevelItemCount()):
        item = tree.topLevelItem(index)
        if item is not None:
            existing[item.data(0, KEY_ROLE)] = item
    for position, (key, texts) in enumerate(rows):
        item = existing.get(key)
        if item is None:
            item = QTreeWidgetItem()
            item.setData(0, KEY_ROLE, key)
            tree.insertTopLevelItem(min(position, tree.topLevelItemCount()), item)
            existing[key] = item
        for column, text in enumerate(texts):
            if item.text(column) != text:
                item.setText(column, text)
    return existing


@dataclass
class _LogStats:
    lines: int
    problems: int
    changed_at: float
    rate_per_min: float = 0.0


class ServicePicker(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Watch a Windows service")
        self.resize(520, 520)
        self.filter = QLineEdit(self)
        self.filter.setPlaceholderText("Filter services…")
        self.list = QListWidget(self)
        self.list.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
        for service in list_services():
            item = QListWidgetItem(f"{service.display_name}  ({service.name}) — {service.state}", self.list)
            item.setData(Qt.ItemDataRole.UserRole, service.name)
        self.filter.textChanged.connect(self._filter)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel, self)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addWidget(self.filter)
        layout.addWidget(self.list, 1)
        layout.addWidget(buttons)

    def _filter(self, text: str) -> None:
        needle = text.lower()
        for row in range(self.list.count()):
            item = self.list.item(row)
            item.setHidden(needle not in item.text().lower())

    def chosen(self) -> list[str]:
        return [str(item.data(Qt.ItemDataRole.UserRole)) for item in self.list.selectedItems()]


class DashboardWindow(QDialog):
    """Non-modal overview window; ``mask_secrets`` (when given and true) masks secrets in the "Latest problem" text."""

    def __init__(
        self,
        tabs: Callable[[], list[LogTab]],
        show_tab: Callable[[LogTab], None],
        services: Callable[[], list[str]],
        set_services: Callable[[list[str]], None],
        parent: QWidget | None = None,
        *,
        mask_secrets: Callable[[], bool] | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Live dashboard")
        self.resize(1000, 520)
        self._tabs, self._show_tab = tabs, show_tab
        self._services, self._set_services = services, set_services
        self._mask_secrets = mask_secrets
        self._stats: dict[int, _LogStats] = {}

        self.logs = QTreeWidget(self)
        self.logs.setHeaderLabels(["Log", "Status", "Lines", "Lines/min", "Errors", "Latest problem"])
        self.logs.setRootIsDecorated(False)
        self.logs.header().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.logs.header().setStretchLastSection(True)
        self.logs.itemDoubleClicked.connect(self._open)
        self.services_tree = QTreeWidget(self)
        self.services_tree.setHeaderLabels(["Service", "State"])
        self.services_tree.setRootIsDecorated(False)
        self.services_tree.header().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        add = QPushButton("Add service…", self)
        add.clicked.connect(self._add_services)
        remove = QPushButton("Remove", self)
        remove.clicked.connect(self._remove_service)
        service_buttons = QHBoxLayout()
        service_buttons.addWidget(add)
        service_buttons.addWidget(remove)
        service_buttons.addStretch(1)
        services_box = QWidget(self)
        services_layout = QVBoxLayout(services_box)
        services_layout.setContentsMargins(0, 0, 0, 0)
        services_layout.addWidget(QLabel("<b>Windows services</b> (read-only; you get a notification when one stops)"))
        services_layout.addWidget(self.services_tree, 1)
        services_layout.addLayout(service_buttons)
        split = QSplitter(Qt.Orientation.Vertical, self)
        split.addWidget(self.logs)
        split.addWidget(services_box)
        split.setSizes([320, 180])
        note = QLabel(
            "Open logs (Watch → Watch a folder, or Follow) refresh every 2 s. Double-click a log to go to it."
        )
        note.setObjectName("dialogNote")
        layout = QVBoxLayout(self)
        layout.addWidget(note)
        layout.addWidget(split, 1)
        self._timer = QTimer(self)  # runs only while visible: started in showEvent, stopped in hideEvent
        self._timer.setInterval(REFRESH_MS)
        self._timer.timeout.connect(self.refresh)

    @property
    def is_polling(self) -> bool:
        return self._timer.isActive()

    # ---- refresh -------------------------------------------------------------------------------------------------
    def refresh(self) -> None:
        self._refresh_logs()
        self._refresh_services()

    def _refresh_logs(self) -> None:
        now = time.monotonic()
        tabs = self._tabs()
        rows: list[tuple[object, list[str]]] = []
        grew: set[int] = set()
        for tab in tabs:
            texts, problems_grew = self._log_row(tab, now)
            rows.append((id(tab), texts))
            if problems_grew:
                grew.add(id(tab))
        alive = {id(tab) for tab in tabs}
        self._stats = {key: stats for key, stats in self._stats.items() if key in alive}
        for key, item in _sync_rows(self.logs, rows).items():
            if key in grew:
                item.setForeground(PROBLEMS_COLUMN, QColor(GREW_COLOR))
            else:
                item.setData(PROBLEMS_COLUMN, Qt.ItemDataRole.ForegroundRole, None)  # back to the theme's colour

    def _log_row(self, tab: LogTab, now: float) -> tuple[list[str], bool]:
        """The row texts of one log, and whether its problem count went up since the last refresh."""
        doc = tab.document
        lines = doc.source.line_count()
        problems = sum(s.count for s in doc.mark_summaries() if s.name.lower().startswith(PROBLEM_WORDS))
        previous = self._stats.get(id(tab))
        if previous is None:
            stats = _LogStats(lines, problems, now)
        else:
            grown = lines - previous.lines
            elapsed = max(now - previous.changed_at, 1e-6) if grown else 0
            rate = grown * 60 / elapsed if grown else previous.rate_per_min * 0.5  # decays while quiet
            stats = _LogStats(lines, problems, now if grown else previous.changed_at, rate)
            if problems > previous.problems:
                stats.changed_at = now
        self._stats[id(tab)] = stats
        status = "missing" if doc.is_missing else ("live" if tab.follow else "open")
        if tab.follow and now - stats.changed_at > IDLE_AFTER_S:
            status = "live · idle"
        texts = [doc.title, status, f"{lines:,}", f"{stats.rate_per_min:,.0f}", f"{problems:,}",
                 self._latest_problem(tab)]  # fmt: skip
        return texts, previous is not None and problems > previous.problems

    def _latest_problem(self, tab: LogTab) -> str:
        doc = tab.document
        for summary, rows in zip(doc.mark_summaries(), doc.rule_marks(), strict=False):
            if summary.name.lower().startswith(PROBLEM_WORDS) and len(rows):
                text = doc.source.get_line(int(rows[-1]))
                if self._mask_secrets is not None and self._mask_secrets():
                    text = mask(text)  # before truncating: a cut-off secret might no longer be recognised
                return text[:MAX_PROBLEM_CHARS]
        return ""

    def _refresh_services(self) -> None:
        names = self._services()
        states = service_states(names) if names else {}
        items = _sync_rows(self.services_tree, [(name, [name, state]) for name, state in states.items()])
        for name, state in states.items():
            items[name].setForeground(1, QColor(STATE_COLORS.get(state, "#F5A524")))

    # ---- actions -------------------------------------------------------------------------------------------------
    def _open(self, item: QTreeWidgetItem, _column: int) -> None:
        key = item.data(0, KEY_ROLE)
        tab = next((t for t in self._tabs() if id(t) == key), None)
        if tab is not None:
            self._show_tab(tab)

    def _add_services(self) -> None:
        picker = ServicePicker(self)
        if picker.exec():
            current = self._services()
            self._set_services(current + [n for n in picker.chosen() if n not in current])
            self.refresh()

    def _remove_service(self) -> None:
        item = self.services_tree.currentItem()
        if item is not None:
            self._set_services([n for n in self._services() if n != item.text(0)])
            self.refresh()

    # ---- polling only while visible (Esc / Close only hide the window) -------------------------------------------
    def showEvent(self, event: QShowEvent) -> None:
        super().showEvent(event)
        if not self._timer.isActive():
            self.refresh()  # it may have been hidden for a while
            self._timer.start()

    def hideEvent(self, event: QHideEvent) -> None:
        self._timer.stop()
        super().hideEvent(event)
