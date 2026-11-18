"""Dialog: choose Windows event channels (or an .evtx file), time range and levels to open as a log tab."""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QRadioButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from ..core.winevent.reader import COMMON_CHANNELS, EventLogError, EventQuery, list_channels

TIME_RANGES: dict[str, timedelta | None] = {
    "Last hour": timedelta(hours=1),
    "Last 6 hours": timedelta(hours=6),
    "Last 24 hours": timedelta(days=1),
    "Last 7 days": timedelta(days=7),
    "Last 30 days": timedelta(days=30),
    "Everything": None,
}
LEVELS = (("Critical", 1), ("Error", 2), ("Warning", 3), ("Information", 4), ("Verbose", 5))
DEFAULT_CHANNELS = ("Application", "System")
ERROR_COLOR = "#E5484D"


class EventLogDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Open Windows Event Logs")
        self.resize(620, 620)
        self._all_channels: list[str] | None = None
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Open | QDialogButtonBox.StandardButton.Cancel, self)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        self.error = QLabel(self)
        self.error.setStyleSheet(f"color: {ERROR_COLOR};")
        self.error.hide()
        layout = QVBoxLayout(self)
        self._build_sources(layout)
        layout.addSpacing(6)
        layout.addLayout(self._build_options())
        layout.addWidget(self.error)
        layout.addWidget(buttons)
        self._update_enabled()

    def _build_sources(self, layout: QVBoxLayout) -> None:
        self.from_machine = QRadioButton("Event logs on this computer", self)
        self.from_file = QRadioButton("Exported event log file (.evtx)", self)
        self.from_machine.setChecked(True)
        group = QButtonGroup(self)
        group.addButton(self.from_machine)
        group.addButton(self.from_file)
        self.from_machine.toggled.connect(self._update_enabled)

        self.channel_filter = QLineEdit(self)
        self.channel_filter.setPlaceholderText("Filter channels (e.g. PowerShell, IIS, TaskScheduler)…")
        self.channel_filter.textChanged.connect(self._filter_channels)
        self.channels = QListWidget(self)
        for name in COMMON_CHANNELS:
            self._add_channel(name)
        self.more = QPushButton("Show all channels on this computer", self)
        self.more.clicked.connect(self._load_all_channels)
        self.admin_note = QLabel("The Security log needs LogLens to run as administrator.", self)
        self.admin_note.setObjectName("dialogNote")

        self.file_path = QLineEdit(self)
        self.file_path.setPlaceholderText("C:\\path\\to\\exported.evtx")
        browse = QPushButton("Browse…", self)
        browse.clicked.connect(self._browse)
        file_row = QHBoxLayout()
        file_row.addWidget(self.file_path, 1)
        file_row.addWidget(browse)

        layout.addWidget(self.from_machine)
        layout.addWidget(self.channel_filter)
        layout.addWidget(self.channels, 1)
        layout.addWidget(self.more, 0, Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(self.admin_note)
        layout.addSpacing(6)
        layout.addWidget(self.from_file)
        layout.addLayout(file_row)

    def _build_options(self) -> QFormLayout:
        self.time_range = QComboBox(self)
        self.time_range.addItems(list(TIME_RANGES))
        self.time_range.setCurrentText("Last 24 hours")
        self.levels: dict[int, QCheckBox] = {}
        level_row = QHBoxLayout()
        for name, value in LEVELS:
            box = QCheckBox(name, self)
            box.setChecked(value <= 4)
            box.toggled.connect(lambda _checked: self.error.hide())
            level_row.addWidget(box)
            self.levels[value] = box
        level_row.addStretch(1)
        self.max_events = QSpinBox(self)
        self.max_events.setRange(100, 2_000_000)
        self.max_events.setSingleStep(10_000)
        self.max_events.setValue(50_000)
        self.max_events.setToolTip("Newest events first; reading messages takes a while for very large logs")
        self.follow = QCheckBox("Keep following: add new events live as Windows logs them", self)
        self.follow.setChecked(True)
        form = QFormLayout()
        form.addRow("Time range", self.time_range)
        form.addRow("Levels", self._wrap(level_row))
        form.addRow("Max events per log", self.max_events)
        form.addRow("", self.follow)
        return form

    @staticmethod
    def _wrap(inner: QHBoxLayout) -> QWidget:
        widget = QWidget()
        inner.setContentsMargins(0, 0, 0, 0)
        widget.setLayout(inner)
        return widget

    # ---- channels ------------------------------------------------------------------------------------------------
    def _add_channel(self, name: str) -> None:
        item = QListWidgetItem(name, self.channels)
        item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
        item.setCheckState(Qt.CheckState.Checked if name in DEFAULT_CHANNELS else Qt.CheckState.Unchecked)

    def _load_all_channels(self) -> None:
        if self._all_channels is not None:
            return
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)  # listing every channel takes a moment
        try:
            self._all_channels = list_channels()
        except EventLogError as exc:
            self.admin_note.setText(str(exc))
            return
        finally:
            QApplication.restoreOverrideCursor()
        checked = self.selected_channels()
        self.channels.clear()
        for name in self._all_channels:
            self._add_channel(name)
            if name in checked:
                self.channels.item(self.channels.count() - 1).setCheckState(Qt.CheckState.Checked)
        self.more.setEnabled(False)
        self._filter_channels(self.channel_filter.text())

    def _filter_channels(self, text: str) -> None:
        if text and self._all_channels is None:
            self._load_all_channels()
        needle = text.lower()
        for row in range(self.channels.count()):
            item = self.channels.item(row)
            item.setHidden(bool(needle) and needle not in item.text().lower())

    def selected_channels(self) -> list[str]:
        return [
            self.channels.item(row).text()
            for row in range(self.channels.count())
            if self.channels.item(row).checkState() == Qt.CheckState.Checked
        ]

    def _browse(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Open event log file", "", "Event logs (*.evtx);;All files (*)")
        if path:
            self.file_path.setText(path)
            self.from_file.setChecked(True)

    def _update_enabled(self) -> None:
        machine = self.from_machine.isChecked()
        for widget in (self.channel_filter, self.channels, self.more):
            widget.setEnabled(machine)
        self.file_path.setEnabled(not machine)

    # ---- result --------------------------------------------------------------------------------------------------
    def problem(self) -> str | None:
        """Why the choices can't be opened, or None."""
        if not any(box.isChecked() for box in self.levels.values()):
            return "Choose at least one level."
        if self.from_file.isChecked():
            path = self.file_path.text().strip()
            return None if path and Path(path).is_file() else "Choose an existing .evtx file."
        return None if self.selected_channels() else "Choose at least one event log."

    def accept(self) -> None:
        problem = self.problem()
        if problem:
            self.error.setText(f"⚠ {problem}")
            self.error.show()
            return
        super().accept()

    def queries(self) -> list[EventQuery]:
        span = TIME_RANGES[self.time_range.currentText()]
        since = datetime.now().astimezone() - span if span is not None else None
        levels = tuple(value for value, box in self.levels.items() if box.isChecked())
        levels = () if len(levels) == len(LEVELS) else levels
        limit = self.max_events.value()
        if self.from_file.isChecked():
            path = self.file_path.text().strip()
            return [EventQuery(path, is_file=True, since=since, levels=levels, max_events=limit)] if path else []
        return [
            EventQuery(channel, since=since, levels=levels, max_events=limit) for channel in self.selected_channels()
        ]

    @property
    def keep_following(self) -> bool:
        return self.follow.isChecked() and not self.from_file.isChecked()

    def title(self) -> str:
        if self.from_file.isChecked():
            return Path(self.file_path.text().strip()).stem or "evtx"
        return "+".join(c.replace("/", "-").split("-")[-1] for c in self.selected_channels())[:60] or "events"
