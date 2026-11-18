"""Dialogs for live watch: alert rules, and folders whose newest log is followed."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..core.search import SearchQuery
from ..core.watch import KIND_NEW_PATTERN, AlertRule, WatchProfile, default_alert_rules, new_pattern_rule

COLUMNS = ["On", "Name", "Pattern", "Regex", "Matches", "Within (s)", "Quiet for (s)"]
NEW_PATTERN_TEXT = "‹any new kind of message›"
CHECK_COLUMNS = (0, 3)


def _note(text: str, parent: QWidget) -> QLabel:
    label = QLabel(text, parent)
    label.setObjectName("dialogNote")
    label.setWordWrap(True)
    return label


class AlertRulesDialog(QDialog):
    """Edit alert rules; they run on lines appended to every open log."""

    def __init__(self, rules: list[AlertRule], run_in_tray: bool, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Alerts")
        self.resize(860, 380)
        self.table = QTableWidget(0, len(COLUMNS), self)
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.verticalHeader().setVisible(False)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        for rule in rules:
            self._append(rule)
        self.error = QLabel(self)
        self.error.setStyleSheet("color: #E5484D;")
        self.tray = QCheckBox("Keep running in the notification area when the window is closed", self)
        self.tray.setChecked(run_in_tray)

        buttons_row = QHBoxLayout()
        for text, slot in (("Add", self._add), ("Remove", self._remove), ("Add suggestions", self._suggestions)):
            button = QPushButton(text, self)
            button.clicked.connect(slot)
            buttons_row.addWidget(button)
        buttons_row.addStretch(1)
        box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel, self)
        box.accepted.connect(self._accept)
        box.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addWidget(
            _note(
                "A rule fires when its pattern matches the given number of new lines within the time window, in any "
                "open log that is growing. After firing it stays quiet for a while, so one incident gives one "
                "notification. Click the notification to jump to the line.",
                self,
            )
        )
        layout.addWidget(self.table, 1)
        layout.addLayout(buttons_row)
        layout.addWidget(self.error)
        layout.addWidget(self.tray)
        layout.addWidget(box)

    def _append(self, rule: AlertRule) -> None:
        row = self.table.rowCount()
        self.table.insertRow(row)
        pattern = NEW_PATTERN_TEXT if rule.kind == KIND_NEW_PATTERN else rule.query.pattern
        values = ["", rule.name, pattern, "", str(rule.threshold), str(rule.window_s), str(rule.cooldown_s)]
        for column, value in enumerate(values):
            item = QTableWidgetItem(value)
            if column in CHECK_COLUMNS:
                checked = rule.enabled if column == 0 else rule.query.regex
                item.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
                item.setCheckState(Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked)
            self.table.setItem(row, column, item)

    def _add(self) -> None:
        self._append(AlertRule("New rule", SearchQuery("ERROR"), enabled=True))
        item = self.table.item(self.table.rowCount() - 1, 1)
        if item is not None:
            self.table.editItem(item)

    def _remove(self) -> None:
        for row in sorted({index.row() for index in self.table.selectedIndexes()}, reverse=True):
            self.table.removeRow(row)

    def _suggestions(self) -> None:
        names = {self._text(r, 1) for r in range(self.table.rowCount())}
        for rule in default_alert_rules():
            if rule.name not in names:
                self._append(rule)

    def _text(self, row: int, column: int) -> str:
        item = self.table.item(row, column)
        return item.text().strip() if item is not None else ""

    def _checked(self, row: int, column: int) -> bool:
        item = self.table.item(row, column)
        return item is not None and item.checkState() == Qt.CheckState.Checked

    def rules(self) -> list[AlertRule]:
        """The table as rules; raises ValueError naming the first invalid row."""
        out = []
        for row in range(self.table.rowCount()):
            if self._text(row, 2) == NEW_PATTERN_TEXT:
                template = new_pattern_rule()
                quiet = max(int(self._text(row, 6) or 0), 0)
                name = self._text(row, 1) or template.name
                out.append(replace(template, name=name, cooldown_s=quiet, enabled=self._checked(row, 0)))
                continue
            query = SearchQuery(self._text(row, 2), regex=self._checked(row, 3), case_sensitive=False)
            error = query.validate() if query.pattern else "empty pattern"
            if error:
                raise ValueError(f"Row {row + 1}: {error}")
            try:
                numbers = [int(self._text(row, c)) for c in (4, 5, 6)]
            except ValueError as exc:
                raise ValueError(f"Row {row + 1}: numbers expected in the last three columns") from exc
            name = self._text(row, 1) or query.pattern
            out.append(AlertRule(name, query, max(numbers[0], 1), max(numbers[1], 1), max(numbers[2], 0),
                                 self._checked(row, 0)))  # fmt: skip
        return out

    def _accept(self) -> None:
        try:
            self.rules()
        except ValueError as exc:
            self.error.setText(str(exc))
            return
        self.accept()


class WatchFolderDialog(QDialog):
    """Pick a folder + file pattern; LogLens follows whichever matching file is newest."""

    def __init__(self, folder: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Watch a folder")
        self.folder = QLineEdit(folder, self)
        browse = QPushButton("Browse…", self)
        browse.clicked.connect(self._browse)
        folder_row = QHBoxLayout()
        folder_row.addWidget(self.folder, 1)
        folder_row.addWidget(browse)
        self.pattern = QLineEdit("*.log", self)
        self.pattern.setToolTip("Several patterns separated by ';', e.g. *.log;*.txt")
        self.recursive = QCheckBox("Include subfolders", self)
        self.name = QLineEdit(self)
        self.name.setPlaceholderText("defaults to the folder name")
        form = QFormLayout()
        form.addRow("Folder", folder_row)
        form.addRow("Files", self.pattern)
        form.addRow("", self.recursive)
        form.addRow("Name", self.name)
        box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel, self)
        box.accepted.connect(self._accept)
        box.rejected.connect(self.reject)
        self.error = QLabel(self)
        self.error.setStyleSheet("color: #E5484D;")
        self.error.setWordWrap(True)
        self.error.hide()
        self.folder.textChanged.connect(lambda _text: self.error.hide())
        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(
            _note(
                "For rolling logs (a new file per day or size): LogLens opens the newest matching file live and "
                "switches to the next one as soon as it appears.",
                self,
            )
        )
        layout.addWidget(self.error)
        layout.addWidget(box)

    def _browse(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Folder to watch", self.folder.text())
        if folder:
            self.folder.setText(folder)

    def problem(self) -> str | None:
        """Why the folder can't be watched, or None."""
        folder = self.folder.text().strip()
        if not folder:
            return "Choose a folder to watch."
        if not Path(folder).is_dir():
            return f"Folder not found: {folder}"
        return None

    def _accept(self) -> None:
        problem = self.problem()
        if problem:
            self.error.setText(f"⚠ {problem}")
            self.error.show()
            return
        self.accept()

    def profile(self) -> WatchProfile:
        folder = self.folder.text().strip()
        name = self.name.text().strip() or folder.rstrip("\\/").rsplit("\\", 1)[-1].rsplit("/", 1)[-1] or folder
        return WatchProfile(name, folder, self.pattern.text().strip() or "*.log", self.recursive.isChecked())
