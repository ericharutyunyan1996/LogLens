"""The incident builder window: pinned lines from any logs on one timeline, with labels, notes and a report."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..core import incident as store
from ..core.incident import LABELS, Incident, PinnedLine
from ..core.pseudonyms import Pseudonymizer

ITEM_ROLE = Qt.ItemDataRole.UserRole
FILE_FILTER = "LogLens incident (*.incident.json)"


class IncidentWindow(QWidget):
    """Non-modal window. ``open_line(path, source, line)`` jumps to a pinned line (opening the file when needed)."""

    def __init__(  # noqa: PLR0915 - builds the whole window
        self, incident: Incident, open_line: Callable[[str, str, int], None], parent: QWidget | None = None
    ) -> None:
        super().__init__(parent, Qt.WindowType.Window)
        self.setWindowTitle("Incident")
        self.resize(1100, 640)
        self.incident = incident
        self._open_line = open_line
        self._path: Path | None = None
        intro = QLabel(
            "Pin the lines that tell the story (Analyze → Add selected lines to the incident), label them "
            "(trigger, symptom, root cause, fix), add notes, and export a report. Lines from different logs share "
            "one timeline.",
            self,
        )
        intro.setWordWrap(True)
        intro.setObjectName("dialogNote")
        self.title_edit = QLineEdit(incident.title, self)
        self.title_edit.setPlaceholderText("Title of the incident")
        self.title_edit.textChanged.connect(self._title_changed)
        self.summary = QPlainTextEdit(incident.summary, self)
        self.summary.setPlaceholderText("What happened, in a few sentences…")
        self.summary.setMaximumHeight(80)
        self.summary.textChanged.connect(self._summary_changed)
        self.tree = QTreeWidget(self)
        self.tree.setHeaderLabels(["Time", "Log", "Line", "Label", "Text", "Note"])
        self.tree.setRootIsDecorated(False)
        self.tree.setSelectionMode(QTreeWidget.SelectionMode.ExtendedSelection)
        self.tree.header().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        for column, width in enumerate((150, 130, 60, 100, 420, 200)):
            self.tree.setColumnWidth(column, width)
        self.tree.itemDoubleClicked.connect(self._double_clicked)
        self.tree.itemChanged.connect(self._item_changed)
        self.label_box = QComboBox(self)
        for label in LABELS:
            self.label_box.addItem(label or "(no label)", label)
        set_label = QPushButton("Label selected", self)
        set_label.clicked.connect(self.label_selected)
        remove = QPushButton("Remove selected", self)
        remove.clicked.connect(self.remove_selected)
        opener = QPushButton("Open…", self)
        opener.clicked.connect(self.open_file)
        saver = QPushButton("Save…", self)
        saver.clicked.connect(self.save_file)
        export = QPushButton("Export report…", self)
        export.setObjectName("primary")
        export.clicked.connect(self.export_report)
        self.mask_box = QCheckBox("Mask secrets", self)
        self.mask_box.setChecked(True)
        self.anonymize_box = QCheckBox("Replace people and machines", self)
        self.anonymize_box.setToolTip("Users, IP addresses, e-mails and server names become consistent pseudonyms")
        self.status = QLabel(self)
        self.status.setObjectName("aiStatus")
        row = QHBoxLayout()
        row.addWidget(self.label_box)
        row.addWidget(set_label)
        row.addWidget(remove)
        row.addStretch(1)
        row.addWidget(opener)
        row.addWidget(saver)
        bottom = QHBoxLayout()
        bottom.addWidget(self.mask_box)
        bottom.addWidget(self.anonymize_box)
        bottom.addStretch(1)
        bottom.addWidget(export)
        layout = QVBoxLayout(self)
        layout.addWidget(intro)
        layout.addWidget(self.title_edit)
        layout.addWidget(self.summary)
        layout.addLayout(row)
        layout.addWidget(self.tree, 1)
        layout.addWidget(self.status)
        layout.addLayout(bottom)
        self.refresh()

    # ---- the model ---------------------------------------------------------------------------------------------------
    def set_incident(self, incident: Incident) -> None:
        self.incident = incident
        self.title_edit.setText(incident.title)
        self.summary.setPlainText(incident.summary)
        self.refresh()

    def _title_changed(self, text: str) -> None:
        self.incident.title = text

    def _summary_changed(self) -> None:
        self.incident.summary = self.summary.toPlainText()

    def refresh(self) -> None:
        self.tree.blockSignals(True)
        self.tree.clear()
        for item in self.incident.timeline():
            moment = item.moment()
            row = QTreeWidgetItem(
                [
                    f"{moment:%Y-%m-%d %H:%M:%S}" if moment else "—",
                    item.source,
                    str(item.line + 1),
                    item.label,
                    item.text.strip(),
                    item.note,
                ]
            )
            row.setData(0, ITEM_ROLE, item)
            row.setFlags(row.flags() | Qt.ItemFlag.ItemIsEditable)
            self.tree.addTopLevelItem(row)
        self.tree.blockSignals(False)
        count = len(self.incident.items)
        self.status.setText(f"{count} pinned line{'s' if count != 1 else ''}")

    def _selected(self) -> list[PinnedLine]:
        return [i.data(0, ITEM_ROLE) for i in self.tree.selectedItems()]

    def _item_changed(self, row: QTreeWidgetItem, column: int) -> None:
        item = row.data(0, ITEM_ROLE)
        if isinstance(item, PinnedLine) and column == 5:
            item.note = row.text(5)  # only the note is editable in the table
        elif isinstance(item, PinnedLine):
            self.refresh()  # other cells snap back

    def pin(self, source: str, path: str, lines: list[tuple[int, str]]) -> int:
        """Pin ``lines`` ((0-based line, text)) of a log; returns how many were new."""
        added = sum(1 for number, text in lines if self.incident.pin(source, path, number, text) is not None)
        self.refresh()
        return added

    def label_selected(self) -> None:
        label = str(self.label_box.currentData())
        for item in self._selected():
            item.label = label
        self.refresh()

    def remove_selected(self) -> None:
        for item in self._selected():
            self.incident.unpin(item)
        self.refresh()

    def _double_clicked(self, row: QTreeWidgetItem, column: int) -> None:
        item = row.data(0, ITEM_ROLE)
        if column != 5 and isinstance(item, PinnedLine):
            self._open_line(item.path, item.source, item.line)
        elif column == 5:
            self.tree.editItem(row, 5)

    # ---- files and report --------------------------------------------------------------------------------------------
    def open_file(self) -> None:
        target, _ = QFileDialog.getOpenFileName(self, "Open an incident", "", FILE_FILTER + ";;All files (*)")
        if not target:
            return
        try:
            self.set_incident(store.load(Path(target)))
        except ValueError as exc:
            QMessageBox.warning(self, "Incident", str(exc))
            return
        self._path = Path(target)

    def save_file(self) -> None:
        default = str(self._path or Path.home() / f"{self.incident.title or 'incident'}.incident.json")
        target, _ = QFileDialog.getSaveFileName(self, "Save the incident", default, FILE_FILTER)
        if not target:
            return
        self._path = Path(target)
        try:
            store.save(self.incident, self._path)
        except OSError as exc:
            QMessageBox.warning(self, "Incident", f"Could not save: {exc}")
            return
        self.status.setText(f"Saved {self._path.name}")

    def report(self) -> str:
        transform = Pseudonymizer(secrets=False).line if self.anonymize_box.isChecked() else None
        return store.render_markdown(self.incident, mask_secrets=self.mask_box.isChecked(), transform=transform)

    def export_report(self) -> None:
        target, _ = QFileDialog.getSaveFileName(
            self, "Export the report", f"{self.incident.title or 'incident'}.md", "Markdown (*.md)"
        )
        if target:
            try:
                Path(target).write_text(self.report(), encoding="utf-8")
            except OSError as exc:
                QMessageBox.warning(self, "Incident", f"Could not write the report: {exc}")
                return
            self.status.setText(f"Report written to {Path(target).name}")
