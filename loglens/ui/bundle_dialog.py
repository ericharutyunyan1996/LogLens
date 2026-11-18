"""Pick which files of a folder / zip bundle to open (and whether to merge them into one timeline)."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..core.bundles import BundleFile
from ..core.units import human_size

PATH_ROLE = Qt.ItemDataRole.UserRole
DEFAULT_SELECTED = 20  # the newest files are pre-selected; opening hundreds of tabs helps nobody


class BundleDialog(QDialog):
    def __init__(self, title: str, files: list[BundleFile], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"Open bundle — {title}")
        self.resize(820, 520)
        self.tree = QTreeWidget(self)
        self.tree.setHeaderLabels(["File", "Size", "Modified"])
        self.tree.setRootIsDecorated(False)
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for index, item in enumerate(files):
            entry = QTreeWidgetItem([item.relative, human_size(item.size), f"{item.modified:%Y-%m-%d %H:%M}"])
            entry.setFlags(entry.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            entry.setCheckState(0, Qt.CheckState.Checked if index < DEFAULT_SELECTED else Qt.CheckState.Unchecked)
            entry.setData(0, PATH_ROLE, str(item.path))
            self.tree.addTopLevelItem(entry)
        select_all = QPushButton("Select all", self)
        select_all.clicked.connect(lambda: self._check_all(Qt.CheckState.Checked))
        select_none = QPushButton("Select none", self)
        select_none.clicked.connect(lambda: self._check_all(Qt.CheckState.Unchecked))
        self.merge = QCheckBox("Also merge the selected logs into one timeline", self)
        self.merge.setChecked(len(files) > 1)
        row = QHBoxLayout()
        row.addWidget(select_all)
        row.addWidget(select_none)
        row.addStretch(1)
        row.addWidget(self.merge)
        note = QLabel(
            f"{len(files):,} log files found, newest first. The newest {DEFAULT_SELECTED} are selected.", self
        )
        note.setObjectName("dialogNote")
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Open | QDialogButtonBox.StandardButton.Cancel, self)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addWidget(note)
        layout.addWidget(self.tree, 1)
        layout.addLayout(row)
        layout.addWidget(buttons)

    def _check_all(self, state: Qt.CheckState) -> None:
        for index in range(self.tree.topLevelItemCount()):
            item = self.tree.topLevelItem(index)
            if item is not None:
                item.setCheckState(0, state)

    def selected(self) -> list[str]:
        out = []
        for index in range(self.tree.topLevelItemCount()):
            item = self.tree.topLevelItem(index)
            if item is not None and item.checkState(0) == Qt.CheckState.Checked:
                out.append(str(item.data(0, PATH_ROLE)))
        return sorted(out, key=lambda p: Path(p).name.lower())
