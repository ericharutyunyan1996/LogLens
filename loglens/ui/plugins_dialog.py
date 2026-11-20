"""Plugins: see what is in the plugins folder, approve or switch off each plugin, show a plugin's report."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices, QGuiApplication
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..core.plugins import PluginInfo, describe_file
from ..settings import Settings

INFO_ROLE = 1000


class PluginsDialog(QDialog):
    def __init__(
        self, folder: Path, settings: Settings, rescan: Callable[[], list[PluginInfo]], parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Plugins")
        self.resize(820, 440)
        self._folder, self._settings, self._rescan = folder, settings, rescan
        intro = QLabel(
            "Plugins add log formats, analyzers and sources. A plugin is Python code that runs with your "
            f"permissions, so nothing runs until you approve it, and a changed file needs approving again. "
            f"Put plugin files (*.py) in:<br><code>{folder}</code>",
            self,
        )
        intro.setWordWrap(True)
        intro.setObjectName("dialogNote")
        self.tree = QTreeWidget(self)
        self.tree.setHeaderLabels(["Plugin", "Version", "Status", "Provides", "Description"])
        self.tree.setRootIsDecorated(False)
        self.tree.itemSelectionChanged.connect(self._update_buttons)
        self.enable_button = QPushButton("Approve and enable…", self)
        self.enable_button.clicked.connect(self.enable_selected)
        self.disable_button = QPushButton("Switch off", self)
        self.disable_button.clicked.connect(self.disable_selected)
        refresh = QPushButton("Refresh", self)
        refresh.clicked.connect(self.refresh)
        folder_button = QPushButton("Open folder", self)
        folder_button.clicked.connect(self._open_folder)
        self.detail = QLabel("", self)
        self.detail.setWordWrap(True)
        row = QHBoxLayout()
        for button in (self.enable_button, self.disable_button, refresh, folder_button):
            row.addWidget(button)
        row.addStretch(1)
        layout = QVBoxLayout(self)
        layout.addWidget(intro)
        layout.addWidget(self.tree, 1)
        layout.addWidget(self.detail)
        layout.addLayout(row)
        self.refresh()

    def refresh(self) -> None:
        self.tree.clear()
        for info in self._rescan():
            name, description = (
                (info.name, info.description) if info.enabled and not info.error else describe_file(info.path)
            )
            provides = ", ".join(
                part
                for part in (
                    f"{len(info.analyzers)} analyzers" if info.analyzers else "",
                    f"{len(info.sources)} sources" if info.sources else "",
                    f"{len(info.formats)} formats" if info.formats else "",
                )
                if part
            )
            item = QTreeWidgetItem([name or info.file, info.version, info.status, provides, description])
            item.setToolTip(2, info.error or info.sha256)
            item.setData(0, INFO_ROLE, info)
            self.tree.addTopLevelItem(item)
        for column in range(4):
            self.tree.resizeColumnToContents(column)
        self._update_buttons()

    def _selected(self) -> PluginInfo | None:
        items = self.tree.selectedItems()
        return items[0].data(0, INFO_ROLE) if items else None

    def _update_buttons(self) -> None:
        info = self._selected()
        self.enable_button.setEnabled(info is not None and not info.enabled)
        self.disable_button.setEnabled(info is not None and info.enabled)
        self.detail.setText(f"⚠ {info.error}" if info is not None and info.error else "")

    def enable_selected(self) -> None:
        info = self._selected()
        if info is None:
            return
        answer = QMessageBox.warning(
            self,
            "Approve plugin",
            f"{info.file} will run as Python code with your permissions: it can read your files and use the "
            "network.\n\n"
            "Only approve plugins you wrote or trust. The approval is tied to this exact file.",
            QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if answer == QMessageBox.StandardButton.Ok:
            self._settings.plugin_enabled[info.file] = info.sha256
            self.refresh()

    def disable_selected(self) -> None:
        info = self._selected()
        if info is not None:
            self._settings.plugin_enabled.pop(info.file, None)
            self.refresh()

    def _open_folder(self) -> None:
        os.makedirs(self._folder, exist_ok=True)  # noqa: PTH103
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(self._folder)))


class ReportDialog(QDialog):
    """A plugin's text report."""

    def __init__(self, title: str, text: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(760, 520)
        self.view = QPlainTextEdit(text, self)
        self.view.setReadOnly(True)
        copy = QPushButton("Copy", self)
        copy.clicked.connect(lambda: QGuiApplication.clipboard().setText(self.view.toPlainText()))
        layout = QVBoxLayout(self)
        layout.addWidget(self.view, 1)
        layout.addWidget(copy)
