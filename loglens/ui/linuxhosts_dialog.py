"""File → WSL & Linux hosts…: tail a file or follow the journal of a WSL distribution or an SSH host."""

from __future__ import annotations

import contextlib

from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from ..core.containers import ContainerError, LogSource
from ..core.linuxhosts import list_wsl_distros, ssh_source, wsl_source


class LinuxHostsDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("WSL and Linux hosts")
        intro = QLabel(
            "Follow a log file or the system journal of a WSL distribution, or of a Linux host over SSH. SSH signs in "
            "with your keys or ssh-agent only: LogLens never asks for or stores a password.",
            self,
        )
        intro.setWordWrap(True)
        intro.setObjectName("dialogNote")
        self.where = QComboBox(self)
        self.where.addItem("A WSL distribution", "wsl")
        self.where.addItem("A Linux host over SSH", "ssh")
        self.where.currentIndexChanged.connect(self._where_changed)
        self.distro = QComboBox(self)
        self.distro.setEditable(True)
        with contextlib.suppress(ContainerError):  # no WSL installed: the box stays empty
            self.distro.addItems(list_wsl_distros())
        self.host = QLineEdit(self)
        self.host.setPlaceholderText("server.example.com")
        self.user = QLineEdit(self)
        self.user.setPlaceholderText("(your ssh config decides)")
        self.what = QComboBox(self)
        self.what.addItem("A log file", "file")
        self.what.addItem("The system journal", "journal")
        self.target = QLineEdit(self)
        self.target.setPlaceholderText("/var/log/syslog   (journal: optional service, like nginx.service)")
        self.lines = QSpinBox(self)
        self.lines.setRange(0, 1_000_000)
        self.lines.setValue(1000)
        self.problem_label = QLabel("", self)
        self.problem_label.setObjectName("dialogProblem")
        form = QFormLayout()
        form.addRow("Where", self.where)
        form.addRow("Distribution", self.distro)
        form.addRow("Host", self.host)
        form.addRow("User", self.user)
        form.addRow("What", self.what)
        form.addRow("Path / service", self.target)
        form.addRow("Most recent lines", self.lines)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel, self)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addWidget(intro)
        layout.addLayout(form)
        layout.addWidget(self.problem_label)
        layout.addWidget(buttons)
        self._where_changed()

    def _where_changed(self) -> None:
        wsl = self.where.currentData() == "wsl"
        self.distro.setEnabled(wsl)
        self.host.setEnabled(not wsl)
        self.user.setEnabled(not wsl)

    def source(self) -> LogSource:
        """The chosen source; raises ContainerError with a plain message when a value is not usable."""
        kind, target, lines = str(self.what.currentData()), self.target.text().strip(), self.lines.value()
        if self.where.currentData() == "wsl":
            return wsl_source(self.distro.currentText().strip(), kind, target, lines=lines)
        return ssh_source(self.host.text().strip(), kind, target, user=self.user.text().strip(), lines=lines)

    def accept(self) -> None:
        try:
            self.source()
        except ContainerError as exc:
            self.problem_label.setText(str(exc))
            return
        super().accept()
