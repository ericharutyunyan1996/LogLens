"""File → Receive logs…: listen for syslog (UDP / TCP) or HTTP posts and follow what arrives as a live log."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

CHOICES = (
    ("syslog-udp", "Syslog over UDP", 5514),
    ("syslog-tcp", "Syslog over TCP", 5514),
    ("http", "HTTP: POST lines to any path", 8514),
)


class ReceiverDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Receive logs")
        intro = QLabel(
            "Other machines and apps can push logs to LogLens. What arrives is written to a log that opens live. "
            "Receiving on other computers' connections lets anyone on your network send lines: use it on networks "
            "you trust, and allow the port in the Windows firewall.",
            self,
        )
        intro.setWordWrap(True)
        intro.setObjectName("dialogNote")
        self.kind = QComboBox(self)
        for key, label, _port in CHOICES:
            self.kind.addItem(label, key)
        self.kind.currentIndexChanged.connect(self._default_port)
        self.scope = QComboBox(self)
        self.scope.addItem("This computer only (127.0.0.1)", "127.0.0.1")
        self.scope.addItem("Other computers can connect (all interfaces)", "0.0.0.0")
        self.port = QSpinBox(self)
        self.port.setRange(1, 65535)
        self.port.setValue(CHOICES[0][2])
        form = QFormLayout()
        form.addRow("Receive", self.kind)
        form.addRow("From", self.scope)
        form.addRow("Port", self.port)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel, self)
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Start receiving")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addWidget(intro)
        layout.addLayout(form)
        layout.addWidget(buttons)

    def _default_port(self) -> None:
        self.port.setValue(next(port for key, _label, port in CHOICES if key == self.kind.currentData()))

    def choice(self) -> tuple[str, str, int]:
        return str(self.kind.currentData()), str(self.scope.currentData()), self.port.value()
