"""File → Log platforms…: read Grafana Loki or Elasticsearch / OpenSearch logs into a log tab."""

from __future__ import annotations

from datetime import timedelta
from urllib.parse import urlparse

from PySide6.QtWidgets import (
    QCheckBox,
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

from ..core.ai import credentials
from ..core.cloud import CloudError, elastic_lines, loki_lines


def secret_name(url: str) -> str:
    return f"cloud:{urlparse(url).netloc.lower()}"


class CloudDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Log platforms")
        intro = QLabel(
            "Read logs from Grafana Loki or Elasticsearch / OpenSearch. The query is limited by time and size and the "
            "result opens as a log. A token is optional; remembering it keeps it in Windows Credential Manager only.",
            self,
        )
        intro.setWordWrap(True)
        intro.setObjectName("dialogNote")
        self.kind = QComboBox(self)
        self.kind.addItem("Grafana Loki (LogQL)", "loki")
        self.kind.addItem("Elasticsearch / OpenSearch", "elastic")
        self.kind.currentIndexChanged.connect(self._kind_changed)
        self.url = QLineEdit(self)
        self.url.setPlaceholderText("https://loki.example.com")
        self.index = QLineEdit(self)
        self.index.setPlaceholderText("logs-*")
        self.query = QLineEdit(self)
        self.hours = QSpinBox(self)
        self.hours.setRange(1, 24 * 30)
        self.hours.setValue(1)
        self.hours.setSuffix(" hours back")
        self.limit = QSpinBox(self)
        self.limit.setRange(1, 50_000)
        self.limit.setValue(5000)
        self.token = QLineEdit(self)
        self.token.setEchoMode(QLineEdit.EchoMode.Password)
        self.token.setPlaceholderText("(optional bearer token)")
        self.remember = QCheckBox("Remember the token in Windows Credential Manager", self)
        self.problem_label = QLabel("", self)
        self.problem_label.setObjectName("dialogProblem")
        form = QFormLayout()
        for label, widget in (
            ("Platform", self.kind),
            ("Address", self.url),
            ("Index", self.index),
            ("Query", self.query),
            ("Period", self.hours),
            ("Most lines", self.limit),
            ("Token", self.token),
        ):
            form.addRow(label, widget)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel, self)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addWidget(intro)
        layout.addLayout(form)
        layout.addWidget(self.remember)
        layout.addWidget(self.problem_label)
        layout.addWidget(buttons)
        self._form = form
        self.url.editingFinished.connect(self._load_token)
        self._kind_changed()

    def _kind_changed(self) -> None:
        loki = self.kind.currentData() == "loki"
        self.index.setEnabled(not loki)
        self.query.setPlaceholderText('{app="shop"} |= "error"' if loki else "level:error  (optional)")

    def _load_token(self) -> None:
        if self.url.text().strip() and not self.token.text():
            try:
                saved = credentials.load_secret(secret_name(self.url.text()))
            except OSError:
                saved = None
            if saved:
                self.token.setText(saved)
                self.remember.setChecked(True)

    def fetch(self) -> list[str]:
        """Run the query (blocking: call it from a worker thread); raises CloudError."""
        span, limit, token = timedelta(hours=self.hours.value()), self.limit.value(), self.token.text().strip()
        if self.kind.currentData() == "loki":
            return loki_lines(self.url.text().strip(), self.query.text(), since=span, limit=limit, token=token)
        return elastic_lines(
            self.url.text().strip(), self.index.text().strip(), self.query.text(), since=span, limit=limit, token=token
        )

    def accept(self) -> None:
        if not self.url.text().strip():
            self.problem_label.setText("Enter the address of the service.")
            return
        if self.remember.isChecked() and self.token.text().strip():
            try:
                credentials.save_secret(secret_name(self.url.text()), self.token.text().strip())
            except OSError as exc:
                self.problem_label.setText(f"The token could not be saved: {exc}")
                return
        super().accept()


__all__ = ["CloudDialog", "CloudError", "secret_name"]
