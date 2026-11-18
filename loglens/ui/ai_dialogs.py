"""AI settings dialog and the 'preview before sending' dialog."""

from __future__ import annotations

import threading

from PySide6.QtCore import Qt
from PySide6.QtGui import QShowEvent
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from ..core.ai import credentials
from ..core.ai.claude import AIError, missing_dependency
from ..core.ai.config import (
    ALWAYS_REDACTED,
    DEFAULT_LOCAL_URLS,
    EFFORTS,
    LOCAL_APIS,
    PROVIDER_LABELS,
    SUGGESTED_MODELS,
    AIConfig,
    Provider,
    Redact,
)
from ..core.ai.explain import ExplainRequest
from ..core.ai.local import list_models
from ..services.ai_service import AIService, secret_name
from ..services.analysis_jobs import AnalysisRunner, Progress, Task

REDACTION_LABELS: dict[Redact, str] = {
    Redact.SECRETS: "Secrets — passwords, API keys, tokens, JWTs, credentials in URLs",
    Redact.EMAILS: "E-mail addresses",
    Redact.IP_ADDRESSES: "IP addresses",
    Redact.USER_PATHS: "User names (profile paths, DOMAIN\\name, user 'name')",
    Redact.HOSTNAMES: "Host / domain names",
    Redact.GUIDS: "GUIDs / correlation IDs",
}
PRIVACY_NOTE = (
    "Nothing is sent automatically. Only when you click <b>Explain</b>, the selected line and its surrounding lines "
    "are sent to the provider below — after redaction, and (if enabled) after you have seen a preview."
)


def _models_task(config: AIConfig) -> Task:
    """A runner task listing the local server's models; returns the list, or the AIError when unreachable."""

    def task(_cancel: threading.Event, _report: Progress) -> list[str] | AIError:
        try:
            return list_models(config)
        except AIError as exc:
            return exc

    return task


class AISettingsDialog(QDialog):
    def __init__(self, config: AIConfig, service: AIService, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("AI assistant settings")
        self.setMinimumWidth(640)
        self._service = service
        self._listening = False  # connected to the long-lived service's connectionTested
        self._listen(True)
        self._models_job = AnalysisRunner(self)  # lists local models off the UI thread (the server may be slow)
        self._models_job.finished.connect(self._on_models_listed)
        self._models_job.failed.connect(self._on_models_failed)

        self.enabled = QCheckBox("Enable the AI assistant", self)
        self.enabled.setChecked(config.enabled)
        note = QLabel(PRIVACY_NOTE, self)
        note.setWordWrap(True)
        note.setObjectName("dialogNote")

        layout = QVBoxLayout(self)
        layout.addWidget(self.enabled)
        layout.addWidget(note)
        layout.addWidget(self._connection_group(config))
        layout.addWidget(self._request_group(config))
        layout.addWidget(self._privacy_group(config))
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel, self)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self._on_provider_changed()

    # ---- groups --------------------------------------------------------------------------------------------------
    def _connection_group(self, config: AIConfig) -> QGroupBox:
        group = QGroupBox("Connection", self)
        form = QFormLayout(group)
        self.provider = QComboBox(group)
        for provider, label in PROVIDER_LABELS.items():
            self.provider.addItem(label, provider.value)
        self.provider.setCurrentIndex(self.provider.findData(config.provider.value))
        self.provider.currentIndexChanged.connect(self._on_provider_changed)
        form.addRow("Provider", self.provider)

        self.api_key = QLineEdit(group)
        self.api_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.api_key.setPlaceholderText("paste a key and click Save key")
        self.key_state = QLabel(group)
        save_key = QPushButton("Save key", group)
        save_key.clicked.connect(self._save_key)
        remove_key = QPushButton("Remove key", group)
        remove_key.clicked.connect(self._remove_key)
        key_row = QHBoxLayout()
        key_row.addWidget(self.api_key, 1)
        key_row.addWidget(save_key)
        key_row.addWidget(remove_key)
        self.key_row_widget = QWidget(group)
        self.key_row_widget.setLayout(key_row)
        form.addRow("API key", self.key_row_widget)
        form.addRow("", self.key_state)

        self.aws_region = QLineEdit(config.aws_region, group)
        self.gcp_project = QLineEdit(config.gcp_project, group)
        self.gcp_region = QLineEdit(config.gcp_region, group)
        self.foundry_resource = QLineEdit(config.foundry_resource, group)
        self.platform_rows = {
            Provider.BEDROCK: [("AWS region", self.aws_region)],
            Provider.VERTEX: [("GCP project", self.gcp_project), ("GCP region", self.gcp_region)],
            Provider.FOUNDRY: [("Foundry resource", self.foundry_resource)],
        }
        for rows in self.platform_rows.values():
            for label, widget in rows:
                form.addRow(label, widget)
        self._local_rows(form, config, group)
        self.env_note = QLabel("Uses ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN or an `ant auth login` profile.", group)
        self.env_note.setObjectName("dialogNote")
        form.addRow("", self.env_note)
        self.dependency_note = QLabel(group)
        self.dependency_note.setObjectName("warningNote")
        self.dependency_note.setWordWrap(True)
        self.dependency_note.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        form.addRow("", self.dependency_note)

        self.compatibility = QCheckBox("Compatibility mode for company AI gateways / proxies", group)
        self.compatibility.setChecked(config.compatibility_mode)
        self.compatibility.setToolTip(
            "Sends the classic request format (API version 2023-06-01). Needed by some gateways; LogLens switches it "
            "on automatically when a gateway rejects the newer format."
        )
        form.addRow("", self.compatibility)

        test = QPushButton("Test connection", group)
        test.clicked.connect(self._test)
        self.test_result = QLabel(group)
        self.test_result.setWordWrap(True)
        test_row = QHBoxLayout()
        test_row.addWidget(test)
        test_row.addWidget(self.test_result, 1)
        form.addRow("", self._wrap(test_row))
        self._form = form
        return group

    def _local_rows(self, form: QFormLayout, config: AIConfig, group: QWidget) -> None:
        self.local_api = QComboBox(group)
        for key, label in LOCAL_APIS.items():
            self.local_api.addItem(label, key)
        self.local_api.setCurrentIndex(max(self.local_api.findData(config.local_api), 0))
        self.local_api.currentIndexChanged.connect(self._on_local_api_changed)
        self.local_url = QLineEdit(config.local_url, group)
        self.local_model = QComboBox(group)
        self.local_model.setEditable(True)
        self.local_model.setCurrentText(config.local_model)
        editor = self.local_model.lineEdit()
        if editor is not None:
            editor.setPlaceholderText("e.g. llama3.1, qwen2.5:14b, mistral-nemo")
        self.refresh_models_button = QPushButton("Refresh", group)
        self.refresh_models_button.setToolTip("List the models installed on the server")
        self.refresh_models_button.clicked.connect(self.refresh_local_models)
        model_row = QHBoxLayout()
        model_row.addWidget(self.local_model, 1)
        model_row.addWidget(self.refresh_models_button)
        self.local_model_row = self._wrap(model_row)
        self.local_note = QLabel(
            "Runs entirely on this computer — nothing is sent over the network. Ollama: install it from ollama.com, "
            "then e.g. <code>ollama pull llama3.1</code>. Larger models answer better but need more memory; without "
            "a GPU an answer can take a minute or more.",
            group,
        )
        self.local_note.setObjectName("dialogNote")
        self.local_note.setWordWrap(True)
        self.local_remote = QCheckBox(
            "Allow a model server on another computer (log lines will then be sent over the network)", group
        )
        self.local_remote.setChecked(config.local_allow_remote)
        self.local_rows: list[QWidget] = [
            self.local_api, self.local_url, self.local_model_row, self.local_remote, self.local_note,
        ]  # fmt: skip
        form.addRow("Server type", self.local_api)
        form.addRow("Server address", self.local_url)
        form.addRow("Local model", self.local_model_row)
        form.addRow("", self.local_remote)
        form.addRow("", self.local_note)

    def _on_local_api_changed(self) -> None:
        if self.local_url.text().strip() in DEFAULT_LOCAL_URLS.values():  # keep a custom address
            self.local_url.setText(DEFAULT_LOCAL_URLS[str(self.local_api.currentData())])

    def refresh_local_models(self) -> None:
        """List the server's models in the background; the combo box is filled when the answer arrives."""
        self.refresh_models_button.setEnabled(False)
        self.test_result.setText("Listing models…")
        self._models_job.run_task(_models_task(self.config()))

    def _on_models_listed(self, result: object) -> None:
        self.refresh_models_button.setEnabled(True)
        if isinstance(result, AIError):
            self.test_result.setText(f"⚠ {result}")
            return
        assert isinstance(result, list)
        models = [str(m) for m in result]
        current = self.local_model.currentText()
        self.local_model.clear()
        self.local_model.addItems(models)
        self.local_model.setCurrentText(current if current in models or not models else models[0])
        self.test_result.setText(f"✓ {len(models)} models installed." if models else "⚠ No models installed yet.")

    def _on_models_failed(self, message: str) -> None:
        self.refresh_models_button.setEnabled(True)
        self.test_result.setText(f"⚠ {message}")

    def _request_group(self, config: AIConfig) -> QGroupBox:
        group = QGroupBox("Requests", self)
        form = QFormLayout(group)
        self.model = QComboBox(group)
        self.model.setEditable(True)
        self.model.addItems(SUGGESTED_MODELS)
        self.model.setCurrentText(config.model)
        form.addRow("Model", self.model)
        self.effort = QComboBox(group)
        self.effort.addItems(EFFORTS)
        self.effort.setCurrentText(config.effort)
        self.effort.setToolTip("Higher effort = deeper reasoning, slower and more tokens")
        form.addRow("Effort", self.effort)
        self.before = QSpinBox(group)
        self.before.setRange(0, 500)
        self.before.setValue(config.context_before)
        self.after = QSpinBox(group)
        self.after.setRange(0, 500)
        self.after.setValue(config.context_after)
        context_row = QHBoxLayout()
        for label, spin in (("before", self.before), ("after", self.after)):
            context_row.addWidget(spin)
            context_row.addWidget(QLabel(label, group))
        context_row.addStretch(1)
        form.addRow("Context lines", self._wrap(context_row))
        self._request_form = form
        return group

    def _privacy_group(self, config: AIConfig) -> QGroupBox:
        group = QGroupBox("Privacy", self)
        layout = QVBoxLayout(group)
        active = config.redaction_set()
        self.redactions: dict[Redact, QCheckBox] = {}
        for category, label in REDACTION_LABELS.items():
            box = QCheckBox(f"Redact {label}", group)
            box.setChecked(category in active)
            if category in ALWAYS_REDACTED:  # never sent: the box shows it, but can't be switched off
                box.setEnabled(False)
                box.setToolTip("Always on: secrets are never sent to an AI provider.")
            layout.addWidget(box)
            self.redactions[category] = box
        self.preview = QCheckBox("Show me exactly what will be sent before sending", group)
        self.preview.setChecked(config.preview_before_send)
        layout.addWidget(self.preview)
        return group

    @staticmethod
    def _wrap(inner: QHBoxLayout) -> QWidget:
        widget = QWidget()
        inner.setContentsMargins(0, 0, 0, 0)
        widget.setLayout(inner)
        return widget

    # ---- behaviour -----------------------------------------------------------------------------------------------
    def config(self) -> AIConfig:
        return AIConfig(
            enabled=self.enabled.isChecked(),
            provider=Provider(self.provider.currentData()),
            model=self.model.currentText().strip() or SUGGESTED_MODELS[0],
            effort=self.effort.currentText(),
            context_before=self.before.value(),
            context_after=self.after.value(),
            preview_before_send=self.preview.isChecked(),
            compatibility_mode=self.compatibility.isChecked(),
            redactions=[c.value for c, box in self.redactions.items() if box.isChecked()],
            aws_region=self.aws_region.text().strip(),
            gcp_project=self.gcp_project.text().strip(),
            gcp_region=self.gcp_region.text().strip() or "global",
            foundry_resource=self.foundry_resource.text().strip(),
            local_api=str(self.local_api.currentData()),
            local_url=self.local_url.text().strip() or DEFAULT_LOCAL_URLS[str(self.local_api.currentData())],
            local_model=self.local_model.currentText().strip(),
            local_allow_remote=self.local_remote.isChecked(),
        )

    def _on_provider_changed(self) -> None:
        provider = Provider(self.provider.currentData())
        needs_key = provider in {Provider.API_KEY, Provider.FOUNDRY}
        self._form.setRowVisible(self.key_row_widget, needs_key)
        self._form.setRowVisible(self.key_state, needs_key)
        for platform, rows in self.platform_rows.items():
            for _label, widget in rows:
                self._form.setRowVisible(widget, platform is provider)
        self._form.setRowVisible(self.env_note, provider is Provider.ENVIRONMENT)
        local = provider is Provider.LOCAL
        for local_widget in self.local_rows:
            self._form.setRowVisible(local_widget, local)
        self._form.setRowVisible(self.compatibility, not local)
        self._request_form.setRowVisible(self.model, not local)
        self._request_form.setRowVisible(self.effort, not local)
        hint = missing_dependency(provider)
        self.dependency_note.setText(f"⚠ {hint}" if hint else "")
        self._form.setRowVisible(self.dependency_note, hint is not None)
        self._refresh_key_state()

    def _refresh_key_state(self) -> None:
        try:
            saved = credentials.load_secret(secret_name(self.config())) is not None
        except OSError as exc:
            self.key_state.setText(f"Credential Manager error: {exc}")
            return
        self.key_state.setText("✓ A key is saved in Windows Credential Manager." if saved else "No key saved yet.")

    def _save_key(self) -> None:
        key = self.api_key.text().strip()
        if not key:
            self.key_state.setText("Paste a key first.")
            return
        try:
            credentials.save_secret(secret_name(self.config()), key)
        except OSError as exc:
            self.key_state.setText(f"Could not save: {exc}")
            return
        self.api_key.clear()
        self._refresh_key_state()

    def _remove_key(self) -> None:
        try:
            credentials.delete_secret(secret_name(self.config()))
        except OSError as exc:
            self.key_state.setText(f"Could not remove: {exc}")
            return
        self._refresh_key_state()

    def _test(self) -> None:
        self.test_result.setText("Testing…")
        self._service.test_connection(self.config(), api_key=self.api_key.text().strip() or None)

    def _on_tested(self, ok: bool, message: str, compatibility_needed: bool) -> None:
        if compatibility_needed:
            self.compatibility.setChecked(True)
        self.test_result.setText(("✓ " if ok else "⚠ ") + message)

    # ---- lifetime: the service outlives the dialog ---------------------------------------------------------------
    def _listen(self, on: bool) -> None:
        if on and not self._listening:
            self._service.connectionTested.connect(self._on_tested)
        elif not on and self._listening:
            self._service.connectionTested.disconnect(self._on_tested)
        self._listening = on

    def showEvent(self, event: QShowEvent) -> None:
        self._listen(True)  # shown again after done()
        super().showEvent(event)

    def done(self, result: int) -> None:
        """Closed (OK, Cancel, Esc, ×): stop listening to the service and drop a pending model listing."""
        self._listen(False)
        self._models_job.cancel()
        self.refresh_models_button.setEnabled(True)
        super().done(result)


class AIPreviewDialog(QDialog):
    """Shows — and lets the user edit — the exact text that will be sent. Nothing leaves the machine before Send."""

    def __init__(self, request: ExplainRequest, destination: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Send to AI — review and edit")
        self.resize(860, 600)
        self._original = request.user_text
        counts = ", ".join(f"{label} × {n}" for label, n in sorted(request.redaction_counts.items()))
        summary = QLabel(
            f"This text will be sent to <b>{destination}</b> — <b>edit it freely</b>: delete lines or replace values "
            "you don't want to share. Exactly what you see is sent.<br>"
            f"Already redacted automatically: {counts if counts else 'nothing matched the enabled redaction rules'}.",
            self,
        )
        summary.setWordWrap(True)
        self.text = QPlainTextEdit(request.user_text, self)
        self.text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.text.textChanged.connect(self._update_counter)
        self.counter = QLabel(self)
        self.counter.setObjectName("dialogNote")
        reset = QPushButton("Reset to original", self)
        reset.clicked.connect(lambda: self.text.setPlainText(self._original))
        tools = QHBoxLayout()
        tools.addWidget(self.counter, 1)
        tools.addWidget(reset)
        self.dont_ask = QCheckBox("Don't show this preview again (you can turn it back on in AI settings)", self)
        buttons = QDialogButtonBox(self)
        self.send_button = buttons.addButton("Send", QDialogButtonBox.ButtonRole.AcceptRole)
        self.send_button.setDefault(True)
        buttons.addButton(QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addWidget(summary)
        layout.addWidget(self.text, 1)
        layout.addLayout(tools)
        layout.addWidget(self.dont_ask, 0, Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(buttons)
        self._update_counter()

    def edited_text(self) -> str:
        return self.text.toPlainText()

    def _update_counter(self) -> None:
        text = self.edited_text()
        changed = " · edited" if text != self._original else ""
        self.counter.setText(f"{len(text):,} characters · {text.count(chr(10)) + 1:,} lines{changed}")
        self.send_button.setEnabled(bool(text.strip()))
