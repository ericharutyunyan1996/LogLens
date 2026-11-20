"""AI settings dialog and the 'preview before sending' dialog."""

from __future__ import annotations

import html
import threading
from typing import ClassVar

from PySide6.QtCore import Qt, SignalInstance
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
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from ..core.ai import credentials
from ..core.ai.claude import SECRET_LABELS, AIError, missing_dependency
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
from ..core.ai.status import STATUS_LABELS, ProviderStatus, TestResult
from ..core.ai.validation import preflight
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
CLOUD_CREDENTIALS_NOTE = (
    "LogLens does not store Google Cloud or AWS credentials: they stay with gcloud / the AWS CLI (or the "
    "GOOGLE_APPLICATION_CREDENTIALS file). To sign them out, run: gcloud auth application-default revoke "
    "(Google) or aws sso logout (AWS)."
)
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
        self._ok_button = buttons.button(QDialogButtonBox.StandardButton.Ok)
        self._on_provider_changed()
        self._status = ProviderStatus.NOT_TESTED
        self._tested_signature: tuple[object, ...] | None = None
        for signal in self._settings_signals():
            signal.connect(self._invalidate_status)
        self.enabled.toggled.connect(self._invalidate_status)
        self._invalidate_status()

    # ---- groups --------------------------------------------------------------------------------------------------
    def _connection_group(self, config: AIConfig) -> QGroupBox:  # noqa: PLR0915 - one statement per settings control
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
        self.forget_button = QPushButton("Remove all saved credentials…", group)
        self.forget_button.setToolTip("Delete every API key LogLens has stored in Windows Credential Manager")
        self.forget_button.clicked.connect(self._forget_all)
        form.addRow("", self.forget_button)
        self.cloud_note = QLabel(CLOUD_CREDENTIALS_NOTE, group)
        self.cloud_note.setObjectName("dialogNote")
        self.cloud_note.setWordWrap(True)
        self.cloud_note.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        form.addRow("", self.cloud_note)
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
        self.test_result.setTextFormat(Qt.TextFormat.RichText)
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
    def _is_local(self) -> bool:
        return Provider(self.provider.currentData()) is Provider.LOCAL

    def config(self) -> AIConfig:
        return AIConfig(
            enabled=self.enabled.isChecked(),
            provider=Provider(self.provider.currentData()),
            model=self.model.currentText().strip() or (SUGGESTED_MODELS[0] if self._is_local() else ""),
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
        self._form.setRowVisible(self.cloud_note, provider in {Provider.VERTEX, Provider.BEDROCK})
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
        """Delete the key of the selected provider from Windows Credential Manager (and check that it is gone)."""
        name = secret_name(self.config())
        try:
            removed = credentials.delete_secrets([name])
        except OSError as exc:
            self.key_state.setText(f"Could not remove: {exc}")
            return
        self.api_key.clear()
        self._refresh_key_state()
        if removed:
            self.key_state.setText("✓ The saved key was deleted from Windows Credential Manager.")
        self._invalidate_status()

    def _forget_all(self) -> None:
        """Delete EVERY credential LogLens has saved (after asking), then verify that nothing is left."""
        try:
            present = credentials.saved_secrets(SECRET_LABELS)
        except OSError as exc:
            QMessageBox.warning(self, "Saved credentials", f"Could not read Windows Credential Manager: {exc}")
            return
        if not present:
            QMessageBox.information(self, "Saved credentials", "LogLens has no saved credentials.")
            return
        listing = "\n".join(f"  • {SECRET_LABELS[name]}" for name in present)
        answer = QMessageBox.warning(
            self,
            "Remove saved credentials",
            f"Delete these from Windows Credential Manager?\n\n{listing}\n\nYou will have to paste the key(s) again "
            "to use that provider. This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            removed = credentials.delete_secrets(present)
            left = credentials.saved_secrets(SECRET_LABELS)
        except OSError as exc:
            QMessageBox.warning(self, "Saved credentials", f"Could not remove everything: {exc}")
            self._refresh_key_state()
            return
        self.api_key.clear()
        self._refresh_key_state()
        self._invalidate_status()
        if left:
            QMessageBox.warning(self, "Saved credentials", f"Still stored: {', '.join(SECRET_LABELS[n] for n in left)}")
        else:
            self.key_state.setText(f"✓ Removed {len(removed)} saved credential(s) from Windows Credential Manager.")

    # ---- status: always the result of real validation, never a remembered "OK" ---------------------------------------
    STATUS_COLORS: ClassVar[dict[ProviderStatus, str]] = {
        ProviderStatus.CONNECTED: "#2e8b57",
        ProviderStatus.NOT_TESTED: "#8a8a8a",
        ProviderStatus.NOT_CONFIGURED: "#8a8a8a",
        ProviderStatus.INCOMPLETE: "#c08a00",
    }

    def _settings_signals(self) -> list[SignalInstance]:
        """Every control whose value changes what a connection would do."""
        widgets = [
            self.provider, self.model, self.aws_region, self.gcp_project, self.gcp_region, self.foundry_resource,
            self.local_api, self.local_url, self.local_model, self.local_remote, self.compatibility, self.api_key,
        ]  # fmt: skip
        out: list[SignalInstance] = []
        for widget in widgets:
            for name in ("currentTextChanged", "textChanged", "toggled"):
                signal = getattr(widget, name, None)
                if signal is not None:
                    out.append(signal)
                    break
        return out

    def _signature(self) -> tuple[object, ...]:
        config = self.config()
        return (config.provider, config.model, config.aws_region, config.gcp_project, config.gcp_region,
                config.foundry_resource, config.local_api, config.local_url, config.local_model,
                config.local_allow_remote, config.compatibility_mode, hash(self.api_key.text()))  # fmt: skip

    def _typed_or_saved_key(self) -> str | None:
        typed = self.api_key.text().strip()
        if typed:
            return typed
        try:
            return credentials.load_secret(secret_name(self.config()))
        except OSError:
            return None

    def _show_status(self, status: ProviderStatus, message: str = "") -> None:
        self._status = status
        color = self.STATUS_COLORS.get(status, "#c0504d")
        detail = f" — {html.escape(message)}" if message else ""
        self.test_result.setText(f"<span style='color:{color}'>● <b>{STATUS_LABELS[status]}</b></span>{detail}")

    def _invalidate_status(self, *_args: object) -> None:
        """A setting changed: a past result no longer says anything about the new settings."""
        self._tested_signature = None
        problem = preflight(self.config(), self._typed_or_saved_key())
        if problem is not None:
            self._show_status(problem.status, problem.message)
        else:
            self._show_status(ProviderStatus.NOT_TESTED, "click Test connection to verify these settings.")
        self._update_ok()

    def _save_problem(self) -> TestResult | None:
        """Why these settings cannot be saved yet, or None. Only an ENABLED assistant needs complete settings: an
        incomplete or malformed configuration is never stored as if it were usable."""
        if not self.enabled.isChecked():
            return None
        config = self.config()
        stored: str | None = None
        if config.needs_api_key:
            try:
                stored = credentials.load_secret(secret_name(config))
            except OSError:
                stored = None
            if not stored and self.api_key.text().strip():
                return TestResult(
                    ProviderStatus.INCOMPLETE, "You typed a key but have not saved it yet: click Save key."
                )
        return preflight(config, stored)

    def _update_ok(self) -> None:
        problem = self._save_problem()
        self._ok_button.setEnabled(problem is None)
        self._ok_button.setToolTip(problem.message if problem is not None else "")

    def accept(self) -> None:
        """OK saves only settings that pass validation (or an assistant that is switched off)."""
        problem = self._save_problem()
        if problem is not None:
            self._show_status(problem.status, problem.message)
            QMessageBox.warning(
                self,
                "AI settings can't be saved yet",
                f"{problem.message}\n\nFix this, or untick 'Enable the AI assistant' to save without it.",
            )
            return
        super().accept()

    @property
    def status(self) -> ProviderStatus:
        return self._status

    def _test(self) -> None:
        problem = preflight(self.config(), self._typed_or_saved_key())
        if problem is not None:  # nothing to ask the provider yet
            self._show_status(problem.status, problem.message)
            return
        self._tested_signature = self._signature()
        self._show_status(ProviderStatus.NOT_TESTED, "testing…")
        self._service.test_connection(self.config(), api_key=self.api_key.text().strip() or None)

    def _on_tested(self, result: TestResult) -> None:
        if self._tested_signature is None or self._tested_signature != self._signature():
            return  # the settings changed while the test ran: its answer is about something else now
        if result.compatibility_needed:
            self.compatibility.setChecked(True)  # (re-triggers invalidation: that is a changed setting)
            self._tested_signature = self._signature()
        self._show_status(result.status, result.message)

    # ---- lifetime: the service outlives the dialog ---------------------------------------------------------------
    def _listen(self, on: bool) -> None:
        if on and not self._listening:
            self._service.testResult.connect(self._on_tested)
        elif not on and self._listening:
            self._service.testResult.disconnect(self._on_tested)
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
