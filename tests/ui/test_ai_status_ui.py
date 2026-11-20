"""The AI settings dialog's status indicator: real results only, reset whenever a setting changes."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable

from PySide6.QtWidgets import QApplication

from loglens.core.ai.claude import AIError
from loglens.core.ai.config import AIConfig, Provider
from loglens.core.ai.status import ProviderStatus
from loglens.services.ai_service import AIService
from loglens.ui.ai_dialogs import AISettingsDialog


class FakeProvider:
    compatibility_used = False

    def __init__(self, gate: threading.Event | None = None, error: AIError | None = None) -> None:
        self.gate, self.error = gate, error

    def test_connection(self) -> str:
        if self.gate is not None:
            self.gate.wait(10)
        if self.error is not None:
            raise self.error
        return "qwen2.5:7b (local)"


def make_dialog(provider: FakeProvider) -> AISettingsDialog:
    service = AIService(factory=lambda _config, _key: provider)
    dialog = AISettingsDialog(AIConfig(enabled=True, provider=Provider.LOCAL, local_model="qwen2.5:7b"), service)
    dialog.show()
    return dialog


def test_status_follows_validation_test_result_and_setting_changes(
    qapp: QApplication, wait_for: Callable[..., None]
) -> None:
    dialog = make_dialog(FakeProvider())
    assert dialog.status is ProviderStatus.NOT_TESTED  # complete settings, never tested
    dialog.local_model.setCurrentText("")
    assert dialog.status is ProviderStatus.NOT_CONFIGURED  # nothing chosen yet
    dialog.local_model.setCurrentText("qwen2.5:7b")
    dialog._test()
    wait_for(lambda: dialog.status is ProviderStatus.CONNECTED)
    assert "Connected" in dialog.test_result.text() and "qwen2.5:7b" in dialog.test_result.text()
    dialog.local_url.setText("http://127.0.0.1:9999")  # any setting change drops the old result
    assert dialog.status is ProviderStatus.NOT_TESTED
    dialog.local_url.setText("localhost:11434")  # malformed address
    assert dialog.status is ProviderStatus.INCOMPLETE and "http://" in dialog.test_result.text()
    dialog.close()


def test_failure_statuses_are_shown_with_their_message(qapp: QApplication, wait_for: Callable[..., None]) -> None:
    error = AIError("Permission denied: the identity may not use this model.", ProviderStatus.PERMISSION_DENIED)
    dialog = make_dialog(FakeProvider(error=error))
    dialog._test()
    wait_for(lambda: dialog.status is ProviderStatus.PERMISSION_DENIED)
    assert "Permission denied" in dialog.test_result.text() and "may not use this model" in dialog.test_result.text()
    dialog.close()


def test_vertex_fields_are_validated_in_the_dialog(qapp: QApplication) -> None:
    dialog = make_dialog(FakeProvider())
    dialog.provider.setCurrentIndex(dialog.provider.findData(Provider.VERTEX.value))
    dialog._invalidate_status()
    assert dialog.status is ProviderStatus.NOT_CONFIGURED  # no project yet
    dialog.gcp_project.setText("Not A Project")
    assert dialog.status is ProviderStatus.INCOMPLETE
    dialog.gcp_project.setText("my-project-123")
    assert dialog.status is ProviderStatus.NOT_TESTED
    dialog.close()


def test_an_answer_for_old_settings_is_never_shown_as_connected(
    qapp: QApplication, wait_for: Callable[..., None]
) -> None:
    gate = threading.Event()
    dialog = make_dialog(FakeProvider(gate=gate))
    dialog._test()  # the provider is still "thinking" ...
    dialog.local_url.setText("http://127.0.0.1:12345")  # ... when the user edits the address
    gate.set()
    deadline = time.monotonic() + 1.5
    while time.monotonic() < deadline:  # let the (now stale) answer arrive
        qapp.processEvents()
        time.sleep(0.01)
    assert dialog.status is ProviderStatus.NOT_TESTED
    dialog.close()


# ---- deleting saved credentials ------------------------------------------------------------------------------------------
class FakeStore:
    """An in-memory stand-in for Windows Credential Manager, so the dialog tests never touch the real keys."""

    def __init__(self) -> None:
        self.data = {"anthropic-api-key": "sk-ant-api03-" + "k" * 30, "foundry-api-key": "foundry-secret-value"}

    def install(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        from loglens.core.ai import credentials

        monkeypatch.setattr(credentials, "load_secret", self.data.get)
        monkeypatch.setattr(credentials, "save_secret", self.data.__setitem__)
        monkeypatch.setattr(credentials, "delete_secret", lambda name: self.data.pop(name, None))


def test_remove_key_deletes_only_the_selected_providers_key(qapp: QApplication, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    store = FakeStore()
    store.install(monkeypatch)
    service = AIService(factory=lambda _c, _k: FakeProvider())
    dialog = AISettingsDialog(AIConfig(enabled=True, provider=Provider.API_KEY), service)
    dialog.show()
    assert "saved" in dialog.key_state.text().lower()
    dialog._remove_key()
    assert "anthropic-api-key" not in store.data and "foundry-api-key" in store.data  # the other key is untouched
    assert "deleted" in dialog.key_state.text()
    assert dialog.status is ProviderStatus.NOT_CONFIGURED  # no key any more: the status says so, not "connected"
    dialog.close()


def test_remove_all_saved_credentials_asks_first_and_deletes_everything(qapp: QApplication, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from PySide6.QtWidgets import QMessageBox

    store = FakeStore()
    store.install(monkeypatch)
    asked: list[str] = []
    answers = iter([QMessageBox.StandardButton.Cancel, QMessageBox.StandardButton.Yes])

    def fake_warning(_parent, _title, text, *_args):  # type: ignore[no-untyped-def]
        asked.append(text)
        return next(answers)

    monkeypatch.setattr(QMessageBox, "warning", fake_warning)
    dialog = AISettingsDialog(
        AIConfig(enabled=True, provider=Provider.API_KEY), AIService(factory=lambda _c, _k: FakeProvider())
    )
    dialog.show()
    dialog._forget_all()  # the user says Cancel: nothing is deleted
    assert len(store.data) == 2
    assert "Anthropic API key" in asked[0] and "Microsoft Foundry API key" in asked[0]  # it lists what will go
    dialog._forget_all()  # the user confirms
    assert store.data == {}
    assert "Removed 2" in dialog.key_state.text()
    assert dialog.api_key.text() == ""
    dialog.close()


def test_cloud_providers_explain_where_their_credentials_live(qapp: QApplication) -> None:
    dialog = AISettingsDialog(
        AIConfig(enabled=True, provider=Provider.VERTEX), AIService(factory=lambda _c, _k: FakeProvider())
    )
    dialog.show()
    assert dialog.cloud_note.isVisible() and "gcloud auth application-default revoke" in dialog.cloud_note.text()
    dialog.provider.setCurrentIndex(dialog.provider.findData(Provider.LOCAL.value))
    assert not dialog.cloud_note.isVisible()
    dialog.close()


# ---- OK only saves settings that pass validation -------------------------------------------------------------------------
def _dialog(monkeypatch, provider: Provider, *, enabled: bool = True, stored: dict | None = None, **fields):  # type: ignore[no-untyped-def]
    from PySide6.QtWidgets import QMessageBox

    store = FakeStore()
    store.data = dict(stored or {})
    store.install(monkeypatch)
    warned: list[str] = []
    monkeypatch.setattr(QMessageBox, "warning", lambda _p, _t, text, *_a: warned.append(text))
    dialog = AISettingsDialog(
        AIConfig(enabled=enabled, provider=provider, **fields), AIService(factory=lambda _c, _k: FakeProvider())
    )
    dialog.show()
    return dialog, warned, store


def test_enabled_assistant_without_a_key_cannot_be_saved(qapp: QApplication, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from PySide6.QtWidgets import QDialog

    dialog, warned, _store = _dialog(monkeypatch, Provider.API_KEY)
    assert not dialog._ok_button.isEnabled() and "No API key" in dialog._ok_button.toolTip()
    dialog.accept()  # e.g. the Enter key
    assert warned and "No API key" in warned[0] and "Enable the AI assistant" in warned[0]
    assert dialog.isVisible() and dialog.result() != QDialog.DialogCode.Accepted  # still open, nothing saved
    dialog.close()


def test_invalid_or_empty_cloud_fields_cannot_be_saved(qapp: QApplication, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from PySide6.QtWidgets import QDialog

    dialog, warned, _store = _dialog(monkeypatch, Provider.VERTEX, gcp_project="")
    assert not dialog._ok_button.isEnabled()  # project ID missing
    dialog.gcp_project.setText("Not A Project")
    assert not dialog._ok_button.isEnabled()  # malformed
    dialog.gcp_project.setText("my-project-123")
    dialog.gcp_region.setText("mars")
    assert not dialog._ok_button.isEnabled()  # bad region
    dialog.gcp_region.setText("us-east5")
    dialog.model.setCurrentText("")
    assert (
        not dialog._ok_button.isEnabled() and "model" in dialog._ok_button.toolTip().lower()
    )  # an empty model is not replaced
    dialog.model.setCurrentText("claude-opus-5-5")
    assert dialog._ok_button.isEnabled()  # everything valid: now it can be saved
    dialog.accept()
    assert not warned and dialog.result() == QDialog.DialogCode.Accepted
    assert dialog.config().model == "claude-opus-5-5" and dialog.config().gcp_project == "my-project-123"


def test_a_typed_key_that_was_not_saved_blocks_saving(qapp: QApplication, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    dialog, _warned, store = _dialog(monkeypatch, Provider.API_KEY)
    dialog.api_key.setText("sk-ant-api03-" + "k" * 30)
    assert not dialog._ok_button.isEnabled() and "Save key" in dialog._ok_button.toolTip()  # typed, not stored
    dialog._save_key()  # the user clicks Save key
    assert store.data.get("anthropic-api-key")
    dialog._invalidate_status()
    assert dialog._ok_button.isEnabled()
    dialog.close()


def test_a_switched_off_assistant_can_be_saved_with_empty_fields(qapp: QApplication, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from PySide6.QtWidgets import QDialog

    dialog, warned, _store = _dialog(monkeypatch, Provider.VERTEX, enabled=False, gcp_project="")
    assert dialog._ok_button.isEnabled()
    dialog.accept()
    assert not warned and dialog.result() == QDialog.DialogCode.Accepted
    dialog.enabled.setChecked(True)  # ... but switching it on requires complete settings again
    assert not dialog._ok_button.isEnabled()
