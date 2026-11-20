"""File → Servers… and the server picker of Open Windows Event Logs."""

from __future__ import annotations

from collections.abc import Callable

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QMessageBox

from loglens.core.ai import credentials
from loglens.core.winevent import remote
from loglens.core.winevent.remote import ServerCheck, ServerProfile, ServerStatus
from loglens.settings import Settings
from loglens.ui import servers_dialog
from loglens.ui.eventlog_dialog import EventLogDialog
from loglens.ui.servers_dialog import ServerEditDialog, ServersDialog

WEB = ServerProfile("Web 01", "web01.corp.example")
DB = ServerProfile("DB", "db01", use_credentials=True, user="CORP\\svc-logs", auth="ntlm")


@pytest.fixture
def store(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """In-memory Credential Manager: the tests never touch the real one."""
    data: dict[str, str] = {}
    monkeypatch.setattr(credentials, "load_secret", data.get)
    monkeypatch.setattr(credentials, "save_secret", data.__setitem__)
    monkeypatch.setattr(credentials, "delete_secret", lambda name: data.pop(name, None))
    return data


def test_adding_a_server_with_credentials_stores_the_password_only_in_credential_manager(
    qapp: QApplication, store: dict[str, str]
) -> None:
    dialog = ServerEditDialog([], None)
    dialog.name.setText("DB")
    dialog.host.setText("db01")
    dialog.saved.setChecked(True)
    dialog.user.setText("CORP\\svc-logs")
    dialog.accept()  # no password yet
    assert dialog.error.text().endswith("Enter the password for the saved credentials.") and not store
    dialog.password.setText("Sup3r-Secret-pw")
    dialog.accept()
    assert store == {"server:DB": "Sup3r-Secret-pw"}  # in the store ...
    settings = Settings()
    settings.set_servers([dialog.profile()])
    assert "Sup3r-Secret-pw" not in str(
        settings.to_dict() if hasattr(settings, "to_dict") else settings.server_list
    )  # ... never in settings
    assert dialog.profile() == DB.__class__("DB", "db01", True, "CORP\\svc-logs", "negotiate")


def test_invalid_and_duplicate_entries_are_refused(qapp: QApplication) -> None:
    dialog = ServerEditDialog([WEB], None)
    dialog.name.setText("web 01")  # same name, other case
    dialog.host.setText("web02")
    dialog.accept()
    assert "already a server called" in dialog.error.text()
    dialog.name.setText("Web 02")
    dialog.host.setText("bad host name")
    dialog.accept()
    assert "not a valid host name" in dialog.error.text()
    dialog.host.setText("web02.corp.example")
    dialog.accept()
    assert dialog.result() == dialog.DialogCode.Accepted


def test_test_button_connects_for_real_with_what_is_typed_and_explains_a_failure(
    qapp: QApplication, wait_for: Callable[..., None], monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[tuple[ServerProfile, str | None]] = []

    def fake_check(profile: ServerProfile, password: str | None = None, **_k: object) -> ServerCheck:
        seen.append((profile, password))
        return ServerCheck(ServerStatus.ACCESS_DENIED, str(remote.explain(5, profile)))

    monkeypatch.setattr(servers_dialog, "check_server", fake_check)
    dialog = ServerEditDialog([], None)
    dialog.name.setText("DB")
    dialog.host.setText("db01")
    dialog.saved.setChecked(True)
    dialog.user.setText("svc")
    dialog.password.setText("typed-pw")
    dialog.test_button.click()
    wait_for(lambda: "Access denied" in dialog.outcome.text())
    assert seen[0][1] == "typed-pw"  # the typed password was used, nothing was saved to test it
    assert "Event Log Readers" in dialog.outcome.text() and dialog.test_button.isEnabled()


def test_servers_list_add_edit_remove_persists_and_removing_deletes_the_saved_password(
    qapp: QApplication, store: dict[str, str], monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:  # type: ignore[no-untyped-def]
    settings = Settings()
    settings.set_servers([WEB, DB])
    store["server:DB"] = "pw"
    monkeypatch.setattr(Settings, "save", lambda self, path=None: None)
    monkeypatch.setattr(QMessageBox, "warning", lambda *_a: QMessageBox.StandardButton.Yes)
    dialog = ServersDialog(settings)
    assert [dialog.tree.topLevelItem(i).text(0) for i in range(2)] == ["Web 01", "DB"]
    dialog.tree.setCurrentItem(dialog.tree.topLevelItem(1))
    dialog.remove()
    assert [s.name for s in settings.servers()] == ["Web 01"]
    assert "server:DB" not in store  # the saved password is gone with the server (verified deletion)
    dialog.tree.setCurrentItem(dialog.tree.topLevelItem(0))
    dialog.remove()
    assert settings.servers() == [] and not dialog.edit_button.isEnabled()


def test_test_all_shows_each_servers_result(
    qapp: QApplication, wait_for: Callable[..., None], monkeypatch: pytest.MonkeyPatch
) -> None:
    results = {
        "Web 01": ServerCheck(ServerStatus.CONNECTED, "Signed in; 1,284 event channels found."),
        "DB": ServerCheck(ServerStatus.UNREACHABLE, "db01 did not answer on port 135"),
    }
    monkeypatch.setattr(servers_dialog, "check_server", lambda profile, *_a, **_k: results[profile.name])
    settings = Settings()
    settings.set_servers([WEB, DB])
    dialog = ServersDialog(settings)
    dialog.test_all()
    wait_for(lambda: all("testing" not in dialog.tree.topLevelItem(i).text(3) for i in range(2)))
    assert dialog.tree.topLevelItem(0).text(3).startswith("Connected") and dialog.tree.topLevelItem(1).text(
        3
    ).startswith("Unreachable")


# ---- the picker in Open Windows Event Logs -------------------------------------------------------------------------------------
def test_event_log_dialog_reads_every_chosen_computer_and_channel(qapp: QApplication) -> None:
    dialog = EventLogDialog(None, [WEB, DB])
    assert dialog.sources.count() == 3  # This computer + 2 servers
    assert [s.name if s else None for s in dialog.selected_sources()] == [None]  # only this computer by default
    dialog.sources.item(1).setCheckState(Qt.CheckState.Checked)  # Web 01
    dialog.sources.item(2).setCheckState(Qt.CheckState.Checked)  # DB
    queries = dialog.queries()
    assert {(q.server.name if q.server else "", q.channel) for q in queries} == {
        (server, channel) for server in ("", "Web 01", "DB") for channel in ("Application", "System")
    }
    assert "Web 01" in dialog.title() and "DB" in dialog.title() and "local" in dialog.title()
    for row in range(3):
        dialog.sources.item(row).setCheckState(Qt.CheckState.Unchecked)
    assert dialog.problem() == "Choose at least one computer."


def test_without_servers_the_dialog_is_unchanged_and_points_to_the_servers_menu(qapp: QApplication) -> None:
    dialog = EventLogDialog(None)
    assert not dialog.sources.isVisible() and not dialog.servers_note.isHidden()
    assert [q.server for q in dialog.queries()] == [None, None]  # Application and System of this computer, as before
    assert dialog.title() == "Application+System"
