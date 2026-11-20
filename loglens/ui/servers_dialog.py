"""File → Servers…: the other Windows servers LogLens reads Event Viewer logs from.

A server is a name, an address and how to sign in: the current Windows account (domain servers just work) or a user
name and a password saved in Windows Credential Manager. The password is never written to the settings file. *Test*
makes a real connection and says what is wrong and which setting to change when it fails.
"""

from __future__ import annotations

from functools import partial

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..core.ai import credentials
from ..core.winevent import remote
from ..core.winevent.remote import AUTH_METHODS, ServerCheck, ServerProfile, ServerStatus, check_server
from ..settings import Settings
from .payload_view import Background

OK_COLOR, WARN_COLOR, ERROR_COLOR = "#2e8b57", "#c08a00", "#c0504d"


def _status_color(status: ServerStatus) -> str:
    return OK_COLOR if status is ServerStatus.CONNECTED else ERROR_COLOR


class ServerEditDialog(QDialog):
    """Add or change one server. OK checks the entries; Test connects for real with what is typed (nothing is saved)."""

    def __init__(
        self, existing: list[ServerProfile], profile: ServerProfile | None = None, parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Edit server" if profile else "Add server")
        self.setMinimumWidth(520)
        self._others = [s.name.lower() for s in existing if profile is None or s.name != profile.name]
        self._original = profile
        self.name = QLineEdit(profile.name if profile else "", self)
        self.name.setPlaceholderText("e.g. Web 01")
        self.host = QLineEdit(profile.host if profile else "", self)
        self.host.setPlaceholderText("server name or IP address, e.g. web01.corp.example")
        self.current = QRadioButton("This Windows account (best for servers in your domain)", self)
        self.saved = QRadioButton("Saved credentials", self)
        self.user = QLineEdit(profile.user if profile else "", self)
        self.user.setPlaceholderText("DOMAIN\\user, user@domain, or a local account of that server")
        self.password = QLineEdit(self)
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setPlaceholderText(
            "saved password is kept; type to replace it" if profile and profile.use_credentials else "password"
        )
        self.auth = QComboBox(self)
        for key, label in AUTH_METHODS.items():
            self.auth.addItem(label, key)
        self.auth.setCurrentIndex(max(self.auth.findData(profile.auth if profile else "negotiate"), 0))
        (self.saved if profile and profile.use_credentials else self.current).setChecked(True)
        note = QLabel(
            "Passwords go only into Windows Credential Manager, never into settings or logs. The server must allow "
            "remote Event Log access (firewall rule group 'Remote Event Log Management') and the account must be in "
            "its 'Event Log Readers' group.",
            self,
        )
        note.setWordWrap(True)
        note.setObjectName("dialogNote")
        self.test_button = QPushButton("Test connection", self)
        self.outcome = QLabel(self)
        self.outcome.setWordWrap(True)
        self.outcome.setTextFormat(Qt.TextFormat.PlainText)
        test_row = QHBoxLayout()
        test_row.addWidget(self.test_button)
        test_row.addWidget(self.outcome, 1)
        form = QFormLayout()
        form.addRow("Name", self.name)
        form.addRow("Address", self.host)
        form.addRow("Sign in as", self.current)
        form.addRow("", self.saved)
        form.addRow("User", self.user)
        form.addRow("Password", self.password)
        form.addRow("Method", self.auth)
        self.error = QLabel(self)
        self.error.setStyleSheet(f"color: {ERROR_COLOR};")
        self.error.setWordWrap(True)
        self.error.hide()
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel, self)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(note)
        layout.addLayout(test_row)
        layout.addWidget(self.error)
        layout.addWidget(buttons)
        self._tester = Background(self, self._on_checked)
        self.test_button.clicked.connect(self._test)
        self.saved.toggled.connect(self._sync)
        self._sync()

    def _sync(self) -> None:
        saved = self.saved.isChecked()
        for widget in (self.user, self.password, self.auth):
            widget.setEnabled(saved)
        self.outcome.clear()

    def profile(self) -> ServerProfile:
        return ServerProfile(
            name=self.name.text().strip(),
            host=self.host.text().strip(),
            use_credentials=self.saved.isChecked(),
            user=self.user.text().strip() if self.saved.isChecked() else "",
            auth=str(self.auth.currentData()),
        )

    def _typed_or_saved_password(self) -> str | None:
        typed = self.password.text()
        if typed:
            return typed
        if (
            self._original is not None
            and self._original.use_credentials
            and self._original.name == self.name.text().strip()
        ):
            try:
                return credentials.load_secret(remote.secret_name(self._original))
            except OSError:
                return None
        return None

    def problem(self) -> str | None:
        profile = self.profile()
        found = remote.validate(profile)
        if found:
            return found
        if profile.name.lower() in self._others:
            return f"There is already a server called '{profile.name}'."
        if profile.use_credentials and not self._typed_or_saved_password():
            return "Enter the password for the saved credentials."
        return None

    def _test(self) -> None:
        profile = self.profile()
        problem = remote.validate(profile)
        if problem:
            self.outcome.setStyleSheet(f"color: {ERROR_COLOR};")
            self.outcome.setText(problem)
            return
        password = self._typed_or_saved_password() if profile.use_credentials else None
        self.test_button.setEnabled(False)
        self.outcome.setStyleSheet("")
        self.outcome.setText(f"Connecting to {profile.host} …")
        self._tester.start(lambda: check_server(profile, password))

    def _on_checked(self, result: object) -> None:
        self.test_button.setEnabled(True)
        if isinstance(result, Exception):
            self.outcome.setStyleSheet(f"color: {ERROR_COLOR};")
            self.outcome.setText(f"The test failed: {result}")
            return
        check: ServerCheck = result  # type: ignore[assignment]
        self.outcome.setStyleSheet(f"color: {_status_color(check.status)};")
        self.outcome.setText(f"{check.label}: {check.message}")

    def accept(self) -> None:
        problem = self.problem()
        if problem:
            self.error.setText(f"⚠ {problem}")
            self.error.show()
            return
        profile = self.profile()
        try:
            if profile.use_credentials:
                password = self._typed_or_saved_password()
                if self.password.text():
                    credentials.save_secret(remote.secret_name(profile), self.password.text())
                elif self._original is not None and self._original.name != profile.name and password:
                    credentials.save_secret(remote.secret_name(profile), password)  # renamed: the password follows
                    remote.forget_password(self._original)
            elif self._original is not None and self._original.use_credentials:
                remote.forget_password(self._original)  # switched back to the Windows account: nothing stays stored
        except OSError as exc:
            self.error.setText(f"⚠ Could not save the password in Windows Credential Manager: {exc}")
            self.error.show()
            return
        super().accept()


class ServersDialog(QDialog):
    """The list of servers. Changes are saved at once (there is no Cancel): a password is already stored when OK'd."""

    def __init__(self, settings: Settings, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Servers")
        self.resize(760, 420)
        self._settings = settings
        self._servers = settings.servers()
        self._testers: dict[str, Background] = {}
        intro = QLabel(
            "Other Windows servers whose Event Viewer logs LogLens can read (File → Open Windows Event Logs). "
            "Nothing is installed on them.",
            self,
        )
        intro.setWordWrap(True)
        intro.setObjectName("dialogNote")
        self.tree = QTreeWidget(self)
        self.tree.setHeaderLabels(["Name", "Address", "Sign in as", "Last test"])
        self.tree.setRootIsDecorated(False)
        self.tree.setUniformRowHeights(True)
        self.tree.setColumnWidth(0, 150)
        self.tree.setColumnWidth(1, 190)
        self.tree.setColumnWidth(2, 190)
        self.tree.itemDoubleClicked.connect(lambda *_a: self.edit())
        self.add_button = QPushButton("Add…", self)
        self.edit_button = QPushButton("Edit…", self)
        self.remove_button = QPushButton("Remove", self)
        self.test_button = QPushButton("Test", self)
        self.test_all_button = QPushButton("Test all", self)
        self.add_button.clicked.connect(self.add)
        self.edit_button.clicked.connect(self.edit)
        self.remove_button.clicked.connect(self.remove)
        self.test_button.clicked.connect(self.test_selected)
        self.test_all_button.clicked.connect(self.test_all)
        row = QHBoxLayout()
        for button in (self.add_button, self.edit_button, self.remove_button):
            row.addWidget(button)
        row.addStretch(1)
        row.addWidget(self.test_button)
        row.addWidget(self.test_all_button)
        close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close, self)
        close.rejected.connect(self.accept)
        close.accepted.connect(self.accept)
        layout = QVBoxLayout(self)
        layout.addWidget(intro)
        layout.addWidget(self.tree, 1)
        layout.addLayout(row)
        layout.addWidget(close)
        self.tree.currentItemChanged.connect(lambda *_a: self._update_buttons())
        self._fill()

    # -- list ---------------------------------------------------------------------------------------------------
    def _fill(self, keep: str = "") -> None:
        self.tree.clear()
        for server in self._servers:
            item = QTreeWidgetItem([server.name, server.host, server.sign_in, "not tested"])
            item.setData(0, Qt.ItemDataRole.UserRole, server.name)
            self.tree.addTopLevelItem(item)
            if server.name == keep:
                self.tree.setCurrentItem(item)
        first = self.tree.topLevelItem(0)
        if not keep and first is not None:
            self.tree.setCurrentItem(first)
        self._update_buttons()

    def _update_buttons(self) -> None:
        has = self._selected() is not None
        for button in (self.edit_button, self.remove_button, self.test_button):
            button.setEnabled(has)
        self.test_all_button.setEnabled(bool(self._servers))

    def _selected(self) -> ServerProfile | None:
        item = self.tree.currentItem()
        name = item.data(0, Qt.ItemDataRole.UserRole) if item is not None else None
        return next((s for s in self._servers if s.name == name), None)

    def servers(self) -> list[ServerProfile]:
        return list(self._servers)

    def _save(self) -> None:
        self._settings.set_servers(self._servers)
        self._settings.save()

    # -- actions ------------------------------------------------------------------------------------------------
    def add(self) -> None:
        dialog = ServerEditDialog(self._servers, None, self)
        if dialog.exec():
            profile = dialog.profile()
            self._servers.append(profile)
            self._save()
            self._fill(profile.name)

    def edit(self) -> None:
        current = self._selected()
        if current is None:
            return
        dialog = ServerEditDialog(self._servers, current, self)
        if dialog.exec():
            profile = dialog.profile()
            self._servers[self._servers.index(current)] = profile
            self._save()
            self._fill(profile.name)

    def remove(self) -> None:
        current = self._selected()
        if current is None:
            return
        stored = ""
        if current.use_credentials:
            stored = f"\n\nIts saved password will be deleted from Windows Credential Manager ({current.user})."
        answer = QMessageBox.warning(
            self,
            "Remove server",
            f"Remove '{current.name}' ({current.host}) from LogLens?{stored}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            remote.forget_password(current)  # verified: raises if Windows still holds it
        except OSError as exc:
            QMessageBox.warning(self, "Remove server", f"The saved password could not be deleted: {exc}")
            return
        self._servers.remove(current)
        self._save()
        self._fill()

    def _row(self, name: str) -> QTreeWidgetItem | None:
        for index in range(self.tree.topLevelItemCount()):
            item = self.tree.topLevelItem(index)
            if item is not None and item.text(0) == name:
                return item
        return None

    def _tester_for(self, name: str) -> Background:
        if name not in self._testers:
            self._testers[name] = Background(self, partial(self._on_checked, name))
        return self._testers[name]

    def _test(self, server: ServerProfile) -> None:
        item = self._row(server.name)
        if item is None:
            return
        item.setText(3, "testing …")
        self._tester_for(server.name).start(lambda: check_server(server))

    def test_selected(self) -> None:
        current = self._selected()
        if current is not None:
            self._test(current)

    def test_all(self) -> None:
        for server in self._servers:
            self._test(server)

    def _on_checked(self, name: str, result: object) -> None:
        item = self._row(name)
        if item is None:
            return
        if isinstance(result, Exception):
            item.setText(3, f"test failed: {result}")
            return
        check: ServerCheck = result  # type: ignore[assignment]
        item.setText(3, f"{check.label}: {check.message}")
        item.setToolTip(3, check.message)
        item.setForeground(3, QColor(_status_color(check.status)))
