"""Live watch in the main window: alert notifications (tray), run-in-tray, and watched folders."""

from __future__ import annotations

from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING

from PySide6.QtCore import QObject, QTimer, Signal
from PySide6.QtWidgets import QMenu, QMessageBox, QSystemTrayIcon

from .. import APP_NAME
from ..core.service_status import service_states
from ..core.watch import Alert, AlertRule, WatchProfile, newest_file
from ..services.log_document import LogDocument
from ..services.watch_service import AlertMonitor, FolderWatcher
from ..settings import Settings
from .icons import logo_icon
from .watch_dialogs import AlertRulesDialog, WatchFolderDialog

if TYPE_CHECKING:
    from .main_window import MainWindow

TRAY_MESSAGE_MS = 8_000
SERVICE_POLL_MS = 5_000  # watched Windows services are checked this often (read-only, ~50 ms)


class WatchController(QObject):
    watchesChanged = Signal()

    def __init__(self, settings: Settings, window: MainWindow) -> None:
        super().__init__(window)
        self._settings = settings
        self._window = window
        self.monitor = AlertMonitor(settings.alert_rules(), self)
        self.monitor.alertFired.connect(self._on_alert)
        self._folders: dict[str, FolderWatcher] = {}
        self._last_alert: tuple[Alert, LogDocument] | None = None
        self._service_states: dict[str, str] = {}
        self._service_timer = QTimer(self)
        self._service_timer.setInterval(SERVICE_POLL_MS)
        self._service_timer.timeout.connect(self._poll_services)
        if settings.watched_services:
            self._service_timer.start()
        self.tray: QSystemTrayIcon | None = None
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray = QSystemTrayIcon(logo_icon(), self)
            self.tray.setToolTip(APP_NAME)
            menu = QMenu(window)
            menu.addAction("Show LogLens", self._show_window)
            menu.addSeparator()
            menu.addAction("Quit", window.quit_app)
            self.tray.setContextMenu(menu)
            self.tray.activated.connect(self._on_tray_activated)
            self.tray.messageClicked.connect(self._jump_to_last_alert)
            self.tray.show()

    # ---- alerts --------------------------------------------------------------------------------------------------
    def watch_document(self, document: LogDocument) -> None:
        self.monitor.watch(document)

    def edit_alerts(self) -> None:
        dialog = AlertRulesDialog(self._settings.alert_rules(), self._settings.run_in_tray, self._window)
        if not dialog.exec():
            return
        rules = dialog.rules()
        self._settings.set_alert_rules(rules)
        self._settings.run_in_tray = dialog.tray.isChecked()
        self._settings.save()
        self.monitor.set_rules(rules)
        self._window.statusBar().showMessage(f"{len([r for r in rules if r.enabled])} alert rules active", 5000)

    def _on_alert(self, alert: Alert, document: LogDocument) -> None:
        self._last_alert = (alert, document)
        text = AlertMonitor.describe(alert)
        self._window.statusBar().showMessage(f"⚠ {text.splitlines()[0]} — line {alert.last_line + 1:,}", 15000)
        if self.tray is not None:
            self.tray.showMessage(
                f"{APP_NAME} alert", text, QSystemTrayIcon.MessageIcon.Warning, TRAY_MESSAGE_MS
            )  # fmt: skip

    def _jump_to_last_alert(self) -> None:
        self._show_window()
        if self._last_alert is not None:
            alert, document = self._last_alert
            self._window.show_line(document, alert.last_line)

    # ---- tray ----------------------------------------------------------------------------------------------------
    @property
    def keeps_running(self) -> bool:
        """Closing the window hides it to the tray instead of quitting."""
        return self.tray is not None and self._settings.run_in_tray

    def _on_tray_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason in (QSystemTrayIcon.ActivationReason.Trigger, QSystemTrayIcon.ActivationReason.DoubleClick):
            self._show_window()

    def _show_window(self) -> None:
        self._window.showNormal()
        self._window.raise_()
        self._window.activateWindow()

    def notify(self, title: str, text: str) -> None:
        if self.tray is not None:
            self.tray.showMessage(title, text, QSystemTrayIcon.MessageIcon.Information, TRAY_MESSAGE_MS)

    # ---- services ------------------------------------------------------------------------------------------------
    def watched_services(self) -> list[str]:
        return list(self._settings.watched_services)

    def set_watched_services(self, names: list[str]) -> None:
        self._settings.watched_services = names
        self._settings.save()
        self._service_states = {k: v for k, v in self._service_states.items() if k in names}
        if names:
            self._service_timer.start()
        else:
            self._service_timer.stop()

    def _poll_services(self) -> None:
        states = service_states(self._settings.watched_services)
        for name, state in states.items():
            before = self._service_states.get(name)
            if before is not None and before != state:
                self._window.statusBar().showMessage(f"⚠ Service {name}: {before} → {state}", 15000)
                self.notify(f"{APP_NAME} — service {name}", f"{before} → {state}")
        self._service_states = states

    # ---- folders -------------------------------------------------------------------------------------------------
    def watch_folder_dialog(self) -> None:
        dialog = WatchFolderDialog(self._settings.last_dir, self._window)
        if dialog.exec():
            profile = dialog.profile()
            profiles = [p for p in self._settings.watch_profiles() if p.name != profile.name] + [profile]
            self._settings.set_watch_profiles(profiles)
            self._settings.save()
            self.start(profile)

    def start(self, profile: WatchProfile) -> None:
        newest = newest_file(profile.folder, profile.pattern, recursive=profile.recursive)
        if newest is None:
            QMessageBox.information(
                self._window, APP_NAME, f"No files matching {profile.pattern} in {profile.folder} yet — LogLens "
                "will open the first one that appears.",
            )  # fmt: skip
        else:
            self._window.open_live(str(newest))
        self.stop(profile.name)
        watcher = FolderWatcher(profile, newest, self)
        watcher.newestChanged.connect(lambda path, p=profile: self._on_newer_file(p, path))
        self._folders[profile.name] = watcher
        self.watchesChanged.emit()

    def stop(self, name: str) -> None:
        watcher = self._folders.pop(name, None)
        if watcher is not None:
            watcher.stop()
            watcher.deleteLater()
            self.watchesChanged.emit()

    def forget(self, name: str) -> None:
        self.stop(name)
        self._settings.set_watch_profiles([p for p in self._settings.watch_profiles() if p.name != name])
        self._settings.save()
        self.watchesChanged.emit()

    def active(self) -> list[str]:
        return sorted(self._folders)

    def _on_newer_file(self, profile: WatchProfile, path: str) -> None:
        self._window.open_live(path)
        self.notify(f"{APP_NAME} — {profile.name}", f"Now following the newer file {Path(path).name}")

    def fill_menu(self, menu: QMenu) -> None:
        """Watch menu: start saved profiles, stop running ones."""
        menu.clear()
        menu.addAction("Watch a folder…", self.watch_folder_dialog)
        menu.addAction("Alerts…", self.edit_alerts)
        menu.addAction("Live dashboard…", self._window.open_dashboard)
        profiles = self._settings.watch_profiles()
        running = set(self._folders)
        if profiles:
            menu.addSeparator()
            for profile in profiles:
                if profile.name in running:
                    menu.addAction(f"Stop watching {profile.name}", partial(self.stop, profile.name))
                else:
                    menu.addAction(f"Watch {profile.name}  ({profile.folder})", partial(self.start, profile))
            forget = menu.addMenu("Forget folder")
            for profile in profiles:
                forget.addAction(profile.name, partial(self.forget, profile.name))

    def rules(self) -> list[AlertRule]:
        return self._settings.alert_rules()
