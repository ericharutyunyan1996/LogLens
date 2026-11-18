"""Saved filters and shareable packs: keeps every tab's filter panel in sync with the settings, imports/exports."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QObject, Signal
from PySide6.QtWidgets import QFileDialog, QInputDialog, QMessageBox, QWidget

from ..core.highlight import HighlightRule
from ..core.packs import Pack, PackError, SavedFilter, merge_filters
from ..settings import Settings
from .filter_panel import FilterPanel

PACK_FILTER = "LogLens packs (*.loglens.json *.json);;All files (*)"


class PacksController(QObject):
    rulesImported = Signal(list)  # list[HighlightRule] — the window applies them like the highlighter dialog

    def __init__(self, settings: Settings, window: QWidget) -> None:
        super().__init__(window)
        self._settings = settings
        self._window = window
        self._panels: list[FilterPanel] = []

    def attach(self, panel: FilterPanel) -> None:
        self._panels.append(panel)
        panel.destroyed.connect(lambda _obj=None, p=panel: self._panels.remove(p) if p in self._panels else None)
        panel.set_saved_filters(self._settings.saved_filters())
        panel.saveFilterRequested.connect(lambda p=panel: self.save_current(p))
        panel.deleteFilterRequested.connect(self.delete)
        panel.packImportRequested.connect(self.import_pack)
        panel.packExportRequested.connect(self.export_pack)

    # ---- saved filters -------------------------------------------------------------------------------------------
    def save_current(self, panel: FilterPanel) -> None:
        name, ok = QInputDialog.getText(self._window, "Save filter", "Name for this filter:")
        name = name.strip()
        if not ok or not name:
            return
        saved = [f for f in self._settings.saved_filters() if f.name != name]
        saved.append(panel.snapshot(name))
        self._store(saved)
        panel.show_status(f"Saved filter “{name}” — find it under Saved ▾ in every tab")

    def delete(self, name: str) -> None:
        self._store([f for f in self._settings.saved_filters() if f.name != name])

    def _store(self, filters: list[SavedFilter]) -> None:
        self._settings.set_saved_filters(filters)
        self._settings.save()
        for panel in self._panels:
            panel.set_saved_filters(filters)

    # ---- packs ---------------------------------------------------------------------------------------------------
    def export_pack(self) -> None:
        default = str(Path(self._settings.last_dir or Path.home()) / "my-filters.loglens.json")
        target, _ = QFileDialog.getSaveFileName(self._window, "Export pack", default, PACK_FILTER)
        if not target:
            return
        pack = Pack(Path(target).stem, tuple(self._settings.saved_filters()), tuple(self._settings.rules()))
        try:
            Path(target).write_text(pack.to_json(), encoding="utf-8")
        except OSError as exc:
            QMessageBox.warning(self._window, "Export pack", f"Could not write {target}:\n{exc}")
            return
        QMessageBox.information(
            self._window,
            "Export pack",
            f"Exported {len(pack.filters)} saved filters and {len(pack.highlights)} highlighters to\n{target}",
        )

    def import_pack(self) -> None:
        source, _ = QFileDialog.getOpenFileName(self._window, "Import pack", self._settings.last_dir, PACK_FILTER)
        if not source:
            return
        try:
            pack = Pack.from_json(Path(source).read_text(encoding="utf-8"))
        except UnicodeDecodeError:
            QMessageBox.warning(
                self._window, "Import pack", f"Could not import {Path(source).name}:\nIt is not a UTF-8 text file."
            )
            return
        except (OSError, PackError) as exc:
            QMessageBox.warning(self._window, "Import pack", f"Could not import {Path(source).name}:\n{exc}")
            return
        before = len(self._settings.saved_filters())
        merged = merge_filters(self._settings.saved_filters(), pack.filters)
        self._store(merged)
        message = f"Added {len(merged) - before} saved filters."
        if pack.highlights and self._confirm_highlights(pack.highlights):
            self.rulesImported.emit(list(pack.highlights))
            message += f" Replaced your highlighters with the pack's {len(pack.highlights)}."
        QMessageBox.information(self._window, "Import pack", message)

    def _confirm_highlights(self, rules: tuple[HighlightRule, ...]) -> bool:
        answer = QMessageBox.question(
            self._window,
            "Import pack",
            f"The pack also has {len(rules)} highlighters. Replace your current highlighters with them?",
        )
        return answer == QMessageBox.StandardButton.Yes
