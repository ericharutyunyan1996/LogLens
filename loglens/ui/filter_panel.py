"""Filter panel above the results list: search box, pinned filter chips, level chips, results header.

Builds a :class:`~loglens.core.filters.FilterSpec` from the UI state and emits it; it holds no search logic itself.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from functools import partial

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QAction, QColor, QGuiApplication, QIcon, QKeyEvent, QKeySequence
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QProgressBar,
    QSizePolicy,
    QSpinBox,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from ..core.filters import FilterMode, FilterSpec, FilterTerm, TimeRange
from ..core.packs import SavedFilter
from ..core.search import SearchQuery
from .icons import dot_pixmap, themed_icon
from .theme import is_dark

LIVE_SEARCH_DELAY_MS = 350
MAX_PASTED_TERMS = 20


class SearchLineEdit(QLineEdit):
    """Search box that turns a multi-line paste into several terms instead of one mangled line."""

    multiLinePasted = Signal(list)  # list[str] — non-empty lines

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if event.matches(QKeySequence.StandardKey.Paste):
            text = QGuiApplication.clipboard().text()
            lines = [line.strip() for line in text.splitlines() if line.strip()]
            if len(lines) > 1:
                self.multiLinePasted.emit(lines)
                return
        super().keyPressEvent(event)


MODE_LABELS = {FilterMode.ALL: "Must match (AND)", FilterMode.ANY: "Any of (OR)", FilterMode.NONE: "Exclude (NOT)"}


@dataclass(frozen=True, slots=True)
class LevelOption:
    name: str
    color: str
    query: SearchQuery
    count: int | None = None


def _level_text(option: LevelOption) -> str:
    return f"{option.name}  {option.count:,}" if option.count is not None else option.name


class FilterPanel(QWidget):
    specChanged = Signal(object)  # FilterSpec
    nextRequested = Signal()
    prevRequested = Signal()
    contextChanged = Signal(int)
    copyRequested = Signal()
    exportRequested = Signal()
    wholeRecordsChanged = Signal(bool)
    timeRangeRequested = Signal()
    saveFilterRequested = Signal()
    deleteFilterRequested = Signal(str)
    packImportRequested = Signal()
    packExportRequested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("filterPanel")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self._pinned: list[FilterTerm] = []
        self._time_range: TimeRange | None = None
        self._saved: list[SavedFilter] = []
        self._levels: list[LevelOption] = []
        self._level_buttons: list[QToolButton] = []
        self._live = False
        self._live_timer = QTimer(self)
        self._live_timer.setSingleShot(True)
        self._live_timer.setInterval(LIVE_SEARCH_DELAY_MS)
        self._live_timer.timeout.connect(self.apply)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 6, 8, 4)
        layout.setSpacing(5)
        layout.addLayout(self._search_row())
        self.chip_row = QHBoxLayout()
        self.chip_row.setSpacing(4)
        layout.addLayout(self.chip_row)
        layout.addLayout(self._results_row())
        self.refresh_icons()
        self._rebuild_chips()

    # ---- construction --------------------------------------------------------------------------------------------
    def _search_row(self) -> QHBoxLayout:
        self.combo = QComboBox(self)
        self.combo.setEditable(True)
        self.combo.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self.combo.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.edit = SearchLineEdit(self.combo)
        self.edit.multiLinePasted.connect(self.add_any_terms)
        self.combo.setLineEdit(self.edit)
        self.edit.setPlaceholderText("Search…  Enter = find · + pins a filter · F3 / Shift+F3 = next / previous")
        self.edit.setClearButtonEnabled(True)
        self.edit.returnPressed.connect(self.apply)
        self.edit.textEdited.connect(self._on_text_edited)
        self.find_action = self.edit.addAction(themed_icon("find", is_dark()), QLineEdit.ActionPosition.LeadingPosition)

        self.regex = self._toggle(".*", "Regular expression")
        self.case = self._toggle("Aa", "Match case")
        self.include_btn = self._button("+ Include", "Pin as a filter: lines must match", self._pin_include)
        self.exclude_btn = self._button("− Exclude", "Pin as a filter: hide lines that match", self._pin_exclude)
        self.time_btn = self._button("Time…", "Only lines in a time range (Ctrl+Shift+R)", self.timeRangeRequested.emit)
        self.saved_btn = self._button("Saved ▾", "Saved filters and shareable packs", lambda: None)
        self.saved_btn.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.saved_btn.setMenu(QMenu(self.saved_btn))
        self.saved_btn.menu().aboutToShow.connect(self._fill_saved_menu)
        self.prev_btn = self._button("", "Previous match (Shift+F3)", self.prevRequested.emit, icon="up")
        self.next_btn = self._button("", "Next match (F3)", self.nextRequested.emit, icon="down")

        row = QHBoxLayout()
        row.setSpacing(4)
        row.addWidget(self.combo, 1)
        for widget in (self.regex, self.case):
            row.addWidget(widget)
        row.addSpacing(6)
        for widget in (self.include_btn, self.exclude_btn, self.time_btn, self.saved_btn):
            row.addWidget(widget)
        row.addSpacing(6)
        row.addWidget(self.prev_btn)
        row.addWidget(self.next_btn)
        return row

    def _results_row(self) -> QHBoxLayout:
        self.status = QLabel(self)
        self.status.setObjectName("searchStatus")
        self.progress = QProgressBar(self)
        self.progress.setFixedWidth(90)
        self.progress.setMaximumHeight(6)
        self.progress.setTextVisible(False)
        self.progress.hide()
        context_label = QLabel("Context", self)
        context_label.setObjectName("searchStatus")
        self.context = QSpinBox(self)
        self.context.setRange(0, 50)
        self.context.setToolTip("Lines shown before and after every match (dimmed)")
        self.context.valueChanged.connect(self.contextChanged)
        self.whole_records = QToolButton(self)
        self.whole_records.setObjectName("optionToggle")
        self.whole_records.setText("Whole records")
        self.whole_records.setToolTip(
            "Show every match with its whole multi-line record (stack trace, dumped body, header block)"
        )
        self.whole_records.setCheckable(True)
        self.whole_records.setVisible(False)
        self.whole_records.toggled.connect(self.wholeRecordsChanged)
        self.copy_btn = self._button("Copy", "Copy the lines shown below", self.copyRequested.emit)
        self.export_btn = self._button("Export…", "Save the lines shown below to a file", self.exportRequested.emit)
        self.clear_btn = self._button("Clear", "Remove all filters", self.clear)

        row = QHBoxLayout()
        row.setSpacing(6)
        row.addWidget(self.status)
        row.addWidget(self.progress)
        row.addStretch(1)
        for widget in (self.whole_records, context_label, self.context, self.copy_btn, self.export_btn, self.clear_btn):
            row.addWidget(widget)
        return row

    def _toggle(self, text: str, tip: str) -> QToolButton:
        button = QToolButton(self)
        button.setObjectName("optionToggle")
        button.setText(text)
        button.setToolTip(tip)
        button.setCheckable(True)
        button.toggled.connect(lambda _checked: self.apply() if self.edit.text() else None)
        return button

    def _button(self, text: str, tip: str, slot: Callable[[], object], icon: str = "") -> QToolButton:
        button = QToolButton(self)
        button.setObjectName("panelButton")
        button.setText(text)
        button.setToolTip(tip)
        button.setAutoRaise(True)
        if icon:
            button.setProperty("iconName", icon)
        button.clicked.connect(slot)
        return button

    # ---- public API ----------------------------------------------------------------------------------------------
    def refresh_icons(self) -> None:
        dark = is_dark()
        for button in (self.prev_btn, self.next_btn):
            button.setIcon(themed_icon(button.property("iconName"), dark))
        self.find_action.setIcon(themed_icon("find", dark))

    def set_live(self, live: bool) -> None:
        """Search while typing (only sensible for files that search in a fraction of a second)."""
        self._live = live

    def set_levels(self, levels: list[LevelOption]) -> None:
        """New level options. Count updates (frequent while a log grows) only relabel the chips: rebuilding them
        would destroy an open chip menu under the user's mouse."""
        same = [o.name for o in levels] == [o.name for o in self._levels] and len(self._level_buttons) == len(levels)
        selected = {o.name for o, b in zip(self._levels, self._level_buttons, strict=False) if b.isChecked()}
        self._levels = levels
        if same:
            for option, button in zip(levels, self._level_buttons, strict=True):
                button.setText(_level_text(option))
            return
        self._rebuild_chips(selected)

    def select_levels(self, names: set[str]) -> None:
        """Check exactly the level chips whose name is in ``names`` (applies the filter once)."""
        for option, button in zip(self._levels, self._level_buttons, strict=False):
            button.blockSignals(True)
            button.setChecked(option.name in names)
            button.blockSignals(False)
        self.apply()

    def set_records_available(self, available: bool) -> None:
        """Offer 'Whole records' only for logs that have multi-line records."""
        self.whole_records.setVisible(available)

    # ---- saved filters -------------------------------------------------------------------------------------------
    def set_saved_filters(self, saved: list[SavedFilter]) -> None:
        self._saved = list(saved)

    def _fill_saved_menu(self) -> None:
        menu = self.saved_btn.menu()
        menu.clear()
        save = menu.addAction("Save current filter…", self.saveFilterRequested.emit)
        save.setEnabled(bool(self._pinned) or not self.spec().is_empty)
        if self._saved:
            menu.addSeparator()
            for item in self._saved:
                menu.addAction(item.name, partial(self.apply_saved, item))
            delete = menu.addMenu("Delete")
            for item in self._saved:
                delete.addAction(item.name, partial(self.deleteFilterRequested.emit, item.name))
        menu.addSeparator()
        menu.addAction("Import pack…", self.packImportRequested.emit)
        menu.addAction("Export pack…", self.packExportRequested.emit)

    def snapshot(self, name: str) -> SavedFilter:
        """The panel's current state as a saved filter (the search box text becomes a 'must match' term)."""
        spec = self.spec()
        whole = self.whole_records.isChecked()
        return SavedFilter(name, spec.terms, spec.level_names, self.context.value(), whole)

    def apply_saved(self, saved: SavedFilter) -> None:
        """Replace the panel state with ``saved`` and run it (unknown level names are ignored)."""
        self._pinned = list(saved.terms)
        self.edit.clear()
        self.context.setValue(saved.context)
        self.whole_records.setChecked(saved.whole_records and self.whole_records.isVisible())
        self._rebuild_chips(set(saved.levels))
        self.apply()
        self.show_status(f"Applied saved filter “{saved.name}”")

    def set_time_range(self, window: TimeRange | None) -> None:
        self._time_range = window
        self._rebuild_chips(self._selected_level_names())
        self.apply()

    @property
    def time_range(self) -> TimeRange | None:
        return self._time_range

    def level_names(self) -> list[str]:
        return [o.name for o in self._levels]

    def set_text(self, text: str) -> None:
        self.edit.setText(text)
        self.focus()

    def focus(self) -> None:
        self.edit.setFocus()
        self.edit.selectAll()

    def spec(self) -> FilterSpec:
        terms = list(self._pinned)
        text = self.edit.text()
        if text:
            terms.append(FilterTerm(self._query(text), FilterMode.ALL))
        chosen = [o for o, b in zip(self._levels, self._level_buttons, strict=False) if b.isChecked()]
        return FilterSpec(
            tuple(terms), tuple(o.query for o in chosen), tuple(o.name for o in chosen), time_range=self._time_range
        )

    def apply(self) -> None:
        self._live_timer.stop()
        self.specChanged.emit(self.spec())

    def clear(self) -> None:
        self._pinned.clear()
        self._time_range = None
        self.edit.clear()
        for button in self._level_buttons:
            button.setChecked(False)
        self._rebuild_chips()
        self.apply()

    def show_progress(self, done: int, total: int) -> None:
        self.progress.setVisible(done < total)
        self.progress.setMaximum(max(total, 1))
        self.progress.setValue(done)

    def show_status(self, text: str, error: bool = False) -> None:
        self.status.setText(text)
        self.status.setStyleSheet("color: #E5484D;" if error else "")

    # ---- chips ---------------------------------------------------------------------------------------------------
    def _query(self, text: str) -> SearchQuery:
        return SearchQuery(text, regex=self.regex.isChecked(), case_sensitive=self.case.isChecked())

    def pin_current(self, mode: FilterMode) -> None:
        """Pin the search box text as a filter chip with the given mode."""
        text = self.edit.text()
        if not text:
            return
        self._pinned.append(FilterTerm(self._query(text), mode))
        self.edit.clear()
        self._rebuild_chips(self._selected_level_names())
        self.apply()

    def add_any_terms(self, lines: list[str]) -> None:
        """Pin each line as an 'any of' filter (e.g. several error messages pasted from a ticket)."""
        for line in lines[:MAX_PASTED_TERMS]:
            self._pinned.append(FilterTerm(self._query(line), FilterMode.ANY))
        self._rebuild_chips(self._selected_level_names())
        self.apply()
        skipped = len(lines) - MAX_PASTED_TERMS
        note = f" (first {MAX_PASTED_TERMS}; {skipped} skipped)" if skipped > 0 else ""
        self.show_status(f"Pasted {min(len(lines), MAX_PASTED_TERMS)} lines as 'any of' filters{note}")

    def _pin_include(self) -> None:
        self.pin_current(FilterMode.ALL)

    def _pin_exclude(self) -> None:
        self.pin_current(FilterMode.NONE)

    def _rebuild_chips(self, selected_levels: set[str] | None = None) -> None:
        while self.chip_row.count():
            item = self.chip_row.takeAt(0)
            widget = item.widget() if item is not None else None
            if widget is not None:
                widget.deleteLater()
        self._level_buttons = []
        selected_levels = selected_levels or set()
        if self._levels:
            label = QLabel("Levels", self)
            label.setObjectName("searchStatus")
            self.chip_row.addWidget(label)
        for option in self._levels:
            button = QToolButton(self)
            button.setObjectName("levelChip")
            button.setCheckable(True)
            button.setChecked(option.name in selected_levels)
            color = QColor(option.color)
            color.setAlpha(255)
            button.setIcon(QIcon(dot_pixmap(color.name())))
            button.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
            button.setText(_level_text(option))
            button.setToolTip(f"Show only {option.name} lines (combine several; works with search terms)")
            button.toggled.connect(lambda _checked: self.apply())
            self.chip_row.addWidget(button)
            self._level_buttons.append(button)
        if self._time_range is not None:
            self.chip_row.addWidget(self._time_chip(self._time_range))
        if self._pinned:
            label = QLabel("  Filters", self)
            label.setObjectName("searchStatus")
            self.chip_row.addWidget(label)
        for index, term in enumerate(self._pinned):
            self.chip_row.addWidget(self._filter_chip(index, term))
        self.chip_row.addStretch(1)

    def _filter_chip(self, index: int, term: FilterTerm) -> QToolButton:
        chip = QToolButton(self)
        chip.setObjectName("filterChip")
        chip.setProperty("mode", term.mode.value)
        chip.setText(f"{term.label}  ▾")
        chip.setToolTip(f"{MODE_LABELS[term.mode]} — click to change or remove")
        chip.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        menu = QMenu(chip)
        for mode, label in MODE_LABELS.items():
            action = QAction(label, menu)
            action.setCheckable(True)
            action.setChecked(mode is term.mode)
            action.triggered.connect(lambda _c=False, i=index, m=mode: self._set_mode(i, m))
            menu.addAction(action)
        menu.addSeparator()
        remove = menu.addAction("Remove")
        remove.triggered.connect(lambda _c=False, i=index: self._remove(i))
        chip.setMenu(menu)
        return chip

    def _time_chip(self, window: TimeRange) -> QToolButton:
        chip = QToolButton(self)
        chip.setObjectName("filterChip")
        chip.setProperty("mode", "time")
        chip.setText(f"🕒 {window.label()}  ▾")
        chip.setToolTip("Only lines in this time range — click to change or remove")
        chip.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        menu = QMenu(chip)
        menu.addAction("Change…", self.timeRangeRequested.emit)
        menu.addAction("Remove", lambda: self.set_time_range(None))
        chip.setMenu(menu)
        return chip

    def _set_mode(self, index: int, mode: FilterMode) -> None:
        self._pinned[index] = FilterTerm(self._pinned[index].query, mode)
        self._rebuild_chips(self._selected_level_names())
        self.apply()

    def _remove(self, index: int) -> None:
        del self._pinned[index]
        self._rebuild_chips(self._selected_level_names())
        self.apply()

    def _selected_level_names(self) -> set[str]:
        return {o.name for o, b in zip(self._levels, self._level_buttons, strict=False) if b.isChecked()}

    def _on_text_edited(self, _text: str) -> None:
        if self._live:
            self._live_timer.start()
