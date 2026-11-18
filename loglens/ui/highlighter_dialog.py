"""Editor for highlighter rules."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QCheckBox,
    QColorDialog,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..core.highlight import HighlightRule, default_rules, style_line

COLS = ["On", "Name", "Pattern", "Regex", "Case", "Whole line", "Scrollbar", "Level chip", "Text", "Background"]
COL_ON, COL_NAME, COL_PATTERN, COL_REGEX, COL_CASE, COL_WHOLE, COL_MARK, COL_LEVEL, COL_FG, COL_BG = range(len(COLS))


class HighlighterDialog(QDialog):
    def __init__(self, rules: list[HighlightRule], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Highlighters")
        self.resize(980, 460)
        self.table = QTableWidget(0, len(COLS), self)
        self.table.setHorizontalHeaderLabels(COLS)
        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.cellDoubleClicked.connect(self._on_double_click)

        self.preview_input = QLineEdit(self)
        self.preview_input.setPlaceholderText("Type a sample log line to test the rules…")
        self.preview_input.textChanged.connect(self._update_preview)
        self.preview = QLabel(self)
        self.preview.setTextFormat(Qt.TextFormat.PlainText)

        buttons = QHBoxLayout()
        for text, slot in [
            ("Add", self._add),
            ("Remove", self._remove),
            ("Move up", lambda: self._move(-1)),
            ("Move down", lambda: self._move(1)),
            ("Reset to defaults", self._reset),
        ]:
            b = QPushButton(text, self)
            b.clicked.connect(slot)
            buttons.addWidget(b)
        buttons.addStretch(1)
        box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel, self)
        box.accepted.connect(self.accept)
        box.rejected.connect(self.reject)

        lay = QVBoxLayout(self)
        lay.addWidget(
            QLabel(
                "Rules are applied top to bottom; the first matching whole-line rule colours the line. "
                "Double-click a colour cell to change it.",
                self,
            )
        )
        lay.addWidget(self.table, 1)
        lay.addLayout(buttons)
        lay.addWidget(self.preview_input)
        lay.addWidget(self.preview)
        lay.addWidget(box)
        for rule in rules:
            self._append(rule)

    # ---- table <-> rules -----------------------------------------------------------------------------------------
    def _check(self, value: bool) -> QWidget:
        w = QWidget(self.table)
        cb = QCheckBox(w)
        cb.setChecked(value)
        lay = QHBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(cb)
        cb.toggled.connect(self._update_preview)
        return w

    def _checked(self, row: int, col: int) -> bool:
        cell = self.table.cellWidget(row, col)
        box = cell.findChild(QCheckBox) if cell is not None else None
        return bool(box is not None and box.isChecked())

    def _color_item(self, color: str | None) -> QTableWidgetItem:
        item = QTableWidgetItem(color or "")
        item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        if color:
            item.setBackground(QColor(color))
        return item

    def _append(self, rule: HighlightRule, row: int | None = None) -> None:
        row = self.table.rowCount() if row is None else row
        self.table.insertRow(row)
        self.table.setCellWidget(row, COL_ON, self._check(rule.enabled))
        self.table.setItem(row, COL_NAME, QTableWidgetItem(rule.name))
        self.table.setItem(row, COL_PATTERN, QTableWidgetItem(rule.pattern))
        self.table.setCellWidget(row, COL_REGEX, self._check(rule.regex))
        self.table.setCellWidget(row, COL_CASE, self._check(rule.case_sensitive))
        self.table.setCellWidget(row, COL_WHOLE, self._check(rule.whole_line))
        self.table.setCellWidget(row, COL_MARK, self._check(rule.scrollbar_mark))
        self.table.setCellWidget(row, COL_LEVEL, self._check(rule.level_filter))
        self.table.setItem(row, COL_FG, self._color_item(rule.fg))
        self.table.setItem(row, COL_BG, self._color_item(rule.bg))

    def _rule_at(self, row: int) -> HighlightRule:
        def text(col: int) -> str:
            item = self.table.item(row, col)
            return item.text().strip() if item else ""

        return HighlightRule(
            name=text(COL_NAME) or "rule",
            pattern=text(COL_PATTERN),
            regex=self._checked(row, COL_REGEX),
            case_sensitive=self._checked(row, COL_CASE),
            fg=text(COL_FG) or None,
            bg=text(COL_BG) or None,
            whole_line=self._checked(row, COL_WHOLE),
            scrollbar_mark=self._checked(row, COL_MARK),
            level_filter=self._checked(row, COL_LEVEL),
            enabled=self._checked(row, COL_ON),
        )

    def rules(self) -> list[HighlightRule]:
        return [r for r in (self._rule_at(i) for i in range(self.table.rowCount())) if r.pattern]

    def accept(self) -> None:
        """Refuse rules whose pattern is invalid or could freeze the view (they would silently never match)."""
        for row in range(self.table.rowCount()):
            rule = self._rule_at(row)
            problem = rule.problem() if rule.pattern else None
            if problem:
                self.table.selectRow(row)
                QMessageBox.warning(self, "Highlighters", f"Rule “{rule.name}”: pattern {rule.pattern!r} {problem}.")
                return
        super().accept()

    # ---- actions -------------------------------------------------------------------------------------------------
    def _add(self) -> None:
        self._append(HighlightRule("New rule", "", bg="#4000A0FF"))
        item = self.table.item(self.table.rowCount() - 1, COL_PATTERN)
        if item is not None:
            self.table.editItem(item)

    def _remove(self) -> None:
        for row in sorted({i.row() for i in self.table.selectedIndexes()}, reverse=True):
            self.table.removeRow(row)

    def _move(self, delta: int) -> None:
        row = self.table.currentRow()
        target = row + delta
        if row < 0 or not 0 <= target < self.table.rowCount():
            return
        rule = self._rule_at(row)
        self.table.removeRow(row)
        self._append(rule, target)
        self.table.selectRow(target)

    def _reset(self) -> None:
        self.table.setRowCount(0)
        for rule in default_rules():
            self._append(rule)

    def _on_double_click(self, row: int, col: int) -> None:
        if col not in (COL_FG, COL_BG):
            return
        cell = self.table.item(row, col)
        current = cell.text() if cell is not None else ""
        color = QColorDialog.getColor(
            QColor(current) if current else QColor("#ff0000"),
            self,
            "Pick colour",
            QColorDialog.ColorDialogOption.ShowAlphaChannel,
        )
        if color.isValid():
            self.table.setItem(row, col, self._color_item(color.name(QColor.NameFormat.HexArgb)))
            self._update_preview()

    def _update_preview(self) -> None:
        sample = self.preview_input.text()
        if not sample:
            self.preview.setText("")
            return
        style = style_line(self.rules(), sample)
        self.preview.setText(
            f"line colour: fg={style.fg or '-'} bg={style.bg or '-'};  {len(style.spans)} highlighted span(s)"
        )
        self.preview.setStyleSheet(f"background: {QColor(style.bg).name() if style.bg else 'transparent'};")
