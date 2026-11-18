"""Custom format editor: a layout pattern (log4net / log4j / NLog / Serilog) or a regex with named groups, tested live
against the first lines of the current log."""

from __future__ import annotations

from collections.abc import Sequence
from typing import cast

from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..core.formats import LAYOUT_STYLES, CustomFormat, FormatError, LayoutStyle, extract_records

PREVIEW_LINES = 40
KIND_LAYOUT, KIND_REGEX = "layout", "regex"
EXAMPLES = {
    KIND_LAYOUT: "%date [%thread] %-5level %logger - %message%newline",
    KIND_REGEX: r"^(?P<time>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d[.,]\d+) (?P<level>\w+) (?P<message>.*)$",
}


class FormatDialog(QDialog):
    def __init__(
        self, sample: Sequence[str], existing: CustomFormat | None = None, parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Custom log format")
        self.resize(940, 640)
        self._sample = list(sample[:PREVIEW_LINES])
        self.name = QLineEdit(existing.name if existing else "", self)
        self.name.setPlaceholderText("e.g. My service log")
        self.kind = QComboBox(self)
        self.kind.addItem("Layout pattern (log4net, log4j, NLog, Serilog)", KIND_LAYOUT)
        self.kind.addItem("Regular expression with named groups", KIND_REGEX)
        self.layout_style = QComboBox(self)
        for style in LAYOUT_STYLES:
            self.layout_style.addItem("detect from the pattern" if style == "auto" else style, style)
        self.pattern = QPlainTextEdit(self)
        self.pattern.setMaximumHeight(80)
        self.multiline = QCheckBox("Lines that don't match continue the previous record (stack traces, dumps)", self)
        if existing is not None:
            self.kind.setCurrentIndex(0 if existing.layout else 1)
            self.layout_style.setCurrentIndex(max(self.layout_style.findData(existing.style), 0))
            self.pattern.setPlainText(existing.layout or existing.regex)
            self.multiline.setChecked(existing.multiline)
        else:
            self.pattern.setPlainText(EXAMPLES[KIND_LAYOUT])
            self.multiline.setChecked(True)
        self.status = QLabel(self)
        self.status.setWordWrap(True)
        self.preview = QTableWidget(self)
        self.preview.horizontalHeader().setStretchLastSection(True)
        self.preview.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        for widget in (self.kind, self.layout_style):
            widget.currentIndexChanged.connect(self._update)
        self.kind.currentIndexChanged.connect(self._kind_changed)
        self.pattern.textChanged.connect(self._update)
        self.multiline.toggled.connect(self._update)

        form = QFormLayout()
        form.addRow("Name", self.name)
        form.addRow("Defined by", self.kind)
        form.addRow("Layout style", self.layout_style)
        form.addRow("Pattern", self.pattern)
        form.addRow("", self.multiline)
        note = QLabel(
            "Paste the layout from your logging configuration (log4net <code>conversionPattern</code>, NLog "
            "<code>layout</code>, Serilog <code>outputTemplate</code>), or write a regex whose named groups become "
            "columns (<code>time</code>, <code>level</code> and <code>message</code> are recognised).",
            self,
        )
        note.setObjectName("dialogNote")
        note.setWordWrap(True)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel, self)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(note)
        layout.addWidget(self.status)
        layout.addWidget(self.preview, 1)
        layout.addWidget(buttons)
        self._form = form
        self._kind_changed()
        self._update()

    def custom_format(self) -> CustomFormat:
        text = self.pattern.toPlainText().strip()
        name = self.name.text().strip() or "Custom format"
        if self.kind.currentData() == KIND_LAYOUT:
            style = cast("LayoutStyle", self.layout_style.currentData())
            return CustomFormat(name, layout=text, style=style, multiline=self.multiline.isChecked())
        return CustomFormat(name, regex=text, multiline=self.multiline.isChecked())

    def _kind_changed(self) -> None:
        layout = self.kind.currentData() == KIND_LAYOUT
        self._form.setRowVisible(self.layout_style, layout)
        current = self.pattern.toPlainText().strip()
        if not current or current in EXAMPLES.values():
            self.pattern.setPlainText(EXAMPLES[str(self.kind.currentData())])

    def _update(self) -> None:
        try:
            fmt = self.custom_format().to_format()
        except (FormatError, ValueError) as exc:
            self.status.setText(f"<span style='color:#E5484D'>⚠ {exc}</span>")
            self.preview.clear()
            self.preview.setRowCount(0)
            return
        records = extract_records(fmt, self._sample)
        parsed = sum(1 for r in records if r.parsed)
        columns = list(fmt.fields)
        self.preview.clear()
        self.preview.setColumnCount(len(columns) + 1)
        self.preview.setHorizontalHeaderLabels(["line", *columns])
        self.preview.setRowCount(len(records))
        for row, record in enumerate(records):
            self.preview.setItem(row, 0, QTableWidgetItem(str(record.line + 1)))
            for column, name in enumerate(columns, start=1):
                value = record.fields.get(name, "") if record.parsed else (record.fields.get(fmt.message_field, ""))
                if not record.parsed and name != fmt.message_field:
                    value = ""
                self.preview.setItem(row, column, QTableWidgetItem(value.replace("\n", " ⏎ ")[:300]))
        lines = len(self._sample)
        color = "#30A46C" if parsed and parsed >= len(records) * 0.8 else "#C98500"
        self.status.setText(
            f"<span style='color:{color}'>{parsed} of {len(records)} records parsed</span> from the first {lines} "
            f"lines · columns: {', '.join(columns)}"
        )

    def _accept(self) -> None:
        try:
            self.custom_format().validate()
        except (FormatError, ValueError) as exc:
            self.status.setText(f"<span style='color:#E5484D'>⚠ {exc}</span>")
            return
        if not self.name.text().strip():
            self.status.setText("<span style='color:#E5484D'>⚠ Give the format a name.</span>")
            return
        self.accept()
