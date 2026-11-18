"""Columns view: the log as a table of parsed fields (time, level, logger, message, …).

Virtual: one row per file line, parsed only when visible (with a small cache), so it works for files of any size.
Lines a format doesn't parse (continuations of multi-line records, banners) show their text in the message column.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Sequence

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QPersistentModelIndex, Qt, Signal
from PySide6.QtGui import QColor, QFont, QFontMetrics
from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QTableView, QWidget

from ..core.formats import Fields, LineParser, LogFormat
from ..core.secrets import MASK, has_secrets, mask
from ..core.text_source import TextLogSource

CACHE_ROWS = 5_000
MAX_COLUMNS = 30
MAX_CELL_CHARS = 1_000
SAMPLE_FOR_COLUMNS = 500  # parsed lines used to find the columns of formats with dynamic fields (JSON, CSV)
LEVEL_COLORS = {"Critical": "#E0204A", "Error": "#E5484D", "Warning": "#C98500", "Debug": "#8b949e", "Trace": "#8b949e"}
_Index = QModelIndex | QPersistentModelIndex


def column_order(fmt: LogFormat, sample: Sequence[Fields]) -> list[str]:
    """Columns: time and level first, the format's other fields, message last."""
    names: list[str] = list(fmt.fields)
    if fmt.dynamic_fields or not names:
        seen: dict[str, None] = {}
        for fields in sample:
            seen.update(dict.fromkeys(fields))
        names = list(seen)
    first = [n for n in (fmt.time_field, fmt.level_field) if n and n in names]
    last = [fmt.message_field] if fmt.message_field and fmt.message_field in names else []
    middle = [n for n in names if n not in first and n not in last]
    return (first + middle)[: MAX_COLUMNS - len(last)] + last


def masked_cell(column: str, value: str) -> str:
    """``value`` with secrets masked. A value split off by the format (``password`` column = ``hunter2``) has no key
    of its own, so it is also checked as ``column=value``."""
    if has_secrets(value):
        return mask(value)
    probe = f"{column}={value}"
    if not value or not has_secrets(probe):
        return value
    hidden = mask(probe)
    return hidden[len(column) + 1 :] if hidden.startswith(f"{column}=") else MASK


class ColumnsModel(QAbstractTableModel):
    """Table model over the parsed lines; set :attr:`mask_secrets` to show secret values masked."""

    def __init__(self, source: TextLogSource, fmt: LogFormat, context: Sequence[str]) -> None:
        super().__init__()
        self.source = source
        self.format = fmt
        self._mask_secrets = False
        self._parser = self._new_parser(context)
        self._rows = source.line_count()
        self._cache: OrderedDict[int, Fields | None] = OrderedDict()
        sample = [f for f in (self._parse(i) for i in range(min(self._rows, SAMPLE_FOR_COLUMNS))) if f]
        self.columns = column_order(fmt, sample) or [fmt.message_field or "message"]
        self._message_column = (
            self.columns.index(fmt.message_field) if fmt.message_field in self.columns else len(self.columns) - 1
        )

    def _new_parser(self, context: Sequence[str]) -> LineParser:
        parser = self.format.new_parser()
        for line in context:
            if not parser.consume_meta(line):
                parser.parse(line)
        return parser

    def _parse(self, row: int) -> Fields | None:
        if row in self._cache:
            self._cache.move_to_end(row)
            return self._cache[row]
        line = self.source.get_line(row)
        fields = None if self._parser.consume_meta(line) else self._parser.parse(line)
        self._cache[row] = fields
        if len(self._cache) > CACHE_ROWS:
            self._cache.popitem(last=False)
        return fields

    @property
    def mask_secrets(self) -> bool:
        return self._mask_secrets

    @mask_secrets.setter
    def mask_secrets(self, enabled: bool) -> None:
        """Mask secret values in the cells (the view repaints at once)."""
        if enabled == self._mask_secrets:
            return
        self._mask_secrets = enabled
        if self._rows and self.columns:
            self.dataChanged.emit(
                self.index(0, 0), self.index(self._rows - 1, len(self.columns) - 1), [Qt.ItemDataRole.DisplayRole]
            )

    def grow(self) -> None:
        """New lines were appended (tail)."""
        count = self.source.line_count()
        if count > self._rows:
            self.beginInsertRows(QModelIndex(), self._rows, count - 1)
            self._rows = count
            self.endInsertRows()

    # ---- Qt model ------------------------------------------------------------------------------------------------
    def rowCount(self, parent: _Index = QModelIndex()) -> int:  # noqa: B008 - Qt's default argument
        return 0 if parent.isValid() else self._rows

    def columnCount(self, parent: _Index = QModelIndex()) -> int:  # noqa: B008
        return 0 if parent.isValid() else len(self.columns)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole) -> object:
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == Qt.Orientation.Horizontal:
            return self.columns[section] if section < len(self.columns) else None
        return f"{section + 1:,}"

    def data(self, index: _Index, role: int = Qt.ItemDataRole.DisplayRole) -> object:
        if not index.isValid() or role not in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ForegroundRole):
            return None
        fields = self._parse(index.row())
        column = index.column()
        if fields is None:  # continuation / unparsed line: its text in the message column
            if role == Qt.ItemDataRole.ForegroundRole:
                return QColor("#8b949e")
            if column != self._message_column:
                return ""
            line = self.source.get_line(index.row())
            return (mask(line) if self._mask_secrets else line)[:MAX_CELL_CHARS]
        name = self.columns[column]
        value = fields.get(name, "")
        if role == Qt.ItemDataRole.ForegroundRole:
            level = self.format.level_of(fields)
            color = LEVEL_COLORS.get(level)
            return QColor(color) if color else None
        if self._mask_secrets:
            value = masked_cell(name, value)  # before truncating: a cut-off secret might no longer be recognised
        return value[:MAX_CELL_CHARS].replace("\n", " ⏎ ")


class ColumnsView(QTableView):
    currentRowChanged = Signal(int)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.setWordWrap(False)
        self.setAlternatingRowColors(True)
        self.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.verticalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Fixed)
        self.horizontalHeader().setStretchLastSection(True)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)

    def set_font(self, font: QFont) -> None:
        self.setFont(font)
        self.verticalHeader().setDefaultSectionSize(QFontMetrics(font).height() + 4)

    def set_columns_model(self, model: ColumnsModel) -> None:
        old = self.model()
        self.setModel(model)
        if old is not None:
            old.deleteLater()
        self.selectionModel().currentRowChanged.connect(
            lambda current, _prev: self.currentRowChanged.emit(current.row())
        )
        metrics = QFontMetrics(self.font())
        for column, name in enumerate(model.columns[:-1]):
            sample = max((len(str(model.data(model.index(r, column)) or "")) for r in range(min(model.rowCount(), 50))),
                         default=0)  # fmt: skip
            width = metrics.horizontalAdvance("M") * min(max(sample, len(name)) + 2, 40)
            self.setColumnWidth(column, width)

    def select_row(self, row: int) -> None:
        model = self.model()
        if model is None or not 0 <= row < model.rowCount() or self.currentIndex().row() == row:
            return
        self.blockSignals(True)
        self.setCurrentIndex(model.index(row, 0))
        self.scrollTo(model.index(row, 0), QAbstractItemView.ScrollHint.PositionAtCenter)
        self.blockSignals(False)
