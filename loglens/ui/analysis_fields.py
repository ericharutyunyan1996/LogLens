"""Analyze pages that use the log's format: field facets (value counts) and SQL over the parsed records."""

from __future__ import annotations

import re
import sqlite3
import threading
from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTreeWidgetItem,
    QWidget,
)

from ..core.field_stats import EXAMPLE_QUERIES, FieldCounts, field_counts, load_queries, load_sqlite, save_queries
from ..core.formats import LogFormat
from ..paths import app_data_dir
from ..services.analysis_jobs import AnalysisRunner, Analyzer, Progress, Task
from .analysis_base import AnalysisPage, fill_tree, make_row, make_tree

if TYPE_CHECKING:
    from .log_tab import LogTab

MAX_RESULT_ROWS = 10_000
MAX_CELL_CHARS = 500
# SQLite virtual-machine steps between checks of the cancel flag: frequent enough to stop within milliseconds,
# rare enough that the check costs nothing measurable.
SQL_PROGRESS_STEPS = 100_000
NAME_ROLE = Qt.ItemDataRole.UserRole


def _format_of(tab: LogTab) -> LogFormat | None:
    return tab.document.log_format


class FieldsPage(AnalysisPage):
    title = "Fields"
    intro = (
        "Value counts of every field of the log's format (level, logger, thread, status, user, …). Pick a field on "
        "the left; double-click a value to filter the log by it. The format is detected automatically — change it "
        "with the format chip in the file header."
    )

    def __init__(self, tab: LogTab, parent: QWidget | None = None) -> None:
        super().__init__(tab, parent)
        self._counts: FieldCounts | None = None
        self.fields = QListWidget(self)
        self.fields.currentItemChanged.connect(self._show_field)
        self.values = make_tree(["Value", "Records", "Share %"], self)
        self.values.itemDoubleClicked.connect(self._filter_value)
        split = QSplitter(Qt.Orientation.Horizontal, self)
        split.addWidget(self.fields)
        split.addWidget(self.values)
        split.setSizes([220, 640])
        self.body.addWidget(split, 1)

    def analyzer(self) -> Analyzer:
        fmt = _format_of(self.tab)
        context = self.tab.document.format_context()

        def analyze(lines: Iterable[tuple[int, str]]) -> object:
            if fmt is None:
                return "The log's format is still being detected — try again in a moment."
            return field_counts(fmt, lines, context=context)

        return analyze

    def show_result(self, result: object) -> None:
        if isinstance(result, str):
            self.status.setText(result)
            return
        assert isinstance(result, FieldCounts)
        self._counts = result
        fmt = _format_of(self.tab)
        name = fmt.display_name if fmt else "?"
        self.status.setText(
            f"<b>{result.parsed:,} records</b> parsed as {name} · {result.unparsed:,} other lines "
            f"(continuations, banners) · {len(result.fields)} fields"
        )
        self.fields.clear()
        for field_name, counter in sorted(result.fields.items(), key=lambda kv: len(kv[1])):
            item = QListWidgetItem(f"{field_name}  ({len(counter):,} values)", self.fields)
            item.setData(NAME_ROLE, field_name)
        if self.fields.count():
            self.fields.setCurrentRow(0)

    def _show_field(self, item: QListWidgetItem | None, _previous: QListWidgetItem | None) -> None:
        if item is None or self._counts is None:
            return
        total = self._counts.parsed or 1
        rows = [make_row([value or "(empty)", count, round(100 * count / total, 2)])
                for value, count in self._counts.top(str(item.data(NAME_ROLE)), 1000)]  # fmt: skip
        fill_tree(self.values, rows)
        self.values.sortByColumn(1, Qt.SortOrder.DescendingOrder)

    def _filter_value(self, item: QTreeWidgetItem, _column: int) -> None:
        value = item.text(0)
        if value and value != "(empty)":
            self.filterRequested.emit(rf"(?<![\w.]){re.escape(value)}(?![\w.])")


@dataclass(frozen=True, slots=True)
class QueryResult:
    """Outcome of one SQL query: column names and the first rows, or the SQLite error message."""

    headers: tuple[str, ...] = ()
    rows: tuple[tuple[object, ...], ...] = ()
    error: str = ""


def query_task(connection: sqlite3.Connection, sql: str, lock: threading.Lock) -> Task:
    """A runner task executing ``sql`` (first MAX_RESULT_ROWS rows). Cancelling the job aborts the query: SQLite's
    progress handler checks the cancel event, and ``connection.interrupt()`` stops it at once."""

    def task(cancel: threading.Event, _report: Progress) -> QueryResult:
        with lock:  # one statement at a time per connection; closing the connection waits for it
            if cancel.is_set():
                return QueryResult(error="cancelled")
            connection.set_progress_handler(cancel.is_set, SQL_PROGRESS_STEPS)
            try:
                cursor = connection.execute(sql)
                rows = cursor.fetchmany(MAX_RESULT_ROWS)
                headers = tuple(str(d[0]) for d in cursor.description or ())
                cursor.close()  # an unfinished statement would keep a later interrupt() in effect
            except sqlite3.Error as exc:
                return QueryResult(error=str(exc))
            finally:
                connection.set_progress_handler(None, 0)
        return QueryResult(headers, tuple(tuple(row) for row in rows))

    return task


class SqlPage(AnalysisPage):
    title = "SQL"
    intro = (
        "Ask anything in SQL: the parsed records are loaded into a table <code>log</code> with <code>_line, _time, "
        "_level, _message</code> plus one column per field. Double-click a result with a <code>_line</code> to jump."
    )

    def __init__(self, tab: LogTab, parent: QWidget | None = None) -> None:
        super().__init__(tab, parent)
        self._connection: sqlite3.Connection | None = None
        self._query_lock = threading.Lock()
        self._query_busy = False
        self.query_runner = AnalysisRunner(self)
        self.query_runner.finished.connect(self._on_query_finished)
        self.query_runner.failed.connect(self._on_query_failed)
        self._library_path = app_data_dir() / "sql_queries.json"
        self.library = QComboBox(self)
        self.library.activated.connect(self._pick)
        save = QPushButton("Save query…", self)
        save.clicked.connect(self._save)
        self.run_query_button = run = QPushButton("Run query", self)
        run.setObjectName("primary")
        run.clicked.connect(self.run_query)
        self.cancel_query_button = QPushButton("Cancel query", self)
        self.cancel_query_button.clicked.connect(self.cancel_query)
        self.cancel_query_button.hide()
        self.query = QPlainTextEdit(EXAMPLE_QUERIES[0][1], self)
        self.query.setMaximumHeight(110)
        self.columns_note = QLabel(self)
        self.columns_note.setObjectName("dialogNote")
        self.columns_note.setWordWrap(True)
        self.table = QTableWidget(self)
        self.table.itemDoubleClicked.connect(self._jump_row)
        row = QHBoxLayout()
        row.addWidget(QLabel("Library:", self))
        row.addWidget(self.library, 1)
        row.addWidget(save)
        row.addWidget(run)
        row.addWidget(self.cancel_query_button)
        self.body.addLayout(row)
        self.body.addWidget(self.query)
        self.body.addWidget(self.columns_note)
        self.body.addWidget(self.table, 1)
        self.run_button.setText("Load records")
        self._fill_library()

    def _fill_library(self) -> None:
        self.library.clear()
        for name, sql in [*EXAMPLE_QUERIES, *load_queries(self._library_path)]:
            self.library.addItem(name, sql)

    def _pick(self, index: int) -> None:
        self.query.setPlainText(str(self.library.itemData(index)))

    def _save(self) -> None:
        name, ok = QInputDialog.getText(self, "Save query", "Name:")
        if ok and name.strip():
            saved = [q for q in load_queries(self._library_path) if q[0] != name.strip()]
            save_queries(self._library_path, [*saved, (name.strip(), self.query.toPlainText())])
            self._fill_library()

    def analyzer(self) -> Analyzer:
        fmt = _format_of(self.tab)
        context = self.tab.document.format_context()

        def analyze(lines: Iterable[tuple[int, str]]) -> object:
            if fmt is None:
                return "The log's format is still being detected — try again in a moment."
            return load_sqlite(fmt, lines, context=context)

        return analyze

    def show_result(self, result: object) -> None:
        if isinstance(result, str):
            self.status.setText(result)
            return
        assert isinstance(result, tuple)
        connection, rows = result
        self._replace_connection(connection)
        columns = [r[1] for r in connection.execute("PRAGMA table_info(log)").fetchall()]
        self.status.setText(f"<b>{rows:,} records</b> loaded into table <code>log</code>.")
        self.columns_note.setText("Columns: " + ", ".join(columns))
        self.run_query()

    def _replace_connection(self, connection: sqlite3.Connection | None) -> None:
        self.cancel_query()  # a query still running on the old connection
        old, self._connection = self._connection, connection
        if old is not None:
            with self._query_lock:  # a cancelled query may still be unwinding on its worker (interrupted: briefly)
                old.close()

    # ---- running a query (on a worker: a heavy query must not freeze the window) --------------------------------
    @property
    def query_busy(self) -> bool:
        return self._query_busy

    def set_busy(self, busy: bool, status: str = "") -> None:
        super().set_busy(busy, status)
        self.run_query_button.setEnabled(not busy and not self._query_busy)

    def _set_query_busy(self, busy: bool) -> None:
        self._query_busy = busy
        self.run_query_button.setEnabled(not busy and not self.busy)
        self.run_button.setEnabled(not busy and not self.busy)
        self.cancel_query_button.setVisible(busy)
        self.progress.setVisible(busy or self.busy)
        if busy:
            self.progress.setRange(0, 0)

    def run_query(self) -> None:
        if self._connection is None:
            self.status.setText("Click “Load records” first (it reads the log into the SQL table).")
            return
        if self._query_busy:
            return
        self._set_query_busy(True)
        self.status.setText("Running query…")
        self.query_runner.run_task(query_task(self._connection, self.query.toPlainText(), self._query_lock))

    def cancel_query(self) -> None:
        """Stop the running query; a result that still arrives for it is dropped."""
        self.query_runner.cancel()
        if not self._query_busy:
            return
        if self._connection is not None:
            self._connection.interrupt()
        self._set_query_busy(False)
        self.status.setText("Query cancelled.")

    def cancel(self) -> None:
        self.cancel_query()
        super().cancel()

    def _on_query_failed(self, message: str) -> None:
        self._set_query_busy(False)
        self.status.setText(f"⚠ {message}")

    def _on_query_finished(self, result: object) -> None:
        self._set_query_busy(False)
        assert isinstance(result, QueryResult)
        if result.error:
            self.status.setText(f"⚠ {result.error}")
            return
        self.table.clear()
        self.table.setColumnCount(len(result.headers))
        self.table.setHorizontalHeaderLabels(list(result.headers))
        self.table.setRowCount(len(result.rows))
        for r, values in enumerate(result.rows):
            for c, value in enumerate(values):
                self.table.setItem(r, c, QTableWidgetItem("" if value is None else str(value)[:MAX_CELL_CHARS]))
        more = f" (first {MAX_RESULT_ROWS:,})" if len(result.rows) == MAX_RESULT_ROWS else ""
        self.status.setText(f"{len(result.rows):,} result rows{more}")

    def _jump_row(self, item: QTableWidgetItem) -> None:
        headers = [
            h.text() if (h := self.table.horizontalHeaderItem(c)) else "" for c in range(self.table.columnCount())
        ]
        if "_line" in headers:
            cell = self.table.item(item.row(), headers.index("_line"))
            if cell is not None and cell.text().isdigit():
                self.lineRequested.emit(int(cell.text()) - 1)
