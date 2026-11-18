"""Analysis window for one log: HTTP statistics, request/response transactions (more pages plug in the same way).

Each page runs its analyzer through :class:`AnalysisRunner` over the whole file or the current filter's matches,
then renders the result. Clicking a row jumps to the line in the log; endpoints can be turned into a filter.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING

import numpy as np
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QShowEvent
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..core.http import ERROR_STATUS_MIN, HttpSummary, Transaction, pair_transactions, parse_lines, summarize
from ..core.patterns import Pattern, PatternDiff, compare, mine, template_regex
from ..services.analysis_jobs import (
    AnalysisScope,
    Analyzer,
    Progress,
    iter_lines,
)
from .analysis_base import LINE_ROLE, AnalysisPage, fill_tree, make_row, make_tree
from .analysis_fields import FieldsPage, SqlPage

if TYPE_CHECKING:
    from .log_tab import LogTab

MAX_TRANSACTION_ROWS = 20_000


def endpoint_regex(method: str, path: str) -> str:
    """Regex matching log lines of a normalised endpoint ("GET /users/{id}")."""
    parts = [re.escape(part) for part in path.split("{id}")]
    return rf"\b{re.escape(method)}\s+\S*?" + r"[^\s/?]+".join(parts) + r"(?:[?\s]|$)"


def _http_analyzer(lines: Iterable[tuple[int, str]]) -> HttpSummary:
    return summarize(parse_lines(lines))


class HttpPage(AnalysisPage):
    title = "HTTP requests"
    intro = (
        "Requests found in access logs (IIS/W3C, Apache/nginx) or application lines (method + path, status, "
        "duration): per-endpoint counts, errors and latency. Double-click an endpoint to filter the log by it; "
        "double-click a request to jump to it."
    )

    def __init__(self, tab: LogTab, parent: QWidget | None = None) -> None:
        super().__init__(tab, parent)
        self.endpoints = make_tree(["Endpoint", "Requests", "Errors", "Error %", "p50 ms", "p95 ms", "p99 ms", "Max ms",
                                "Statuses"], self)  # fmt: skip
        self.endpoints.itemDoubleClicked.connect(self._filter_endpoint)
        self.slowest = make_tree(["Duration ms", "Status", "Method", "Path", "Time", "Line"], self)
        self.statuses = make_tree(["Status", "Requests"], self)
        self.clients = make_tree(["Client", "Requests"], self)
        self.minutes = make_tree(["Minute", "Requests", "Errors"], self)
        for tree in (self.slowest,):
            tree.itemDoubleClicked.connect(lambda item, _c: self.jump(item))
        details = QTabWidget(self)
        details.addTab(self.slowest, "Slowest requests")
        details.addTab(self.statuses, "Status codes")
        details.addTab(self.minutes, "Busiest minutes")
        details.addTab(self.clients, "Clients")
        split = QSplitter(Qt.Orientation.Vertical, self)
        split.addWidget(self.endpoints)
        split.addWidget(details)
        split.setSizes([300, 220])
        self.body.addWidget(split)

    def analyzer(self) -> Analyzer:
        return _http_analyzer

    def show_result(self, result: object) -> None:
        assert isinstance(result, HttpSummary)
        summary = result
        if not summary.total:
            self.status.setText("No HTTP requests recognised in these lines.")
            return
        classes = "  ".join(f"{name}: {count:,}" for name, count in summary.status_classes if count)
        latency = (
            f" · latency p50 {summary.p50_ms:,.0f} ms, p95 {summary.p95_ms:,.0f} ms, max {summary.max_ms:,.0f} ms"
            if summary.p50_ms is not None and summary.p95_ms is not None and summary.max_ms is not None
            else ""
        )
        self.status.setText(
            f"<b>{summary.total:,} requests</b> · {summary.errors:,} errors ({summary.error_rate:.1%}){latency}"
            f"<br>{classes}"
        )
        fill_tree(self.endpoints, [
            make_row([e.endpoint, e.count, e.errors, round(100 * e.error_rate, 1), e.p50_ms, e.p95_ms, e.p99_ms,
                  e.max_ms, ", ".join(f"{s}×{n}" for s, n in e.top_statuses[:4])])
            for e in summary.endpoints
        ])  # fmt: skip
        fill_tree(self.slowest, [
            make_row([r.duration_ms, r.status, r.method, r.path, f"{r.time:%Y-%m-%d %H:%M:%S}" if r.time else "",
                  r.line + 1], r.line)
            for r in summary.slowest
        ])  # fmt: skip
        fill_tree(self.statuses, [make_row([status, count]) for status, count in summary.top_statuses])
        fill_tree(self.clients, [make_row([client, count]) for client, count in summary.top_clients])
        busiest = sorted(summary.per_minute, key=lambda m: (m[2], m[1]), reverse=True)[:50]
        fill_tree(self.minutes, [make_row([f"{m:%Y-%m-%d %H:%M}", n, errors]) for m, n, errors in busiest])
        self.endpoints.sortByColumn(1, Qt.SortOrder.DescendingOrder)

    def _filter_endpoint(self, item: QTreeWidgetItem, _column: int) -> None:
        method, _, path = item.text(0).partition(" ")
        if path:
            self.filterRequested.emit(endpoint_regex(method, path))


def _transactions_analyzer(lines: Iterable[tuple[int, str]]) -> list[Transaction]:
    return pair_transactions(lines)


class TransactionsPage(AnalysisPage):
    title = "Request / response"
    intro = (
        "Requests paired with the responses that answer them — by a shared request / trace / correlation id or "
        "GUID, else by thread. Find requests that never got an answer, failed, or were slow. Double-click to jump."
    )
    VIEWS = ("All", "Unanswered", "Errors (status ≥ 500)", "Slowest 5 %")

    def __init__(self, tab: LogTab, parent: QWidget | None = None) -> None:
        super().__init__(tab, parent)
        self._transactions: list[Transaction] = []
        self.view = QComboBox(self)
        self.view.addItems(list(self.VIEWS))
        self.view.currentIndexChanged.connect(self._render)
        bookmark = QPushButton("Bookmark lines of selected", self)
        bookmark.clicked.connect(self._bookmark_selected)
        row = QHBoxLayout()
        row.addWidget(QLabel("Show", self))
        row.addWidget(self.view)
        row.addStretch(1)
        row.addWidget(bookmark)
        headers = ["Request line", "Method", "Path", "Status", "Duration ms", "Response line", "Key / thread", "Lines"]
        self.tree = make_tree(headers, self)
        self.tree.itemDoubleClicked.connect(lambda item, _c: self.jump(item))
        self.body.addLayout(row)
        self.body.addWidget(self.tree, 1)

    def analyzer(self) -> Analyzer:
        return _transactions_analyzer

    def show_result(self, result: object) -> None:
        assert isinstance(result, list)
        self._transactions = result
        paired = sum(1 for t in result if t.paired)
        self.status.setText(
            f"<b>{len(result):,} requests</b> · {paired:,} answered · {len(result) - paired:,} without a response"
            if result
            else "No request/response lines recognised in these lines."
        )
        self._render()

    def selected_view(self) -> list[Transaction]:
        items = self._transactions
        match self.view.currentIndex():
            case 1:
                return [t for t in items if not t.paired]
            case 2:
                return [t for t in items if t.status is not None and t.status >= ERROR_STATUS_MIN]
            case 3:
                timed = sorted((t for t in items if t.duration_ms is not None), key=lambda t: t.duration_ms or 0.0)
                return timed[int(len(timed) * 0.95) :][::-1]
        return items

    def _render(self) -> None:
        rows = [
            make_row([t.request_line + 1, t.method, t.path, t.status, t.duration_ms,
                  t.response_line + 1 if t.response_line is not None else None, t.key or t.thread, len(t.all_lines)],
                 t.request_line)
            for t in self.selected_view()[:MAX_TRANSACTION_ROWS]
        ]  # fmt: skip
        fill_tree(self.tree, rows)

    def _bookmark_selected(self) -> None:
        wanted = {int(item.data(0, LINE_ROLE)) for item in self.tree.selectedItems()}
        lines = [line for t in self._transactions if t.request_line in wanted for line in t.all_lines]
        if lines:
            self.bookmarksRequested.emit(lines)


def _patterns_analyzer(lines: Iterable[tuple[int, str]]) -> list[Pattern]:
    return mine(lines)


class PatternsPage(AnalysisPage):
    title = "Patterns"
    intro = (
        "Lines grouped into message patterns (numbers, ids, paths, … become placeholders) — see at a glance what a "
        "log or a filter result is made of, and how often. Double-click to jump to the first line of a pattern."
    )
    aggregateRequested = Signal(list, str)  # [(count, line, template, sample)], scope description

    def __init__(self, tab: LogTab, parent: QWidget | None = None) -> None:
        super().__init__(tab, parent)
        self._patterns: list[Pattern] = []
        self._total = 0
        self.tree = make_tree(["Lines", "Share %", "Pattern", "First line", "Last line"], self)
        self.tree.itemDoubleClicked.connect(lambda item, _c: self.jump(item))
        filter_button = QPushButton("Filter by selected pattern", self)
        filter_button.clicked.connect(self._filter_selected)
        explain = QPushButton("Explain these patterns with AI…", self)
        explain.setToolTip("Sends the most frequent patterns with one example each (redacted, preview first)")
        explain.clicked.connect(self._explain)
        row = QHBoxLayout()
        row.addWidget(filter_button)
        row.addWidget(explain)
        row.addStretch(1)
        self.body.addWidget(self.tree, 1)
        self.body.addLayout(row)

    def analyzer(self) -> Analyzer:
        return _patterns_analyzer

    def show_result(self, result: object) -> None:
        assert isinstance(result, list)
        self._patterns = result
        self._total = sum(p.count for p in result) or 1
        self.status.setText(f"<b>{len(result):,} patterns</b> in {self._total:,} lines")
        rows = []
        for pattern in result:
            item = make_row([pattern.count, round(100 * pattern.count / self._total, 2), pattern.template,
                         pattern.first_line + 1, pattern.last_line + 1], pattern.first_line)  # fmt: skip
            item.setToolTip(2, pattern.sample)
            rows.append(item)
        fill_tree(self.tree, rows)
        self.tree.sortByColumn(0, Qt.SortOrder.DescendingOrder)

    def _filter_selected(self) -> None:
        item = self.tree.currentItem()
        regex = template_regex(item.text(2)) if item is not None else None
        if regex:
            self.filterRequested.emit(regex)
        elif item is not None:
            self.status.setText("This pattern has too little fixed text to filter by.")

    def _explain(self) -> None:
        if self._patterns:
            chosen = [(p.count, p.first_line, p.template, p.sample) for p in self._patterns]
            self.aggregateRequested.emit(chosen, self.scope.currentData().description)


class ComparePage(AnalysisPage):
    title = "Compare"
    intro = (
        "What is different? Compare the message patterns of this log with another open log, or the lines before "
        "the selected line with the lines after it: new kinds of messages, ones that disappeared, and ones that "
        "became much more (or less) frequent."
    )

    def __init__(self, tab: LogTab, others: Callable[[], list[LogTab]], parent: QWidget | None = None) -> None:
        self._others = others
        super().__init__(tab, parent)
        self.new = make_tree(["Lines", "New pattern", "First line"], self)
        self.changed = make_tree(["Before %", "After %", "Change ×", "Pattern"], self)
        self.gone = make_tree(["Lines", "Pattern that disappeared"], self)
        self.new.itemDoubleClicked.connect(lambda item, _c: self.jump(item))
        tabs = QTabWidget(self)
        tabs.addTab(self.new, "New")
        tabs.addTab(self.changed, "More / less frequent")
        tabs.addTab(self.gone, "Gone")
        self.body.addWidget(tabs, 1)

    def refresh_scope(self) -> None:
        """List the open logs as baselines (closed ones disappear); the chosen baseline stays chosen if still open."""
        kept = self.scope.currentData()
        self.scope.clear()
        self.scope.addItem("This log: before the selected line → from the selected line on", None)
        for other in self._others():
            if other is not self.tab:
                self.scope.addItem(f"Baseline: {other.document.title} → this log", other)
                if other is kept:
                    self.scope.setCurrentIndex(self.scope.count() - 1)

    def run(self) -> None:
        baseline_tab = self.scope.currentData()
        source = self.tab.document.source
        if baseline_tab is not None and not any(other is baseline_tab for other in self._others()):
            self.refresh_scope()
            self.status.setText("That log was closed — choose another baseline.")
            return
        if baseline_tab is None:
            split = max(self.tab.main_view.current_row(), 0)
            if split == 0:
                self.status.setText("Select the line where things changed (e.g. the first error), then Analyze.")
                return
            before = (source, AnalysisScope(np.arange(0, split, dtype=np.int64), "before"))
            after = (source, AnalysisScope(np.arange(split, source.line_count(), dtype=np.int64), "after"))
        else:
            before = (baseline_tab.document.source, AnalysisScope(None, "baseline"))
            after = (source, AnalysisScope(None, "this log"))
        self.set_busy(True, "Finding patterns on both sides…")

        def task(cancel: threading.Event, report: Progress) -> PatternDiff:
            sides = [mine(iter_lines(src, scope, cancel=cancel, progress=report)) for src, scope in (before, after)]
            return compare(sides[0], sides[1])

        self.runner.run_task(task)

    def show_result(self, result: object) -> None:
        assert isinstance(result, PatternDiff)
        diff = result
        self.status.setText(
            f"<b>{len(diff.new):,} new</b>, {len(diff.changed):,} changed, {len(diff.gone):,} gone "
            f"({diff.baseline_total:,} → {diff.current_total:,} lines)"
        )
        fill_tree(self.new, [make_row([p.count, p.template, p.first_line + 1], p.first_line) for p in diff.new])
        fill_tree(self.changed, [
            make_row([round(100 * c.baseline_rate, 2), round(100 * c.current_rate, 2), round(c.ratio, 1)
                  if c.ratio != float("inf") else None, c.template], c.current.first_line)
            for c in diff.changed
        ])  # fmt: skip
        fill_tree(self.gone, [make_row([p.count, p.template]) for p in diff.gone])
        self.new.sortByColumn(0, Qt.SortOrder.DescendingOrder)


PAGES: dict[str, type[AnalysisPage]] = {
    "patterns": PatternsPage,
    "fields": FieldsPage,
    "sql": SqlPage,
    "http": HttpPage,
    "transactions": TransactionsPage,
}


class AnalysisWindow(QDialog):
    """Non-modal window with the analysis pages for one log tab.

    ``show_tab`` brings the analysed tab to the front of the main window; it is called before a page jumps to a line
    or filters the log, so the user sees what happened. Call :meth:`shutdown` when the tab closes.
    """

    aggregateRequested = Signal(list, str)  # patterns to explain with AI, scope description

    def __init__(
        self,
        tab: LogTab,
        parent: QWidget | None = None,
        *,
        others: Callable[[], list[LogTab]] | None = None,
        show_tab: Callable[[LogTab], None] | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"Analyze — {tab.document.title}")
        self.setWindowFlag(Qt.WindowType.WindowMaximizeButtonHint, True)
        self.resize(1000, 640)
        self.tab = tab
        self._show_tab = show_tab
        self.tabs = QTabWidget(self)
        self.pages: dict[str, AnalysisPage] = {}
        for key, page_type in PAGES.items():
            self.add_page(key, page_type(tab, self))
        self.add_page("compare", ComparePage(tab, others or (list), self))
        patterns = self.pages["patterns"]
        assert isinstance(patterns, PatternsPage)
        patterns.aggregateRequested.connect(self.aggregateRequested)
        layout = QVBoxLayout(self)
        layout.addWidget(self.tabs)

    def add_page(self, key: str, page: AnalysisPage) -> None:
        page.lineRequested.connect(self._jump)
        page.filterRequested.connect(self._filter)
        page.bookmarksRequested.connect(self.tab.document.toggle_bookmarks)
        self.pages[key] = page
        self.tabs.addTab(page, page.title)

    def show_page(self, key: str) -> None:
        page = self.pages.get(key)
        if page is not None:
            page.refresh_scope()
            self.tabs.setCurrentWidget(page)
        self.show()
        self.raise_()
        self.activateWindow()

    def showEvent(self, event: QShowEvent) -> None:
        """Shown again: the filter, line count and open logs may have changed since the scopes were listed."""
        super().showEvent(event)
        for page in self.pages.values():
            page.refresh_scope()

    def shutdown(self) -> None:
        """Cancel every page's running analysis (the tab is closing)."""
        for page in self.pages.values():
            page.cancel()

    def _bring_tab_forward(self) -> None:
        if self._show_tab is not None:
            self._show_tab(self.tab)

    def _jump(self, line: int) -> None:
        self._bring_tab_forward()
        self.tab.main_view.go_to_row(line)
        window = self.parentWidget()
        if window is not None:
            window.raise_()

    def _filter(self, pattern: str) -> None:
        """Filter the log by the regex ``pattern``: text first, then the Regex toggle, then one search."""
        self._bring_tab_forward()
        panel = self.tab.filter_panel
        for widget in (panel.edit, panel.regex):  # toggling Regex would re-run the old text as a regex
            widget.blockSignals(True)
        try:
            panel.set_text(pattern)
            panel.regex.setChecked(True)
        finally:
            for widget in (panel.edit, panel.regex):
                widget.blockSignals(False)
        panel.apply()
