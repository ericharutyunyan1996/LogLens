"""Script page of the Analyze window: a small Python console over the lines of the log (read-only, time-limited)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtGui import QFont, QFontDatabase
from PySide6.QtWidgets import QComboBox, QHBoxLayout, QLabel, QPlainTextEdit, QVBoxLayout, QWidget

from ..core.scripting import EXAMPLES, LineView, ScriptResult, check_script, run_script
from ..services.analysis_jobs import AnalysisScope, Analyzer
from .analysis_base import AnalysisPage

if TYPE_CHECKING:
    from .log_tab import LogTab


class ScriptPage(AnalysisPage):
    title = "Script"
    intro = (
        "Python over the log's lines, for questions the other pages do not answer. You get <code>lines</code> (the "
        "log, read-only), <code>parse_time(line)</code>, <code>level_of(line)</code>, "
        "<code>table(rows, headers)</code>, "
        "<code>Counter</code>, and the modules re, json, math, statistics, collections, itertools, datetime. "
        "Scripts cannot touch files, the network or other programs, and stop after 30 seconds. "
        "Only run scripts you understand."
    )

    def __init__(self, tab: LogTab, parent: QWidget | None = None) -> None:
        super().__init__(tab, parent)
        self.run_button.setText("Run script")
        mono = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        self.examples = QComboBox(self)
        self.examples.addItem("Examples…", None)
        for name, code in EXAMPLES:
            self.examples.addItem(name, code)
        self.examples.activated.connect(self._load_example)
        self.code = QPlainTextEdit(EXAMPLES[0][1], self)
        self.code.setFont(QFont(mono))
        self.code.setTabStopDistance(4 * self.code.fontMetrics().horizontalAdvance(" "))
        self.output = QPlainTextEdit(self)
        self.output.setReadOnly(True)
        self.output.setFont(QFont(mono))
        self.output.setPlaceholderText("What the script prints appears here.")
        row = QHBoxLayout()
        row.addWidget(QLabel("Script", self))
        row.addWidget(self.examples)
        row.addStretch(1)
        box = QVBoxLayout()
        box.addLayout(row)
        box.addWidget(self.code, 3)
        box.addWidget(self.output, 2)
        self.body.addLayout(box, 1)

    def _load_example(self) -> None:
        code = self.examples.currentData()
        if isinstance(code, str):
            self.code.setPlainText(code)

    def run(self) -> None:
        problem = check_script(self.code.toPlainText())
        if problem:
            self.status.setText(f"⚠ {problem}")
            self.output.clear()
            return
        self.run_script_now()

    def analyzer(self) -> Analyzer:
        raise NotImplementedError  # the page runs a task (see run_task below), not a per-line analyzer

    def _view(self, scope: AnalysisScope) -> LineView:
        source = self.tab.document.source
        count = scope.count(source.line_count())
        if scope.lines is None:
            return LineView(count, source.get_lines)
        lines = scope.lines
        return LineView(count, lambda start, size: source.get_lines_at(lines[start : start + size]))

    def run_script_now(self) -> None:
        scope: AnalysisScope = self.scope.currentData()
        view, code, title = self._view(scope), self.code.toPlainText(), self.tab.document.title
        self.set_busy(True, f"Running on {scope.description}…")
        self.runner.run_task(lambda cancel, _report: run_script(code, view, title=title, cancel=cancel))

    def show_result(self, result: object) -> None:
        assert isinstance(result, ScriptResult)
        self.output.setPlainText(result.output + ("\n… (output shortened)" if result.truncated else ""))
        if result.error:
            self.status.setText(f"⚠ {result.error}")
        else:
            self.status.setText(f"Done in {result.seconds:.2f} s.")
