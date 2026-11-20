"""Charts page of the Analyze window: any field, captured number or line count over time, saved and exported."""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import TYPE_CHECKING

from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QWidget,
)

from ..core.charts import AGGREGATES, ChartData, ChartError, ChartSpec, chart, check
from ..paths import app_data_dir
from ..services.analysis_jobs import Analyzer
from .analysis_base import AnalysisPage
from .chart_widget import ChartWidget

if TYPE_CHECKING:
    from .log_tab import LogTab

SOURCES = (
    ("lines", "Number of lines"),
    ("regex", "A number in the text (pattern)"),
    ("field", "A field of the log's format"),
)
NUMBER_AFTER_WORD = r"(?:took|duration|elapsed)[=: ]+(\d+(?:\.\d+)?)"
EXAMPLES = (
    ChartSpec("Errors per bin", "lines", pattern=r"\b(?:ERROR|FATAL)\b"),
    ChartSpec("Response time (average)", "regex", pattern=NUMBER_AFTER_WORD, aggregate="avg"),
    ChartSpec("Response time (95th percentile)", "regex", pattern=NUMBER_AFTER_WORD, aggregate="p95"),
)


def load_charts() -> list[ChartSpec]:
    try:
        data = json.loads((app_data_dir() / "charts.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    found = (ChartSpec.from_dict(item) for item in data) if isinstance(data, list) else ()
    return [spec for spec in found if spec is not None]


def save_charts(specs: list[ChartSpec]) -> None:
    (app_data_dir() / "charts.json").write_text(json.dumps([s.to_dict() for s in specs], indent=2), encoding="utf-8")


class ChartsPage(AnalysisPage):
    title = "Charts"
    intro = (
        "Chart anything over time: how many lines (or errors) per minute, or the average / 95th percentile of a number "
        "such as a response time, taken from the text with a pattern or from a field of the log's format. "
        "Hover for values; save the chart definition or the picture."
    )

    def __init__(self, tab: LogTab, parent: QWidget | None = None) -> None:
        super().__init__(tab, parent)
        self.run_button.setText("Draw")
        self.source = QComboBox(self)
        for key, label in SOURCES:
            self.source.addItem(label, key)
        self.field_box = QComboBox(self)
        self.pattern = QLineEdit(self)
        self.aggregate = QComboBox(self)
        for key, label in AGGREGATES.items():
            self.aggregate.addItem(label, key)
        self.library = QComboBox(self)
        self.library.activated.connect(self._load_selected)
        save = QPushButton("Save definition", self)
        save.clicked.connect(self.save_definition)
        export = QPushButton("Save picture…", self)
        export.clicked.connect(self.save_picture)
        self.chart_view = ChartWidget(self)
        self.source.currentIndexChanged.connect(self._source_changed)
        form = QFormLayout()
        form.addRow("Chart", self.source)
        form.addRow("Field", self.field_box)
        form.addRow("Pattern", self.pattern)
        form.addRow("Combine as", self.aggregate)
        form.addRow("Saved charts", self.library)
        row = QHBoxLayout()
        row.addWidget(save)
        row.addWidget(export)
        row.addStretch(1)
        self.body.addLayout(form)
        self.body.addWidget(self.chart_view, 1)
        self.body.addLayout(row)
        self._fill_fields()
        self._fill_library()
        self._source_changed()

    # ---- the definition --------------------------------------------------------------------------------------------
    def _fill_fields(self) -> None:
        fmt = self.tab.document.log_format
        self.field_box.clear()
        if fmt is not None:
            for name in fmt.fields:
                if name != fmt.message_field:
                    self.field_box.addItem(name, name)

    def _fill_library(self) -> None:
        self.library.clear()
        self.library.addItem("Choose…", None)
        for spec in [*EXAMPLES, *load_charts()]:
            self.library.addItem(spec.title, spec)

    def _source_changed(self) -> None:
        source = self.source.currentData()
        self.field_box.setEnabled(source == "field")
        self.pattern.setEnabled(source in ("lines", "regex"))
        self.pattern.setPlaceholderText(
            "only count lines matching (optional)"
            if source == "lines"
            else "took (\\d+) ms   (the number is the first group)"
        )

    def spec(self) -> ChartSpec:
        return ChartSpec(
            title=self.library.currentText() if self.library.currentData() else "Chart",
            source=str(self.source.currentData()),
            name=str(self.field_box.currentData() or ""),
            pattern=self.pattern.text().strip(),
            aggregate=str(self.aggregate.currentData()),
        )

    def set_spec(self, spec: ChartSpec) -> None:
        self.source.setCurrentIndex(max(0, self.source.findData(spec.source)))
        self.field_box.setCurrentIndex(max(0, self.field_box.findData(spec.name)))
        self.pattern.setText(spec.pattern)
        self.aggregate.setCurrentIndex(max(0, self.aggregate.findData(spec.aggregate)))

    def _load_selected(self) -> None:
        spec = self.library.currentData()
        if isinstance(spec, ChartSpec):
            self.set_spec(spec)

    def save_definition(self) -> None:
        spec = self.spec()
        problem = check(spec)
        if problem:
            self.status.setText(problem)
            return
        title = self.pattern.text().strip()[:30] or str(self.source.currentText())
        spec = ChartSpec(
            f"{title} ({AGGREGATES[spec.aggregate]})", spec.source, spec.name, spec.pattern, spec.aggregate
        )
        save_charts([s for s in load_charts() if s.title != spec.title] + [spec])
        self._fill_library()
        self.status.setText(f"Saved “{spec.title}”.")

    # ---- running ---------------------------------------------------------------------------------------------------
    def run(self) -> None:
        problem = check(self.spec())
        if problem:
            self.status.setText(problem)
            return
        super().run()

    def analyzer(self) -> Analyzer:
        spec = self.spec()
        fmt = self.tab.document.log_format
        context = self.tab.document.format_context()

        def analyze(lines: Iterable[tuple[int, str]]) -> object:
            try:
                return chart(lines, spec, fmt=fmt, context=context)
            except ChartError as exc:
                return str(exc)

        return analyze

    def show_result(self, result: object) -> None:
        if isinstance(result, str):
            self.status.setText(result)
            return
        assert isinstance(result, ChartData)
        self.chart_view.set_data(result)
        if result.is_empty:
            self.status.setText(
                f"Nothing to chart: {result.skipped:,} lines had no time or no matching value."
                if result.skipped
                else "Nothing to chart."
            )
        else:
            self.status.setText(f"<b>{result.samples:,} values</b> in {len(result.values)} bars of {result.step}.")

    def save_picture(self) -> None:
        if self.chart_view.data is None:
            self.status.setText("Draw a chart first.")
            return
        target, _ = QFileDialog.getSaveFileName(self, "Save chart", "chart.png", "PNG image (*.png)")
        if target:
            self.chart_view.grab().save(target, "PNG")
