"""Trace an id across all open logs: a waterfall of lanes (one per log) and the events in time order."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import TYPE_CHECKING

from PySide6.QtCore import QPointF, QRectF, Qt, Signal
from PySide6.QtGui import QColor, QMouseEvent, QPainter, QPaintEvent, QPen
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QToolTip,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..core.search import SearchQuery
from ..core.trace import Trace, build_trace, render_markdown, trace_ids
from ..services.multi_jobs import LogHits, MultiSearch

if TYPE_CHECKING:
    from .log_tab import LogTab

LABEL_WIDTH, ROW, TOP = 150, 34, 26
ERROR_COLOR = QColor("#D9534F")


class WaterfallWidget(QWidget):
    """Lanes on one time axis: a bar from a log's first to last event, a tick for every event (red for errors)."""

    eventClicked = Signal(int, int)  # lane, line

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.trace: Trace | None = None
        self.setMouseTracking(True)
        self.setMinimumHeight(120)

    def set_trace(self, trace: Trace | None) -> None:
        self.trace = trace
        rows = len(trace.lanes) if trace else 0
        self.setFixedHeight(max(120, TOP + ROW * rows + 24))
        self.update()

    def _x(self, moment: datetime, trace: Trace) -> float:
        assert trace.start is not None and trace.end is not None
        span = max((trace.end - trace.start).total_seconds(), 0.001)
        width = max(self.width() - LABEL_WIDTH - 20, 50)
        return LABEL_WIDTH + width * (moment - trace.start).total_seconds() / span

    def paintEvent(self, _event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        palette = self.palette()
        painter.fillRect(self.rect(), palette.base())
        text = palette.text().color()
        painter.setPen(text)
        trace = self.trace
        if trace is None or not trace.lanes:
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "Enter an id and press Trace.")
            return
        accent = palette.highlight().color()
        for index, lane in enumerate(trace.lanes):
            y = TOP + index * ROW
            painter.setPen(text)
            painter.drawText(
                QRectF(4, y, LABEL_WIDTH - 8, ROW),
                Qt.AlignmentFlag.AlignVCenter,
                painter.fontMetrics().elidedText(lane.label, Qt.TextElideMode.ElideMiddle, LABEL_WIDTH - 8),
            )
            if trace.start is None or lane.start is None or lane.end is None:
                continue
            left, right = self._x(lane.start, trace), self._x(lane.end, trace)
            bar = QColor(accent)
            bar.setAlpha(110)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(bar)
            painter.drawRoundedRect(QRectF(left, y + 8, max(right - left, 3), ROW - 16), 3, 3)
            for event in lane.events:
                if event.time:
                    painter.setPen(QPen(ERROR_COLOR if event.is_error else text, 2 if event.is_error else 1))
                    x = self._x(event.time, trace)
                    painter.drawLine(QPointF(x, y + 5), QPointF(x, y + ROW - 5))
        if trace.start and trace.end:
            painter.setPen(text)
            painter.drawText(QRectF(LABEL_WIDTH, 4, 200, 18), f"{trace.start:%H:%M:%S.%f}"[:-3])
            painter.drawText(
                QRectF(self.width() - 220, 4, 210, 18), Qt.AlignmentFlag.AlignRight, f"+{trace.duration_ms:,.0f} ms"
            )

    def _hit(self, pos: QPointF) -> tuple[int, int, str] | None:
        trace = self.trace
        if trace is None or trace.start is None:
            return None
        lane_index = int((pos.y() - TOP) // ROW)
        if not 0 <= lane_index < len(trace.lanes):
            return None
        best: tuple[float, int, str] | None = None
        for event in trace.lanes[lane_index].events:
            if event.time:
                distance = abs(self._x(event.time, trace) - pos.x())
                if distance <= 6 and (best is None or distance < best[0]):
                    best = (distance, event.line, event.text)
        return (lane_index, best[1], best[2]) if best else None

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        hit = self._hit(event.position())
        if hit:
            QToolTip.showText(event.globalPosition().toPoint(), hit[2][:300], self)
        else:
            QToolTip.hideText()

    def mousePressEvent(self, event: QMouseEvent) -> None:
        hit = self._hit(event.position())
        if hit:
            self.eventClicked.emit(hit[0], hit[1])


class TraceDialog(QDialog):
    def __init__(
        self,
        tabs: Callable[[], list[LogTab]],
        show: Callable[[LogTab, int], None],
        initial: str = "",
        candidates: list[str] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Trace an id across logs")
        self.setWindowFlag(Qt.WindowType.WindowMaximizeButtonHint, True)
        self.resize(1040, 640)
        self._tabs, self._show = tabs, show
        self._by_label: dict[str, LogTab] = {}
        self._hits: list[tuple[str, object, int, list[tuple[int, str]]]] = []
        self._pending = 0
        self.trace: Trace | None = None
        self.search = MultiSearch(self)
        self.search.found.connect(self._found)
        self.search.done.connect(self._done)
        intro = QLabel(
            "Follow one trace, correlation or request id through every open log: each log is a lane, each line with "
            "the id a tick (red = error). Click a tick, or double-click a row below, to jump to the line.",
            self,
        )
        intro.setWordWrap(True)
        intro.setObjectName("dialogNote")
        self.id_box = QComboBox(self)
        self.id_box.setEditable(True)
        self.id_box.addItems(candidates or [])
        self.id_box.setCurrentText(initial)
        edit = self.id_box.lineEdit()
        assert edit is not None
        edit.returnPressed.connect(self.run)
        go = QPushButton("Trace", self)
        go.setObjectName("primary")
        go.clicked.connect(self.run)
        copy = QPushButton("Copy as Markdown", self)
        copy.clicked.connect(self._copy)
        row = QHBoxLayout()
        row.addWidget(QLabel("Id:", self))
        row.addWidget(self.id_box, 1)
        row.addWidget(go)
        row.addWidget(copy)
        self.status = QLabel(self)
        self.status.setObjectName("aiStatus")
        self.status.setWordWrap(True)
        self.waterfall = WaterfallWidget(self)
        self.waterfall.eventClicked.connect(self._jump_lane)
        self.events = QTreeWidget(self)
        self.events.setHeaderLabels(["Time", "Log", "Line", "Text"])
        self.events.setRootIsDecorated(False)
        self.events.header().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.events.header().setStretchLastSection(True)
        self.events.itemDoubleClicked.connect(self._jump_item)
        layout = QVBoxLayout(self)
        layout.addWidget(intro)
        layout.addLayout(row)
        layout.addWidget(self.status)
        layout.addWidget(self.waterfall)
        layout.addWidget(self.events, 1)

    # ---- running ---------------------------------------------------------------------------------------------------
    def run(self) -> None:
        trace_id = self.id_box.currentText().strip()
        if len(trace_id) < 4:
            self.status.setText("Enter an id (at least 4 characters).")
            return
        logs = []
        self._by_label.clear()
        for tab in self._tabs():
            label = tab.document.title
            while label in self._by_label:
                label += "'"
            self._by_label[label] = tab
            logs.append((label, tab, tab.document.source))
        if not logs:
            self.status.setText("Open the logs you want to search first.")
            return
        self._hits, self._pending = [], len(logs)
        self.status.setText(f"Searching {len(logs)} logs…")
        self.search.search(logs, SearchQuery(trace_id, case_sensitive=True))

    def _found(self, hits: object) -> None:
        assert isinstance(hits, LogHits)
        if not hits.error and hits.lines:
            self._hits.append((hits.label, hits.key, hits.total, hits.lines))

    def _done(self, _searched: int) -> None:
        trace = build_trace(self.id_box.currentText().strip(), self._hits)
        self.set_trace(trace)

    def set_trace(self, trace: Trace) -> None:
        self.trace = trace
        self.waterfall.set_trace(trace)
        self.events.clear()
        for event in trace.timeline():
            lane = trace.lanes[event.lane]
            item = QTreeWidgetItem(
                [f"{event.time:%H:%M:%S.%f}"[:-3] if event.time else "—", lane.label, str(event.line + 1), event.text]
            )
            item.setData(0, Qt.ItemDataRole.UserRole, (event.lane, event.line))
            if event.is_error:
                for column in range(4):
                    item.setForeground(column, ERROR_COLOR)
            self.events.addTopLevelItem(item)
        if not trace.lanes:
            self.status.setText("The id was not found in any open log.")
            return
        first = trace.first_error()
        where = f" First error: {trace.lanes[first.lane].label}, line {first.line + 1}." if first else ""
        self.status.setText(
            f"<b>{trace.event_count:,} events</b> in {len(trace.lanes)} logs over {trace.duration_ms:,.0f} ms.{where}"
        )

    # ---- navigation ------------------------------------------------------------------------------------------------
    def _jump_lane(self, lane: int, line: int) -> None:
        if self.trace and 0 <= lane < len(self.trace.lanes):
            tab = self.trace.lanes[lane].key
            if tab is not None:
                self._show(tab, line)  # type: ignore[arg-type]

    def _jump_item(self, item: QTreeWidgetItem, _column: int) -> None:
        lane, line = item.data(0, Qt.ItemDataRole.UserRole)
        self._jump_lane(lane, line)

    def _copy(self) -> None:
        if self.trace:
            QApplication.clipboard().setText(render_markdown(self.trace))


def candidate_ids(lines: list[str]) -> list[str]:
    found: list[str] = []
    for line in lines:
        for value in trace_ids(line):
            if value not in found:
                found.append(value)
    return found
