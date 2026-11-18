"""Timeline strip above the log: activity per time bin, issues on top, spikes marked.

Click a bar to jump to its first line; drag across bars to filter that time range. Renders a
:class:`~loglens.core.histogram.Histogram` computed by the document; holds no other state.
"""

from __future__ import annotations

from datetime import datetime

from PySide6.QtCore import QPoint, QRectF, Qt, Signal
from PySide6.QtGui import QColor, QContextMenuEvent, QMouseEvent, QPainter, QPaintEvent, QPen
from PySide6.QtWidgets import QMenu, QToolTip, QWidget

from ..core.histogram import Histogram
from ..core.winevent.models import EventRecord
from .theme import is_dark

STRIP_HEIGHT = 58
AXIS_HEIGHT = 14
MAX_TOOLTIP_SERIES = 4
MAX_TOOLTIP_EVENTS = 5
EVENT_COLORS = {1: "#E0204A", 2: "#E5484D", 3: "#F5A524"}  # Windows levels: critical, error, warning


class HistogramView(QWidget):
    lineRequested = Signal(int)
    rangeSelected = Signal(object, object)  # datetime start, datetime end (exclusive)
    eventsRequested = Signal(bool)  # show / hide Windows events on the timeline
    eventsClicked = Signal(list)  # list[EventRecord] of the clicked bin

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("histogram")
        self.setFixedHeight(STRIP_HEIGHT)
        self.setMouseTracking(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._histogram: Histogram | None = None
        self._colors: dict[str, QColor] = {}
        self._current_line = -1
        self._drag_from: int | None = None
        self._drag_to: int | None = None
        self._events: list[EventRecord] = []
        self._events_shown = False
        self.setToolTip("Activity over time — click to jump, drag to filter a time range")

    # ---- data ----------------------------------------------------------------------------------------------------
    def set_histogram(self, histogram: Histogram | None, colors: dict[str, QColor]) -> None:
        self._histogram = histogram
        self._colors = colors
        self.update()

    def set_events(self, events: list[EventRecord]) -> None:
        """Windows errors/warnings to mark on the timeline (empty list hides the markers)."""
        self._events = events
        self._events_shown = bool(events)
        self.update()

    def _events_in(self, index: int) -> list[EventRecord]:
        histogram = self._histogram
        if histogram is None or not self._events:
            return []
        begin, end = histogram.bin_start(index), histogram.bin_start(index + 1)
        return [e for e in self._events if begin <= e.time_created < end]

    def set_current_line(self, line: int) -> None:
        if line != self._current_line:
            self._current_line = line
            self.update()

    # ---- geometry ------------------------------------------------------------------------------------------------
    def _bin_at(self, x: float) -> int | None:
        histogram = self._histogram
        if histogram is None or not histogram.bins or self.width() <= 0:
            return None
        return int(min(max(x / self.width() * histogram.bins, 0), histogram.bins - 1))

    def _bar_rect(self, index: int, value: int, peak: int) -> QRectF:
        histogram = self._histogram
        assert histogram is not None
        width = self.width() / histogram.bins
        usable = self.height() - AXIS_HEIGHT - 2
        height = usable * value / peak if peak else 0
        return QRectF(index * width + 0.5, self.height() - AXIS_HEIGHT - height, max(width - 1, 1), height)

    # ---- painting ------------------------------------------------------------------------------------------------
    def paintEvent(self, event: QPaintEvent) -> None:
        painter = QPainter(self)
        dark = is_dark()
        painter.fillRect(self.rect(), QColor("#0d1117" if dark else "#f6f8fa"))
        histogram = self._histogram
        muted = QColor("#8b949e")
        if histogram is None or not histogram.bins:
            painter.setPen(muted)
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "No timeline — no timestamps found yet")
            return
        peak = int(histogram.counts.max(initial=0))
        base = QColor("#3b82f6")
        base.setAlpha(110 if dark else 90)
        for index, value in enumerate(histogram.counts.tolist()):
            if value:
                painter.fillRect(self._bar_rect(index, value, peak), base)
        for name, values in histogram.series.items():  # issues drawn on top, in their highlight colour
            color = self._colors.get(name)
            if color is None:
                continue
            for index, value in enumerate(values.tolist()):
                if value:
                    painter.fillRect(self._bar_rect(index, value, peak), color)
        self._paint_spikes(painter, histogram)
        self._paint_events(painter, histogram)
        self._paint_selection(painter, histogram)
        self._paint_axis(painter, histogram, muted)

    def _paint_spikes(self, painter: QPainter, histogram: Histogram) -> None:
        width = self.width() / histogram.bins
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor("#E5484D"))
        for index in histogram.spikes():
            x = index * width + width / 2
            painter.drawPolygon([QPoint(int(x - 4), 1), QPoint(int(x + 4), 1), QPoint(int(x), 7)])

    def _paint_events(self, painter: QPainter, histogram: Histogram) -> None:
        if not self._events:
            return
        span = (histogram.bin_start(histogram.bins) - histogram.start).total_seconds() or 1.0
        base = self.height() - AXIS_HEIGHT
        painter.setPen(Qt.PenStyle.NoPen)
        for event in self._events:
            fraction = (event.time_created - histogram.start).total_seconds() / span
            if not 0 <= fraction <= 1:
                continue
            x = int(fraction * self.width())
            painter.setBrush(QColor(EVENT_COLORS.get(event.level, "#8b949e")))
            painter.drawPolygon([QPoint(x - 3, base), QPoint(x + 3, base), QPoint(x, base - 6)])

    def contextMenuEvent(self, event: QContextMenuEvent) -> None:
        menu = QMenu(self)
        toggle = menu.addAction("Show Windows errors and warnings on the timeline")
        toggle.setCheckable(True)
        toggle.setChecked(self._events_shown)
        toggle.toggled.connect(self.eventsRequested)
        menu.exec(event.globalPos())

    def _paint_selection(self, painter: QPainter, histogram: Histogram) -> None:
        width = self.width() / histogram.bins
        if self._current_line >= 0:
            x = (histogram.bin_of_line(self._current_line) + 0.5) * width
            painter.setPen(QPen(QColor("#F5A524"), 2))
            painter.drawLine(int(x), 0, int(x), self.height() - AXIS_HEIGHT)
        if self._drag_from is not None and self._drag_to is not None:
            low, high = sorted((self._drag_from, self._drag_to))
            shade = QColor("#3b82f6")
            shade.setAlpha(60)
            painter.fillRect(QRectF(low * width, 0, (high - low + 1) * width, self.height()), shade)

    def _paint_axis(self, painter: QPainter, histogram: Histogram, color: QColor) -> None:
        painter.setPen(color)
        metrics = painter.fontMetrics()
        y = self.height() - 2
        first, last = histogram.bin_start(0), histogram.bin_start(histogram.bins)
        fmt = "%H:%M" if (last - first).days < 1 else "%m-%d %H:%M"
        labels = max(int(self.width() / 120), 2)
        for k in range(labels + 1):
            index = round(k * histogram.bins / labels)
            text = histogram.bin_start(index).astimezone().strftime(fmt)
            x = int(index * self.width() / histogram.bins)
            x = min(
                max(x - metrics.horizontalAdvance(text) // 2, 2), self.width() - metrics.horizontalAdvance(text) - 2
            )
            painter.drawText(x, y, text)

    # ---- interaction ---------------------------------------------------------------------------------------------
    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_from = self._drag_to = self._bin_at(event.position().x())
            self.update()

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        index = self._bin_at(event.position().x())
        if self._drag_from is not None:
            self._drag_to = index
            self.update()
        if index is not None:
            QToolTip.showText(event.globalPosition().toPoint(), self._describe(index), self)

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        histogram, start, end = self._histogram, self._drag_from, self._bin_at(event.position().x())
        self._drag_from = self._drag_to = None
        self.update()
        if histogram is None or start is None or end is None:
            return
        if start == end:
            self.lineRequested.emit(int(histogram.line_edges[start]))
            events = self._events_in(start)
            if events:
                self.eventsClicked.emit(events)
        else:
            low, high = sorted((start, end))
            self.rangeSelected.emit(histogram.bin_start(low), histogram.bin_start(high + 1))

    def _describe(self, index: int) -> str:
        histogram = self._histogram
        if histogram is None:
            return ""
        begin: datetime = histogram.bin_start(index).astimezone()
        end: datetime = histogram.bin_start(index + 1).astimezone()
        lines = [f"<b>{begin:%Y-%m-%d %H:%M:%S} – {end:%H:%M:%S}</b>", f"{int(histogram.counts[index]):,} entries"]
        for name, values in list(histogram.series.items())[:MAX_TOOLTIP_SERIES]:
            if int(values[index]):
                lines.append(f"{name}: {int(values[index]):,}")
        if index in histogram.spikes():
            lines.append("<span style='color:#E5484D'>▲ unusually busy</span>")
        events = self._events_in(index)
        lines.extend(
            f"⚑ {event.time_created.astimezone():%H:%M:%S} {event.provider} {event.event_id}"
            for event in events[:MAX_TOOLTIP_EVENTS]
        )
        if len(events) > MAX_TOOLTIP_EVENTS:
            lines.append(f"⚑ … {len(events) - MAX_TOOLTIP_EVENTS} more Windows events")
        lines.append("<i>click: jump · drag: filter this time range</i>")
        return "<br>".join(lines)
