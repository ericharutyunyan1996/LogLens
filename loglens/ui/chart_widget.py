"""A small chart (bars or a line) over time, drawn with QPainter: hover for values, grab() for an image."""

from __future__ import annotations

import math

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QMouseEvent, QPainter, QPaintEvent, QPen, QPolygonF
from PySide6.QtWidgets import QToolTip, QWidget

from ..core.charts import ChartData

LEFT, RIGHT, TOP, BOTTOM = 64, 16, 28, 34
BAR_AGGREGATES = ("count", "sum")


def nice_ticks(high: float, count: int = 5) -> list[float]:
    """Round axis values from 0 up to just past ``high``."""
    if high <= 0:
        return [0.0, 1.0]
    raw = high / count
    magnitude = 10 ** math.floor(math.log10(raw))
    step = next((m * magnitude for m in (1, 2, 2.5, 5, 10) if m * magnitude >= raw), 10 * magnitude)
    ticks, value = [], 0.0
    while value < high + step:
        ticks.append(round(value, 10))
        value += step
        if len(ticks) > 12:
            break
    return ticks


def short(value: float) -> str:
    absolute = abs(value)
    if absolute >= 1_000_000:
        return f"{value / 1_000_000:g}M"
    if absolute >= 10_000:
        return f"{value / 1_000:g}k"
    return f"{value:,.0f}" if float(value).is_integer() else f"{value:,.2f}"


class ChartWidget(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.data: ChartData | None = None
        self.setMinimumHeight(240)
        self.setMouseTracking(True)

    def set_data(self, data: ChartData | None) -> None:
        self.data = data
        self.update()

    def _plot(self) -> QRectF:
        return QRectF(LEFT, TOP, max(self.width() - LEFT - RIGHT, 10), max(self.height() - TOP - BOTTOM, 10))

    def _geometry(self) -> tuple[QRectF, float, list[float]] | None:
        data = self.data
        if data is None or data.is_empty:
            return None
        high = max(v for v in data.values if v is not None)
        ticks = nice_ticks(high)
        return self._plot(), ticks[-1] or 1.0, ticks

    def paintEvent(self, _event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        palette = self.palette()
        painter.fillRect(self.rect(), palette.base())
        text, grid = palette.text().color(), QColor(palette.text().color())
        grid.setAlpha(40)
        accent = palette.highlight().color()
        geometry = self._geometry()
        if geometry is None:
            painter.setPen(text)
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "Draw a chart to see it here.")
            return
        plot, top, ticks = geometry
        data = self.data
        assert data is not None
        painter.setPen(text)
        painter.drawText(QRectF(LEFT, 4, plot.width(), TOP - 6), Qt.AlignmentFlag.AlignVCenter, data.spec.title)
        for tick in ticks:  # horizontal grid and value labels
            y = plot.bottom() - plot.height() * tick / top
            painter.setPen(QPen(grid, 1))
            painter.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y))
            painter.setPen(text)
            painter.drawText(
                QRectF(0, y - 9, LEFT - 6, 18), Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter, short(tick)
            )
        count = len(data.values)
        slot = plot.width() / max(count, 1)
        label_every = max(1, int(70 // max(slot, 1)) + 1)
        for i, start in enumerate(data.starts):  # time labels
            if i % label_every == 0:
                painter.setPen(text)
                fmt = "%H:%M:%S" if data.step.total_seconds() < 60 else "%H:%M"
                if data.step.total_seconds() >= 86400:
                    fmt = "%m-%d"
                painter.drawText(
                    QRectF(plot.left() + i * slot - 30 + slot / 2, plot.bottom() + 4, 60, 18),
                    Qt.AlignmentFlag.AlignCenter,
                    start.strftime(fmt),
                )
        painter.setPen(Qt.PenStyle.NoPen)
        if data.spec.aggregate in BAR_AGGREGATES:
            painter.setBrush(accent)
            for i, value in enumerate(data.values):
                if value:
                    height = plot.height() * value / top
                    painter.drawRect(
                        QRectF(plot.left() + i * slot + slot * 0.1, plot.bottom() - height, slot * 0.8, height)
                    )
        else:
            points = [
                QPointF(plot.left() + (i + 0.5) * slot, plot.bottom() - plot.height() * value / top)
                for i, value in enumerate(data.values)
                if value is not None
            ]
            painter.setPen(QPen(accent, 2))
            painter.drawPolyline(QPolygonF(points))
            painter.setBrush(accent)
            for point in points:
                painter.drawEllipse(point, 3, 3)

    def _index_at(self, x: float) -> int | None:
        data = self.data
        if data is None or not data.values:
            return None
        plot = self._plot()
        if not plot.left() <= x <= plot.right():
            return None
        return min(int((x - plot.left()) / (plot.width() / len(data.values))), len(data.values) - 1)

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        index = self._index_at(event.position().x())
        data = self.data
        if index is None or data is None:
            QToolTip.hideText()
            return
        value = data.values[index]
        shown = "no data" if value is None else f"{value:,.2f}".rstrip("0").rstrip(".")
        QToolTip.showText(event.globalPosition().toPoint(), f"{data.starts[index]:%Y-%m-%d %H:%M:%S}\n{shown}", self)
