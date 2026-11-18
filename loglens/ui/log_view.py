"""LogView — a virtual, line-based text view for huge files.

Only visible lines are fetched and painted, and the vertical scrollbar works in *line* units, so a 100M-line file
scrolls as smoothly as a 100-line one (QTableView/QPlainTextEdit would allocate per row or overflow pixel ranges).
Word wrap is supported the same way: the top line is the scroll unit and wrapped lines simply take more rows.
"""

from __future__ import annotations

import itertools
import re
from collections.abc import Callable
from dataclasses import dataclass

import numpy as np
from PySide6.QtCore import QPointF, QRect, Qt, QTimer, Signal
from PySide6.QtGui import (
    QColor,
    QContextMenuEvent,
    QFont,
    QFontDatabase,
    QFontMetricsF,
    QGuiApplication,
    QKeyEvent,
    QKeySequence,
    QMouseEvent,
    QPainter,
    QPaintEvent,
    QPalette,
    QPen,
    QResizeEvent,
)
from PySide6.QtWidgets import QAbstractScrollArea, QMenu, QScrollBar, QStyle, QStyleOptionSlider, QWidget

from ..core.ansi import parse_ansi
from ..core.highlight import HighlightRule, LineStyle, style_line
from .models import LineModel

SEARCH_BG = QColor(255, 196, 0, 215)
SEARCH_FG = QColor(20, 20, 20)
BOOKMARK_COLOR = QColor(56, 132, 255)
MAX_COPY_LINES = 200_000
WORD_RE = re.compile(r"[\w\-.:@/\\]+")
LINE_SPACING = 3  # extra pixels between lines


Span = tuple[int, int, str | None, str | None]  # (start, end, fg, bg) in line characters
PARTIAL_SELECTION_ALPHA = 110  # translucent accent behind characters selected within a line
SEARCH_SPAN = "search"  # marker colour value for search-match spans


@dataclass(frozen=True, slots=True)
class _Colors:
    """Colours for one paint pass, derived from the widget palette (works for light and dark themes)."""

    base: QColor
    text: QColor
    highlight: QColor
    selection: QColor
    current: QColor
    gutter_bg: QColor
    gutter_fg: QColor
    divider: QColor

    @classmethod
    def from_palette(cls, palette: QPalette) -> _Colors:
        base = palette.color(QPalette.ColorRole.Base)
        text = palette.color(QPalette.ColorRole.Text)
        highlight = palette.color(QPalette.ColorRole.Highlight)
        dark = base.lightness() < 128

        def with_alpha(color: QColor, alpha: int) -> QColor:
            out = QColor(color)
            out.setAlpha(alpha)
            return out

        return cls(
            base=base,
            text=text,
            highlight=highlight,
            selection=with_alpha(highlight, 90 if dark else 70),
            current=with_alpha(highlight, 70 if dark else 45),
            gutter_bg=base.lighter(118) if dark else base.darker(103),
            gutter_fg=with_alpha(text, 110),
            divider=with_alpha(text, 28),
        )


@dataclass(frozen=True, slots=True)
class _Layout:
    """Geometry for one paint pass."""

    gutter_width: int
    text_x0: int
    width: int
    height: int
    start_char: int  # first visible character (horizontal scroll)
    x_offset: float  # x of start_char
    visible_chars: int
    wrap_chars: int


@dataclass(frozen=True, slots=True)
class _Segment:
    """One visual row of a line: the visible text, its offset in the line and its position."""

    text: str
    start: int
    x: float
    y: int


def _run_colors(spans: list[Span], start: int, end: int, line_fg: QColor) -> tuple[QColor, QColor | None]:
    """Colours of the text run [start, end): later spans override earlier ones."""
    fg, bg = line_fg, None
    for span_start, span_end, span_fg, span_bg in spans:
        if span_start <= start and end <= span_end:
            if span_fg == SEARCH_SPAN:
                fg, bg = SEARCH_FG, SEARCH_BG
                continue
            if span_fg:
                fg = QColor(span_fg)
            if span_bg:
                bg = QColor(span_bg)
    return fg, bg


def monospace_font(family: str = "", size: int = 10) -> QFont:
    families = set(QFontDatabase.families())
    for name in [family, "Cascadia Mono", "Consolas", "Lucida Console"]:
        if name and name in families:
            font = QFont(name, size)
            break
    else:
        font = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        font.setPointSize(size)
    font.setStyleHint(QFont.StyleHint.Monospace)
    font.setFixedPitch(True)
    return font


class MarkScrollBar(QScrollBar):
    """Vertical scrollbar that shows coloured marks (errors, warnings, search hits, bookmarks)."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(Qt.Orientation.Vertical, parent)
        self._marks: list[tuple[np.ndarray, QColor]] = []
        self._total = 0

    def set_marks(self, marks: list[tuple[np.ndarray, QColor]], total_rows: int) -> None:
        self._marks = marks
        self._total = total_rows
        self.update()

    def paintEvent(self, event: QPaintEvent) -> None:
        super().paintEvent(event)
        if self._total <= 0 or not any(len(r) for r, _ in self._marks):
            return
        opt = QStyleOptionSlider()
        self.initStyleOption(opt)
        groove = self.style().subControlRect(
            QStyle.ComplexControl.CC_ScrollBar, opt, QStyle.SubControl.SC_ScrollBarGroove, self
        )
        if groove.height() <= 4:
            groove = self.rect()
        h = groove.height()
        x = groove.left() + groove.width() // 2
        w = max(groove.right() - x, 3)
        p = QPainter(self)
        scale = (h - 2) / max(self._total - 1, 1)
        for rows, color in self._marks:
            if not len(rows):
                continue
            ys = np.unique((rows.astype(np.float64) * scale).astype(np.int32))
            for y in ys.tolist():
                p.fillRect(x, groove.top() + y, w, 2, color)
        p.end()


class LogView(QAbstractScrollArea):
    currentRowChanged = Signal(int)  # row index
    rowActivated = Signal(int)  # double-click / Enter
    wordDoubleClicked = Signal(str)
    contextActionsRequested = Signal(QMenu, int)  # menu, row → owner can add actions

    def __init__(self, parent: QWidget | None = None, show_word_click: bool = True) -> None:
        super().__init__(parent)
        self._model: LineModel | None = None
        self._rules: list[HighlightRule] = []
        self._search: re.Pattern[str] | None = None
        self._bookmarks: Callable[[int], bool] = lambda line: False
        self._tab_width = 4
        self._current = -1
        self._anchor = -1  # selection anchor row
        self._follow = False
        self._wrap = False
        self._show_word_click = show_word_click
        self._cache_first = 0
        self._cache: list[str] = []
        self._dragging = False
        self._press: tuple[int, int] | None = None  # (row, column) where the left button went down
        self._char_selection: tuple[int, int, int] | None = None  # (row, start column, end column) within one line
        self._row_map: list[tuple[int, int, int]] = []  # (y_top, row, char_offset) of each painted visual row
        self._rows_painted = 1

        self.setFrameShape(QAbstractScrollArea.Shape.NoFrame)
        self.setVerticalScrollBar(MarkScrollBar(self))
        self.verticalScrollBar().setSingleStep(1)
        self.verticalScrollBar().valueChanged.connect(self.viewport().update)
        self.horizontalScrollBar().valueChanged.connect(self.viewport().update)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.viewport().setCursor(Qt.CursorShape.IBeamCursor)
        self._autoscroll = QTimer(self)
        self._autoscroll.setInterval(40)
        self._autoscroll.timeout.connect(self._on_autoscroll)
        self._autoscroll_dir = 0
        self.set_font(monospace_font())

    # ---- configuration -------------------------------------------------------------------------------------------
    def set_font(self, font: QFont) -> None:
        self._font = font
        fm = QFontMetricsF(font)
        self._lh = max(int(fm.height()) + LINE_SPACING, 1)
        self._cw = fm.horizontalAdvance("M")
        self._baseline = (self._lh - fm.height()) / 2 + fm.ascent()
        self.horizontalScrollBar().setSingleStep(int(self._cw * 4))
        self._update_scrollbars()
        self.viewport().update()

    def set_model(self, model: LineModel | None) -> None:
        self._model = model
        self._cache = []
        self._current = self._anchor = -1
        self.verticalScrollBar().setValue(0)
        self.model_changed()

    def model(self) -> LineModel | None:
        return self._model

    def set_rules(self, rules: list[HighlightRule]) -> None:
        self._rules = rules
        self.viewport().update()

    def set_search_pattern(self, pattern: re.Pattern[str] | None) -> None:
        self._search = pattern
        self.viewport().update()

    def set_bookmark_check(self, check: Callable[[int], bool]) -> None:
        self._bookmarks = check

    def set_tab_width(self, width: int) -> None:
        self._tab_width = max(1, width)
        self._cache = []
        self.viewport().update()

    def set_wrap(self, wrap: bool) -> None:
        self._wrap = wrap
        self.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff if wrap else Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )
        self.horizontalScrollBar().setValue(0)
        self._update_scrollbars()
        self.viewport().update()

    def set_follow(self, follow: bool) -> None:
        self._follow = follow
        if follow:
            self.scroll_to_end()

    def set_marks(self, marks: list[tuple[np.ndarray, QColor]]) -> None:
        total = self._model.row_count() if self._model else 0
        self.verticalScrollBar().set_marks(marks, total)  # type: ignore[attr-defined]

    def model_changed(self) -> None:
        """Row count / content changed (indexing progress, tail, new search results)."""
        self._cache = []
        self._update_scrollbars()
        if self._follow:
            self.scroll_to_end()
        self.viewport().update()

    # ---- geometry helpers ----------------------------------------------------------------------------------------
    def _rows(self) -> int:
        return self._model.row_count() if self._model else 0

    def _full_visible_rows(self) -> int:
        if self._wrap:
            return max(self._rows_painted - 1, 1)
        return max(self.viewport().height() // self._lh, 1)

    def _gutter_width(self) -> int:
        digits = len(str(max(self._model.max_file_line(), 1))) if self._model else 1
        return int(18 + (digits + 1) * self._cw)

    def _text_x0(self) -> int:
        return self._gutter_width() + 8

    def _wrap_chars(self) -> int:
        return max(int((self.viewport().width() - self._text_x0() - 6) / self._cw), 10)

    def _update_scrollbars(self) -> None:
        rows = self._rows()
        vbar = self.verticalScrollBar()
        if self._wrap:
            vbar.setRange(0, max(rows - 1, 0))
        else:
            vbar.setRange(0, max(rows - self._full_visible_rows(), 0))
        vbar.setPageStep(self._full_visible_rows())
        hbar = self.horizontalScrollBar()
        if self._wrap:
            hbar.setRange(0, 0)
            return
        max_chars = self._model.max_chars() if self._model else 0
        content_w = self._text_x0() + int(max_chars * self._cw) + 20
        hbar.setRange(0, max(content_w - self.viewport().width(), 0))
        hbar.setPageStep(self.viewport().width())

    def resizeEvent(self, event: QResizeEvent) -> None:
        super().resizeEvent(event)
        self._update_scrollbars()

    def top_row(self) -> int:
        return self.verticalScrollBar().value()

    def current_row(self) -> int:
        return self._current

    def selected_rows(self) -> tuple[int, int]:
        if self._current < 0:
            return -1, -1
        a = self._anchor if self._anchor >= 0 else self._current
        return min(a, self._current), max(a, self._current)

    def _hit(self, y: float) -> tuple[int, int]:
        """(row, char offset of the visual row) under viewport y."""
        if not self._row_map:
            return self.top_row() + int(y // self._lh), 0
        y_top, row, offset = self._row_map[0]
        if y < y_top:
            return row - 1, 0
        for entry in self._row_map:
            if entry[0] > y:
                break
            y_top, row, offset = entry
        if y >= y_top + self._lh:  # below the last painted row (past end of file)
            return row + int((y - y_top) // self._lh), 0
        return row, offset

    def row_at(self, y: float) -> int:
        """Row under viewport coordinate ``y`` (clamped to existing rows)."""
        return min(max(self._hit(y)[0], 0), max(self._rows() - 1, 0))

    def painted_rows(self) -> list[tuple[int, int, int]]:
        """``(y_top, row, char_offset)`` of every visual row in the last paint (several per line when wrapping)."""
        return list(self._row_map)

    # ---- navigation ----------------------------------------------------------------------------------------------
    def scroll_to_end(self) -> None:
        vbar = self.verticalScrollBar()
        rows = self._rows()
        if self._wrap:
            vbar.setValue(max(rows - self._full_visible_rows(), 0))
        else:
            vbar.setValue(vbar.maximum())
        # Following only scrolls: the user's selected line stays selected, so bookmarks, copy and AI act on it.

    def go_to_row(self, row: int, center: bool = True, select: bool = True, emit: bool = True) -> None:
        rows = self._rows()
        if rows == 0:
            return
        row = max(0, min(row, rows - 1))
        vis = self._full_visible_rows()
        top = self.top_row()
        if center and not (top <= row < top + vis):
            self.verticalScrollBar().setValue(row - vis // 2)
        elif row < top:
            self.verticalScrollBar().setValue(row)
        elif row >= top + vis:
            self.verticalScrollBar().setValue(row - vis + 1)
        if select:
            self._current = self._anchor = row
            if emit:
                self.currentRowChanged.emit(row)
        self.viewport().update()

    def _move_current(self, row: int, extend: bool) -> None:
        rows = self._rows()
        if not rows:
            return
        row = max(0, min(row, rows - 1))
        if not extend or self._anchor < 0:
            self._anchor = row
        self._current = row
        self.go_to_row(row, center=False, select=False)
        self.currentRowChanged.emit(row)
        self.viewport().update()

    # ---- text fetching -------------------------------------------------------------------------------------------
    def _texts(self, first: int, count: int) -> list[str]:
        if self._model is None:
            return []
        c0, cache = self._cache_first, self._cache
        if cache and c0 <= first and first + count <= c0 + len(cache):
            return cache[first - c0 : first - c0 + count]
        pad = count  # fetch a little extra around the window for smooth small scrolls
        f0 = max(first - pad, 0)
        self._cache = [t.expandtabs(self._tab_width) for t in self._model.texts(f0, count + 2 * pad)]
        self._cache_first = f0
        return self._cache[first - f0 : first - f0 + count]

    def row_texts(self, first: int, last: int) -> list[str]:
        """Raw text of rows [first, last] inclusive (for copy)."""
        if self._model is None or first < 0:
            return []
        return self._model.texts(first, last - first + 1)

    def current_text(self) -> str:
        """Full text of the current row (not clipped like the painted text)."""
        if self._model is None or self._current < 0:
            return ""
        return self._model.full_text(self._current)

    # ---- painting ------------------------------------------------------------------------------------------------
    def paintEvent(self, event: QPaintEvent) -> None:
        painter = QPainter(self.viewport())
        colors = _Colors.from_palette(self.palette())
        layout = self._paint_layout()
        painter.fillRect(self.viewport().rect(), colors.base)
        painter.fillRect(QRect(0, 0, layout.gutter_width, layout.height), colors.gutter_bg)
        painter.fillRect(QRect(layout.gutter_width - 1, 0, 1, layout.height), colors.divider)
        self._row_map = []
        if self._model is not None:
            self._paint_lines(painter, colors, layout)
        painter.end()

    def _paint_layout(self) -> _Layout:
        rect = self.viewport().rect()
        hscroll = 0 if self._wrap else self.horizontalScrollBar().value()
        text_x0 = self._text_x0()
        start_char = int(hscroll // self._cw)
        return _Layout(
            gutter_width=self._gutter_width(),
            text_x0=text_x0,
            width=rect.width(),
            height=rect.height(),
            start_char=start_char,
            x_offset=text_x0 - (hscroll - start_char * self._cw),
            visible_chars=int((rect.width() - text_x0) / self._cw) + 2,
            wrap_chars=self._wrap_chars(),
        )

    def _paint_lines(self, painter: QPainter, colors: _Colors, layout: _Layout) -> None:
        first = self.top_row()
        texts = self._texts(first, layout.height // self._lh + 1)
        painter.setFont(self._font)
        y = lines_painted = 0
        for offset, text in enumerate(texts):
            if y >= layout.height:
                break
            lines_painted += 1
            y = self._paint_line(painter, colors, layout, first + offset, text, y)
        self._rows_painted = max(lines_painted, 1)

    def _paint_line(  # noqa: PLR0917 - internal paint step
        self, painter: QPainter, colors: _Colors, layout: _Layout, row: int, text: str, y: int
    ) -> int:
        """Paint one (possibly wrapped) line starting at ``y``; returns the y below it."""
        assert self._model is not None
        text, ansi_spans = parse_ansi(text)  # console colour codes: shown as colours, not as escape characters
        segments = list(range(0, max(len(text), 1), layout.wrap_chars)) if self._wrap else [layout.start_char]
        is_context = not self._model.is_hit(row)  # context line around a match: shown dimmed, unstyled
        style = style_line(self._rules, text) if self._rules and not is_context else LineStyle()
        height = self._lh * len(segments)
        first_sel, last_sel = self.selected_rows()
        line_rect = QRect(layout.gutter_width, y, layout.width - layout.gutter_width, height)
        if first_sel <= row <= last_sel:
            painter.fillRect(line_rect, colors.current if first_sel == last_sel else colors.selection)
        elif style.bg:
            painter.fillRect(line_rect, QColor(style.bg))
        if row == self._current:
            painter.fillRect(QRect(layout.gutter_width, y, 3, height), colors.highlight)
        if self._model.gap_before(row):  # lines were skipped between this row and the previous one
            painter.setPen(QPen(colors.gutter_fg, 1, Qt.PenStyle.DashLine))
            painter.drawLine(layout.gutter_width, y, layout.width, y)
        self._paint_gutter(painter, colors, layout, row, y)

        line_fg = colors.gutter_fg if is_context else QColor(style.fg) if style.fg else colors.text
        spans = [] if is_context else ansi_spans + self._spans(text, style)
        for seg_start in segments:
            self._row_map.append((y, row, seg_start))
            if self._wrap:
                segment = _Segment(text[seg_start : seg_start + layout.wrap_chars], seg_start, layout.text_x0, y)
            else:
                segment = _Segment(text[seg_start : seg_start + layout.visible_chars], seg_start, layout.x_offset, y)
            self._paint_char_selection(painter, colors, row, segment)
            if segment.text:
                self._draw_segment(painter, segment, spans, line_fg)
            y += self._lh
        return y

    def _paint_char_selection(self, painter: QPainter, colors: _Colors, row: int, segment: _Segment) -> None:
        selection = self._char_selection
        if selection is None or selection[0] != row:
            return
        start = max(selection[1], segment.start)
        end = min(selection[2], segment.start + max(len(segment.text), 1))
        if end <= start:
            return
        x = segment.x + (start - segment.start) * self._cw
        shade = QColor(colors.highlight)
        shade.setAlpha(PARTIAL_SELECTION_ALPHA)
        painter.fillRect(QRect(int(x), segment.y, int((end - start) * self._cw) + 1, self._lh), shade)

    def _paint_gutter(self, painter: QPainter, colors: _Colors, layout: _Layout, row: int, y: int) -> None:
        assert self._model is not None
        file_line = self._model.file_line(row)
        if self._bookmarks(file_line):
            painter.setBrush(BOOKMARK_COLOR)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawEllipse(QPointF(8, y + self._lh / 2), 4, 4)
        painter.setPen(colors.text if row == self._current else colors.gutter_fg)
        number = str(file_line + 1)
        painter.drawText(QPointF(layout.gutter_width - 6 - len(number) * self._cw, y + self._baseline), number)

    def _spans(self, text: str, style: LineStyle) -> list[Span]:
        """Highlight-rule spans plus search matches (appended last so they win)."""
        spans: list[Span] = list(style.spans)
        if self._search is not None:
            spans.extend(
                (m.start(), m.end(), SEARCH_SPAN, SEARCH_SPAN)
                for m in self._search.finditer(text)
                if m.end() > m.start()
            )
        return spans

    def _draw_segment(self, painter: QPainter, segment: _Segment, spans: list[Span], line_fg: QColor) -> None:
        if not spans:
            painter.setPen(line_fg)
            painter.drawText(QPointF(segment.x, segment.y + self._baseline), segment.text)
            return
        seg_end = segment.start + len(segment.text)
        cuts = {segment.start, seg_end}
        for start, end, _, _ in spans:
            if end > segment.start and start < seg_end:
                cuts.update((max(start, segment.start), min(end, seg_end)))
        for run_start, run_end in itertools.pairwise(sorted(cuts)):
            fg, bg = _run_colors(spans, run_start, run_end, line_fg)
            x = segment.x + (run_start - segment.start) * self._cw
            if bg is not None:
                painter.fillRect(
                    QRect(int(x), segment.y + 1, int((run_end - run_start) * self._cw + 1), self._lh - 2), bg
                )
            painter.setPen(fg)
            painter.drawText(
                QPointF(x, segment.y + self._baseline),
                segment.text[run_start - segment.start : run_end - segment.start],
            )

    # ---- mouse ---------------------------------------------------------------------------------------------------
    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.LeftButton and self._rows():
            row = self.row_at(event.position().y())
            extend = bool(event.modifiers() & Qt.KeyboardModifier.ShiftModifier)
            self._char_selection = None
            self._move_current(row, extend)
            self._press = None if extend else self._position_at(event.position().x(), event.position().y())
            self._dragging = True
        elif event.button() == Qt.MouseButton.RightButton and self._rows():
            row = self.row_at(event.position().y())
            a, b = self.selected_rows()
            if not (a <= row <= b):
                self._move_current(row, False)
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        if not self._dragging:
            return
        y = event.position().y()
        if y < 0:
            self._autoscroll_dir = -1
            self._autoscroll.start()
        elif y > self.viewport().height():
            self._autoscroll_dir = 1
            self._autoscroll.start()
        else:
            self._autoscroll.stop()
            row = self.row_at(y)
            position = self._position_at(event.position().x(), y)
            if self._press is not None and position is not None and position[0] == self._press[0]:
                start, end = sorted((self._press[1], position[1]))  # dragging within one line selects characters
                self._char_selection = (position[0], start, end) if end > start else None
                self.viewport().update()
            elif row != self._current:
                self._char_selection = None
                self._move_current(row, True)

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        self._dragging = False
        self._autoscroll.stop()
        super().mouseReleaseEvent(event)

    def _on_autoscroll(self) -> None:
        self._move_current(self._current + self._autoscroll_dir * 2, True)

    def mouseDoubleClickEvent(self, event: QMouseEvent) -> None:
        if event.button() != Qt.MouseButton.LeftButton or not self._rows():
            return
        row = self.row_at(event.position().y())
        self.rowActivated.emit(row)
        if self._show_word_click:
            word = self._word_at(event.position().x(), event.position().y())
            if word:
                self.wordDoubleClicked.emit(word)

    def _position_at(self, x: float, y: float) -> tuple[int, int] | None:
        """(row, column in the displayed text) under a viewport point, or None outside the text."""
        row, seg_start = self._hit(y)
        if not 0 <= row < self._rows():
            return None
        hscroll = 0 if self._wrap else self.horizontalScrollBar().value()
        column = int((x - self._text_x0() + hscroll) // self._cw + 0.5) + (seg_start if self._wrap else 0)
        return row, max(column, 0)

    def selected_text(self) -> str:
        """The characters selected within one line ("" when whole lines are selected)."""
        selection = self._char_selection
        if selection is None:
            return ""
        texts = self._texts(selection[0], 1)
        return parse_ansi(texts[0])[0][selection[1] : selection[2]] if texts else ""

    def _word_at(self, x: float, y: float) -> str:
        row, seg_start = self._hit(y)
        texts = self._texts(row, 1) if 0 <= row < self._rows() else []
        if not texts:
            return ""
        hscroll = 0 if self._wrap else self.horizontalScrollBar().value()
        col = int((x - self._text_x0() + hscroll) // self._cw) + (seg_start if self._wrap else 0)
        for m in WORD_RE.finditer(texts[0]):
            if m.start() <= col < m.end():
                return m.group(0).strip(".:")
        return ""

    def contextMenuEvent(self, event: QContextMenuEvent) -> None:
        if not self._rows():
            return
        menu = QMenu(self)
        act = menu.addAction("Copy")
        act.setShortcut(QKeySequence.StandardKey.Copy)
        act.triggered.connect(self.copy_selection)
        self.contextActionsRequested.emit(menu, self._current)
        menu.exec(event.globalPos())

    # ---- keyboard ------------------------------------------------------------------------------------------------
    def keyPressEvent(self, event: QKeyEvent) -> None:
        if not event.matches(QKeySequence.StandardKey.Copy):
            self._char_selection = None
        key, mods = event.key(), event.modifiers()
        shift = bool(mods & Qt.KeyboardModifier.ShiftModifier)
        ctrl = bool(mods & Qt.KeyboardModifier.ControlModifier)
        cur = self.top_row() if self._current < 0 else self._current
        page = self._full_visible_rows()
        if event.matches(QKeySequence.StandardKey.Copy):
            self.copy_selection()
        elif key == Qt.Key.Key_Up:
            self._move_current(cur - 1, shift)
        elif key == Qt.Key.Key_Down:
            self._move_current(cur + 1, shift)
        elif key == Qt.Key.Key_PageUp:
            self._move_current(cur - page, shift)
        elif key == Qt.Key.Key_PageDown:
            self._move_current(cur + page, shift)
        elif key == Qt.Key.Key_Home and ctrl:
            self._move_current(0, shift)
        elif key == Qt.Key.Key_End and ctrl:
            self._move_current(self._rows() - 1, shift)
        elif key == Qt.Key.Key_Home:
            self.horizontalScrollBar().setValue(0)
        elif key == Qt.Key.Key_End:
            self.horizontalScrollBar().setValue(self.horizontalScrollBar().maximum())
        elif key == Qt.Key.Key_Left:
            self.horizontalScrollBar().triggerAction(QScrollBar.SliderAction.SliderSingleStepSub)
        elif key == Qt.Key.Key_Right:
            self.horizontalScrollBar().triggerAction(QScrollBar.SliderAction.SliderSingleStepAdd)
        elif key in (Qt.Key.Key_Return, Qt.Key.Key_Enter) and self._current >= 0:
            self.rowActivated.emit(self._current)
        else:
            super().keyPressEvent(event)

    def copy_selection(self) -> None:
        partial = self.selected_text()
        if partial:
            QGuiApplication.clipboard().setText(partial)
            return
        a, b = self.selected_rows()
        if a < 0:
            return
        b = min(b, a + MAX_COPY_LINES - 1)
        QGuiApplication.clipboard().setText("\n".join(self.row_texts(a, b)))
