"""Inline SVG icons (stroke style, tinted to the current palette) and the LogLens logo."""

from __future__ import annotations

from functools import cache

from PySide6.QtCore import QByteArray, QRectF, QSize, Qt
from PySide6.QtGui import QColor, QIcon, QImage, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer

_STROKE = (
    '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" '
    'stroke="{color}" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">{body}</svg>'
)

ICONS: dict[str, str] = {
    "open": '<path d="M3 8V6a2 2 0 0 1 2-2h4l2 2h7a2 2 0 0 1 2 2v1"/>'
    '<path d="M3 8v10a2 2 0 0 0 2 2h12.6a2 2 0 0 0 1.9-1.4l1.9-6.2A1 1 0 0 0 20.4 11H7.3a2 2 0 0 0-1.9 1.4L3.4 19"/>',
    "reload": '<path d="M20 12a8 8 0 1 1-2.3-5.7"/><path d="M20 4v4.5h-4.5"/>',
    "follow": '<path d="M12 4v11"/><path d="m7.5 10.5 4.5 4.5 4.5-4.5"/><path d="M5 20h14"/>',
    "find": '<circle cx="11" cy="11" r="6.5"/><path d="m20 20-4.2-4.2"/>',
    "goto": '<path d="M4 7h9"/><path d="M4 12h5"/><path d="M4 17h9"/><path d="M13 12h7"/><path d="m17 9 3 3-3 3"/>',
    "bookmark": '<path d="M7 3.5h10a1 1 0 0 1 1 1V21l-6-4-6 4V4.5a1 1 0 0 1 1-1z"/>',
    "highlight": '<path d="m14.5 4.5 5 5"/><path d="M17 2l5 5-9.5 9.5H7.5V11.5z"/><path d="M3 21h8"/>',
    "theme": '<path d="M20.5 13.2A8.5 8.5 0 1 1 10.8 3.5a6.6 6.6 0 0 0 9.7 9.7z"/>',
    "up": '<path d="m6 15 6-6 6 6"/>',
    "down": '<path d="m6 9 6 6 6-6"/>',
    "close": '<path d="M17 7 7 17M7 7l10 10"/>',
    "exclude": '<path d="M3.5 5h17l-6.5 7.5V19l-4 1.5v-8z"/><path d="M3 3l18 18"/>',
    "file": '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/>'
    '<path d="M9 13h6M9 17h4"/>',
    "error": '<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5v5.5M12 16.2v.3"/>',
    "warning": '<path d="M10.3 4.3 2.8 17.5A2 2 0 0 0 4.5 20.5h15a2 2 0 0 0 1.7-3L13.7 4.3a2 2 0 0 0-3.4 0z"/>'
    '<path d="M12 9.5v4M12 16.8v.2"/>',
    "ai": '<path d="M12 3.5l1.9 5.1 5.1 1.9-5.1 1.9-1.9 5.1-1.9-5.1-5.1-1.9 5.1-1.9z"/>'
    '<path d="M18.5 15.5l.8 2 2 .8-2 .8-.8 2-.8-2-2-.8 2-.8z"/>',
    "events": '<rect x="3.5" y="4.5" width="17" height="16" rx="2"/><path d="M3.5 9h17M8 3v3M16 3v3"/>'
    '<path d="M8 13h3M8 16.5h6"/>',
}

LOGO_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
 <defs>
  <linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
   <stop offset="0" stop-color="#4F46E5"/><stop offset="1" stop-color="#0EA5E9"/>
  </linearGradient>
 </defs>
 <rect x="2" y="2" width="60" height="60" rx="15" fill="url(#g)"/>
 <g stroke-linecap="round" stroke-width="4.2" fill="none">
  <path d="M13 17h26" stroke="#ffffff" opacity=".95"/>
  <path d="M13 26.5h17" stroke="#ffffff" opacity=".8"/>
  <path d="M13 36h9" stroke="#FCA5A5"/>
  <path d="M13 45.5h7" stroke="#ffffff" opacity=".65"/>
  <circle cx="39.5" cy="38.5" r="10" stroke="#ffffff" stroke-width="4.6"/>
  <path d="M47 46l6.5 6.5" stroke="#ffffff" stroke-width="5.4"/>
 </g>
</svg>"""


def _render(svg: str, size: int) -> QPixmap:
    renderer = QSvgRenderer(QByteArray(svg.encode()))
    img = QImage(size, size, QImage.Format.Format_ARGB32_Premultiplied)
    img.fill(Qt.GlobalColor.transparent)
    p = QPainter(img)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    renderer.render(p, QRectF(0, 0, size, size))
    p.end()
    return QPixmap.fromImage(img)


@cache
def icon(name: str, color: str = "#5b6170") -> QIcon:
    svg = _STROKE.format(color=color, body=ICONS[name])
    ic = QIcon()
    for size in (16, 20, 24, 32, 48):
        ic.addPixmap(_render(svg, size))
    return ic


def themed_icon(name: str, dark: bool) -> QIcon:
    return icon(name, "#c9cdd6" if dark else "#4b5160")


@cache
def logo_icon() -> QIcon:
    ic = QIcon()
    for size in (16, 24, 32, 48, 64, 128, 256):
        ic.addPixmap(_render(LOGO_SVG, size))
    return ic


def logo_pixmap(size: int) -> QPixmap:
    return _render(LOGO_SVG, size)


def dot_pixmap(color: str, size: int = 10) -> QPixmap:
    pm = QPixmap(QSize(size, size))
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor(color))
    p.drawEllipse(1, 1, size - 2, size - 2)
    p.end()
    return pm
