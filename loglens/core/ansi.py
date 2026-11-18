"""ANSI escape sequences in logs (console output captured to files, containers, Node/Python colour loggers).

:func:`parse_ansi` returns the visible text plus colour spans for SGR sequences (16 colours, 256-colour and 24-bit);
every other escape sequence (cursor movement, erase, OSC titles) is removed.
"""

from __future__ import annotations

import re

ESC = "\x1b"
_SEQUENCE = re.compile(r"\x1b(?:\[(?P<params>[0-9;:?]*)(?P<final>[@-~])|\][^\x07\x1b]*(?:\x07|\x1b\\)?|[@-Z\\-_])")
# Standard VGA-ish palette, readable on light and dark backgrounds.
BASIC = ("#3b3b3b", "#cd3131", "#0dbc79", "#b58900", "#2472c8", "#bc3fbc", "#11a8cd", "#a0a0a0")
BRIGHT = ("#666666", "#f14c4c", "#23d18b", "#d7ba00", "#3b8eea", "#d670d6", "#29b8db", "#e5e5e5")
CUBE_LEVELS = (0, 95, 135, 175, 215, 255)

Span = tuple[int, int, str | None, str | None]  # (start, end, fg, bg) in visible characters


def has_ansi(text: str) -> bool:
    return ESC in text


def _color_256(index: int) -> str | None:
    if 0 <= index < 8:
        return BASIC[index]
    if index < 16:
        return BRIGHT[index - 8]
    if index < 232:
        value = index - 16
        r, g, b = CUBE_LEVELS[value // 36], CUBE_LEVELS[value // 6 % 6], CUBE_LEVELS[value % 6]
        return f"#{r:02x}{g:02x}{b:02x}"
    if index < 256:
        level = 8 + (index - 232) * 10
        return f"#{level:02x}{level:02x}{level:02x}"
    return None


def _apply(codes: list[int], fg: str | None, bg: str | None) -> tuple[str | None, str | None]:
    """New (fg, bg) after one SGR parameter list."""
    i = 0
    while i < len(codes):
        code = codes[i]
        if code == 0:
            fg = bg = None
        elif 30 <= code <= 37:
            fg = BASIC[code - 30]
        elif 90 <= code <= 97:
            fg = BRIGHT[code - 90]
        elif 40 <= code <= 47:
            bg = BASIC[code - 40]
        elif 100 <= code <= 107:
            bg = BRIGHT[code - 100]
        elif code == 39:
            fg = None
        elif code == 49:
            bg = None
        elif code in (38, 48) and i + 1 < len(codes):
            color, used = _extended(codes[i + 1 :])
            if code == 38:
                fg = color
            else:
                bg = color
            i += used
        i += 1
    return fg, bg


def _extended(rest: list[int]) -> tuple[str | None, int]:
    """Colour of a ``38;5;n`` / ``38;2;r;g;b`` tail and how many parameters it used."""
    if rest[0] == 5 and len(rest) > 1:
        return _color_256(rest[1]), 2
    if rest[0] == 2 and len(rest) > 3:
        r, g, b = (max(0, min(v, 255)) for v in rest[1:4])
        return f"#{r:02x}{g:02x}{b:02x}", 4
    return None, 1


def parse_ansi(text: str) -> tuple[str, list[Span]]:
    """Visible text and colour spans; text without escape sequences is returned unchanged with no spans."""
    if ESC not in text:
        return text, []
    out: list[str] = []
    spans: list[Span] = []
    fg: str | None = None
    bg: str | None = None
    visible = 0
    run_start = 0
    position = 0
    for match in _SEQUENCE.finditer(text):
        chunk = text[position : match.start()]
        out.append(chunk)
        visible += len(chunk)
        position = match.end()
        if match["final"] != "m":
            continue  # not a colour change: just drop it
        if (fg or bg) and visible > run_start:
            spans.append((run_start, visible, fg, bg))
        codes = [int(part) if part.isdigit() else 0 for part in (match["params"] or "0").replace(":", ";").split(";")]
        fg, bg = _apply(codes, fg, bg)
        run_start = visible
    tail = text[position:]
    out.append(tail)
    visible += len(tail)
    if (fg or bg) and visible > run_start:
        spans.append((run_start, visible, fg, bg))
    return "".join(out), spans


def strip_ansi(text: str) -> str:
    return parse_ansi(text)[0] if ESC in text else text
