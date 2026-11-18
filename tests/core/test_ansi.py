"""ANSI colour sequences become colour spans over the visible text; other sequences are dropped."""

from __future__ import annotations

from loglens.core.ansi import BASIC, BRIGHT, parse_ansi, strip_ansi

ESC = "\x1b"


def test_basic_bright_and_reset() -> None:
    text, spans = parse_ansi(f"{ESC}[31mERROR{ESC}[0m plain {ESC}[1;92mok{ESC}[39m")
    assert text == "ERROR plain ok"
    assert spans == [(0, 5, BASIC[1], None), (12, 14, BRIGHT[2], None)]


def test_256_truecolor_background_and_other_sequences() -> None:
    text, spans = parse_ansi(f"{ESC}[2K{ESC}]0;title\x07{ESC}[38;5;196;48;2;0;0;255mhot{ESC}[m cold")
    assert text == "hot cold"
    assert spans == [(0, 3, "#ff0000", "#0000ff")]


def test_plain_text_untouched() -> None:
    assert parse_ansi("no escapes here") == ("no escapes here", [])
    assert strip_ansi(f"{ESC}[33mwarn{ESC}[0m") == "warn"
