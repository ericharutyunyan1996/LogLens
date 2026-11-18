"""Encoding detection."""

from __future__ import annotations

import codecs

import pytest

from loglens.core.encoding import detect_encoding


@pytest.mark.parametrize(
    ("data", "codec", "bom"),
    [
        (b"hello\nworld\n", "utf-8", 0),
        (codecs.BOM_UTF8 + "héllo\n".encode(), "utf-8", 3),
        (codecs.BOM_UTF16_LE + "hello\n".encode("utf-16-le"), "utf-16-le", 2),
        ("hello world\r\n".encode("utf-16-le"), "utf-16-le", 0),
        ("hello world\r\n".encode("utf-16-be"), "utf-16-be", 0),
    ],
)
def test_detect_encoding(data: bytes, codec: str, bom: int) -> None:
    enc = detect_encoding(data)
    assert (enc.codec, enc.bom_len) == (codec, bom)


def test_detect_ansi_fallback() -> None:
    enc = detect_encoding("caf\xe9 cr\xe8me\n".encode("cp1252"))
    assert enc.codec != "utf-8" and enc.unit == 1
