"""Line index + TextLogSource: lines, encodings, tail, truncation, rotation."""

from __future__ import annotations

import codecs
import os
from pathlib import Path
from typing import BinaryIO

import numpy as np
import pytest

from loglens.core.text_source import Change, TextLogSource
from tests.helpers import all_lines, make_source


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b"", []),
        (b"\n", [""]),
        (b"a", ["a"]),
        (b"a\n", ["a"]),
        (b"a\nb", ["a", "b"]),
        (b"a\r\nb\r\n", ["a", "b"]),
        (b"a\n\n\nb\n", ["a", "", "", "b"]),
    ],
)
def test_lines_utf8(tmp_path: Path, data: bytes, expected: list[str]) -> None:
    src = make_source(tmp_path, data)
    assert src.line_count() == len(expected)
    assert all_lines(src) == expected


def test_lines_utf16_with_bom(tmp_path: Path) -> None:
    text = "first ünïcode\r\nsecond\r\nthird"
    src = make_source(tmp_path, codecs.BOM_UTF16_LE + text.encode("utf-16-le"))
    assert all_lines(src) == ["first ünïcode", "second", "third"]


def test_utf16_newline_byte_inside_char_is_not_a_newline(tmp_path: Path) -> None:
    # U+0A0A encodes as 0A 0A in UTF-16 — must not be treated as line breaks.
    text = "aਊb\nc"
    src = make_source(tmp_path, codecs.BOM_UTF16_LE + text.encode("utf-16-le"))
    assert all_lines(src) == ["aਊb", "c"]


def test_index_small_chunks_match_big_chunks(tmp_path: Path) -> None:
    data = b"".join(b"line %d %s\n" % (i, b"x" * (i % 37)) for i in range(5000))
    p = tmp_path / "c.log"
    p.write_bytes(data)
    a, b = TextLogSource(p), TextLogSource(p)
    a.build_index()
    with p.open("rb") as f:
        b.index.scan(f, len(data), chunk=4093)  # odd chunk size crosses lines everywhere
    assert np.array_equal(a.snapshot().ends, b.snapshot().ends)
    assert b.line_count() == 5000
    assert b.get_line(4999) == "line 4999 " + "x" * (4999 % 37)


def test_tail_append_and_partial_line(tmp_path: Path) -> None:
    p = tmp_path / "tail.log"
    p.write_bytes(b"one\ntw")
    src = TextLogSource(p)
    src.build_index()
    assert all_lines(src) == ["one", "tw"]
    with p.open("ab") as f:
        f.write(b"o\nthree\n")
    assert src.check_change() is Change.GROWN
    src.build_index()
    assert all_lines(src) == ["one", "two", "three"]
    assert src.check_change() is Change.NONE


def test_truncation_detected(tmp_path: Path) -> None:
    p = tmp_path / "trunc.log"
    p.write_bytes(b"aaaa\nbbbb\ncccc\n")
    src = TextLogSource(p)
    src.build_index()
    p.write_bytes(b"new\n")
    assert src.check_change() is Change.RESET
    src.reset()
    src.build_index()
    assert all_lines(src) == ["new"]


def test_failed_reset_leaves_source_unchanged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A rotated file that is briefly locked: reset() fails, and the next poll must still say RESET (not GROWN)."""
    import loglens.core.text_source as text_source_mod

    p = tmp_path / "rot.log"
    p.write_bytes(b"line 1\n")
    src = TextLogSource(p)
    src.build_index()
    p.rename(tmp_path / "rot.log.1")
    p.write_bytes(b"line 1\nline 2\nline 3\n")  # the new file starts like the old one, but is another file
    assert src.check_change() is Change.RESET

    real_open = text_source_mod.open_shared
    calls: list[str | os.PathLike[str]] = []

    def locked_once(path: str | os.PathLike[str]) -> BinaryIO:
        calls.append(path)
        if len(calls) == 1:
            raise PermissionError(13, "locked by the rotation", str(path))
        return real_open(path)

    monkeypatch.setattr(text_source_mod, "open_shared", locked_once)
    identity, index, encoding = src.identity, src.index, src.encoding
    with pytest.raises(OSError):
        src.reset()
    assert (src.identity, src.index, src.encoding) == (identity, index, encoding)
    assert src.check_change() is Change.RESET
    src.reset()
    src.build_index()
    assert all_lines(src) == ["line 1", "line 2", "line 3"]


def test_encoding_redetected_when_an_empty_file_grows(tmp_path: Path) -> None:
    """Tailing a freshly created (empty) log: UTF-8 was only a guess, UTF-16 content must trigger a re-index."""
    p = tmp_path / "fresh.log"
    p.write_bytes(b"")
    src = TextLogSource(p)
    src.build_index()
    p.write_bytes(codecs.BOM_UTF16_LE + "héllo\r\nwörld\r\n".encode("utf-16-le"))
    assert src.check_change() is Change.RESET
    src.reset()
    src.build_index()
    assert src.encoding.codec == "utf-16-le"
    assert all_lines(src) == ["héllo", "wörld"]


def test_fresh_utf8_file_keeps_growing(tmp_path: Path) -> None:
    p = tmp_path / "fresh.log"
    p.write_bytes(b"")
    src = TextLogSource(p)
    src.build_index()
    with p.open("ab") as f:
        f.write(b"first line\n")
    assert src.check_change() is Change.GROWN
    src.build_index()
    with p.open("ab") as f:
        f.write(b"second line\n")
    assert src.check_change() is Change.GROWN
    src.build_index()
    assert all_lines(src) == ["first line", "second line"]


def test_rewritten_beyond_old_size_is_reset(tmp_path: Path) -> None:
    """Truncated and rewritten between two polls (same file, now bigger): must not be mistaken for growth."""
    p = tmp_path / "rw.log"
    p.write_bytes(b"2026-01-01 10:00:00 a\n2026-01-01 10:00:01 b\n")
    src = TextLogSource(p)
    src.build_index()
    p.write_bytes(b"2026-02-02 08:00:00 new first line\n2026-02-02 08:00:01 second line\n")
    assert src.check_change() is Change.RESET


def test_file_can_be_renamed_while_open(tmp_path: Path) -> None:
    """Log rotation renames the file; our shared handles must not block it."""
    from loglens.core.fileio import open_shared

    p = tmp_path / "rot.log"
    p.write_bytes(b"x\n")
    with open_shared(p):
        p.rename(tmp_path / "rot.log.1")
    assert (tmp_path / "rot.log.1").exists()


def test_long_line_clipped_for_display(tmp_path: Path) -> None:
    src = make_source(tmp_path, b"short\n" + b"y" * 200_000 + b"\nend\n")
    lines = all_lines(src)
    assert lines[0] == "short" and lines[2] == "end"
    assert lines[1].startswith("y" * 1000) and "clipped" in lines[1]
    assert src.max_line_chars == 200_000


def test_full_line_is_not_clipped(tmp_path: Path) -> None:
    payload = '{"items":[' + ",".join(f'{{"n":{i}}}' for i in range(12000)) + "]}"
    src = make_source(
        tmp_path, f"2026-11-11 13:47:26,153 [18] TRACE TraceLogger - [Response] Content : {payload}\nnext\n".encode()
    )
    assert "clipped" in src.get_line(0)
    full = src.get_full_line(0)
    assert full.endswith("]}") and len(full) > 64 * 1024
    from loglens.core.payloads import pretty_text

    assert '"n": 11999' in pretty_text(full)
