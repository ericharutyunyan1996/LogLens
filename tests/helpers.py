"""Shared test helpers."""

from __future__ import annotations

from pathlib import Path

from loglens.core.text_source import TextLogSource


def make_source(tmp_path: Path, data: bytes, name: str = "t.log") -> TextLogSource:
    """Write ``data`` to a file and return an indexed TextLogSource for it."""
    path = tmp_path / name
    path.write_bytes(data)
    source = TextLogSource(path)
    assert source.build_index()
    return source


def all_lines(source: TextLogSource) -> list[str]:
    return source.get_lines(0, source.line_count())
