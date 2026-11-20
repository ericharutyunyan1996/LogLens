"""Compressed logs are unpacked once into a cache and reused."""

from __future__ import annotations

import gzip
from pathlib import Path

import pytest

from loglens.core import compressed
from loglens.core.compressed import CompressedError, clear_cache, is_compressed, unpack_gz


def make(path: Path, text: str) -> Path:
    with gzip.open(path, "wb") as handle:
        handle.write(text.encode("utf-8"))
    return path


def test_unpack_and_reuse(tmp_path: Path) -> None:
    archive = make(tmp_path / "app.log.gz", "line one\nline two\n")
    cache = tmp_path / "cache"
    first = unpack_gz(archive, cache)
    assert first.read_text(encoding="utf-8") == "line one\nline two\n" and first.name.startswith("app.log [")
    stamp = first.stat().st_mtime_ns
    assert unpack_gz(archive, cache) == first and first.stat().st_mtime_ns == stamp
    make(archive, "changed\n")  # a different archive gets its own file
    assert unpack_gz(archive, cache) != first
    assert clear_cache(cache) == 2 and not list(cache.iterdir())


def test_bad_and_oversized_archives(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bad = tmp_path / "bad.gz"
    bad.write_bytes(b"not gzip at all")
    with pytest.raises(CompressedError, match="could not be unpacked"):
        unpack_gz(bad, tmp_path / "c")
    big = make(tmp_path / "big.gz", "x" * 5000)
    monkeypatch.setattr(compressed, "MAX_UNPACKED_BYTES", 1000)
    with pytest.raises(CompressedError, match="not opened"):
        unpack_gz(big, tmp_path / "c")
    assert not list((tmp_path / "c").glob("*.part"))


def test_is_compressed() -> None:
    assert is_compressed("a.LOG.GZ") and not is_compressed("a.log")
