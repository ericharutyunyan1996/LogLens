"""Folder / zip bundles: log files recognised, zips extracted safely."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from loglens.core.bundles import BundleError, extract_zip, is_log_file, list_log_files


def test_recognises_log_files() -> None:
    for name in ("app.log", "app.log.1", "app.log.2026-11-13", "server.out", "events.evtx", "x.jsonl", "u_ex.log.old"):
        assert is_log_file(name), name
    for name in ("photo.png", "setup.exe", "notes.docx"):
        assert not is_log_file(name), name


def test_list_folder(tmp_path: Path) -> None:
    (tmp_path / "sub").mkdir()
    for name in ("a.log", "sub/b.log.1", "readme.md"):
        (tmp_path / name).write_text("x", encoding="utf-8")
    assert sorted(f.relative.replace("\\", "/") for f in list_log_files(tmp_path)) == ["a.log", "sub/b.log.1"]


def test_extract_zip_and_reject_unsafe(tmp_path: Path) -> None:
    good = tmp_path / "bundle.zip"
    with zipfile.ZipFile(good, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("logs/app.log", "2026-11-13 10:00:00 INFO hi\n")
        z.writestr("image.png", b"\x89PNG")
    out = extract_zip(good, tmp_path / "out")
    assert [p.relative_to(tmp_path / "out").as_posix() for p in out] == ["logs/app.log"]

    evil = tmp_path / "evil.zip"
    with zipfile.ZipFile(evil, "w") as z:
        z.writestr("../../escape.log", "x")
    with pytest.raises(BundleError, match="Unsafe path"):
        extract_zip(evil, tmp_path / "evil-out")

    bomb = tmp_path / "bomb.zip"
    with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("big.log", "A" * 5_000_000)
    with pytest.raises(BundleError, match="zip bomb"):
        extract_zip(bomb, tmp_path / "bomb-out")
