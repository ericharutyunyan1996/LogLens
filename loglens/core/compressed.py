"""Open compressed logs (``.gz``) directly: they are unpacked once into a cache folder and read like any other log."""

from __future__ import annotations

import gzip
import hashlib
import shutil
from pathlib import Path

MAX_UNPACKED_BYTES = 8 * 1024**3  # a gzip bomb must not fill the disk
CHUNK = 1024 * 1024


class CompressedError(Exception):
    """The archive cannot be unpacked (message is shown to the user)."""


def is_compressed(path: str | Path) -> bool:
    return Path(path).suffix.lower() == ".gz"


def unpack_gz(path: Path, cache_dir: Path) -> Path:
    """Unpack ``path`` into ``cache_dir`` (reused when the archive has not changed) and return the plain file."""
    stat = path.stat()
    key = hashlib.sha256(f"{path.resolve()}|{stat.st_size}|{stat.st_mtime_ns}".encode()).hexdigest()[:12]
    target = cache_dir / f"{path.stem} [{key}]"
    if target.is_file():
        return target
    cache_dir.mkdir(parents=True, exist_ok=True)
    partial = target.with_name(target.name + ".part")
    written = 0
    try:
        with gzip.open(path, "rb") as source, partial.open("wb") as out:
            while chunk := source.read(CHUNK):
                written += len(chunk)
                if written > MAX_UNPACKED_BYTES:
                    raise CompressedError(
                        f"{path.name} unpacks to more than {MAX_UNPACKED_BYTES // 1024**3} GB: not opened."
                    )
                out.write(chunk)
        partial.replace(target)
    except (OSError, EOFError, gzip.BadGzipFile) as exc:
        partial.unlink(missing_ok=True)
        raise CompressedError(f"{path.name} could not be unpacked: {exc}") from exc
    except CompressedError:
        partial.unlink(missing_ok=True)
        raise
    return target


def clear_cache(cache_dir: Path) -> int:
    """Delete unpacked files; returns how many were removed."""
    count = 0
    if cache_dir.is_dir():
        for item in cache_dir.iterdir():
            if item.is_file():
                item.unlink(missing_ok=True)
                count += 1
            elif item.is_dir():
                shutil.rmtree(item, ignore_errors=True)
    return count
