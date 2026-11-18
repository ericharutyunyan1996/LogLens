"""Opening log files without getting in the way of the application that writes them.

Python's built-in open() on Windows does not pass FILE_SHARE_DELETE, so while we hold a handle the writer cannot
rename/delete the file — which breaks log rotation. We open through CreateFileW with full sharing instead, and
never memory-map (a mapped section would make the writer's truncate fail with ERROR_USER_MAPPED_FILE).
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

if sys.platform == "win32":
    import msvcrt

    import pywintypes
    import win32con
    import win32file

    _SHARE_ALL = win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE


def open_shared(path: str | os.PathLike[str]) -> BinaryIO:
    """Open a file for binary reading with read/write/delete sharing on Windows."""
    if sys.platform != "win32":
        return Path(path).open("rb")
    try:
        handle = win32file.CreateFile(
            os.fspath(path),
            win32con.GENERIC_READ,
            _SHARE_ALL,
            None,
            win32con.OPEN_EXISTING,
            win32con.FILE_ATTRIBUTE_NORMAL,
            None,
        )
    except pywintypes.error as exc:
        # Map to the OSError subclasses callers expect (FileNotFoundError, PermissionError, ...).
        raise OSError(None, exc.strerror, os.fspath(path), exc.winerror) from exc
    fd = msvcrt.open_osfhandle(int(handle.Detach()), os.O_RDONLY | os.O_BINARY)
    return os.fdopen(fd, "rb")


@dataclass(frozen=True)
class FileIdentity:
    """Enough to tell whether the file at a path is still the same file (rotation detection)."""

    size: int
    ino: int
    dev: int
    ctime_ns: int

    def same_file(self, other: FileIdentity) -> bool:
        if self.ino and other.ino:
            return self.ino == other.ino and self.dev == other.dev
        return self.ctime_ns == other.ctime_ns


def file_identity(path: str | os.PathLike[str]) -> FileIdentity:
    st = Path(path).stat()
    ctime = getattr(st, "st_birthtime_ns", st.st_ctime_ns)
    return FileIdentity(st.st_size, st.st_ino, st.st_dev, ctime)
