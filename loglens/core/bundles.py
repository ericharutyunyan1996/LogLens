"""Log bundles: a folder or a zip of logs (support bundles, collected diagnostics) opened as one investigation.

Zips are extracted safely before opening: entries can't escape the target folder (zip-slip, drive letters, alternate
data streams, device names), and total size, file count and compression ratio are bounded (zip bombs). Log files
are recognised by extension and by rotation suffixes.
"""

from __future__ import annotations

import os
import re
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath

LOG_EXTENSIONS = frozenset({
    ".log", ".txt", ".out", ".err", ".trace", ".json", ".jsonl", ".ndjson", ".csv", ".tsv", ".evtx", ".wer", ".xml",
    ".etl.txt",
})  # fmt: skip
ROTATED = re.compile(r"\.(?:log|txt|out)(?:\.\d+|\.\d{4}-?\d{2}-?\d{2}(?:[-_.]\d+)?|\.old|\.bak|\.gz)?$", re.IGNORECASE)
MAX_LISTED_FILES = 5_000
MAX_ZIP_FILES = 5_000
MAX_ZIP_BYTES = 8 * 1024**3  # 8 GiB extracted at most
MAX_COMPRESSION_RATIO = 200  # more than this per entry looks like a zip bomb
_INVALID_NAME_CHARS = frozenset('<>:"|?*')  # not allowed in Windows file names (':' also selects a drive or a stream)
_RESERVED_NAMES = frozenset({
    "con", "prn", "aux", "nul", "conin$", "conout$",
    *(f"{device}{n}" for device in ("com", "lpt") for n in (*"123456789", "¹", "²", "³")),
})  # fmt: skip


class BundleError(Exception):
    """The bundle can't be opened (unsafe or too large zip, unreadable folder)."""


@dataclass(frozen=True, slots=True)
class BundleFile:
    path: Path
    relative: str  # path inside the bundle, for display
    size: int
    modified: datetime

    @property
    def is_event_log(self) -> bool:
        return self.path.suffix.lower() == ".evtx"


def is_log_file(name: str) -> bool:
    lower = name.lower()
    return Path(lower).suffix in LOG_EXTENSIONS or bool(ROTATED.search(lower))


def list_log_files(folder: Path, *, max_files: int = MAX_LISTED_FILES) -> list[BundleFile]:
    """Log files under ``folder`` (recursive), newest first."""
    found: list[BundleFile] = []
    for root, _dirs, files in os.walk(folder, onerror=lambda _e: None):
        for name in files:
            if not is_log_file(name):
                continue
            path = Path(root) / name
            try:
                stat = path.stat()
            except OSError:
                continue
            relative = str(path.relative_to(folder))
            found.append(BundleFile(path, relative, stat.st_size, datetime.fromtimestamp(stat.st_mtime).astimezone()))
            if len(found) >= max_files:
                return sorted(found, key=lambda f: f.modified, reverse=True)
    return sorted(found, key=lambda f: f.modified, reverse=True)


def _is_safe_part(part: str) -> bool:
    """One path component that Windows maps to a plain file or folder name inside the target folder."""
    if not part or part.endswith((".", " ")):  # "", ".", "..", and names Windows silently trims (a. → a)
        return False
    if any(c in _INVALID_NAME_CHARS or ord(c) < 32 for c in part):  # ':' = drive or alternate data stream
        return False
    return part.split(".", 1)[0].rstrip(" ").lower() not in _RESERVED_NAMES  # con.log is the console device


def safe_member_path(name: str) -> PurePosixPath | None:
    """The member's relative path, or None if writing it could leave the target folder or reach a device.

    Rejected: absolute, UNC and drive paths, ``..``, empty components, any ``:`` (a drive anywhere in the path, or an
    NTFS alternate data stream), components ending in a dot or space, characters Windows forbids, and reserved device
    names (CON, PRN, AUX, NUL, COM1-9, LPT1-9 — with any extension).
    """
    parts = name.replace("\\", "/").split("/")
    if not all(_is_safe_part(part) for part in parts):  # a leading "/" (absolute or UNC) yields an empty first part
        return None
    return PurePosixPath(*parts)


def _plan_extraction(members: list[zipfile.ZipInfo], target: Path) -> list[tuple[zipfile.ZipInfo, Path]]:
    """Destination of every member; raises BundleError before anything is written if any member is unsafe."""
    root = target.resolve()
    plan = []
    for member in members:
        relative = safe_member_path(member.filename)
        if relative is None:
            raise BundleError(f"Unsafe path in the zip: {member.filename}")
        if member.compress_size and member.file_size / member.compress_size > MAX_COMPRESSION_RATIO:
            raise BundleError(f"{member.filename} is compressed suspiciously well (possible zip bomb).")
        destination = target.joinpath(*relative.parts)
        if not destination.resolve().is_relative_to(root):  # e.g. through a junction or link inside the target
            raise BundleError(f"Unsafe path in the zip: {member.filename}")
        plan.append((member, destination))
    return plan


def extract_zip(archive: Path, target: Path) -> list[Path]:
    """Extract the log files of ``archive`` into ``target``; raises BundleError for unsafe or oversized archives.

    Every member is checked before the first file is written, so an unsafe archive leaves nothing behind.
    """
    try:
        with zipfile.ZipFile(archive) as bundle:
            members = [m for m in bundle.infolist() if not m.is_dir() and is_log_file(m.filename)]
            if len(members) > MAX_ZIP_FILES:
                raise BundleError(f"The zip holds more than {MAX_ZIP_FILES:,} log files.")
            total = sum(m.file_size for m in members)
            if total > MAX_ZIP_BYTES:
                raise BundleError(f"The logs in the zip would take {total / 1024**3:.1f} GiB — too large to extract.")
            extracted = []
            for member, destination in _plan_extraction(members, target):
                destination.parent.mkdir(parents=True, exist_ok=True)
                with bundle.open(member) as source, destination.open("wb") as out:
                    while chunk := source.read(1024 * 1024):
                        out.write(chunk)
                extracted.append(destination)
            return extracted
    except (zipfile.BadZipFile, OSError) as exc:
        raise BundleError(f"Could not read {archive.name}: {exc}") from exc
