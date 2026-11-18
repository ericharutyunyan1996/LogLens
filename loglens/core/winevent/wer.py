"""Windows Error Reporting (WER): parse ``Report.wer`` crash reports and find them in the standard report folders.

A ``Report.wer`` file is an INI-like list of ``Key=Value`` lines, usually UTF-16 LE with a BOM. The interesting parts
are the event type (APPCRASH, CLR20r3, BEX64, AppHangB1 …), the problem signature (``Sig[n].Name``/``Sig[n].Value``:
application, faulting module, exception code, offset …) and the list of loaded modules.

The problem-signature layouts and the names of well-known exception codes live here too, because the
"Windows Error Reporting 1001" event carries the same signature as P1…P10 (see ``entities``).
"""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ..encoding import detect_encoding
from ..fileio import open_shared
from ..kb.codes import describe_code
from ..timeparse import to_local

log = logging.getLogger(__name__)

REPORT_FILE = "Report.wer"
REPORT_SUBDIRS = ("ReportArchive", "ReportQueue")
MAX_REPORT_BYTES = 4 * 1024 * 1024  # real reports are a few KiB (loaded-module lists included); never read more
ENCODING_SAMPLE_BYTES = 64 * 1024
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
FILETIME_TICKS_PER_MICROSECOND = 10  # FILETIME counts 100 ns intervals since 1601-01-01 UTC
BOM = "\N{ZERO WIDTH NO-BREAK SPACE}"  # a decoded byte-order mark left at the start of the text
_INDEXED_KEY = re.compile(r"^(?P<base>\w+)\[(?P<index>\d+)\](?:\.(?P<part>\w+))?$")

# Descriptive problem-signature names (Report.wer ``Sig[n].Name``) → fact name. The first match wins, so for
# store apps "Package Full Name" (Sig[0]) is preferred over the less useful "Application Name" (praid:App).
SIGNATURE_NAMES: dict[str, str] = {
    "application name": "app_name",
    "package full name": "app_name",
    "application version": "app_version",
    "fault module name": "faulting_module",
    "fault module version": "module_version",
    "exception code": "exception_code",
    "exception offset": "fault_offset",
}

_CRASH_LAYOUT = {"app_name": 1, "app_version": 2, "faulting_module": 4, "module_version": 5}
_HANG_LAYOUT = {"app_name": 1, "app_version": 2}
_STORE_HANG_LAYOUT = {"app_name": 1}  # P3 of a store-app hang is the hosting process' version, not the app's
# 1-based positions P1…P10 per WER event type, used where the signature has no descriptive names
# (the 1001 event, CLR20r3 reports whose names are just "Problem Signature 01" …).
SIGNATURE_LAYOUTS: dict[str, dict[str, int]] = {
    "appcrash": {**_CRASH_LAYOUT, "exception_code": 7, "fault_offset": 8},
    "bex": {**_CRASH_LAYOUT, "fault_offset": 7, "exception_code": 8},
    "bex64": {**_CRASH_LAYOUT, "fault_offset": 7, "exception_code": 8},
    "clr20r3": {**_CRASH_LAYOUT, "fault_offset": 8, "exception_type": 9},
    "moappcrash": {
        "app_name": 1,
        "app_version": 3,
        "faulting_module": 5,
        "module_version": 6,
        "exception_code": 8,
        "fault_offset": 9,
    },
    "apphangb1": _HANG_LAYOUT,
    "apphangxprocb1": _HANG_LAYOUT,
    "moapphang": _STORE_HANG_LAYOUT,
    "moapphangxproc": _STORE_HANG_LAYOUT,
}
CRASH_EVENT_TYPES = frozenset({"appcrash", "bex", "bex64", "clr20r3", "moappcrash"})
HANG_EVENT_TYPES = frozenset({"apphangb1", "apphangxprocb1", "moapphang", "moapphangxproc"})

# Short names for exception codes that commonly end a process; anything else falls back to Windows' own message.
EXCEPTION_NAMES: dict[int, str] = {
    0x40000015: "fatal application exit (abort)",
    0x80000003: "breakpoint",
    0xC0000005: "access violation",
    0xC0000006: "in-page I/O error",
    0xC000001D: "illegal instruction",
    0xC0000094: "integer divide by zero",
    0xC00000FD: "stack overflow",
    0xC0000135: "DLL not found",
    0xC0000142: "DLL initialization failed",
    0xC0000374: "heap corruption",
    0xC0000409: "stack buffer overrun / fail-fast",
    0xC0000417: "invalid parameter (C runtime)",
    0xC0000602: "fail-fast exception",
    0xC06D007E: "module not found (delay load)",
    0xC06D007F: "procedure not found (delay load)",
    0xE0434352: "unhandled .NET exception",
    0xE06D7363: "unhandled C++ exception",
}


def parse_hex(text: str) -> int | None:
    """``c0000005`` / ``0xC0000005`` → int (None if not hex)."""
    value = text.strip().lower().removeprefix("0x")
    if not value:
        return None
    try:
        return int(value, 16)
    except ValueError:
        return None


def describe_exception(code: int) -> str:
    """Short description of an exception code ("access violation"), or Windows' message, or ""."""
    name = EXCEPTION_NAMES.get(code)
    if name:
        return name
    message = describe_code(code) or ""
    return message.split(". ")[0].rstrip(".")


def exception_label(code: int) -> str:
    """``0xC0000005 (access violation)``."""
    description = describe_exception(code)
    return f"0x{code:08X} ({description})" if description else f"0x{code:08X}"


def map_signature(event_type: str, values: Sequence[str], names: Sequence[str] = ()) -> dict[str, str]:
    """Problem-signature values → fact names (``app_name``, ``faulting_module``, ``exception_code`` …).

    Descriptive names (Report.wer) win; the positional layout of the event type fills in the rest.
    """
    mapped: dict[str, str] = {}
    for name, value in zip(names, values, strict=False):
        target = SIGNATURE_NAMES.get(name.strip().lower())
        if target and value and target not in mapped:
            mapped[target] = value
    for target, position in SIGNATURE_LAYOUTS.get(event_type.strip().lower(), {}).items():
        if target not in mapped and position <= len(values) and values[position - 1]:
            mapped[target] = values[position - 1]
    return mapped


def filetime_to_datetime(text: str) -> datetime | None:
    """A FILETIME written as a decimal number → aware UTC datetime."""
    try:
        ticks = int(text.strip())
    except ValueError:
        return None
    if ticks <= 0:
        return None
    try:
        return FILETIME_EPOCH + timedelta(microseconds=ticks // FILETIME_TICKS_PER_MICROSECOND)
    except OverflowError:
        return None


@dataclass(frozen=True, slots=True)
class WerReport:
    """One parsed ``Report.wer``. ``fields`` keeps every raw ``Key=Value`` line."""

    event_type: str = ""  # APPCRASH, CLR20r3, BEX64, AppHangB1, …
    event_time: datetime | None = None  # aware UTC
    report_id: str = ""
    app_name: str = ""
    app_version: str = ""
    app_path: str = ""
    faulting_module: str = ""
    module_version: str = ""
    exception_code: int | None = None
    exception_type: str = ""  # .NET exception type (CLR20r3)
    fault_offset: str = ""
    friendly_name: str = ""  # e.g. "Stopped working"
    signature: dict[str, str] = field(default_factory=dict)  # Sig[n].Name → Sig[n].Value, in order
    dynamic_signature: dict[str, str] = field(default_factory=dict)
    ui: tuple[str, ...] = ()
    loaded_modules: tuple[str, ...] = ()
    fields: dict[str, str] = field(default_factory=dict)
    path: Path | None = None

    @property
    def is_crash(self) -> bool:
        return self.event_type.lower() in CRASH_EVENT_TYPES

    @property
    def is_hang(self) -> bool:
        return self.event_type.lower() in HANG_EVENT_TYPES

    def summary(self) -> str:
        """One line: local time, event type and what happened."""
        app = " ".join(part for part in (self.app_name or "unknown application", self.app_version) if part)
        module = " ".join(part for part in (self.faulting_module, self.module_version) if part)
        if self.is_hang:
            what = f"{app} stopped responding"
        elif self.exception_type:
            what = f"{app} crashed with unhandled .NET exception {self.exception_type}"
            what += f" in {module}" if module else ""
        elif self.is_crash or module or self.exception_code is not None:
            what = f"{app} crashed" + (f" in {module}" if module else "")
            if self.exception_code is not None:
                what += f" — exception {exception_label(self.exception_code)}"
            what += f" at offset {self.fault_offset}" if self.fault_offset else ""
        else:
            what = app
        stamp = to_local(self.event_time).strftime("%Y-%m-%d %H:%M:%S ") if self.event_time else ""
        return f"{stamp}{self.event_type or 'WER report'}: {what}"


def _indexed(lines: dict[str, str]) -> dict[str, dict[int, dict[str, str]]]:
    """``Sig[3].Name=x`` → {"sig": {3: {"name": "x"}}}; ``UI[2]=y`` → {"ui": {2: {"": "y"}}}."""
    table: dict[str, dict[int, dict[str, str]]] = {}
    for key, value in lines.items():
        match = _INDEXED_KEY.match(key)
        if match is not None:
            slot = table.setdefault(match["base"].lower(), {}).setdefault(int(match["index"]), {})
            slot[(match["part"] or "").lower()] = value
    return table


def _named_pairs(entries: dict[int, dict[str, str]]) -> dict[str, str]:
    return {parts.get("name") or f"P{index + 1}": parts.get("value", "") for index, parts in sorted(entries.items())}


def _ordered(entries: dict[int, dict[str, str]], part: str = "") -> list[str]:
    """Values by index, with "" for gaps, so list position == index."""
    if not entries:
        return []
    values = [""] * (max(entries) + 1)
    for index, parts in entries.items():
        values[index] = parts.get(part, "")
    return values


def parse_report(text: str, *, path: Path | None = None) -> WerReport:
    """Parse the text of a ``Report.wer`` file (already decoded)."""
    lines: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip().lstrip(BOM)
        if not line or line.startswith((";", "[")) or "=" not in line:
            continue
        key, _, value = line.partition("=")
        lines[key.strip()] = value.strip()
    table = _indexed(lines)
    signatures = table.get("sig", {})
    event_type = lines.get("EventType", "")
    mapped = map_signature(event_type, _ordered(signatures, "value"), _ordered(signatures, "name"))
    return WerReport(
        event_type=event_type,
        event_time=filetime_to_datetime(lines.get("EventTime", "")),
        report_id=lines.get("ReportIdentifier", ""),
        app_name=mapped.get("app_name") or lines.get("NsAppName") or lines.get("AppName", ""),
        app_version=mapped.get("app_version", ""),
        app_path=lines.get("AppPath", ""),
        faulting_module=mapped.get("faulting_module", ""),
        module_version=mapped.get("module_version", ""),
        exception_code=parse_hex(mapped.get("exception_code", "")),
        exception_type=mapped.get("exception_type", ""),
        fault_offset=_offset(mapped.get("fault_offset", "")),
        friendly_name=lines.get("FriendlyEventName", ""),
        signature=_named_pairs(signatures),
        dynamic_signature=_named_pairs(table.get("dynamicsig", {})),
        ui=tuple(value for value in _ordered(table.get("ui", {})) if value),
        loaded_modules=tuple(value for value in _ordered(table.get("loadedmodule", {})) if value),
        fields=lines,
        path=path,
    )


def _offset(text: str) -> str:
    """``000000000004f7a1`` → ``0x4f7a1``; anything that is not hex is kept as written."""
    value = parse_hex(text)
    return f"0x{value:x}" if value is not None else text.strip()


def read_report(path: str | os.PathLike[str]) -> WerReport:
    """Read and parse a ``Report.wer`` file (UTF-16 or UTF-8, BOM or not). Raises OSError if it cannot be read."""
    with open_shared(path) as handle:
        raw = handle.read(MAX_REPORT_BYTES)
    encoding = detect_encoding(raw[:ENCODING_SAMPLE_BYTES])
    text = raw[encoding.bom_len :].decode(encoding.codec, errors="replace")
    return parse_report(text, path=Path(path))


def default_report_roots() -> list[Path]:
    """Machine-wide and per-user WER folders (ReportArchive = sent/handled, ReportQueue = waiting)."""
    roots: list[Path] = []
    for variable in ("ProgramData", "LOCALAPPDATA"):
        base = os.environ.get(variable)
        if base:
            roots.extend(Path(base) / "Microsoft" / "Windows" / "WER" / sub for sub in REPORT_SUBDIRS)
    return roots


def find_reports(roots: Iterable[Path] | None = None, *, since: datetime | None = None) -> list[Path]:
    """``Report.wer`` files under ``roots`` (default: ``default_report_roots()``), newest first.

    ``since`` filters on the report file's modification time. Folders that are missing or unreadable are skipped.
    """
    found: list[tuple[float, Path]] = []
    threshold = since.timestamp() if since is not None else None
    for root in default_report_roots() if roots is None else roots:
        try:
            folders = [entry for entry in Path(root).iterdir() if entry.is_dir()]
        except OSError as exc:
            log.debug("skipping WER folder %s: %s", root, exc)
            continue
        for folder in folders:
            report = folder / REPORT_FILE
            try:
                modified = report.stat().st_mtime
            except OSError:
                continue
            if threshold is None or modified >= threshold:
                found.append((modified, report))
    found.sort(key=lambda item: item[0], reverse=True)
    return [report for _, report in found]
