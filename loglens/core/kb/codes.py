"""Describe Windows error codes (Win32, HRESULT, NTSTATUS) with the system's own message tables."""

from __future__ import annotations

import re
import sys
from functools import cache

if sys.platform == "win32":
    import pywintypes
    import win32api
    import win32con

HEX_CODE = re.compile(r"(?<![\w.])0x[0-9a-fA-F]{8}(?![0-9a-fA-F])")
_PLACEHOLDER = re.compile(r"%(?:\d+|[a-zA-Z]{1,3})")
NTSTATUS_SEVERITY_ERROR = 0xC0000000


def find_codes(text: str) -> list[int]:
    """Failure codes (high bit set — HRESULT/NTSTATUS failures) written as 8-digit hex in ``text``, in order."""
    seen: dict[int, None] = {}
    for m in HEX_CODE.finditer(text):
        value = int(m.group(0), 16)
        if value & 0x80000000:
            seen.setdefault(value, None)
    return list(seen)


@cache
def describe_code(code: int) -> str | None:
    """Windows' message for ``code`` (placeholders like %1 / %p replaced by …), or None if unknown."""
    if sys.platform != "win32":  # pragma: no cover
        return None
    sources = ("ntdll", "system") if code & NTSTATUS_SEVERITY_ERROR == NTSTATUS_SEVERITY_ERROR else ("system", "ntdll")
    for source in sources:
        message = _ntstatus(code) if source == "ntdll" else _system(code)
        if message:
            return _PLACEHOLDER.sub("…", " ".join(message.split()))
    return None


def _system(code: int) -> str | None:
    flags = win32con.FORMAT_MESSAGE_FROM_SYSTEM | win32con.FORMAT_MESSAGE_IGNORE_INSERTS
    try:
        return str(win32api.FormatMessage(flags, None, code, 0, None)).strip() or None
    except pywintypes.error:
        return None


def _ntstatus(code: int) -> str | None:
    flags = win32con.FORMAT_MESSAGE_FROM_HMODULE | win32con.FORMAT_MESSAGE_IGNORE_INSERTS
    try:
        module = win32api.GetModuleHandle("ntdll.dll")
        # pywin32 accepts an HMODULE as the source with FORMAT_MESSAGE_FROM_HMODULE; the type stub only allows str
        return str(win32api.FormatMessage(flags, module, code, 0, None)).strip() or None  # type: ignore[arg-type]
    except pywintypes.error:
        return None
