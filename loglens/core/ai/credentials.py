"""API keys live in the Windows Credential Manager (per user), never in settings.json.

Failures surface as ``OSError`` so callers don't depend on pywin32 types.
"""

from __future__ import annotations

import sys
from collections.abc import Iterable

if sys.platform == "win32":
    import pywintypes
    import win32cred

TARGET_PREFIX = "LogLens/"
ERROR_NOT_FOUND = 1168


def _target(name: str) -> str:
    return TARGET_PREFIX + name


def _os_error(exc: Exception) -> OSError:
    return OSError(getattr(exc, "winerror", None), getattr(exc, "strerror", str(exc)))


def save_secret(name: str, value: str) -> None:
    if sys.platform != "win32":  # pragma: no cover - Windows product
        raise OSError("secure credential storage is only available on Windows")
    try:
        win32cred.CredWrite(
            {
                "Type": win32cred.CRED_TYPE_GENERIC,
                "TargetName": _target(name),
                "UserName": "LogLens",
                "CredentialBlob": value,
                "Persist": win32cred.CRED_PERSIST_LOCAL_MACHINE,
                "Comment": "LogLens AI assistant",
            },
            0,
        )
    except pywintypes.error as exc:
        raise _os_error(exc) from exc


def load_secret(name: str) -> str | None:
    if sys.platform != "win32":  # pragma: no cover
        return None
    try:
        credential = win32cred.CredRead(_target(name), win32cred.CRED_TYPE_GENERIC, 0)
    except pywintypes.error as exc:
        if exc.winerror == ERROR_NOT_FOUND:
            return None
        raise _os_error(exc) from exc
    blob = credential["CredentialBlob"]
    return blob.decode("utf-16-le") if isinstance(blob, bytes) else str(blob)


def saved_secrets(names: Iterable[str]) -> list[str]:
    """The names (of ``names``) that currently have a stored value."""
    return [name for name in names if load_secret(name) is not None]


def delete_secrets(names: Iterable[str]) -> list[str]:
    """Delete every stored secret among ``names`` and return the ones that were there.

    Each deletion is checked by reading the entry back: if Windows still returns it, ``OSError`` is raised instead of
    reporting success. A secret that was never stored is not an error.
    """
    removed: list[str] = []
    for name in names:
        if load_secret(name) is None:
            continue
        delete_secret(name)
        if load_secret(name) is not None:
            raise OSError(f"The saved credential '{name}' is still stored after deleting it.")
        removed.append(name)
    return removed


def delete_secret(name: str) -> None:
    if sys.platform != "win32":  # pragma: no cover
        return
    try:
        win32cred.CredDelete(_target(name), win32cred.CRED_TYPE_GENERIC, 0)
    except pywintypes.error as exc:
        if exc.winerror != ERROR_NOT_FOUND:
            raise _os_error(exc) from exc
