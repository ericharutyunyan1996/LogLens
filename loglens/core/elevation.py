"""Administrator rights: detect them, and relaunch LogLens elevated (UAC prompt) with the same files open.

Some logs need elevation: the Security event log, Windows Setup / Panther logs, some WER reports. LogLens never asks
for rights up front; it offers a restart when it meets such a log.

Elevating is only offered for an executable the user's own (unelevated) programs can't replace: a LogLens installed
per user (under %LOCALAPPDATA%), unpacked in Downloads or run from %TEMP% could be swapped by any process running as
the user, which would then get administrator rights through the UAC prompt the user approves for "LogLens".
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

log = logging.getLogger(__name__)
SHELL_EXECUTE_OK = 32  # ShellExecuteW returns a value > 32 on success
NEW_WINDOW_FLAG = "--new-window"  # the elevated copy must not hand its files back to this (unelevated) window
# Folders the signed-in user can write to without elevation. os.access can't tell on Windows (it ignores ACLs), so
# the executable's location is compared with these instead.
USER_WRITABLE_FOLDERS = ("LOCALAPPDATA", "APPDATA", "USERPROFILE", "TEMP", "TMP")


def is_admin() -> bool:
    if sys.platform != "win32":  # pragma: no cover - Windows product
        return False
    import ctypes  # noqa: PLC0415 - Windows-only API

    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def relaunch_command(paths: Sequence[str]) -> tuple[str, list[str]]:
    """Executable and arguments that start this LogLens (frozen exe or ``python -m loglens``) with ``paths``."""
    arguments = [NEW_WINDOW_FLAG, *paths]
    if getattr(sys, "frozen", False):
        return sys.executable, arguments
    return sys.executable, ["-m", "loglens", *arguments]


def _normalized(path: str) -> str:
    return os.path.normcase(os.path.realpath(path))


def _is_inside(path: str, folder: str) -> bool:
    try:
        return os.path.commonpath([path, folder]) == folder
    except ValueError:  # different drives
        return False


def _user_writable_folder(executable: str) -> str | None:
    """The user-writable folder (from USER_WRITABLE_FOLDERS) that contains ``executable``, if any."""
    target = _normalized(executable)
    for variable in USER_WRITABLE_FOLDERS:
        folder = os.environ.get(variable, "").strip()
        if folder and _is_inside(target, _normalized(folder)):
            return folder
    return None


def elevation_is_safe() -> tuple[bool, str]:
    """Whether "Restart as administrator" may elevate this LogLens, and why not (or a warning) as text.

    A frozen LogLens inside the user profile, %APPDATA%, %LOCALAPPDATA% or %TEMP% is refused: anything running as the
    user could replace it before it runs elevated. Running from source is a developer setup: allowed, with a warning
    (the interpreter and the checkout are usually user-writable too).
    """
    if not getattr(sys, "frozen", False):
        return True, (
            f"LogLens runs from source ({sys.executable}); the elevated copy will run code from a folder your account "
            "can change. Fine for development, not for production use."
        )
    folder = _user_writable_folder(sys.executable)
    if folder is not None:
        return False, (
            f"LogLens runs from {Path(sys.executable).parent}, inside {folder}, which programs running under your "
            "account can change — restarting it as administrator could run a replaced program with full rights. "
            "Install LogLens for all users (in Program Files) to open logs that need administrator rights, or start "
            "it with “Run as administrator” from a trusted location."
        )
    return True, ""


def _shell_execute_runas(executable: str, parameters: str) -> int:  # pragma: no cover - shows the UAC prompt
    import ctypes  # noqa: PLC0415 - Windows-only API

    return int(ctypes.windll.shell32.ShellExecuteW(None, "runas", executable, parameters, None, 1))


def relaunch_elevated(paths: Sequence[str]) -> bool:
    """Start an elevated LogLens (Windows shows the UAC prompt); False if refused as unsafe, declined or failed.

    Call :func:`elevation_is_safe` first to tell the user why it is refused.
    """
    if sys.platform != "win32":  # pragma: no cover - Windows product
        return False
    safe, reason = elevation_is_safe()
    if not safe:
        log.warning("not restarting as administrator: %s", reason)
        return False
    if reason:
        log.warning("restarting as administrator: %s", reason)
    executable, arguments = relaunch_command(paths)
    try:
        result = _shell_execute_runas(executable, subprocess.list2cmdline(arguments))
    except (AttributeError, OSError) as exc:
        log.warning("elevated relaunch failed: %s", exc)
        return False
    return result > SHELL_EXECUTE_OK
