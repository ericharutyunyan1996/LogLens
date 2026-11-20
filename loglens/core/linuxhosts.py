"""Logs of WSL distributions and Linux hosts (over the Windows ``ssh.exe``): tail a file or follow the journal.

Uses the programs Windows already has (``wsl.exe``, ``ssh.exe``). SSH runs with ``BatchMode``: it signs in with your
keys / ssh-agent only and never asks for or stores a password. Every value that reaches a command line is validated.
"""

from __future__ import annotations

import re
import subprocess
import sys

from .containers import NO_WINDOW, ContainerError, LogSource, find_tool

HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")
USER = re.compile(r"^[A-Za-z_][A-Za-z0-9._-]{0,63}$")
DISTRO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,63}$")
REMOTE_PATH = re.compile(r"^/[A-Za-z0-9_./@+:~-]{1,500}$")
UNIT = re.compile(r"^[A-Za-z0-9_.@:-]{1,100}$")


def _check(pattern: re.Pattern[str], value: str, what: str) -> str:
    if not pattern.match(value or "") or ".." in value.split("/"):
        raise ContainerError(f"'{value}' is not a valid {what}.")
    return value


def list_wsl_distros() -> list[str]:
    """Installed WSL distributions (``wsl.exe`` prints UTF-16)."""
    path = find_tool("wsl")
    if path is None:
        raise ContainerError("WSL is not installed (wsl.exe was not found).")
    try:
        done = subprocess.run([path, "-l", "-q"], capture_output=True, timeout=20, creationflags=NO_WINDOW, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ContainerError(f"wsl.exe did not answer: {exc}") from exc
    text = (
        done.stdout.decode("utf-16-le", "replace") if b"\x00" in done.stdout else done.stdout.decode("utf-8", "replace")
    )
    names = [line.strip().strip("\ufeff") for line in text.splitlines()]
    return [n for n in names if n and DISTRO.match(n)]


def _command(kind: str, target: str, lines: int, follow: bool) -> list[str]:
    count = str(max(0, min(int(lines), 1_000_000)))
    if kind == "file":
        return ["tail", "-n", count, *(["-F"] if follow else []), _check(REMOTE_PATH, target, "path")]
    if kind == "journal":
        argv = ["journalctl", "--no-pager", "-o", "short-iso", "-n", count]
        if target:
            argv += ["-u", _check(UNIT, target, "service name")]
        return [*argv, "-f"] if follow else argv
    raise ContainerError(f"unknown kind {kind!r}")


def wsl_source(distro: str, kind: str, target: str = "", *, lines: int = 1000, follow: bool = True) -> LogSource:
    _check(DISTRO, distro, "distribution name")
    argv = ("wsl", "-d", distro, "--", *_command(kind, target, lines, follow))
    return LogSource("wsl", f"wsl {distro} {target or 'journal'}".strip(), argv, follow)


def ssh_source(
    host: str, kind: str, target: str = "", *, user: str = "", lines: int = 1000, follow: bool = True
) -> LogSource:
    _check(HOST, host, "host name")
    login = ["-l", _check(USER, user, "user name")] if user else []
    remote = " ".join(_command(kind, target, lines, follow))  # every part is validated: no quoting is needed
    argv = ("ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", *login, host, remote)
    return LogSource("ssh", f"ssh {host} {target or 'journal'}".strip(), argv, follow)


def explain_ssh_failure(text: str) -> str:
    low = text.lower()
    if "permission denied" in low:
        return "SSH sign-in failed: LogLens uses your keys or ssh-agent only (no passwords). Add your key to the host."
    if "could not resolve" in low or "name or service not known" in low:
        return "The host name could not be found."
    if "timed out" in low or "connection refused" in low:
        return "The host did not answer on the SSH port."
    if "host key verification failed" in low:
        return "The host key is not trusted yet: connect once with `ssh <host>` in a terminal and accept it."
    return f"ssh failed: {' '.join(text.split())[:300] or 'no details'}"


IS_WINDOWS = sys.platform == "win32"
