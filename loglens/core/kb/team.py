"""A team knowledge folder: shared knowledge packs (TOML) and runbooks, optionally kept in Git.

Everything in the folder is read-only for LogLens: packs (``*.toml`` in the ``[[entry]]`` schema) become knowledge
entries marked "Team knowledge folder", and an entry's ``runbook`` is a web link or a file inside the folder
(``runbooks/db-timeout.md``). Updating the folder is the team's own Git workflow; LogLens only offers ``git pull``.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from .knowledge import ORIGIN_TEAM, KBEntry

log = logging.getLogger(__name__)
MAX_PACK_BYTES = 2_000_000
MAX_PACKS = 200
RUNBOOK_SUFFIXES = {".md", ".markdown", ".txt", ".html", ".htm", ".pdf"}
GIT_TIMEOUT_S = 60.0
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0


@dataclass(slots=True)
class TeamKnowledge:
    folder: Path
    entries: list[KBEntry] = field(default_factory=list)
    packs: list[str] = field(default_factory=list)  # pack files that were read
    problems: list[str] = field(default_factory=list)  # files / entries that were skipped, with the reason


def load_folder(folder: Path | str) -> TeamKnowledge:
    """Read every ``*.toml`` pack under ``folder``; bad files and entries are reported, never fatal."""
    root = Path(folder)
    result = TeamKnowledge(root)
    if not root.is_dir():
        result.problems.append(f"The folder {root} was not found.")
        return result
    seen: set[str] = set()
    files = sorted(p for p in root.rglob("*.toml") if ".git" not in p.parts)[:MAX_PACKS]
    for path in files:
        name = path.relative_to(root).as_posix()
        try:
            if path.stat().st_size > MAX_PACK_BYTES:
                result.problems.append(f"{name}: larger than {MAX_PACK_BYTES // 1_000_000} MB, skipped.")
                continue
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
            result.problems.append(f"{name}: cannot read ({exc}).")
            continue
        result.packs.append(name)
        for item in data.get("entry", []):
            try:
                entry = KBEntry.from_dict(item, ORIGIN_TEAM)
            except (KeyError, ValueError, TypeError, OverflowError) as exc:
                result.problems.append(f"{name}: an entry was skipped ({exc!r}).")
                continue
            except Exception as exc:  # a bad regular expression in a shared file must not stop the others  # noqa: BLE001
                result.problems.append(f"{name}: an entry was skipped ({exc}).")
                continue
            if entry.id in seen:
                result.problems.append(f"{name}: the id '{entry.id}' is used twice; the first one is kept.")
                continue
            seen.add(entry.id)
            result.entries.append(entry)
    return result


def runbook_target(runbook: str, folder: Path | str | None) -> tuple[str, str] | None:
    """(kind, target) for an entry's runbook: ``("url", …)`` for http(s) links, ``("file", path)`` for a file that
    exists inside ``folder``; None for anything else (other schemes, paths that leave the folder, missing files)."""
    text = runbook.strip()
    if not text:
        return None
    parsed = urlparse(text)
    if parsed.scheme in ("http", "https") and parsed.netloc:
        return "url", text
    if parsed.scheme or folder is None or text.startswith(("/", "\\")) or ":" in text:
        return None
    root = Path(folder).resolve()
    target = (root / text).resolve()
    if root not in target.parents or target.suffix.lower() not in RUNBOOK_SUFFIXES or not target.is_file():
        return None
    return "file", str(target)


def is_git_repo(folder: Path | str) -> bool:
    return (Path(folder) / ".git").exists()


def git_pull(folder: Path | str) -> tuple[bool, str]:
    """``git pull --ff-only`` in ``folder`` with the user's own git (their credentials, their remote)."""
    git = shutil.which("git")
    if git is None:
        return False, "Git is not installed (or not on PATH)."
    if not is_git_repo(folder):
        return False, "This folder is not a Git repository."
    try:
        done = subprocess.run(
            [git, "-C", str(folder), "pull", "--ff-only"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=GIT_TIMEOUT_S,
            creationflags=NO_WINDOW,
            check=False,
            stdin=subprocess.DEVNULL,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
    except subprocess.TimeoutExpired:
        return False, f"git did not finish within {GIT_TIMEOUT_S:.0f} seconds."
    except OSError as exc:
        return False, f"Could not run git: {exc}"
    output = " ".join((done.stdout or done.stderr or "").split())[:300]
    return done.returncode == 0, output or ("Up to date." if done.returncode == 0 else "git failed.")
