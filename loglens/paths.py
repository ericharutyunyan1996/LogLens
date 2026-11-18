"""Where LogLens keeps its own files."""

from __future__ import annotations

import os
from pathlib import Path


def app_data_dir() -> Path:
    base = os.environ.get("APPDATA") or str(Path.home() / ".config")
    path = Path(base) / "LogLens"
    path.mkdir(parents=True, exist_ok=True)
    return path


def settings_file() -> Path:
    return app_data_dir() / "settings.json"


def log_dir() -> Path:
    """Logs are machine-local and must never go under Program Files (not writable by standard users)."""
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or str(Path.home() / ".cache")
    path = Path(base) / "LogLens" / "logs"
    path.mkdir(parents=True, exist_ok=True)
    return path


def log_file() -> Path:
    return log_dir() / "loglens.log"


def event_exports_dir() -> Path:
    """Where Windows Event Log exports are written (machine-local, not roaming)."""
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or str(Path.home() / ".cache")
    path = Path(base) / "LogLens" / "eventlogs"
    path.mkdir(parents=True, exist_ok=True)
    return path
