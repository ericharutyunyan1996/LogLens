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


def unpacked_dir() -> Path:
    """Where compressed logs (.gz) are unpacked to, so they open like ordinary logs."""
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or str(Path.home() / ".cache")
    path = Path(base) / "LogLens" / "unpacked"
    path.mkdir(parents=True, exist_ok=True)
    return path


def plugins_dir() -> Path:
    """Plugin files (*.py) live here; the folder is created when LogLens first looks at it."""
    path = app_data_dir() / "plugins"
    path.mkdir(parents=True, exist_ok=True)
    return path


def plugin_logs_dir() -> Path:
    """Where lines read by a source plugin are written, so they open as an ordinary log tab."""
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or str(Path.home() / ".cache")
    path = Path(base) / "LogLens" / "plugins"
    path.mkdir(parents=True, exist_ok=True)
    return path


def container_logs_dir() -> Path:
    """Where Docker / Kubernetes log captures are written (machine-local, not roaming)."""
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or str(Path.home() / ".cache")
    path = Path(base) / "LogLens" / "containers"
    path.mkdir(parents=True, exist_ok=True)
    return path


def event_exports_dir() -> Path:
    """Where Windows Event Log exports are written (machine-local, not roaming)."""
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or str(Path.home() / ".cache")
    path = Path(base) / "LogLens" / "eventlogs"
    path.mkdir(parents=True, exist_ok=True)
    return path
