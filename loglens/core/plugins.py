"""Plugins: Python files in ``%APPDATA%\\LogLens\\plugins`` that add log formats, analyzers and sources.

A plugin is one ``.py`` file with a few module-level names (interface version 1):

``PLUGIN``     ``{"name": …, "version": …, "api": 1, "description": …}``
``ANALYZERS``  ``[{"title": …, "run": fn(lines) -> str}]``   a report over the open log (``lines``: an iterable of str)
``FORMATS``    ``[{"name": …, "regex": …, …}]``               log formats in the same shape as File → Log formats
``SOURCES``    ``[{"title": …, "read": fn() -> iterable of str}]``   a place to read lines from, opened as a log tab

Plugins are ordinary Python code that runs with your permissions, so nothing runs until you enable it, and a plugin
stops being enabled when its file changes (the approval is tied to the file's SHA-256).
"""

from __future__ import annotations

import hashlib
import importlib.util
import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any

from .formats.base import FormatError, LogFormat
from .formats.custom import CustomFormat

log = logging.getLogger(__name__)
API_VERSION = 1
MAX_PLUGINS = 50
MAX_REPORT_CHARS = 200_000
MAX_SOURCE_LINES = 1_000_000


@dataclass(frozen=True, slots=True)
class Analyzer:
    plugin: str
    title: str
    run: Callable[[Iterable[str]], str]


@dataclass(frozen=True, slots=True)
class Source:
    plugin: str
    title: str
    read: Callable[[], Iterable[str]]


@dataclass(slots=True)
class PluginInfo:
    file: str  # file name inside the plugins folder
    path: Path
    sha256: str
    name: str = ""
    version: str = ""
    description: str = ""
    enabled: bool = False
    error: str = ""  # why it could not be loaded (enabled plugins only)
    analyzers: list[Analyzer] = field(default_factory=list)
    sources: list[Source] = field(default_factory=list)
    formats: list[LogFormat] = field(default_factory=list)

    @property
    def title(self) -> str:
        return self.name or self.file

    @property
    def status(self) -> str:
        if self.error:
            return "Problem"
        return "Enabled" if self.enabled else "Off"


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _text(value: object, default: str = "") -> str:
    return value if isinstance(value, str) else default


def load_module(path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(f"loglens_plugin_{path.stem}", path)
    if spec is None or spec.loader is None:
        raise ImportError("not a Python file")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _read_manifest(info: PluginInfo, module: ModuleType) -> None:
    """Fill ``info`` from the module's names; raises ValueError with a plain message for a bad plugin."""
    meta = getattr(module, "PLUGIN", None)
    if not isinstance(meta, dict):
        raise ValueError("it has no PLUGIN = {...} description")
    if meta.get("api") != API_VERSION:
        raise ValueError(f"it was written for plugin interface {meta.get('api')!r}; this LogLens uses {API_VERSION}")
    info.name, info.version, info.description = (_text(meta.get(k)) for k in ("name", "version", "description"))
    for item in _list(module, "ANALYZERS"):
        run = item.get("run") if isinstance(item, dict) else None
        if not callable(run) or not _text(item.get("title")):
            raise ValueError("an ANALYZERS entry needs a 'title' and a callable 'run'")
        info.analyzers.append(Analyzer(info.title, item["title"], run))
    for item in _list(module, "SOURCES"):
        read = item.get("read") if isinstance(item, dict) else None
        if not callable(read) or not _text(item.get("title")):
            raise ValueError("a SOURCES entry needs a 'title' and a callable 'read'")
        info.sources.append(Source(info.title, item["title"], read))
    for item in _list(module, "FORMATS"):
        try:
            info.formats.append(CustomFormat.from_dict(item).to_format())
        except (FormatError, TypeError, KeyError, ValueError) as exc:
            raise ValueError(f"a FORMATS entry is not valid: {exc}") from exc


def _list(module: ModuleType, name: str) -> list[Any]:
    value = getattr(module, name, [])
    if not isinstance(value, list | tuple):
        raise ValueError(f"{name} must be a list")
    return list(value)


def scan(folder: Path, enabled: dict[str, str]) -> list[PluginInfo]:
    """Plugins in ``folder``; only the ones whose file matches the approval in ``enabled`` are loaded (run)."""
    found: list[PluginInfo] = []
    if not folder.is_dir():
        return found
    for path in sorted(folder.glob("*.py"))[:MAX_PLUGINS]:
        try:
            info = PluginInfo(path.name, path, file_hash(path))
        except OSError as exc:
            log.warning("plugin %s unreadable: %s", path, exc)
            continue
        info.enabled = enabled.get(path.name) == info.sha256
        if info.enabled:
            try:
                _read_manifest(info, load_module(path))
            except Exception as exc:  # noqa: BLE001 - a broken plugin must never take the app down
                info.error = f"{type(exc).__name__}: {exc}"
                info.analyzers, info.sources, info.formats = [], [], []
                log.warning("plugin %s failed to load: %s", path.name, exc)
        found.append(info)
    return found


def describe_file(path: Path) -> tuple[str, str]:
    """(name, description) of a plugin that is not enabled, read without running it (from its source text)."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")[:20_000]
    except OSError:
        return "", ""
    import ast  # noqa: PLC0415

    try:
        tree = ast.parse(text)
    except SyntaxError:
        return "", "(the file has a syntax error)"
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "PLUGIN" for t in node.targets):
            try:
                meta = ast.literal_eval(node.value)
            except ValueError:
                return "", ""
            if isinstance(meta, dict):
                return _text(meta.get("name")), _text(meta.get("description"))
    return "", ""


def run_analyzer(analyzer: Analyzer, lines: Iterable[str]) -> str:
    """The analyzer's report; a failing plugin yields a readable error instead of an exception."""
    try:
        result = analyzer.run(lines)
    except Exception as exc:  # noqa: BLE001 - plugin code
        return f"The plugin '{analyzer.plugin}' failed: {type(exc).__name__}: {exc}"
    text = result if isinstance(result, str) else str(result)
    return text if len(text) <= MAX_REPORT_CHARS else text[:MAX_REPORT_CHARS] + "\n… (shortened)"


def read_source(source: Source) -> list[str]:
    """The lines a source plugin provides (bounded); errors become a one-line message."""
    try:
        out: list[str] = []
        for line in source.read():
            out.append(str(line).rstrip("\r\n"))
            if len(out) >= MAX_SOURCE_LINES:
                break
    except Exception as exc:  # noqa: BLE001 - plugin code
        return [f"The plugin '{source.plugin}' failed: {type(exc).__name__}: {exc}"]
    return out
