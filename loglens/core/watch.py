"""Live watch: alert rules over newly appended lines, and "follow the newest file in a folder" profiles.

Pure logic (no Qt, no timers): callers feed matches with the time they were seen; the evaluator decides when a rule
fires, honouring a threshold within a sliding window and a cooldown so a burst produces one notification.
"""

from __future__ import annotations

import fnmatch
import os
from collections import deque
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .patterns import PatternMiner
from .search import SearchQuery

DEFAULT_WINDOW_S = 60
DEFAULT_COOLDOWN_S = 300  # after firing, a rule stays quiet this long (one toast per incident, not per line)
MAX_FOLDER_ENTRIES = 50_000  # stop scanning absurdly large folders
NEW_PATTERN_BASELINE_LINES = 50_000  # recent lines that define "known" messages for the new-pattern alert
KIND_MATCH = "match"  # lines matching the rule's query
KIND_NEW_PATTERN = "new-pattern"  # a kind of message the log never wrote before


@dataclass(frozen=True, slots=True)
class AlertRule:
    name: str
    query: SearchQuery
    threshold: int = 1  # matches needed within ``window_s`` to fire
    window_s: int = DEFAULT_WINDOW_S
    cooldown_s: int = DEFAULT_COOLDOWN_S
    enabled: bool = True
    kind: str = KIND_MATCH

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "name": self.name,
            "pattern": self.query.pattern,
            "regex": self.query.regex,
            "case_sensitive": self.query.case_sensitive,
            "threshold": self.threshold,
            "window_s": self.window_s,
            "cooldown_s": self.cooldown_s,
            "enabled": self.enabled,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AlertRule:
        query = SearchQuery(
            str(data["pattern"]), regex=bool(data.get("regex")), case_sensitive=bool(data.get("case_sensitive"))
        )
        return cls(
            str(data.get("name") or data["pattern"]),
            query,
            max(int(data.get("threshold", 1)), 1),
            max(int(data.get("window_s", DEFAULT_WINDOW_S)), 1),
            max(int(data.get("cooldown_s", DEFAULT_COOLDOWN_S)), 0),
            bool(data.get("enabled", True)),
            KIND_NEW_PATTERN if data.get("kind") == KIND_NEW_PATTERN else KIND_MATCH,
        )


def default_alert_rules() -> list[AlertRule]:
    """Sensible starting points (disabled until the user turns them on)."""
    fatal = SearchQuery(r"\b(?:FATAL|CRITICAL|CRIT|EMERG(?:ENCY)?)\b", regex=True, case_sensitive=True)
    errors = SearchQuery(r"\b(?:ERROR|ERR|FAIL(?:ED|URE)?)\b", regex=True, case_sensitive=True)
    return [
        AlertRule("Fatal / critical line", fatal, threshold=1, enabled=False),
        AlertRule("Burst of errors (10 in a minute)", errors, threshold=10, window_s=60, enabled=False),
        new_pattern_rule(enabled=False),
    ]


def new_pattern_rule(*, enabled: bool = True) -> AlertRule:
    return AlertRule("A new kind of message appears", SearchQuery(""), enabled=enabled, kind=KIND_NEW_PATTERN)


class NewPatternDetector:
    """Knows the message patterns a log has written; reports appended lines that start a new pattern."""

    def __init__(self, baseline: Iterable[tuple[int, str]]) -> None:
        self._miner = PatternMiner()
        for number, text in baseline:
            self._miner.add(number, text)

    def feed(self, lines: Iterable[tuple[int, str]]) -> list[tuple[int, str]]:
        new = []
        for number, text in lines:
            before = len(self._miner)
            self._miner.add(number, text)
            if len(self._miner) > before:
                new.append((number, text))
        return new


@dataclass(frozen=True, slots=True)
class Alert:
    rule: AlertRule
    source: str  # file path / tab title
    count: int  # matches in the window when it fired
    first_line: int  # 0-based line that started the burst
    last_line: int
    sample: str  # text of the last matching line


@dataclass
class _RuleState:
    seen: deque[tuple[float, int]] = field(default_factory=deque)  # (time, line)
    quiet_until: float = 0.0


class AlertEvaluator:
    """Decides when rules fire. ``feed`` is called with the matches of one batch of appended lines."""

    def __init__(self, rules: Sequence[AlertRule], source: str) -> None:
        self.rules = [r for r in rules if r.enabled and r.kind == KIND_MATCH]
        self.source = source
        self._state = [_RuleState() for _ in self.rules]

    def feed(self, now: float, matches: Sequence[Sequence[tuple[int, str]]]) -> list[Alert]:
        """``matches[i]`` = (line, text) pairs matched by ``self.rules[i]`` in this batch, seen at ``now``."""
        fired = []
        for rule, state, hits in zip(self.rules, self._state, matches, strict=True):
            for line, _text in hits:
                state.seen.append((now, line))
            while state.seen and state.seen[0][0] < now - rule.window_s:
                state.seen.popleft()
            if hits and len(state.seen) >= rule.threshold and now >= state.quiet_until:
                fired.append(Alert(rule, self.source, len(state.seen), state.seen[0][1], hits[-1][0], hits[-1][1]))
                state.quiet_until = now + rule.cooldown_s
                state.seen.clear()
        return fired


# ---- folder profiles ---------------------------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class WatchProfile:
    """Follow the newest file matching ``pattern`` in ``folder`` (rolling logs: app-20261113.log, …)."""

    name: str
    folder: str
    pattern: str = "*.log"
    recursive: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "folder": self.folder, "pattern": self.pattern, "recursive": self.recursive}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WatchProfile:
        return cls(
            str(data["name"]), str(data["folder"]), str(data.get("pattern") or "*.log"), bool(data.get("recursive"))
        )


def newest_file(folder: str | Path, pattern: str = "*.log", *, recursive: bool = False) -> Path | None:
    """Most recently modified file matching ``pattern`` (several patterns separated by ';'), or None."""
    patterns = [p.strip() for p in pattern.split(";") if p.strip()] or ["*"]
    best: tuple[float, str] | None = None
    for entry in _entries(Path(folder), recursive):
        if not any(fnmatch.fnmatch(entry.name.lower(), p.lower()) for p in patterns):
            continue
        try:
            stat = entry.stat()
        except OSError:
            continue
        key = (stat.st_mtime, entry.path)
        if best is None or key > best:
            best = key
    return Path(best[1]) if best else None


def _entries(folder: Path, recursive: bool) -> Iterable[os.DirEntry[str]]:
    pending, count = [folder], 0
    while pending:
        try:
            with os.scandir(pending.pop()) as items:
                for entry in items:
                    count += 1
                    if count > MAX_FOLDER_ENTRIES:
                        return
                    if entry.is_file(follow_symlinks=False):
                        yield entry
                    elif recursive and entry.is_dir(follow_symlinks=False):
                        pending.append(Path(entry.path))
        except OSError:
            continue
