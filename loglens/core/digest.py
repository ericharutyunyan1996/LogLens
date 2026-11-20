"""Digest of new problems: what went wrong in some logs since the last digest.

State is kept per file as the number of lines already reported, so a daily digest only says what is new; a file that
became shorter (rotated, truncated) is read from its start again.
"""

from __future__ import annotations

import glob
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from .text_source import TextLogSource
from .triage import TOP, triage

log = logging.getLogger(__name__)
LOG_SUFFIXES = {".log", ".txt", ".out", ".err", ".json", ".jsonl"}
MAX_FILES = 200
MAX_NEW_LINES = 200_000  # per file and digest: a flood is summarised from its first lines (the summary says so)


@dataclass(slots=True)
class FileDigest:
    path: str
    new_lines: int
    errors: int
    warnings: int
    first_error: str = ""
    top_errors: list[tuple[int, str]] = field(default_factory=list)  # (count, pattern)
    truncated: bool = False


@dataclass(slots=True)
class Digest:
    when: datetime
    files: list[FileDigest] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)  # files that could not be read

    @property
    def errors(self) -> int:
        return sum(f.errors for f in self.files)

    @property
    def warnings(self) -> int:
        return sum(f.warnings for f in self.files)

    @property
    def has_news(self) -> bool:
        return bool(self.errors or self.warnings or self.problems)

    def render(self, title: str = "LogLens digest") -> str:
        out = [f"{title} ({self.when:%Y-%m-%d %H:%M})", ""]
        scanned = sum(f.new_lines for f in self.files)
        out.append(
            f"{self.errors:,} errors and {self.warnings:,} warnings in {scanned:,} new lines of {len(self.files)} logs."
        )
        out.append("")
        for f in sorted((f for f in self.files if f.errors or f.warnings), key=lambda f: (-f.errors, -f.warnings)):
            out.append(f"{Path(f.path).name}: {f.errors:,} errors, {f.warnings:,} warnings ({f.new_lines:,} new lines)")
            if f.first_error:
                out.append(f"  first error: {f.first_error}")
            out += [f"  {count:,}× {pattern}" for count, pattern in f.top_errors]
            if f.truncated:
                out.append("  (a very large amount of new lines: only the first ones were examined)")
        out += [f"! {p}" for p in self.problems]
        if not self.has_news:
            out.append("Nothing new to report.")
        return "\n".join(out)


def expand(patterns: list[str]) -> list[Path]:
    """Files named by ``patterns`` (paths, globs or folders; folders contribute their log files)."""
    found: list[Path] = []
    for pattern in patterns:
        matches = [Path(m) for m in glob.glob(pattern, recursive=True)] or [Path(pattern)]  # noqa: PTH207 - user-typed glob
        for path in matches:
            if path.is_dir():
                found += sorted(p for p in path.rglob("*") if p.is_file() and p.suffix.lower() in LOG_SUFFIXES)
            elif path.is_file():
                found.append(path)
    unique = list(dict.fromkeys(p.resolve() for p in found))
    return unique[:MAX_FILES]


def load_state(path: Path) -> dict[str, int]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {str(k): int(v) for k, v in data.items() if isinstance(v, int)} if isinstance(data, dict) else {}


def save_state(path: Path, state: dict[str, int]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=1), encoding="utf-8")


def build(patterns: list[str], state: dict[str, int], *, now: datetime | None = None) -> Digest:
    """Digest of the new lines of every matching file; ``state`` (path → lines reported) is updated in place."""
    digest = Digest(now or datetime.now().astimezone())
    for path in expand(patterns):
        key = str(path)
        try:
            source = TextLogSource(path)
            source.build_index()
            total = source.line_count()
        except OSError as exc:
            digest.problems.append(f"{path.name}: cannot read ({exc})")
            continue
        start = state.get(key, 0)
        if start > total:  # rotated or truncated: everything in it is new
            start = 0
        count = min(total - start, MAX_NEW_LINES)
        state[key] = start + count if count < total - start else total
        if count <= 0:
            digest.files.append(FileDigest(key, 0, 0, 0))
            continue
        result = triage(enumerate(source.get_lines(start, count), start), total)
        digest.files.append(
            FileDigest(
                key,
                count,
                result.problems,
                result.levels.get("Warning", 0),
                f"line {result.first_problem.line + 1}: {result.first_problem.text[:160]}"
                if result.first_problem
                else "",
                [(p.count, p.template[:140]) for p in result.problem_patterns[:TOP]],
                total - start > MAX_NEW_LINES,
            )
        )
    return digest


def build_events(
    channels: list[str],
    state: dict[str, int],
    *,
    server: object | None = None,
    reader: object | None = None,
    now: datetime | None = None,
    first_period: timedelta = timedelta(hours=24),
) -> Digest:
    """Digest of Windows events (errors and warnings) of this computer or ``server`` since the last digest.

    ``state`` remembers, per channel, the time (epoch seconds) up to which events were reported; the first run looks
    back ``first_period``.
    """
    from collections import Counter  # noqa: PLC0415

    from .winevent.reader import EventLogError, EventQuery, read_events  # noqa: PLC0415

    read = reader or read_events
    moment = now or datetime.now().astimezone()
    digest = Digest(moment)
    where = getattr(server, "name", "") or "this computer"
    for channel in channels:
        key = f"event:{where}:{channel}"
        since = datetime.fromtimestamp(state[key]).astimezone() if key in state else moment - first_period
        query = EventQuery(channel, since=since, until=moment, levels=(1, 2, 3), max_events=20_000, server=server)  # type: ignore[arg-type]
        label = f"{where}: {channel}"
        try:
            events = list(read(query))  # type: ignore[operator]
        except EventLogError as exc:
            digest.problems.append(f"{label}: {exc}")
            continue
        state[key] = int(moment.timestamp())
        errors = [e for e in events if e.level in (1, 2)]
        counts = Counter(f"{e.provider} ({e.event_id})" for e in errors)
        first = min(errors, key=lambda e: e.time_created, default=None)
        digest.files.append(
            FileDigest(
                label,
                len(events),
                len(errors),
                len(events) - len(errors),
                f"{first.time_created:%H:%M:%S} {first.provider} ({first.event_id}): {first.text()[:140]}"
                if first
                else "",
                [(n, name) for name, n in counts.most_common(TOP)],
            )
        )
    return digest
