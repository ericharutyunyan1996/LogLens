"""Incident builder: pin lines from any logs to one timeline, label them, add notes, export a report.

Bookmarks mark lines inside one log; an incident collects the lines that tell the story across logs and servers —
what triggered it, the symptoms, the root cause, the fix — in time order, with the evidence kept as text so the report
still makes sense when the logs are gone.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from .secrets import SecretMasker
from .timeparse import parse_line_time

LABELS = ("", "Trigger", "Symptom", "Root cause", "Impact", "Mitigation", "Fix", "Note")
FORMAT_VERSION = 1
MAX_TEXT = 4_000
MAX_ITEMS = 2_000


@dataclass(slots=True)
class PinnedLine:
    source: str  # the log's name as shown in its tab
    path: str  # where to find it again ("" when unknown)
    line: int  # 0-based
    text: str
    time: str = ""  # ISO time of the line, "" when it has none
    label: str = ""
    note: str = ""

    def moment(self) -> datetime | None:
        try:
            return datetime.fromisoformat(self.time) if self.time else None
        except ValueError:
            return None

    @property
    def key(self) -> tuple[str, int]:
        return (self.path or self.source, self.line)


@dataclass(slots=True)
class Incident:
    title: str = "Incident"
    summary: str = ""
    items: list[PinnedLine] = field(default_factory=list)

    def pin(
        self, source: str, path: str, line: int, text: str, *, label: str = "", note: str = ""
    ) -> PinnedLine | None:
        """Add a line (None when it is already pinned or the incident is full)."""
        if len(self.items) >= MAX_ITEMS or any(i.key == (path or source, line) for i in self.items):
            return None
        moment = parse_line_time(text)
        item = PinnedLine(source, path, line, text[:MAX_TEXT], moment.isoformat() if moment else "", label, note)
        self.items.append(item)
        return item

    def unpin(self, item: PinnedLine) -> None:
        self.items = [i for i in self.items if i is not item]

    def timeline(self) -> list[PinnedLine]:
        """Pinned lines in time order; lines without a time keep their pin order after the timed ones."""
        timed = sorted((i for i in self.items if i.moment()), key=lambda i: (i.moment(), i.source, i.line))
        return timed + [i for i in self.items if not i.moment()]

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": FORMAT_VERSION,
            "title": self.title,
            "summary": self.summary,
            "items": [asdict(i) for i in self.items],
        }

    @classmethod
    def from_dict(cls, data: object) -> Incident:
        if not isinstance(data, dict):
            raise ValueError("not an incident file")
        items = []
        for raw in data.get("items", []):
            if not isinstance(raw, dict):
                continue
            try:
                items.append(
                    PinnedLine(
                        str(raw.get("source", "")),
                        str(raw.get("path", "")),
                        int(raw.get("line", 0)),
                        str(raw.get("text", ""))[:MAX_TEXT],
                        str(raw.get("time", "")),
                        str(raw.get("label", "")) if raw.get("label", "") in LABELS else "",
                        str(raw.get("note", "")),
                    )
                )
            except (TypeError, ValueError):
                continue
        return cls(str(data.get("title", "Incident")), str(data.get("summary", "")), items[:MAX_ITEMS])


def save(incident: Incident, path: Path) -> None:
    path.write_text(json.dumps(incident.to_dict(), indent=2), encoding="utf-8")


def load(path: Path) -> Incident:
    try:
        return Incident.from_dict(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError) as exc:
        raise ValueError(f"Cannot read the incident file: {exc}") from exc


def render_markdown(
    incident: Incident, *, mask_secrets: bool = True, transform: Callable[[str], str] | None = None
) -> str:
    """The report: summary, a short list by label, then the timeline with evidence and notes.

    ``mask_secrets`` hides passwords and tokens in the evidence; ``transform`` (e.g. a pseudonymiser) is applied to
    every text that leaves the program.
    """
    masker = SecretMasker()

    def clean(text: str) -> str:
        if mask_secrets:
            text = masker.mask_line(text)
        return transform(text) if transform else text

    out = [f"# {clean(incident.title)}", ""]
    if incident.summary.strip():
        out += [clean(incident.summary.strip()), ""]
    items = incident.timeline()
    labelled = [i for i in items if i.label]
    if labelled:
        out += ["## Key moments", ""]
        for item in labelled:
            when = f"{item.moment():%Y-%m-%d %H:%M:%S}" if item.moment() else "time unknown"
            out.append(
                f"- **{item.label}** ({when}, {clean(item.source)}): "
                f"{clean(item.note) or clean(item.text.strip())[:160]}"
            )
        out.append("")
    out += ["## Timeline", ""]
    if not items:
        out += ["Nothing pinned yet.", ""]
    for item in items:
        moment = item.moment()
        when = f"{moment:%Y-%m-%d %H:%M:%S}" if moment else "time unknown"
        label = f" — **{item.label}**" if item.label else ""
        out.append(f"### {when}{label}")
        out.append(f"`{clean(item.source)}`, line {item.line + 1}")
        out += ["", "```", clean(item.text.rstrip()), "```", ""]
        if item.note.strip():
            out += [clean(item.note.strip()), ""]
    return "\n".join(out)
