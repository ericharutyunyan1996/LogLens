"""Knowledge base model and matching.

``KnowledgeBase.explain(line)`` returns findings for a log line, most specific first:
Windows event (provider + id) → well-known message pattern → error codes (curated entry, else Windows' own text).
Findings from the user's own knowledge base (see ``user_store``) are listed before built-in ones.
"""

from __future__ import annotations

import re
import tomllib
from collections.abc import Iterable
from dataclasses import dataclass
from importlib import resources
from typing import Any

from ..winevent.models import EVENT_LINE
from .codes import describe_code, find_codes

NOISE_LEVELS = ("important", "normal", "benign")

ORIGIN_BUILTIN = "builtin"  # shipped with LogLens (builtin.toml)
ORIGIN_USER = "user"  # written by the user
ORIGIN_AI = "ai"  # an AI answer the user saved
ORIGIN_IMPORTED = "imported"  # imported from a shared knowledge pack
USER_ORIGINS = (ORIGIN_USER, ORIGIN_AI, ORIGIN_IMPORTED)  # entries that live in the user's knowledge base
ORIGIN_LABELS = {
    ORIGIN_BUILTIN: "LogLens knowledge base",
    ORIGIN_USER: "Your knowledge base",
    ORIGIN_AI: "AI answer you saved",
    ORIGIN_IMPORTED: "Imported knowledge pack",
}


def normalize_provider(name: str) -> str:
    """Event provider name as compared by the knowledge base (case-insensitive, "Microsoft-Windows-" optional)."""
    name = name.strip().lower()
    return name.removeprefix("microsoft-windows-")


@dataclass(frozen=True, slots=True)
class KBEntry:
    id: str
    title: str
    explanation: str
    causes: tuple[str, ...] = ()
    steps: tuple[str, ...] = ()
    noise: str = "normal"
    providers: tuple[str, ...] = ()
    event_ids: tuple[int, ...] = ()
    codes: tuple[int, ...] = ()
    patterns: tuple[re.Pattern[str], ...] = ()
    origin: str = "builtin"

    @classmethod
    def from_dict(cls, data: dict[str, Any], origin: str = "builtin") -> KBEntry:
        noise = data.get("noise", "normal")
        if noise not in NOISE_LEVELS:
            raise ValueError(f"{data.get('id')}: noise must be one of {NOISE_LEVELS}")
        return cls(
            id=str(data["id"]),
            title=str(data["title"]),
            explanation=str(data["explanation"]),
            causes=tuple(data.get("causes", ())),
            steps=tuple(data.get("steps", ())),
            noise=noise,
            providers=tuple(normalize_provider(p) for p in data.get("providers", ())),
            event_ids=tuple(int(i) for i in data.get("event_ids", ())),
            codes=tuple(int(c, 16) for c in data.get("codes", ())),
            patterns=tuple(re.compile(p, re.IGNORECASE) for p in data.get("patterns", ())),
            origin=origin,
        )

    def to_dict(self) -> dict[str, Any]:
        """This entry in the ``builtin.toml`` schema (empty fields omitted); ``from_dict`` reads it back."""
        data: dict[str, Any] = {"id": self.id}
        if self.providers:
            data["providers"] = list(self.providers)
        if self.event_ids:
            data["event_ids"] = list(self.event_ids)
        if self.codes:
            data["codes"] = [f"0x{code:08X}" for code in self.codes]
        if self.patterns:
            data["patterns"] = [p.pattern for p in self.patterns]
        data.update(noise=self.noise, title=self.title, explanation=self.explanation)
        if self.causes:
            data["causes"] = list(self.causes)
        if self.steps:
            data["steps"] = list(self.steps)
        return data

    def matches_event(self, provider: str, event_id: int) -> bool:
        if event_id not in self.event_ids:
            return False
        name = normalize_provider(provider)
        return any(p in ("*", name) or name.startswith(p) for p in self.providers)

    def matches(self, text: str) -> bool:
        """Whether this entry explains ``text`` (by event, pattern or error code)."""
        event = EVENT_LINE.match(text)
        if event is not None and self.matches_event(event["provider"], int(event["event_id"])):
            return True
        if any(p.search(text) for p in self.patterns):
            return True
        return bool(self.codes) and any(code in self.codes for code in find_codes(text))


@dataclass(frozen=True, slots=True)
class Finding:
    """One explanation for something seen in a line."""

    kind: str  # "event" | "pattern" | "code" | "system-code"
    matched: str  # what triggered it, e.g. "Service Control Manager 7031" or "0xC0000005"
    title: str
    explanation: str
    causes: tuple[str, ...] = ()
    steps: tuple[str, ...] = ()
    noise: str = "normal"
    source: str = ORIGIN_LABELS[ORIGIN_BUILTIN]  # where the explanation comes from, for display
    origin: str = ORIGIN_BUILTIN  # ORIGIN_* of the KB entry behind it

    @classmethod
    def from_entry(cls, entry: KBEntry, kind: str, matched: str) -> Finding:
        source = ORIGIN_LABELS.get(entry.origin, ORIGIN_LABELS[ORIGIN_BUILTIN])
        return cls(
            kind,
            matched,
            entry.title,
            entry.explanation,
            entry.causes,
            entry.steps,
            entry.noise,
            source=source,
            origin=entry.origin,
        )


class KnowledgeBase:
    def __init__(self, entries: list[KBEntry]) -> None:
        """``entries`` in precedence order: for the same error code the first entry wins."""
        self.entries = entries
        # specific providers first, then wildcard ('*') entries as a last resort (stable: keeps precedence order)
        self._event_entries = sorted((e for e in entries if e.event_ids), key=lambda e: "*" in e.providers)
        self._code_entries: dict[int, KBEntry] = {}
        for entry in entries:
            for code in entry.codes:
                self._code_entries.setdefault(code, entry)
        self._pattern_entries = [e for e in entries if e.patterns]

    @classmethod
    def combined(cls, builtin: KnowledgeBase, user_entries: Iterable[KBEntry]) -> KnowledgeBase:
        """Built-in knowledge plus the user's entries, the user's taking precedence (see :meth:`with_entries`)."""
        return builtin.with_entries(user_entries)

    def with_entries(self, entries: Iterable[KBEntry]) -> KnowledgeBase:
        """A new knowledge base where ``entries`` take precedence over this one's.

        An entry with the same id replaces this knowledge base's entry; all others are kept, with ``entries``
        consulted first (and their findings listed first).
        """
        preferred = list(entries)
        ids = {e.id for e in preferred}
        return KnowledgeBase(preferred + [e for e in self.entries if e.id not in ids])

    @classmethod
    def builtin(cls) -> KnowledgeBase:
        text = resources.files(__package__).joinpath("builtin.toml").read_text(encoding="utf-8")
        return cls.from_toml(text)

    @classmethod
    def from_toml(cls, text: str, origin: str = "builtin") -> KnowledgeBase:
        data = tomllib.loads(text)
        return cls([KBEntry.from_dict(item, origin) for item in data.get("entry", [])])

    def lookup_event(self, provider: str, event_id: int) -> list[KBEntry]:
        return [e for e in self._event_entries if e.matches_event(provider, event_id)]

    def explain(self, text: str) -> list[Finding]:
        """Findings for one line (or record), most specific first; each KB entry appears at most once."""
        findings: list[Finding] = []
        used: set[str] = set()

        def add(entry: KBEntry, kind: str, matched: str) -> None:
            if entry.id not in used:
                used.add(entry.id)
                findings.append(Finding.from_entry(entry, kind, matched))

        event = EVENT_LINE.match(text)
        if event is not None:
            provider, event_id = event["provider"], int(event["event_id"])
            for entry in self.lookup_event(provider, event_id):
                add(entry, "event", f"{provider} {event_id}")
        for entry in self._pattern_entries:
            match = next((m for p in entry.patterns if (m := p.search(text))), None)
            if match is not None:
                add(entry, "pattern", match.group(0))
        for code in find_codes(text):
            label = f"0x{code:08X}"
            code_entry = self._code_entries.get(code)
            if code_entry is not None:
                add(code_entry, "code", label)
            elif label not in used:
                message = describe_code(code)
                if message:
                    used.add(label)
                    findings.append(
                        Finding(
                            "system-code", label, f"{label} — {message}", message, source="Windows error message table"
                        )
                    )
        findings.sort(key=lambda f: f.origin not in USER_ORIGINS)  # stable: the user's own knowledge first
        return findings
