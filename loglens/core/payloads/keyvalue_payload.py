"""Structured fields written as ``key=value`` (logfmt) or ``Key: value, Key2: value`` runs."""

from __future__ import annotations

import re

from .base import Section

_VALUE = r"(?:\"(?:[^\"\\]|\\.)*\"|'[^']*'|[^\s,;&]+)"
_EQ_PAIR = re.compile(rf"(?P<key>[A-Za-z_][\w.\-]*)=(?P<value>{_VALUE})")
_COLON_PAIR = re.compile(r"(?P<key>[A-Za-z_][\w.\-]*): (?P<value>[^,;]+?)(?=\s*[,;]\s*[A-Za-z_][\w.\-]*: |\s*$|\.\s*$)")
_SEPARATOR = re.compile(r"^[\s,;]*$")
MIN_EQ_PAIRS = 3
MIN_COLON_PAIRS = 2


def _runs(pattern: re.Pattern[str], text: str, minimum: int) -> list[list[re.Match[str]]]:
    """Groups of consecutive matches separated only by whitespace/commas/semicolons."""
    runs: list[list[re.Match[str]]] = []
    current: list[re.Match[str]] = []
    for m in pattern.finditer(text):
        if current and not _SEPARATOR.match(text[current[-1].end() : m.start()]):
            if len(current) >= minimum:
                runs.append(current)
            current = []
        current.append(m)
    if len(current) >= minimum:
        runs.append(current)
    return runs


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1].replace('\\"', '"')
    return value


def _table(run: list[re.Match[str]]) -> str:
    width = min(max(len(m["key"]) for m in run), 40)
    return "\n".join(f"{m['key'].ljust(width)} = {_unquote(m['value'].strip())}" for m in run)


class KeyValueFormatter:
    kind = "Fields"

    def find(self, text: str) -> list[Section]:
        out = [
            Section(self.kind, _table(run), run[0].start(), run[-1].end())
            for run in _runs(_EQ_PAIR, text, MIN_EQ_PAIRS)
        ]
        for run in _runs(_COLON_PAIR, text, MIN_COLON_PAIRS):
            section = Section(self.kind, _table(run), run[0].start(), run[-1].end())
            if not any(section.overlaps(s) for s in out):
                out.append(section)
        return out
