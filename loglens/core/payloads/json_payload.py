"""JSON payloads, anywhere in a line (after a log prefix, several per line, nested in string values)."""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

from .base import Section
from .encoding_utils import decode_base64_text

_decoder = json.JSONDecoder()
MAX_DERIVED = 10
MAX_DEPTH = 6


def is_payload(value: object) -> bool:
    """True for JSON values that look like data, not log decoration such as a thread id ``[11]``."""
    if isinstance(value, dict):
        return True
    if isinstance(value, list):
        if any(isinstance(x, (dict, list)) for x in value):
            return True
        return len(value) >= 2 and any(isinstance(x, str) for x in value)
    return False


def dumps(value: object) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False)


def iter_json_values(text: str) -> Iterator[tuple[int, int, Any]]:
    """Non-overlapping ``(start, end, value)`` of payload-like JSON values in ``text``."""
    pos, n = 0, len(text)
    while pos < n:
        starts = [s for s in (text.find("{", pos), text.find("[", pos)) if s >= 0]
        if not starts:
            return
        start = min(starts)
        try:
            value, end = _decoder.raw_decode(text, start)
        except ValueError:
            pos = start + 1
            continue
        if is_payload(value):
            yield start, end, value
            pos = end
        else:
            pos = start + 1


def _walk_strings(value: object, path: str = "", depth: int = 0) -> Iterator[tuple[str, str]]:
    if depth > MAX_DEPTH:
        return
    items: Any = value.items() if isinstance(value, dict) else enumerate(value) if isinstance(value, list) else ()
    for key, child in items:
        sub = f"{path}.{key}" if path else str(key)
        if isinstance(child, str):
            yield sub, child
        else:
            yield from _walk_strings(child, sub, depth + 1)


def _derived_sections(value: object) -> list[Section]:
    """Readable views of string values: multi-line text, JSON-in-a-string, base64-encoded JSON."""
    out: list[Section] = []
    for path, text in _walk_strings(value):
        if len(out) >= MAX_DERIVED:
            break
        if "\n" in text:
            out.append(Section(f"{path} (text)", text))
            continue
        stripped = text.strip()
        if stripped[:1] in "{[" and len(stripped) > 2:
            try:
                inner = json.loads(stripped)
            except ValueError:
                inner = None
            if is_payload(inner):
                out.append(Section(f"{path} (embedded JSON)", dumps(inner)))
                continue
        decoded = decode_base64_text(stripped) if len(stripped) >= 24 else None
        if decoded and decoded.lstrip()[:1] in "{[":
            try:
                inner = json.loads(decoded)
            except ValueError:
                continue
            if is_payload(inner):
                out.append(Section(f"{path} (base64 → JSON)", dumps(inner)))
    return out


class JsonFormatter:
    kind = "JSON"

    def find(self, text: str) -> list[Section]:
        located: list[Section] = []
        derived: list[Section] = []
        for start, end, value in iter_json_values(text):
            located.append(Section(self.kind, dumps(value), start, end))
            derived.extend(_derived_sections(value))
        return located + derived
