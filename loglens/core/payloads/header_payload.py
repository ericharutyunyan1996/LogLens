"""Blocks of ``Name : value`` lines (HTTP headers, configuration dumps) inside a multi-line record."""

from __future__ import annotations

import re

from .base import Section

_HEADER_LINE = re.compile(r"^[ \t]*(?P<key>[A-Za-z][\w\-.]*(?: [\w\-.]+){0,3})[ \t]?:[ \t](?P<value>.*)$", re.M)
MIN_LINES = 3


class HeaderBlockFormatter:
    kind = "Headers"

    def find(self, text: str) -> list[Section]:
        if "\n" not in text:
            return []
        out: list[Section] = []
        block: list[re.Match[str]] = []

        def flush() -> None:
            if len(block) >= MIN_LINES:
                width = min(max(len(m["key"]) for m in block), 40)
                body = "\n".join(f"{m['key'].ljust(width)} : {m['value']}" for m in block)
                out.append(Section(self.kind, body, block[0].start(), block[-1].end()))
            block.clear()

        for m in _HEADER_LINE.finditer(text):
            if block and text[block[-1].end() : m.start()] != "\n":
                flush()
            block.append(m)
        flush()
        return out
