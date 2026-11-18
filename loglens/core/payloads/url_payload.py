"""URLs with query strings and bare ``a=1&b=2`` query strings: show decoded parameters."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, unquote, urlsplit

from .base import Section

_URL = re.compile(r"\bhttps?://[^\s\"'<>`]+")
_QUERY = re.compile(r"(?<![\w/?&=])[\w.\-\[\]]+=[^&\s\"']*(?:&[\w.\-\[\]]+=[^&\s\"']*)+")


def _params_block(query: str) -> list[str]:
    pairs = parse_qsl(query, keep_blank_values=True)
    if not pairs:
        return []
    width = min(max(len(k) for k, _ in pairs), 40)
    return [f"  {k.ljust(width)} = {v}" for k, v in pairs]


class UrlFormatter:
    kind = "URL"

    def find(self, text: str) -> list[Section]:
        out: list[Section] = []
        covered: list[tuple[int, int]] = []
        for m in _URL.finditer(text):
            url = m.group(0).rstrip(".,;:)]}'\"")
            try:
                parts = urlsplit(url)
            except ValueError:  # e.g. "http://[not-an-ipv6" — not a URL we can decode, leave the text as it is
                continue
            if not parts.query:
                continue  # a plain URL is already readable
            lines = [
                f"{parts.scheme}://{parts.netloc}",
                f"path: {unquote(parts.path) or '/'}",
                "query:",
                *_params_block(parts.query),
            ]
            if parts.fragment:
                lines.append(f"fragment: {unquote(parts.fragment)}")
            out.append(Section(self.kind, "\n".join(lines), m.start(), m.start() + len(url)))
            covered.append((m.start(), m.start() + len(url)))
        for m in _QUERY.finditer(text):
            if any(a <= m.start() < b for a, b in covered):
                continue
            block = _params_block(m.group(0))
            if block:
                out.append(Section("Query string", "\n".join(block), m.start(), m.end()))
        return out
