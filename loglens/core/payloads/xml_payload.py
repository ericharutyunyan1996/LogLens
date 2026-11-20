"""XML payloads (SOAP envelopes, XML API bodies, serialized objects) embedded in a line."""

from __future__ import annotations

import re
from xml.dom import minidom
from xml.parsers.expat import ExpatError

from .base import Section

# A real element start: "<name ", "<name>", "<ns:name/" or an XML declaration — not "<NULL>"-style placeholders
# alone (those fail to parse) and not "<2588330>" (names can't start with a digit).
_ELEMENT_START = re.compile(r"<(?:\?xml|[A-Za-z_][\w.\-]*(?::[\w.\-]+)?[\s>/])")
MAX_ATTEMPTS = 20
# A DTD can declare entities that expand exponentially or point at files / URLs: such a document is never parsed
# (it stays visible as plain text).
_DOCTYPE = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)", re.IGNORECASE)


def _pretty(fragment: str) -> str:
    xml = minidom.parseString(fragment).toprettyxml(indent="  ")
    return "\n".join(x for x in xml.splitlines() if x.strip() and not x.startswith("<?xml"))


class XmlFormatter:
    kind = "XML"

    def find(self, text: str) -> list[Section]:
        end = text.rfind(">")
        for attempt, m in enumerate(_ELEMENT_START.finditer(text)):
            start = m.start()
            if attempt >= MAX_ATTEMPTS or end <= start:
                break
            if _DOCTYPE.search(text, start, end + 1):
                return []
            try:
                body = _pretty(text[start : end + 1])
            except (ExpatError, ValueError):
                continue
            return [Section(self.kind, body, start, end + 1)]
        return []
