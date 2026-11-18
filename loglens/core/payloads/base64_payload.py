"""Long base64 tokens that decode to readable text (often JSON, XML or a message body)."""

from __future__ import annotations

import re

from .base import Section
from .encoding_utils import decode_base64_text

# "=" may precede a token (key=TOKEN); padding "=" only ever appears at the token's end.
_TOKEN = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{32,}={0,2}(?![A-Za-z0-9+/=_-])")


class Base64Formatter:
    kind = "Base64 (decoded)"

    def find(self, text: str) -> list[Section]:
        out: list[Section] = []
        for m in _TOKEN.finditer(text):
            decoded = decode_base64_text(m.group(0))
            if decoded:
                out.append(Section(self.kind, decoded, m.start(), m.end()))
        return out
