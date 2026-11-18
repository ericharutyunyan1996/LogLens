"""Small decoding helpers shared by payload formatters."""

from __future__ import annotations

import base64
import binascii
import re

_B64_CHARS = re.compile(r"^[A-Za-z0-9+/_-]+={0,2}$")
_HEX = re.compile(r"^[0-9a-fA-F]+$")
PRINTABLE_RATIO = 0.95


def is_printable_text(text: str) -> bool:
    if not text:
        return False
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    return printable / len(text) >= PRINTABLE_RATIO


def decode_base64_text(token: str) -> str | None:
    """Decode standard or URL-safe base64 to readable UTF-8 text, or None if it isn't text.

    Pure hex strings (ids, hashes) are rejected even though they are valid base64 alphabet.
    """
    if len(token) < 8 or not _B64_CHARS.match(token) or _HEX.match(token):
        return None
    padded = token + "=" * (-len(token) % 4)
    try:
        raw = (
            base64.urlsafe_b64decode(padded)
            if ("-" in token or "_" in token)
            else base64.b64decode(padded, validate=True)
        )
        text = raw.decode("utf-8")
    except (binascii.Error, ValueError):
        return None
    return text if is_printable_text(text) else None
