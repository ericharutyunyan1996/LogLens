"""Text encoding detection for log files.

Windows logs come in a few flavours: UTF-8 (with or without BOM), UTF-16 LE (PowerShell `>` redirection,
many Windows tools), and legacy ANSI code pages. We only need to know two things to index a file:
the codec used to decode lines, and the byte sequence of a newline in that codec.
"""

from __future__ import annotations

import codecs
import locale
from dataclasses import dataclass

# Encodings offered in the UI. Every one except UTF-16 is ASCII-compatible, so b"\n" is a newline byte
# that can never appear inside a multi-byte character.
KNOWN_ENCODINGS: dict[str, str] = {
    "utf-8": "UTF-8",
    "utf-16-le": "UTF-16 LE",
    "utf-16-be": "UTF-16 BE",
    "cp1252": "Windows-1252 (Western)",
    "cp1251": "Windows-1251 (Cyrillic)",
    "cp1250": "Windows-1250 (Central European)",
    "iso8859-1": "ISO-8859-1 (Latin-1)",
    "cp437": "OEM 437 (console)",
}


@dataclass(frozen=True)
class EncodingInfo:
    codec: str  # Python codec name
    bom_len: int = 0  # bytes to skip at the start of the file
    unit: int = 1  # code unit size in bytes (2 for UTF-16)

    @property
    def newline(self) -> bytes:
        return "\n".encode(self.codec)

    @property
    def display_name(self) -> str:
        name = KNOWN_ENCODINGS.get(self.codec, self.codec)
        return f"{name} BOM" if self.bom_len else name


def _ansi_codec() -> str:
    try:
        enc = locale.getencoding()
        codecs.lookup(enc)
        return enc
    except (LookupError, AttributeError):
        return "cp1252"


# (byte-order mark, codec, code unit size)
_BOMS: tuple[tuple[bytes, str, int], ...] = (
    (codecs.BOM_UTF8, "utf-8", 1),
    (codecs.BOM_UTF16_LE, "utf-16-le", 2),
    (codecs.BOM_UTF16_BE, "utf-16-be", 2),
)
UTF16_ZERO_RATIO = 0.3  # share of zero bytes in one byte column that indicates BOM-less UTF-16
UTF16_OTHER_MAX = 0.05  # ... while the other column has almost none


def for_codec(codec: str, sample: bytes = b"") -> EncodingInfo:
    """EncodingInfo for an explicitly chosen codec; skips a matching BOM if the file has one."""
    codec = codecs.lookup(codec).name  # normalise ("UTF8" -> "utf-8")
    for bom, bom_codec, unit in _BOMS:
        if codec == bom_codec:
            return EncodingInfo(codec, len(bom) if sample.startswith(bom) else 0, unit)
    return EncodingInfo(codec, 0, 1)


def _bomless_utf16(sample: bytes) -> EncodingInfo | None:
    """ASCII-heavy UTF-16 without BOM has a zero byte in every other position."""
    if len(sample) < 4:
        return None
    even, odd = sample[0::2], sample[1::2]
    even_zeros, odd_zeros = even.count(0) / len(even), odd.count(0) / len(odd)
    if odd_zeros > UTF16_ZERO_RATIO and even_zeros < UTF16_OTHER_MAX:
        return EncodingInfo("utf-16-le", 0, 2)
    if even_zeros > UTF16_ZERO_RATIO and odd_zeros < UTF16_OTHER_MAX:
        return EncodingInfo("utf-16-be", 0, 2)
    return None


def detect_encoding(sample: bytes) -> EncodingInfo:
    """Guess the encoding from the first bytes of a file (a 64 KiB sample is plenty)."""
    for bom, codec, unit in _BOMS:
        if sample.startswith(bom):
            return EncodingInfo(codec, len(bom), unit)
    utf16 = _bomless_utf16(sample)
    if utf16 is not None:
        return utf16
    try:  # valid UTF-8, allowing a character cut off at the end of the sample?
        codecs.getincrementaldecoder("utf-8")().decode(sample, final=False)
    except UnicodeDecodeError:
        return EncodingInfo(_ansi_codec(), 0, 1)
    return EncodingInfo("utf-8", 0, 1)
