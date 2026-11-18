"""Translate date/time format strings into regexes matching what they print.

Two dialects: ``"dotnet"`` (.NET custom date formats, used by log4net, NLog and Serilog: ``yyyy-MM-dd HH:mm:ss,fff``)
and ``"java"`` (``SimpleDateFormat`` / ``DateTimeFormatter``, used by log4j and Logback: ``yyyy-MM-dd HH:mm:ss,SSS``).
Named formats (log4j ``ISO8601``, ``ABSOLUTE`` …) and the .NET standard formats (``o``, ``s``, ``u`` …) are known too.
The regexes are deliberately a little lenient (a month name is ``[A-Za-z]+``): they find fields, they don't validate.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Literal

from .base import LayoutError

DateDialect = Literal["dotnet", "java"]

ISO_TIMESTAMP = r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|\s?[+-]\d{2}:?\d{2})?"
# A timestamp printed without a known format (e.g. a .NET DateTimeOffset in the current culture): ISO-like or
# day/month/year with optional AM/PM and offset.
ANY_TIMESTAMP = (
    r"\d{1,4}[-/.]\d{1,2}[-/.]\d{1,4}[T ]\d{1,2}:\d{2}:\d{2}(?:[.,]\d+)?(?:\s?[AaPp][Mm])?(?:Z|\s?[+-]\d{2}:?\d{2})?"
)
_TIME_OF_DAY = r"\d{2}:\d{2}:\d{2}(?:[,.]\d+)?"

# .NET standard (single-letter) date formats with a culture-independent shape.
_DOTNET_STANDARD = {
    "o": r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}(?:Z|[+-]\d{2}:\d{2})?",
    "O": r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}(?:Z|[+-]\d{2}:\d{2})?",
    "s": r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}",
    "u": r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}Z",
    "r": r"[A-Za-z]{3}, \d{2} [A-Za-z]{3} \d{4} \d{2}:\d{2}:\d{2} GMT",
    "R": r"[A-Za-z]{3}, \d{2} [A-Za-z]{3} \d{4} \d{2}:\d{2}:\d{2} GMT",
}
_DOTNET_CULTURE_LETTERS = frozenset("dDfFgGmMtTyY")  # culture-dependent standard formats: lenient timestamp

_JAVA_ZONE_NAME = r"[A-Za-z][A-Za-z0-9/_+-]*"


# log4j / log4net named date formats by name prefix (ISO8601_OFFSET_DATE_TIME_HHMM is an ISO8601 variant …);
# order matters: the first matching prefix wins.
_NAMED_DATES: tuple[tuple[str, str], ...] = (
    ("ABSOLUTE", _TIME_OF_DAY),
    ("DATE", r"\d{2} [A-Za-z]{3} \d{4} " + _TIME_OF_DAY),
    ("COMPACT", r"\d{14,}"),
    ("ISO8601_BASIC", r"\d{8}T\d{6}(?:[,.]\d+)?"),
    ("ISO8601", r"\d{4}-\d{2}-\d{2}[T ]" + _TIME_OF_DAY + r"(?:Z|[+-]\d{2}(?::?\d{2})?)?"),
    ("DEFAULT", r"\d{4}-\d{2}-\d{2}[T ]" + _TIME_OF_DAY + r"(?:Z|[+-]\d{2}(?::?\d{2})?)?"),
    ("UNIX", r"\d+"),
)
_NAMED_DATE = re.compile(r"[A-Z][A-Z0-9_]*")


def named_date_regex(name: str) -> str | None:
    """Regex for a log4j / log4net named date format (``ISO8601``, ``ABSOLUTE``, ``DATE`` …), None if not one."""
    key = name.strip()
    if not _NAMED_DATE.fullmatch(key):
        return None
    return next((regex for prefix, regex in _NAMED_DATES if key.startswith(prefix)), None)


def _digits(count: int) -> str:
    """``count`` digits; a single letter (``d``, ``H``) prints 1-2 digits."""
    return rf"\d{{{count}}}" if count > 1 else r"\d{1,2}"


def _two_digits(count: int) -> str:
    return _digits(min(count, 2))


def _month_or_day(count: int) -> str:
    """``MMM`` / ``ddd`` = abbreviated name, ``MMMM`` / ``dddd`` = full name, shorter = number."""
    if count >= 3:
        return r"[A-Za-z]{3}" if count == 3 else r"[A-Za-z]+"
    return _digits(count)


def _exact_digits(count: int) -> str:
    return rf"\d{{{count}}}"


def _dotnet_offset(count: int) -> str:
    return {1: r"[+-]\d{1,2}", 2: r"[+-]\d{2}"}.get(count, r"[+-]\d{2}:\d{2}")


def _java_offset(count: int, *, zulu: bool) -> str:
    z = "Z|" if zulu else ""
    body = {1: r"[+-]\d{2}(?:\d{2})?", 2: r"[+-]\d{4}"}.get(count, r"[+-]\d{2}:\d{2}")
    return f"(?:{z}{body})"


_DOTNET_TOKENS: dict[str, Callable[[int], str]] = {
    "y": lambda n: r"\d{4}" if n >= 3 else _digits(n),
    "M": _month_or_day,
    "d": _month_or_day,
    "H": _two_digits,
    "h": _two_digits,
    "m": _two_digits,
    "s": _two_digits,
    "f": _exact_digits,
    "F": lambda n: rf"\d{{0,{n}}}",
    "t": lambda n: r"[AaPp][Mm]" if n > 1 else r"[AaPp]",
    "z": _dotnet_offset,
    "K": lambda _n: r"(?:Z|[+-]\d{2}:\d{2})?",
    "g": lambda _n: r"[A-Za-z.]+",
}

_JAVA_TOKENS: dict[str, Callable[[int], str]] = {
    "y": lambda n: r"\d{2}" if n == 2 else r"\d{4}",
    "u": lambda n: r"\d{2}" if n == 2 else r"\d{4}",
    "M": _month_or_day,
    "L": _month_or_day,
    "d": _two_digits,
    "H": _two_digits,
    "h": _two_digits,
    "k": _two_digits,
    "K": _two_digits,
    "m": _two_digits,
    "s": _two_digits,
    "S": _exact_digits,
    "n": lambda _n: r"\d+",
    "E": lambda n: r"[A-Za-z]{3}" if n <= 3 else r"[A-Za-z]+",
    "a": lambda _n: r"[AaPp][Mm]",
    "Z": lambda n: r"(?:Z|[+-]\d{2}:\d{2})" if n >= 5 else r"[+-]\d{4}",
    "X": lambda n: _java_offset(n, zulu=True),
    "x": lambda n: _java_offset(n, zulu=False),
    "z": lambda _n: _JAVA_ZONE_NAME,
    "V": lambda _n: _JAVA_ZONE_NAME,
    "D": lambda _n: r"\d{1,3}",
    "w": lambda _n: r"\d{1,2}",
    "W": lambda _n: r"\d{1,2}",
    "F": lambda _n: r"\d{1,2}",
    "G": lambda _n: r"[A-Za-z]+",
}


def _quoted(fmt: str, start: int, quote: str) -> tuple[str, int]:
    """Literal text of a quoted section starting at ``start``; returns (regex, index after the closing quote)."""
    if quote == "'" and fmt.startswith("''", start):
        return "'", start + 2  # Java: '' is a literal quote
    end = fmt.find(quote, start + 1)
    if end < 0:
        raise LayoutError(f"unterminated {quote} quote in date format {fmt!r}", start)
    return re.escape(fmt[start + 1 : end]), end + 1


def date_format_regex(fmt: str, *, dialect: DateDialect = "dotnet") -> str:
    """Regex matching dates printed with format string ``fmt`` (empty format → a lenient ISO-like timestamp)."""
    if not fmt.strip():
        return ISO_TIMESTAMP
    if dialect == "dotnet" and len(fmt) == 1:
        if fmt in _DOTNET_STANDARD:
            return _DOTNET_STANDARD[fmt]
        if fmt in _DOTNET_CULTURE_LETTERS:
            return ANY_TIMESTAMP
    quotes = "'\"" if dialect == "dotnet" else "'"
    tokens = _DOTNET_TOKENS if dialect == "dotnet" else _JAVA_TOKENS
    parts: list[str] = []
    i = 0
    while i < len(fmt):
        char = fmt[i]
        if char in quotes:
            text, i = _quoted(fmt, i, char)
            parts.append(text)
        elif char == "\\" and dialect == "dotnet":
            parts.append(re.escape(fmt[i + 1 : i + 2]))
            i += 2
        elif char == "%" and dialect == "dotnet":
            i += 1  # "%d": single custom specifier marker
        elif char.isascii() and char.isalpha():
            end = i
            while end < len(fmt) and fmt[end] == char:
                end += 1
            translate = tokens.get(char)
            parts.append(translate(end - i) if translate is not None else re.escape(fmt[i:end]))
            i = end
        else:
            parts.append(re.escape(char))
            i += 1
    return "".join(parts)
