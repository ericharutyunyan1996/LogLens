"""Windows log formats with structure a single regex can't express: setupapi sections and CMTrace records.

* **setupapi** (``setupapi.dev.log`` / ``setupapi.app.log``): sections opened by ``>>>  [title]`` and
  ``>>>  Section start <date time>``, closed by ``<<<  Section end`` / ``<<<  [Exit status: …]``. Body lines carry a
  severity prefix (``!!!`` error, ``!`` warning) and a three-letter category (``dvi:``, ``ndv:``, ``inf:`` …); most
  have no timestamp of their own, so each line gets the section's title and the latest time seen.
* **CMTrace** (Configuration Manager / many Windows setup tools):
  ``<![LOG[message]LOG]!><time="HH:mm:ss.fff+bias" date="MM-dd-yyyy" component="…" context="…" type="1|2|3"
  thread="…" file="…">`` — the message may span lines, so records are parsed joined.
"""

from __future__ import annotations

import re

from .base import Fields

# ---- setupapi --------------------------------------------------------------------------------------------------------
SETUPAPI_FIELDS = ("time", "level", "section", "category", "message")
SETUPAPI_LEVELS = {"!!!": "Error", "!": "Warning"}
SETUPAPI_EVIDENCE = re.compile(r"^(?:>>>|<<<)\s+(?:\[|Section (?:start|end))")
_SETUPAPI_LINE = re.compile(r"(?P<marker>>>>|<<<|!!!|!)?[ \t]+(?:(?P<category>[a-z]{3}):[ \t]+)?(?P<message>.*?)\s*")
_SETUPAPI_BRACKET = re.compile(r"\[.*\]\s*")  # [BeginLog], [Boot Session: …]
_SETUPAPI_STAMP = re.compile(r"(?P<date>\d{4}/\d{2}/\d{2}) \d{2}:\d{2}:\d{2}(?:\.\d+)?")
_SETUPAPI_CLOCK = re.compile(r"\s(\d{2}:\d{2}:\d{2}\.\d{3})$")


class SetupApiParser:
    """Stateful: remembers the open section's title and the latest date/time for lines that carry none."""

    __slots__ = ("_date", "_section", "_time")

    def __init__(self) -> None:
        self._section = ""
        self._date = ""
        self._time = ""

    def consume_meta(self, line: str) -> bool:
        return False

    def _update_time(self, message: str) -> None:
        stamp = _SETUPAPI_STAMP.search(message)
        if stamp is not None:
            self._date, self._time = stamp["date"], stamp.group(0)
            return
        clock = _SETUPAPI_CLOCK.search(message)
        if clock is not None and self._date:
            self._time = f"{self._date} {clock.group(1)}"

    def parse(self, text: str) -> Fields | None:
        line = _SETUPAPI_LINE.fullmatch(text)
        if line is not None:
            marker, category, message = line["marker"] or "", line["category"] or "", line["message"]
        else:
            if _SETUPAPI_BRACKET.fullmatch(text) is None:
                return None
            marker, category, message = "", "", text.strip()
        if marker == ">>>" and message.startswith("["):
            self._section = message.strip("[]")
        self._update_time(message)
        fields = {
            "time": self._time,
            "level": marker if marker in SETUPAPI_LEVELS else "",
            "section": self._section,
            "category": category,
            "message": message,
        }
        if marker == "<<<" and message.startswith("[Exit status"):
            self._section = ""  # the section's last line still shows its title
        return fields


# ---- CMTrace ---------------------------------------------------------------------------------------------------------
CMTRACE_FIELDS = ("time", "level", "component", "thread", "context", "file", "message")
CMTRACE_LEVELS = {"1": "Info", "2": "Warning", "3": "Error"}
CMTRACE_START = re.compile(r"\s*<!\[LOG\[")
CMTRACE_RECORD = re.compile(
    r"\s*<!\[LOG\[(?P<message>.*?)\]LOG\]!>"
    r'<time="(?P<clock>[^"]*)"\s+date="(?P<date>[^"]*)"\s+component="(?P<component>[^"]*)"\s+'
    r'context="(?P<context>[^"]*)"\s+type="(?P<level>[^"]*)"\s+thread="(?P<thread>[^"]*)"'
    r'(?:\s+file="(?P<file>[^"]*)")?\s*>',
    re.DOTALL,
)
_CMTRACE_DATE = re.compile(r"(\d{1,2})-(\d{1,2})-(\d{4})")
_CMTRACE_CLOCK = re.compile(r"\d{1,2}:\d{2}:\d{2}(?:\.\d+)?")


def cmtrace_fields(groups: Fields) -> Fields:
    """Merge CMTrace's ``date="MM-dd-yyyy"`` and ``time="HH:mm:ss.fff+bias"`` into one ISO-like ``time``."""
    date = _CMTRACE_DATE.fullmatch(groups["date"])
    clock = _CMTRACE_CLOCK.match(groups["clock"])
    if date is not None and clock is not None:
        month, day, year = date.groups()
        time = f"{year}-{int(month):02d}-{int(day):02d} {clock.group(0)}"
    else:
        time = f"{groups['date']} {groups['clock']}".strip()
    return {
        "time": time,
        "level": groups["level"],
        "component": groups["component"],
        "thread": groups["thread"],
        "context": groups["context"],
        "file": groups["file"],
        "message": groups["message"],
    }
