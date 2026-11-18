"""Parsers for formats whose field names come from the data: JSON lines, Serilog CLEF, logfmt, CSV/TSV and W3C.

The usual time / level / message keys are recognised case-insensitively (ignoring ``_``, ``-`` and spaces) and renamed
to ``time``, ``level`` and ``message`` so every structured format offers the same core columns; all other keys keep
their names. CSV/TSV parsers take the field names from the header row, W3C parsers from the latest ``#Fields:``
directive (it may change mid-file); both are stateful and must see lines in file order.
"""

from __future__ import annotations

import csv
import json
import re
from collections.abc import Mapping
from functools import lru_cache

from .base import Fields
from .generic import TIMESTAMP_HEAD, timestamp_of

JSON_FLATTEN_DEPTH = 2  # nested objects are flattened to dotted keys this deep (log.level, http.request.method)
ROLE_CACHE_SIZE = 512  # distinct key sets remembered (JSON lines of one logger share a handful)
MAX_HEADER_NAME = 64  # a CSV header cell longer than this is data, not a column name
MIN_COLUMNS = 2  # a delimited "table" needs at least two columns

TIME_KEYS = ("time", "timestamp", "@timestamp", "ts", "datetime", "@t", "eventtime", "logtime", "date")
LEVEL_KEYS = ("level", "severity", "lvl", "loglevel", "log.level", "levelname", "@l", "severitytext")
MESSAGE_KEYS = ("message", "msg", "@m", "body", "text", "log", "@mt")
_ROLES = (("time", TIME_KEYS), ("level", LEVEL_KEYS), ("message", MESSAGE_KEYS))

# Numeric levels of pino / bunyan JSON loggers.
NUMERIC_JSON_LEVELS = {"10": "Trace", "20": "Debug", "30": "Info", "40": "Warning", "50": "Error", "60": "Critical"}


def _norm(key: str) -> str:
    return key.lower().replace("_", "").replace("-", "").replace(" ", "")


@lru_cache(maxsize=ROLE_CACHE_SIZE)
def _role_keys(keys: tuple[str, ...]) -> tuple[tuple[str, str], ...]:
    """(original key, canonical name) for the keys playing the time / level / message roles."""
    normalized = [_norm(key) for key in keys]
    chosen: list[tuple[str, str]] = []
    used: set[str] = set()
    for canonical, aliases in _ROLES:
        for alias in aliases:
            match = next((k for k, n in zip(keys, normalized, strict=True) if n == alias and k not in used), None)
            if match is not None:
                chosen.append((match, canonical))
                used.add(match)
                break
    return tuple(chosen)


def canonicalize(values: Mapping[str, str]) -> Fields:
    """``values`` with the time / level / message keys renamed to their canonical names and moved to the front."""
    roles = _role_keys(tuple(values))
    out: Fields = {canonical: values[key] for key, canonical in roles}
    renamed = {key for key, _ in roles}
    for key, value in values.items():
        if key not in renamed:
            out[key if key not in out else f"{key}_"] = value
    return out


def to_text(value: object) -> str:
    """A JSON value as column text (objects and arrays as compact JSON)."""
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return str(value)
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _flatten(obj: Mapping[str, object], prefix: str, out: dict[str, str], depth: int) -> None:
    for key, value in obj.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict) and value and depth < JSON_FLATTEN_DEPTH:
            _flatten(value, f"{name}.", out, depth + 1)
        else:
            out[name] = to_text(value)


def load_object(text: str) -> dict[str, object] | None:
    """The JSON object on a line, or None (not ``{…}``, invalid, or not an object)."""
    stripped = text.strip()
    if not (stripped.startswith("{") and stripped.endswith("}")):
        return None
    try:
        obj = json.loads(stripped)
    except (ValueError, RecursionError):
        return None
    return obj if isinstance(obj, dict) and obj else None


class _Stateless:
    __slots__ = ()

    def consume_meta(self, line: str) -> bool:
        return False


class JsonLinesParser(_Stateless):
    """One JSON object per line; nested objects flattened, usual key aliases renamed to time / level / message."""

    __slots__ = ()

    def parse(self, text: str) -> Fields | None:
        obj = load_object(text)
        if obj is None:
            return None
        flat: dict[str, str] = {}
        _flatten(obj, "", flat, 0)
        return canonicalize(flat)


# ---- Serilog CLEF ----------------------------------------------------------------------------------------------------
_CLEF_EXTRA = {"@tr": "trace_id", "@sp": "span_id"}
_TEMPLATE_HOLE = re.compile(r"\{\{|\}\}|\{[@$]?([A-Za-z0-9_.]+)(?:,-?\d+)?(?::[^}]*)?\}")
CLEF_DEFAULT_LEVEL = "Information"  # CLEF omits @l for Information events


def render_template(template: str, properties: Mapping[str, object]) -> str:
    """A message template (``Hello {Name}``) with property values filled in; unknown holes stay as written."""

    def fill(match: re.Match[str]) -> str:
        whole = match.group(0)
        if whole in ("{{", "}}"):
            return whole[0]
        name = match.group(1)
        return to_text(properties[name]) if name in properties else whole

    return _TEMPLATE_HOLE.sub(fill, template)


class ClefParser(_Stateless):
    """Compact Log Event Format (Serilog / Seq): ``{"@t": …, "@l": …, "@mt" | "@m": …, "@x": …, props}``."""

    __slots__ = ()

    def parse(self, text: str) -> Fields | None:
        if '"@t"' not in text:
            return None
        obj = load_object(text)
        if obj is None or "@t" not in obj:
            return None
        template = to_text(obj.get("@mt", ""))
        message = to_text(obj["@m"]) if "@m" in obj else render_template(template, obj)
        out: Fields = {
            "time": to_text(obj["@t"]),
            "level": to_text(obj.get("@l", CLEF_DEFAULT_LEVEL)),
            "message": message,
            "exception": to_text(obj.get("@x", "")),
            "template": template,
            "event_id": to_text(obj.get("@i", "")),
        }
        extra: dict[str, str] = {}
        for key, value in obj.items():
            if key in _CLEF_EXTRA:
                out[_CLEF_EXTRA[key]] = to_text(value)
            elif not key.startswith("@"):
                if isinstance(value, dict) and value:
                    _flatten(value, f"{key}.", extra, 1)
                else:
                    extra[key] = to_text(value)
        out.update((key, value) for key, value in extra.items() if key not in out)
        return out


# ---- logfmt ----------------------------------------------------------------------------------------------------------
_LOGFMT_PAIR = r'[^\s="]+=(?:"(?:[^"\\]|\\.)*"|[^\s"]*)'
# Two or more pairs and nothing else; pairs are separated by blanks so the regex can't backtrack exponentially.
_LOGFMT_LINE = re.compile(rf"\s*{_LOGFMT_PAIR}(?:\s+{_LOGFMT_PAIR})+\s*")
_LOGFMT_PAIRS = re.compile(r'([^\s="]+)=("(?:[^"\\]|\\.)*"|[^\s"]*)')


def _unquote(value: str) -> str:
    if len(value) < 2 or not value.startswith('"'):
        return value
    try:
        decoded = json.loads(value)
    except ValueError:
        return value[1:-1]
    return decoded if isinstance(decoded, str) else value[1:-1]


class LogfmtParser(_Stateless):
    """``key=value key2="quoted value"`` lines (Heroku / Go logfmt)."""

    __slots__ = ()

    def parse(self, text: str) -> Fields | None:
        if "=" not in text or _LOGFMT_LINE.fullmatch(text) is None:
            return None
        return canonicalize({key: _unquote(value) for key, value in _LOGFMT_PAIRS.findall(text)})


# ---- CSV / TSV -------------------------------------------------------------------------------------------------------
_HEADER_NAME = re.compile(r"[A-Za-z_@#][\w .()\[\]/#@:-]*")


def _looks_like_header(cells: list[str]) -> bool:
    names = [cell.strip() for cell in cells]
    return (
        len(names) >= MIN_COLUMNS
        and len(set(names)) == len(names)
        and all(len(n) <= MAX_HEADER_NAME and _HEADER_NAME.fullmatch(n) for n in names)
    )


class DelimitedParser:
    """CSV / TSV with a header row: the first line that looks like a header names the columns.

    ``delimiters``: candidates tried on the header line (the one producing most columns wins). Quoted fields may not
    span lines.
    """

    __slots__ = ("_delimiter", "_delimiters", "_header", "_names", "_order")

    def __init__(self, delimiters: str) -> None:
        self._delimiters = delimiters
        self._delimiter = delimiters[0]
        self._header: str | None = None
        self._order: list[str] = []  # header cells as written
        self._names: tuple[str, ...] = ()  # the same after renaming time / level / message

    @property
    def columns(self) -> tuple[str, ...]:
        """Column names after renaming (empty until a header has been seen)."""
        return self._names

    def _split(self, line: str, delimiter: str) -> list[str]:
        if '"' not in line:
            return line.split(delimiter)
        return next(csv.reader([line], delimiter=delimiter), [])

    def consume_meta(self, line: str) -> bool:
        stripped = line.strip()
        if self._header is not None:
            return stripped == self._header  # a repeated header (appended file, rotation)
        for delimiter in self._delimiters:
            if delimiter not in stripped:
                continue
            cells = self._split(stripped, delimiter)
            if cells and not cells[-1].strip():
                cells.pop()  # trailing delimiter
            if _looks_like_header(cells):
                self._header, self._delimiter = stripped, delimiter
                names = [cell.strip() for cell in cells]
                self._names = tuple(canonicalize(dict.fromkeys(names, "")))
                self._order = names
                return True
        return False

    def _splits_a_timestamp(self, text: str) -> bool:
        """True if the delimiter near the line start is a timestamp's decimal comma (``10:00:00,123 [1] INFO``).

        A real column boundary right after a timestamp is followed by the next cell; a decimal comma by more text.
        """
        if self._delimiter not in text[:TIMESTAMP_HEAD]:
            return False
        stamp = timestamp_of(text)
        if stamp is None or self._delimiter not in stamp.text:
            return False
        return text[stamp.end : stamp.end + 1] not in (self._delimiter, "", "\r", "\n")

    def parse(self, text: str) -> Fields | None:
        if self._header is None or self._splits_a_timestamp(text):
            return None
        cells = self._split(text.rstrip("\r\n"), self._delimiter)
        if len(cells) == len(self._order) + 1 and not cells[-1].strip():
            cells.pop()  # trailing delimiter
        if len(cells) != len(self._order):
            return None
        return canonicalize(dict(zip(self._order, (cell.strip() for cell in cells), strict=True)))


# ---- W3C extended ----------------------------------------------------------------------------------------------------
_W3C_DIRECTIVE = re.compile(r"#(?P<name>[A-Za-z-]+)\s*:\s*(?P<value>.*)")
_W3C_TOKEN = re.compile(r'"[^"]*"|\S+')


class W3CParser:
    """W3C extended log (IIS, HTTP.sys, proxies): ``#Fields:`` names the columns until the next ``#Fields:``.

    The ``date`` and ``time`` columns are merged into one ``time`` column (``#Date:`` supplies the date when there is no
    date column); ``-`` (no value) becomes empty.
    """

    __slots__ = ("_date", "_fields")

    def __init__(self) -> None:
        self._fields: tuple[str, ...] = ()
        self._date = ""

    @property
    def fields(self) -> tuple[str, ...]:
        return self._fields

    def consume_meta(self, line: str) -> bool:
        if not line.startswith("#"):
            return False
        directive = _W3C_DIRECTIVE.match(line)
        if directive is not None:
            name, value = directive["name"].lower(), directive["value"].strip()
            if name == "fields":
                self._fields = tuple(value.split())
            elif name in ("date", "start-date") and value:
                self._date = value.split()[0]
        return True

    def parse(self, text: str) -> Fields | None:
        if not self._fields:
            return None
        tokens = _W3C_TOKEN.findall(text) if '"' in text else text.split()
        if len(tokens) != len(self._fields):
            return None
        values = {name: ("" if token == "-" else token) for name, token in zip(self._fields, tokens, strict=True)}
        clock = values.pop("time", None)
        date = values.pop("date", None)
        if clock is None:
            if date is not None:
                return {"time": date, **values}
            return values
        day = date if date is not None else self._date
        return {"time": f"{day} {clock}".strip(), **values}
