"""Compile logging-library layout patterns into a :class:`LogFormat` ("paste your layout").

Supported pattern languages:

* **log4net / log4j / Logback** conversion patterns — ``%date{…} [%thread] %-5level %logger - %message%newline``,
  short names (``%d %t %p %c %m %n``), format modifiers (``%-5level``, ``%.30logger``, ``%20.30c``), options
  (``%c{1}``, ``%property{user}``, ``%X{key}``) and log4j wrappers (``%highlight{…}``, ``%style{…}{…}``).
* **NLog** layout renderers — ``${longdate}|${level:uppercase=true}|${logger}|${message}``, options with escaped
  ``\\:`` and nested renderers (``${onexception:${newline}${exception}}``, ``${pad:padding=5:inner=${level}}``).
* **Serilog** output templates — ``{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {Message:lj}{NewLine}``,
  alignment (``{Level,-5}``), ``{{`` / ``}}`` escapes and any custom ``{Property}``.

Each conversion becomes a named group with a regex for its shape: dates through :mod:`.dates`, numbers as ``\\d+``,
loggers as ``\\S+``; free text is lazy up to the next literal, while the message and the last free-text field are
greedy (``%m (%F:%L)`` splits at the *last* parenthesis). Everything after the first newline conversion belongs to
continuation lines (exceptions, stack traces), so compiled layouts are multi-line formats. Unknown conversions become a
field named after the conversion.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, replace
from typing import Literal

from .base import LayoutError, LogFormat
from .dates import ANY_TIMESTAMP, DateDialect, date_format_regex, named_date_regex

LayoutStyle = Literal["log4net", "log4j", "nlog", "serilog", "auto"]
LAYOUT_STYLES: tuple[LayoutStyle, ...] = ("auto", "log4net", "log4j", "nlog", "serilog")

MAX_NESTING = 8  # nested wrappers (%highlight{%style{…}}, ${pad:inner=${uppercase:…}}) deeper than this are refused

# Field kinds: they decide the LogFormat's time / level / message fields.
TIME, LEVEL, MESSAGE, EXCEPTION, LOGGER, THREAD, OTHER = "time", "level", "message", "exception", "logger", "thread", ""
# Conversion roles that don't produce a plain field.
_NEWLINE, _WRAPPER, _PROPERTY, _LITERAL = "newline", "wrapper", "property", "literal"

_LEVEL_REGEX = r"[A-Za-z]+"
_NUMBER = r"\d+"
_WORD = r"\S+"
_FREE = ""  # free text: lazy up to the next literal, greedy when it is the last field


@dataclass(frozen=True, slots=True)
class _Literal:
    text: str


@dataclass(frozen=True, slots=True)
class _Field:
    name: str
    kind: str = OTHER
    regex: str = _FREE
    pad: int = 0  # < 0: padded on the right (left-justified), > 0: padded on the left


@dataclass(frozen=True, slots=True)
class _NewLine:
    pass


_Token = _Literal | _Field | _NewLine


@dataclass(frozen=True, slots=True)
class _Conv:
    """What a conversion name produces: a field (name, kind, regex) or a special role."""

    field: str
    kind: str = OTHER
    regex: str = _FREE


def _table(entries: dict[tuple[str, ...], _Conv]) -> dict[str, _Conv]:
    return {name: conv for names, conv in entries.items() for name in names}


# ---- log4net / log4j ------------------------------------------------------------------------------------------------
_LOG4_COMMON = _table(
    {
        ("date", "d", "utcdate", "utcDate"): _Conv("time", TIME),
        ("timestamp", "r", "relative"): _Conv("elapsed", OTHER, _NUMBER),
        ("thread", "t", "tn", "threadName"): _Conv("thread", THREAD),
        ("T", "tid", "threadId"): _Conv("thread_id", OTHER, _NUMBER),
        ("level", "p", "le", "priority"): _Conv("level", LEVEL, _LEVEL_REGEX),
        ("logger", "c", "lo"): _Conv("logger", LOGGER, _WORD),
        ("message", "m", "msg", "mes"): _Conv("message", MESSAGE),
        ("newline", "n"): _Conv("", _NEWLINE),
        (
            "exception",
            "ex",
            "throwable",
            "xEx",
            "xException",
            "xThrowable",
            "rEx",
            "rException",
            "rThrowable",
        ): _Conv("exception", EXCEPTION),
        ("property", "P", "properties", "X", "mdc", "MDC", "K", "map", "MAP"): _Conv("properties", _PROPERTY),
        ("ndc", "NDC", "x"): _Conv("ndc"),
        ("class", "C", "type"): _Conv("class", OTHER, _WORD),
        ("method", "M"): _Conv("method", OTHER, _WORD),
        ("line", "L"): _Conv("line", OTHER, _NUMBER),
        ("file", "F"): _Conv("file"),
        ("location", "l"): _Conv("location"),
        ("username", "w"): _Conv("user"),
        ("identity",): _Conv("identity"),
        ("appdomain", "a"): _Conv("appdomain"),
        ("pid", "processId"): _Conv("pid", OTHER, _NUMBER),
        ("sn", "sequenceNumber"): _Conv("sequence", OTHER, _NUMBER),
        ("N", "nano"): _Conv("nano", OTHER, _NUMBER),
        ("marker",): _Conv("marker"),
        ("uuid",): _Conv("uuid", OTHER, r"[0-9A-Fa-f-]+"),
        ("stacktrace", "stacktracedetail"): _Conv("stacktrace"),
        ("highlight", "style", "enc", "encode", "replace", "equals", "notEmpty", "maxLen", "maxLength"): _Conv(
            "", _WRAPPER
        ),
    }
)
_LOG4NET = {**_LOG4_COMMON, "u": _Conv("identity")}
_LOG4J = {**_LOG4_COMMON, "u": _Conv("uuid", OTHER, r"[0-9A-Fa-f-]+")}

_LOG4_MODIFIER = re.compile(r"(-)?(\d*)(?:\.-?\d+)?")
_LOG4_WORD = re.compile(r"[A-Za-z][A-Za-z-]*")
_LETTERS = re.compile(r"[A-Za-z]+")

# ---- NLog ------------------------------------------------------------------------------------------------------------
_NLOG_DEFAULT_DATE = "yyyy/MM/dd HH:mm:ss.fff"  # NLog's ${date} without a format
_NLOG = _table(
    {
        ("longdate",): _Conv("time", TIME, r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{4}"),
        ("shortdate",): _Conv("date", OTHER, r"\d{4}-\d{2}-\d{2}"),
        ("time",): _Conv("time", TIME, r"\d{2}:\d{2}:\d{2}\.\d{4}"),
        ("date",): _Conv("time", TIME),
        ("ticks",): _Conv("ticks", OTHER, _NUMBER),
        ("level",): _Conv("level", LEVEL, _LEVEL_REGEX),
        ("logger", "loggername"): _Conv("logger", LOGGER, _WORD),
        ("message",): _Conv("message", MESSAGE),
        ("exception",): _Conv("exception", EXCEPTION),
        ("newline",): _Conv("", _NEWLINE),
        ("threadid",): _Conv("thread", THREAD, _NUMBER),
        ("threadname",): _Conv("thread", THREAD),
        ("callsite",): _Conv("callsite", OTHER, _WORD),
        ("callsite-linenumber",): _Conv("line", OTHER, _NUMBER),
        ("callsite-filename",): _Conv("file"),
        ("processid",): _Conv("pid", OTHER, _NUMBER),
        ("processname",): _Conv("process"),
        ("processtime",): _Conv("elapsed"),
        ("machinename", "hostname"): _Conv("host", OTHER, _WORD),
        ("windows-identity", "identity", "environment-user"): _Conv("user"),
        ("counter", "seq", "sequenceid"): _Conv("sequence", OTHER, _NUMBER),
        ("all-event-properties",): _Conv("properties"),
        (
            "mdlc",
            "mdc",
            "ndlc",
            "scopeproperty",
            "event-properties",
            "event-property",
            "gdc",
            "aspnet-item",
            "environment",
            "var",
            "appsetting",
            "configsetting",
        ): _Conv("properties", _PROPERTY),
        (
            "uppercase",
            "lowercase",
            "pad",
            "trim-whitespace",
            "replace",
            "replace-newlines",
            "when",
            "whenempty",
            "json-encode",
            "xml-encode",
            "url-encode",
            "left",
            "right",
            "substring",
            "wrapline",
            "cached",
            "rot13",
            "norawvalue",
            "filesystem-normalize",
        ): _Conv("", _WRAPPER),
        ("literal",): _Conv("", _LITERAL),
        ("onexception",): _Conv("exception", EXCEPTION),
    }
)

# ---- Serilog ---------------------------------------------------------------------------------------------------------
_SERILOG = {
    "Timestamp": _Conv("time", TIME),
    "UtcTimestamp": _Conv("time", TIME),
    "Level": _Conv("level", LEVEL, _LEVEL_REGEX),
    "Message": _Conv("message", MESSAGE),
    "Exception": _Conv("exception", EXCEPTION),
    "NewLine": _Conv("", _NEWLINE),
    "SourceContext": _Conv("logger", LOGGER, r"\S*"),
    "Properties": _Conv("properties", OTHER, r"\{.*\}"),  # rendered as an object: {…}
    "ThreadId": _Conv("thread", THREAD, _NUMBER),
    "ThreadName": _Conv("thread", THREAD),
    "ProcessId": _Conv("pid", OTHER, _NUMBER),
    "MachineName": _Conv("host", OTHER, _WORD),
}
_SERILOG_HOLE = re.compile(r"[@$]?(?P<name>[A-Za-z_][A-Za-z0-9_.]*)(?:,(?P<align>-?\d+))?(?::(?P<format>.*))?", re.S)
_SERILOG_LEVEL_FORMAT = re.compile(r"[utw](\d*)")

_NAME_JUNK = re.compile(r"\W+")
_WHITESPACE = re.compile(r"(\s+)")


def _field_name(raw: str) -> str:
    """A valid regex group name for ``raw`` (non-word characters → ``_``)."""
    name = _NAME_JUNK.sub("_", raw.strip()).strip("_")
    if not name:
        return "field"
    return f"f_{name}" if name[0].isdigit() else name


# ---- style detection -------------------------------------------------------------------------------------------------
_LOG4_CONVERSION = re.compile(r"%[-\d.]*[A-Za-z]")
_SERILOG_PROPERTY = re.compile(r"(?<!\{)\{[@$]?[A-Za-z_][A-Za-z0-9_.]*(?:,-?\d+)?(?::[^{}]*)?\}")


def detect_layout_style(pattern: str) -> LayoutStyle:
    """The layout language of ``pattern`` (never ``"auto"``); raises :class:`LayoutError` when it can't tell."""
    if "${" in pattern:
        return "nlog"
    if _LOG4_CONVERSION.search(pattern):
        return "log4j" if "SSS" in pattern else "log4net"
    if _SERILOG_PROPERTY.search(pattern):
        return "serilog"
    raise LayoutError("cannot tell the layout style: no %conversion, ${renderer} or {Property} found")


# ---- shared helpers --------------------------------------------------------------------------------------------------
def _matching_brace(text: str, start: int, *, opener: str = "{") -> int:
    """Index of the ``}`` closing the brace at ``start`` (nested braces and ``\\`` escapes respected)."""
    depth = 0
    i = start
    while i < len(text):
        char = text[i]
        if char == "\\":
            i += 2
            continue
        if text.startswith(opener, i):
            depth += 1
            i += len(opener)
            continue
        if char == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise LayoutError(f"unbalanced {opener!r}: no closing '}}'", start)


def _date_regex(option: str, dialect: DateDialect) -> str:
    """Regex for a date conversion's format option (named log4j formats first)."""
    named = named_date_regex(option)
    return named if named is not None else date_format_regex(option, dialect=dialect)


def _with_pad(tokens: list[_Token], pad: int) -> list[_Token]:
    """Apply a padding modifier to a wrapper whose content is a single field."""
    if pad and len(tokens) == 1 and isinstance(tokens[0], _Field):
        return [replace(tokens[0], pad=pad)]
    return tokens


# ---- log4net / log4j tokenizer ---------------------------------------------------------------------------------------
def _longest_known(word: str, table: dict[str, _Conv]) -> str:
    """Longest prefix of ``word`` that is a known conversion (log4net/log4j read names greedily); "" if none."""
    for end in range(len(word), 0, -1):
        if word[:end] in table:
            return word[:end]
    return ""


def _read_options(pattern: str, start: int) -> tuple[list[str], int]:
    """``{option}`` groups directly after a conversion name; returns (options, index after them)."""
    options: list[str] = []
    i = start
    while i < len(pattern) and pattern[i] == "{":
        end = _matching_brace(pattern, i)
        options.append(pattern[i + 1 : end])
        i = end + 1
    return options, i


class _Log4Tokenizer:
    """log4net / log4j / Logback conversion patterns."""

    def __init__(self, style: LayoutStyle) -> None:
        self.style = style
        self.table = _LOG4J if style == "log4j" else _LOG4NET

    def tokens(self, pattern: str, depth: int = 0) -> list[_Token]:
        if depth > MAX_NESTING:
            raise LayoutError("layout nested too deeply")
        out: list[_Token] = []
        literal: list[str] = []
        i = 0
        while i < len(pattern):
            if pattern[i] != "%":
                literal.append(pattern[i])
                i += 1
                continue
            if pattern.startswith("%%", i):
                literal.append("%")
                i += 2
                continue
            if literal:
                out.append(_Literal("".join(literal)))
                literal.clear()
            produced, i = self._conversion(pattern, i, depth)
            out.extend(produced)
        if literal:
            out.append(_Literal("".join(literal)))
        return out

    def _conversion(self, pattern: str, start: int, depth: int) -> tuple[list[_Token], int]:
        modifier = _LOG4_MODIFIER.match(pattern, start + 1)
        assert modifier is not None  # every group is optional
        word = _LOG4_WORD.match(pattern, modifier.end())
        if word is None:
            raise LayoutError("missing conversion name after '%'", start)
        name = _longest_known(word.group(0), self.table)
        if not name:
            letters = _LETTERS.match(word.group(0))
            assert letters is not None  # the word starts with a letter
            name = letters.group(0)
        options, end = _read_options(pattern, modifier.end() + len(name))
        width = int(modifier.group(2) or 0)
        pad = -width if modifier.group(1) else width
        conv = self.table.get(name, _Conv(_field_name(name)))
        return self._expand(conv, options, pad, depth), end

    def _expand(self, conv: _Conv, options: list[str], pad: int, depth: int) -> list[_Token]:
        option = options[0] if options else ""
        if conv.kind == _NEWLINE:
            return [_NewLine()]
        if conv.kind == _WRAPPER:
            return _with_pad(self.tokens(option, depth + 1), pad) if option else []
        if conv.kind == TIME:
            dialect: DateDialect = "java" if self.style == "log4j" or "SSS" in option else "dotnet"
            regex = _date_regex(option, dialect) if option else _date_regex("ISO8601", dialect)
            return [_Field(conv.field, TIME, regex, pad)]
        if conv.kind == _PROPERTY:
            return [_Field(_field_name(option) if option else conv.field, OTHER, _FREE, pad)]
        return [_Field(conv.field, conv.kind, conv.regex, pad)]


# ---- NLog tokenizer --------------------------------------------------------------------------------------------------
def _split_top(text: str, separator: str) -> list[str]:
    """Split on ``separator`` outside nested ``${…}`` and not escaped with ``\\``."""
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    i = 0
    while i < len(text):
        char = text[i]
        if char == "\\" and i + 1 < len(text):
            current.append(text[i : i + 2])
            i += 2
            continue
        if text.startswith("${", i):
            depth += 1
            current.append("${")
            i += 2
            continue
        if char == "}" and depth:
            depth -= 1
        elif char == separator and not depth:
            parts.append("".join(current))
            current = []
            i += 1
            continue
        current.append(char)
        i += 1
    parts.append("".join(current))
    return parts


def _unescape(text: str) -> str:
    return re.sub(r"\\(.)", r"\1", text) if "${" not in text else text


def _nlog_options(segments: list[str]) -> dict[str, str]:
    """``name=value`` options (keys lower-cased); a first segment without ``=`` is the default parameter."""
    options: dict[str, str] = {}
    last = ""
    for index, segment in enumerate(segments):
        key, sep, value = segment.partition("=")
        if sep and "${" not in key:
            last = key.strip().lower()
            options[last] = _unescape(value)
        elif index == 0:
            options[""] = _unescape(segment)
        elif last:
            options[last] += ":" + _unescape(segment)  # an unescaped ':' inside a value (format=HH:mm:ss)
    return options


class _NLogTokenizer:
    """NLog layouts: ``${renderer:option=value}`` with nesting (wrappers, ``onexception``)."""

    def tokens(self, pattern: str, depth: int = 0) -> list[_Token]:
        if depth > MAX_NESTING:
            raise LayoutError("layout nested too deeply")
        out: list[_Token] = []
        literal: list[str] = []
        i = 0
        while i < len(pattern):
            if not pattern.startswith("${", i):
                literal.append(pattern[i])
                i += 1
                continue
            end = _matching_brace(pattern, i, opener="${")
            if literal:
                out.append(_Literal("".join(literal)))
                literal.clear()
            out.extend(self._renderer(pattern[i + 2 : end], i, depth))
            i = end + 1
        if literal:
            out.append(_Literal("".join(literal)))
        return out

    def _renderer(self, body: str, position: int, depth: int) -> list[_Token]:
        segments = _split_top(body, ":")
        name = segments[0].strip().lower()
        if not name:
            raise LayoutError("empty ${} renderer", position)
        options = _nlog_options(segments[1:])
        pad = int(options["padding"]) if re.fullmatch(r"-?\d+", options.get("padding", "")) else 0
        conv = _NLOG.get(name, _Conv(_field_name(name)))
        structural = self._structural(name, conv, options, pad, depth)
        return structural if structural is not None else [self._field(name, conv, options, pad)]

    def _structural(self, name: str, conv: _Conv, options: dict[str, str], pad: int, depth: int) -> list[_Token] | None:
        """Tokens of renderers that aren't a plain field (newline, wrappers, literals); None for plain fields."""
        inner = options.get("inner", options.get("", ""))
        if conv.kind == _NEWLINE:
            return [_NewLine()]
        if conv.kind == _WRAPPER:
            return _with_pad(self.tokens(inner, depth + 1), pad) if inner else []
        if conv.kind == _LITERAL:
            return [_Literal(options.get("text", inner))]
        if name == "onexception" and "${newline}" in inner.lower():
            return []  # the exception goes to continuation lines
        return None

    def _field(self, name: str, conv: _Conv, options: dict[str, str], pad: int) -> _Field:
        if name == "date":
            return _Field("time", TIME, _date_regex(options.get("format", _NLOG_DEFAULT_DATE), "dotnet"), pad)
        if name == "level":
            return _Field("level", LEVEL, self._level_regex(options.get("format", "")), pad)
        if conv.kind == _PROPERTY:
            key = options.get("item") or options.get("name") or options.get("inner") or options.get("", "")
            return _Field(_field_name(key) if key else conv.field, OTHER, _FREE, pad)
        return _Field(conv.field, conv.kind, conv.regex, pad)

    @staticmethod
    def _level_regex(fmt: str) -> str:
        lowered = fmt.lower()
        if lowered == "ordinal":
            return _NUMBER
        if lowered == "firstcharacter":
            return r"[A-Za-z]"
        return _LEVEL_REGEX


# ---- Serilog tokenizer -----------------------------------------------------------------------------------------------
class _SerilogTokenizer:
    """Serilog output templates (properties don't nest)."""

    def tokens(self, pattern: str) -> list[_Token]:
        out: list[_Token] = []
        literal: list[str] = []
        i = 0
        while i < len(pattern):
            char = pattern[i]
            if char in "{}" and pattern.startswith(char * 2, i):
                literal.append(char)
                i += 2
                continue
            if char == "}":
                raise LayoutError("unbalanced '}' (write '}}' for a literal brace)", i)
            if char != "{":
                literal.append(char)
                i += 1
                continue
            end = pattern.find("}", i + 1)
            if end < 0 or "{" in pattern[i + 1 : end]:
                raise LayoutError("unbalanced '{' (write '{{' for a literal brace)", i)
            hole = _SERILOG_HOLE.fullmatch(pattern, i + 1, end)
            if hole is None:
                raise LayoutError(f"invalid property {pattern[i : end + 1]!r}", i)
            if literal:
                out.append(_Literal("".join(literal)))
                literal.clear()
            out.extend(self._property(hole))
            i = end + 1
        if literal:
            out.append(_Literal("".join(literal)))
        return out

    @staticmethod
    def _property(hole: re.Match[str]) -> list[_Token]:
        name, fmt = hole["name"], hole["format"] or ""
        pad = int(hole["align"]) if hole["align"] else 0
        conv = _SERILOG.get(name, _Conv(_field_name(name)))
        if conv.kind == _NEWLINE:
            return [_NewLine()]
        if conv.kind == TIME:
            return [_Field("time", TIME, _date_regex(fmt, "dotnet") if fmt else ANY_TIMESTAMP, pad)]
        if conv.kind == LEVEL:
            level = _SERILOG_LEVEL_FORMAT.fullmatch(fmt)
            width = level.group(1) if level else ""
            return [_Field("level", LEVEL, rf"[A-Za-z]{{1,{width}}}" if width else _LEVEL_REGEX, pad)]
        return [_Field(conv.field, conv.kind, conv.regex, pad)]


# ---- regex assembly --------------------------------------------------------------------------------------------------
_LINE_BREAK = re.compile(r"[\r\n]")


def _first_line(tokens: list[_Token]) -> list[_Literal | _Field]:
    """Tokens before the first newline (conversion or literal line break), adjacent literals merged."""
    merged: list[_Literal | _Field] = []
    for token in tokens:
        if isinstance(token, _NewLine):
            break
        if isinstance(token, _Literal):
            text, *after_break = _LINE_BREAK.split(token.text, maxsplit=1)
            if merged and isinstance(merged[-1], _Literal):
                merged[-1] = _Literal(merged[-1].text + text)
            elif text:
                merged.append(_Literal(text))
            if after_break:
                break
        else:
            merged.append(token)
    if merged and isinstance(merged[-1], _Literal):
        tail = merged[-1].text.rstrip()  # trailing spaces before the newline are often trimmed by writers
        merged[-1:] = [_Literal(tail)] if tail else []
    return merged


def _literal_regex(text: str) -> str:
    """Escaped literal; runs of whitespace match one or more blanks (padding varies)."""
    return "".join(r"[ \t]+" if part.isspace() else re.escape(part) for part in _WHITESPACE.split(text) if part)


def _unique(name: str, seen: Counter[str]) -> str:
    seen[name] += 1
    return name if seen[name] == 1 else f"{name}_{seen[name]}"


@dataclass(frozen=True, slots=True)
class _Assembled:
    regex: str
    fields: tuple[str, ...]
    roles: dict[str, str]  # kind → first field of that kind


def _assemble(tokens: list[_Token]) -> _Assembled:
    line = _first_line(tokens)
    field_positions = [index for index, token in enumerate(line) if isinstance(token, _Field)]
    if not field_positions:
        raise LayoutError("the layout has no fields")
    last_field = field_positions[-1]
    seen: Counter[str] = Counter()
    parts = ["^"]
    names: list[str] = []
    roles: dict[str, str] = {}
    for index, token in enumerate(line):
        if isinstance(token, _Literal):
            parts.append(_literal_regex(token.text))
            continue
        name = _unique(token.name, seen)
        names.append(name)
        roles.setdefault(token.kind, name)
        greedy = index == last_field or token.kind == MESSAGE  # the message keeps "(" / " - " it contains
        body = token.regex or (".*" if greedy else ".*?")
        group = f"(?P<{name}>{body})"
        parts.append(f"{group} *" if token.pad < 0 else f" *{group}" if token.pad > 0 else group)
    parts.append(r"\s*$")
    return _Assembled("".join(parts), tuple(names), roles)


def _tokens(pattern: str, style: LayoutStyle) -> list[_Token]:
    if style == "nlog":
        return _NLogTokenizer().tokens(pattern)
    if style == "serilog":
        return _SerilogTokenizer().tokens(pattern)
    return _Log4Tokenizer(style).tokens(pattern)


@dataclass(frozen=True, slots=True)
class CompiledLayout:
    """A layout pattern translated to a regex (see :func:`layout_regex`)."""

    style: LayoutStyle  # the resolved style (never "auto")
    regex: str
    fields: tuple[str, ...]
    roles: dict[str, str]  # field kind ("time", "level", "message" …) → first field of that kind


def layout_regex(pattern: str, *, style: LayoutStyle = "auto") -> CompiledLayout:
    """Translate a layout pattern into a regex source with one named group per field; raises :class:`LayoutError`."""
    if not pattern.strip():
        raise LayoutError("empty layout pattern")
    if style not in LAYOUT_STYLES:
        raise LayoutError(f"unknown layout style {style!r}")
    resolved = detect_layout_style(pattern) if style == "auto" else style
    assembled = _assemble(_tokens(pattern, resolved))
    return CompiledLayout(resolved, assembled.regex, assembled.fields, assembled.roles)


def compile_layout(
    pattern: str, *, style: LayoutStyle = "auto", name: str = "", display_name: str = "", priority: int = 0
) -> LogFormat:
    """Compile a log4net / log4j / NLog / Serilog layout pattern into a multi-line :class:`LogFormat`.

    Raises :class:`LayoutError` for unbalanced braces, a dangling ``%``, an unknown style or a layout without fields.
    """
    compiled = layout_regex(pattern, style=style)
    try:
        regex = re.compile(compiled.regex)
    except re.error as error:  # e.g. a date format producing an invalid regex
        raise LayoutError(f"layout compiles to an invalid regex: {error}") from error
    return LogFormat(
        name=name or "layout",
        display_name=display_name or name or pattern,
        fields=compiled.fields,
        regex=regex,
        multiline=True,
        time_field=compiled.roles.get(TIME, ""),
        level_field=compiled.roles.get(LEVEL, ""),
        message_field=compiled.roles.get(MESSAGE, ""),
        priority=priority,
        description=f"{compiled.style} layout: {pattern}",
    )
