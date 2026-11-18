"""Built-in catalog of well-known, public log formats.

Logging-library layouts are written as their layout patterns and compiled by :mod:`.layout`, so the catalog doubles as
a test of the compiler. Order matters only as the last detection tie-break (earlier wins): specific formats first,
the generic timestamp + level + message fallback last.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from types import MappingProxyType

from .base import Fields, LogFormat, RegexParser, Transform
from .generic import GENERIC_FIELDS, GenericParser
from .layout import LayoutStyle, compile_layout
from .structured import NUMERIC_JSON_LEVELS, ClefParser, DelimitedParser, JsonLinesParser, LogfmtParser, W3CParser
from .windows import (
    CMTRACE_FIELDS,
    CMTRACE_LEVELS,
    CMTRACE_RECORD,
    CMTRACE_START,
    SETUPAPI_EVIDENCE,
    SETUPAPI_FIELDS,
    SETUPAPI_LEVELS,
    SetupApiParser,
    cmtrace_fields,
)

# ---- syslog ----------------------------------------------------------------------------------------------------------
SYSLOG_SEVERITIES = ("emerg", "alert", "crit", "err", "warning", "notice", "info", "debug")  # RFC 5424 §6.2.1
SYSLOG_FACILITIES = (
    *("kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv", "ftp"),
    *("ntp", "security", "console", "solaris-cron"),
    *(f"local{n}" for n in range(8)),
)
MAX_PRI = len(SYSLOG_FACILITIES) * len(SYSLOG_SEVERITIES) - 1  # 191
SYSLOG_LEVELS = {
    "emerg": "Critical",
    "alert": "Critical",
    "crit": "Critical",
    "err": "Error",
    "warning": "Warning",
    "notice": "Info",
    "info": "Info",
    "debug": "Debug",
}
_BSD_TIME = r"[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}"
_ISO_TIME = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})"
SYSLOG_3164 = re.compile(
    rf"(?:<(?P<pri>\d{{1,3}})>)?(?P<time>{_BSD_TIME}|{_ISO_TIME}) (?P<host>\S+) "
    r"(?P<app>[^\s:\[]+)(?:\[(?P<pid>[^\]]*)\])?: ?(?P<message>.*)"
)
SYSLOG_5424 = re.compile(
    r"<(?P<pri>\d{1,3})>(?P<version>\d{1,2}) (?P<time>\S+) (?P<host>\S+) (?P<app>\S+) (?P<procid>\S+) "
    r'(?P<msgid>\S+) (?P<structured_data>-|(?:\[(?:[^\]"\\]|\\.|"(?:[^"\\]|\\.)*")*\])+)(?: (?P<message>.*))?'
)


def _severity_facility(fields: Fields) -> tuple[str, str] | None:
    """(severity, facility) names from the ``<PRI>`` value; ("", "") without one; None when out of range."""
    raw = fields.pop("pri", "")
    if not raw:
        return "", ""
    value = int(raw)
    if value > MAX_PRI:
        return None
    return SYSLOG_SEVERITIES[value % 8], SYSLOG_FACILITIES[value // 8]


def _rfc3164(fields: Fields) -> Fields | None:
    pri = _severity_facility(fields)
    if pri is None:
        return None
    return {"time": fields["time"], "level": pri[0], "facility": pri[1], **fields}


def _rfc5424(fields: Fields) -> Fields | None:
    pri = _severity_facility(fields)
    if pri is None:
        return None
    values = {key: "" if value == "-" else value for key, value in fields.items()}  # "-" is the NILVALUE
    values["message"] = values["message"].removeprefix("\ufeff")  # BOM marks a UTF-8 message
    return {"time": values.pop("time"), "level": pri[0], "facility": pri[1], **values}


# ---- regex formats ---------------------------------------------------------------------------------------------------
_CLF = (
    r'(?P<host>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?:(?P<method>[A-Z]+) (?P<path>[^ "]*)'
    r'(?: (?P<protocol>[^"]*))?|[^"]*)" (?P<status>\d{3}) (?P<size>\d+|-)'
)
CLF_COMMON = re.compile(_CLF + r"\s*$")
CLF_COMBINED = re.compile(
    _CLF + r' "(?P<referer>(?:[^"\\]|\\.)*)" "(?P<agent>(?:[^"\\]|\\.)*)"(?: (?P<extra>.*?))?\s*$'
)
CBS = re.compile(
    r"(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}), (?P<level>[A-Za-z]+)\s+(?P<component>[A-Za-z][\w.-]*)"
    r"(?:\s+(?P<message>.*))?$"
)
WINDOWS_UPDATE = re.compile(
    r"(?P<time>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d+) +(?P<pid>\d+) +(?P<tid>\d+) +(?P<component>\S+)"
    r"(?: +(?P<message>.*))?$"
)
# LogLens' own one-line form of Windows events (EventRecord.to_line in core/winevent/models.py).
WINDOWS_EVENTS = re.compile(
    r"(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3} [+-]\d{2}:\d{2}) (?P<level>\w+) "
    r"\[(?P<channel>[^\]]+)\] (?P<provider>.+?) \((?P<event_id>\d+)\) — (?P<message>.*?)"
    r"(?: ‖ (?P<details>\{.*\}))?\s*$"
)
WINDOWS_EVENT_LEVELS = {"Information": "Info", "Verbose": "Trace", "AuditFailure": "Warning", "AuditSuccess": "Info"}
SPRING_BOOT = re.compile(
    r"(?P<time>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\.\d{3}(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<level>[A-Z]+)\s+"
    r"(?P<pid>\d+) --- (?:\[(?P<app>[^\]]*)\] )?\[\s*(?P<thread>[^\]]*)\]\s+(?P<logger>\S+)\s+: (?P<message>.*)"
)
PYTHON_LOGGING = re.compile(
    r"(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) - (?P<logger>.+?) - (?P<level>[A-Z]+) - (?P<message>.*)"
)
MEL_CONSOLE = re.compile(
    r"(?:\[?(?P<time>\d{4}-\d{2}-\d{2}[T ][\d:.,]+(?:Z|\s?[+-]\d{2}:\d{2})?|\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)\]?\s+)?"
    r"(?P<level>trce|dbug|info|warn|fail|crit): (?P<category>[^\s\[]+)\[(?P<event_id>-?\d+)\]"
    r"(?:\s+(?P<message>.*))?$"
)
MEL_LEVELS = {"trce": "Trace", "dbug": "Debug", "info": "Info", "warn": "Warning", "fail": "Error", "crit": "Critical"}


@dataclass(frozen=True, slots=True)
class _Extras:
    """Optional parts of a regex format definition."""

    transform: Transform | None = None
    fields: tuple[str, ...] = ()  # default: the regex groups
    multiline: bool = False
    level_map: Mapping[str, str] | None = None
    filename_hints: tuple[str, ...] = ()
    description: str = ""


def _regex_format(name: str, display: str, regex: re.Pattern[str], extras: _Extras = _Extras()) -> LogFormat:
    fields = extras.fields or tuple(regex.groupindex)
    transform = extras.transform
    return LogFormat(
        name=name,
        display_name=display,
        fields=fields,
        regex=regex,
        parser_factory=(lambda: RegexParser(regex, transform)) if transform is not None else None,
        multiline=extras.multiline,
        time_field="time" if "time" in fields else "",
        level_field="level" if "level" in fields else "",
        message_field="message" if "message" in fields else "",
        level_map=MappingProxyType(dict(extras.level_map or {})),
        filename_hints=extras.filename_hints,
        description=extras.description,
    )


def _layout(name: str, display: str, pattern: str, style: LayoutStyle) -> LogFormat:
    compiled = compile_layout(pattern, style=style, name=name, display_name=display)
    return replace(compiled, description=f"{display}: {pattern}")


# ---- catalog ---------------------------------------------------------------------------------------------------------
_CORE = ("time", "level", "message")
_JSON_HINTS = ("*.json", "*.jsonl", "*.ndjson", "*.json.log")

LOG4NET = _layout(
    "log4net", "log4net / log4j (date [thread] level logger - message)",
    "%date [%thread] %-5level %logger - %message%newline", "log4net",
)  # fmt: skip
LOG4J = _layout(
    "log4j", "log4j (date level class:line - message)", "%d{yyyy-MM-dd HH:mm:ss} %-5p %c{1}:%L - %m%n", "log4j"
)
LOG4J2_CONSOLE = _layout(
    "log4j2", "log4j2 / Logback console (time [thread] level logger - message)",
    "%d{HH:mm:ss.SSS} [%t] %-5level %logger{36} - %msg%n", "log4j",
)  # fmt: skip
NLOG = _layout(
    "nlog", "NLog default (longdate|level|logger|message)",
    "${longdate}|${level:uppercase=true}|${logger}|${message:withexception=true}", "nlog",
)  # fmt: skip
SERILOG = _layout(
    "serilog", "Serilog text file (default template)",
    "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {Message:lj}{NewLine}{Exception}", "serilog",
)  # fmt: skip
SERILOG_CONSOLE = _layout(
    "serilog_console", "Serilog console (default template)",
    "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}", "serilog",
)  # fmt: skip
PYTHON = _regex_format(
    "python_logging", "Python logging (asctime - name - levelname - message)", PYTHON_LOGGING, _Extras(multiline=True)
)
SPRING = _regex_format("spring_boot", "Spring Boot / Logback default", SPRING_BOOT, _Extras(multiline=True))
MEL = _regex_format(
    "mel_console",
    "Microsoft.Extensions.Logging console",
    MEL_CONSOLE,
    _Extras(multiline=True, level_map=MEL_LEVELS, description="level: Category[EventId] with the message below"),
)
CLEF = LogFormat(
    name="clef",
    display_name="Serilog CLEF (compact JSON)",
    fields=("time", "level", "message", "exception", "template", "event_id"),
    parser_factory=ClefParser,
    time_field="time",
    level_field="level",
    message_field="message",
    filename_hints=(*_JSON_HINTS, "*.clef"),
    dynamic_fields=True,
    specificity=8,
    description='one JSON object per line with "@t", "@l", "@m"/"@mt", "@x"',
)
JSON_LINES = LogFormat(
    name="json",
    display_name="JSON lines",
    fields=_CORE,
    parser_factory=JsonLinesParser,
    time_field="time",
    level_field="level",
    message_field="message",
    level_map=MappingProxyType(NUMERIC_JSON_LEVELS),
    filename_hints=_JSON_HINTS,
    dynamic_fields=True,
    specificity=4,
    description="one JSON object per line; time / level / message keys recognised by their usual names",
)
LOGFMT = LogFormat(
    name="logfmt",
    display_name="logfmt (key=value)",
    fields=_CORE,
    parser_factory=LogfmtParser,
    time_field="time",
    level_field="level",
    message_field="message",
    level_map=MappingProxyType(NUMERIC_JSON_LEVELS),
    dynamic_fields=True,
    specificity=4,
)
W3C = LogFormat(
    name="w3c",
    display_name="W3C extended (IIS, HTTP.sys)",
    fields=("time",),
    parser_factory=W3CParser,
    time_field="time",
    filename_hints=("u_ex*.log", "u_in*.log", "u_nc*.log", "ex*.log", "httperr*.log"),
    evidence=re.compile(r"^#Fields:"),
    dynamic_fields=True,
    stateful=True,
    specificity=10,
    description="columns from the latest #Fields: directive; date and time merged into one time column (UTC)",
    times_utc=True,  # W3C extended log format: "Times are recorded in UTC" (IIS, HTTP.sys)
)
APACHE_COMBINED = _regex_format(
    "apache_combined",
    "Apache / nginx combined",
    CLF_COMBINED,
    _Extras(filename_hints=("access*.log", "*access.log", "*access_log*")),
)
APACHE_COMMON = _regex_format(
    "apache_common",
    "Apache / nginx common (CLF)",
    CLF_COMMON,
    _Extras(filename_hints=("access*.log", "*access.log", "*access_log*")),
)
SYSLOG_RFC5424 = _regex_format(
    "syslog_rfc5424",
    "Syslog RFC 5424",
    SYSLOG_5424,
    _Extras(
        transform=_rfc5424,
        fields=("time", "level", "facility", "version", "host", "app", "procid", "msgid", "structured_data", "message"),
        level_map=SYSLOG_LEVELS,
        filename_hints=("syslog*", "*.syslog"),
    ),
)
SYSLOG_RFC3164 = _regex_format(
    "syslog_rfc3164",
    "Syslog RFC 3164 (BSD)",
    SYSLOG_3164,
    _Extras(
        transform=_rfc3164,
        fields=("time", "level", "facility", "host", "app", "pid", "message"),
        level_map=SYSLOG_LEVELS,
        filename_hints=("syslog*", "messages*", "*.syslog", "auth.log*", "kern.log*"),
    ),
)
CMTRACE = LogFormat(
    name="cmtrace",
    display_name="CMTrace (<![LOG[…]LOG]!>)",
    fields=CMTRACE_FIELDS,
    regex=CMTRACE_RECORD,
    parser_factory=lambda: RegexParser(CMTRACE_RECORD, cmtrace_fields),
    multiline=True,
    record_start=CMTRACE_START,
    joined=True,
    time_field="time",
    level_field="level",
    message_field="message",
    level_map=MappingProxyType(CMTRACE_LEVELS),
    evidence=CMTRACE_START,
)
SETUPAPI = LogFormat(
    name="setupapi",
    display_name="Windows setupapi (device install sections)",
    fields=SETUPAPI_FIELDS,
    parser_factory=SetupApiParser,
    time_field="time",
    level_field="level",
    message_field="message",
    level_map=MappingProxyType(SETUPAPI_LEVELS),
    filename_hints=("setupapi*.log",),
    evidence=SETUPAPI_EVIDENCE,
    stateful=True,
    description="!!! = error, ! = warning; each line carries its section title and the latest time seen",
)
WINDOWS_CBS = _regex_format(
    "cbs",
    "Windows CBS / DISM",
    CBS,
    _Extras(multiline=True, level_map={"Perf": "Debug"}, filename_hints=("cbs*.log", "dism*.log")),
)
WINDOWS_UPDATE_LOG = _regex_format(
    "windows_update",
    "Windows Update (decoded ETL)",
    WINDOWS_UPDATE,
    _Extras(filename_hints=("windowsupdate*.log",)),
)
WINDOWS_EVENT_LINES = _regex_format(
    "windows_events",
    "Windows events (LogLens export)",
    WINDOWS_EVENTS,
    _Extras(level_map=WINDOWS_EVENT_LEVELS),
)
CSV = LogFormat(
    name="csv",
    display_name="CSV with header",
    fields=(),
    parser_factory=lambda: DelimitedParser(",;"),
    time_field="time",
    level_field="level",
    message_field="message",
    filename_hints=("*.csv",),
    dynamic_fields=True,
    stateful=True,
    specificity=3,
    description="comma- or semicolon-separated; the header row names the columns",
)
TSV = LogFormat(
    name="tsv",
    display_name="TSV with header",
    fields=(),
    parser_factory=lambda: DelimitedParser("\t"),
    time_field="time",
    level_field="level",
    message_field="message",
    filename_hints=("*.tsv", "*.tab"),
    dynamic_fields=True,
    stateful=True,
    specificity=3,
    description="tab-separated; the header row names the columns",
)
GENERIC = LogFormat(
    name="generic",
    display_name="Generic (timestamp, level, message)",
    fields=GENERIC_FIELDS,
    parser_factory=GenericParser,
    multiline=True,
    time_field="time",
    level_field="level",
    message_field="message",
    fallback=True,
    description="any line starting with a known timestamp; other lines continue the record above",
)

BUILTIN_FORMATS: tuple[LogFormat, ...] = (
    CLEF,
    JSON_LINES,
    LOGFMT,
    W3C,
    CMTRACE,
    SETUPAPI,
    WINDOWS_EVENT_LINES,
    WINDOWS_CBS,
    WINDOWS_UPDATE_LOG,
    SYSLOG_RFC5424,
    SYSLOG_RFC3164,
    APACHE_COMBINED,
    APACHE_COMMON,
    LOG4NET,
    LOG4J,
    LOG4J2_CONSOLE,
    NLOG,
    SERILOG,
    SERILOG_CONSOLE,
    SPRING,
    PYTHON,
    MEL,
    TSV,
    CSV,
    GENERIC,
)
