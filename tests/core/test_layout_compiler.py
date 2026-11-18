"""Layout-pattern compiler (log4net / log4j / NLog / Serilog → regex) and the date-format translator."""

from __future__ import annotations

import re

import pytest

from loglens.core.formats import LayoutError, compile_layout, date_format_regex, detect_layout_style, extract_records
from loglens.core.formats.dates import DateDialect, named_date_regex
from loglens.core.formats.layout import MAX_NESTING, LayoutStyle

# (pattern, style, a line the layout would write, expected fields)
ROUND_TRIPS: list[tuple[str, LayoutStyle, str, dict[str, str]]] = [
    # ---- log4net ----
    (
        "%date [%thread] %-5level %logger - %message%newline",
        "log4net",
        "2026-11-13 10:00:00,123 [Worker 3] INFO  Shop.Program - Started - ok",
        {
            "time": "2026-11-13 10:00:00,123",
            "thread": "Worker 3",
            "level": "INFO",
            "logger": "Shop.Program",
            "message": "Started - ok",
        },
    ),
    (
        "%utcdate{ABSOLUTE} %5level %-20.20logger{1} [%property{user}] %message%newline%exception",
        "log4net",
        "10:00:00,123  WARN Cache                [alice] Low memory",
        {"time": "10:00:00,123", "level": "WARN", "logger": "Cache", "user": "alice", "message": "Low memory"},
    ),
    (
        "%timestamp %-5p %c %x %m%n",
        "log4net",
        "1234 INFO  App req-7 Started",
        {"elapsed": "1234", "level": "INFO", "logger": "App", "ndc": "req-7", "message": "Started"},
    ),
    (
        "%date{yyyy-MM-dd HH:mm:ss.fff} %level %class.%method:%line - %message",
        "log4net",
        "2026-11-13 10:00:00.123 ERROR Shop.Orders.Process:42 - failed",
        {"time": "2026-11-13 10:00:00.123", "class": "Shop.Orders", "method": "Process", "line": "42"},
    ),
    (
        "%date{dd MMM yyyy HH:mm:ss} %-5level %username %appdomain %message",
        "log4net",
        "13 Nov 2026 10:00:00 DEBUG svc-user Shop.exe tick",
        {"time": "13 Nov 2026 10:00:00", "user": "svc-user", "appdomain": "Shop.exe", "message": "tick"},
    ),
    # ---- log4j / Logback ----
    (
        "%d %-5p [%t] %c{1} %X{requestId} - %m%n",
        "log4j",
        "2026-11-13 10:00:00,123 INFO  [main] App r-1 - hello",
        {"time": "2026-11-13 10:00:00,123", "thread": "main", "requestId": "r-1", "message": "hello"},
    ),
    (
        "%d{ISO8601} %highlight{%-5level}{FATAL=red} %style{%logger}{bright,cyan}: %msg%n%throwable",
        "log4j",
        "2026-11-13T10:00:00,123 ERROR com.example.App: boom",
        {"time": "2026-11-13T10:00:00,123", "level": "ERROR", "logger": "com.example.App", "message": "boom"},
    ),
    (
        "%d{yyyy-MM-dd'T'HH:mm:ss.SSSZ} [%T] %m",
        "log4j",
        "2026-11-13T10:00:00.123+0100 [17] hello",
        {"time": "2026-11-13T10:00:00.123+0100", "thread_id": "17", "message": "hello"},
    ),
    (
        "%d{HH:mm:ss} 100%% %m (%F:%L)",
        "log4j",
        "10:00:00 100% failed (twice) (App.java:10)",
        {"message": "failed (twice)", "file": "App.java", "line": "10"},
    ),
    (
        "%d{HH:mm:ss.SSS} %sn %pid %zork %m",
        "log4j",
        "10:00:00.123 5 4242 anything here",
        {"sequence": "5", "pid": "4242", "zork": "anything", "message": "here"},
    ),
    # ---- NLog ----
    (
        "${longdate}|${level:uppercase=true}|${logger}|${message:withexception=true}",
        "nlog",
        "2026-11-13 10:00:00.1234|INFO|Shop.Program|Starting | with pipe",
        {
            "time": "2026-11-13 10:00:00.1234",
            "level": "INFO",
            "logger": "Shop.Program",
            "message": "Starting | with pipe",
        },
    ),
    (
        r"${date:format=yyyy-MM-dd HH\:mm\:ss.fff} ${level:uppercase=true:padding=-5} ${threadid} "
        r"${logger:shortName=true} ${message}${onexception:${newline}${exception:format=tostring}}",
        "nlog",
        "2026-11-13 10:00:00.123 WARN  12 Cache low memory",
        {
            "time": "2026-11-13 10:00:00.123",
            "level": "WARN",
            "thread": "12",
            "logger": "Cache",
            "message": "low memory",
        },
    ),
    (
        "${longdate} ${uppercase:${level}} ${mdlc:item=CorrelationId} ${callsite} ${message}",
        "nlog",
        "2026-11-13 10:00:00.1234 ERROR c-42 Shop.Orders.Process failed hard",
        {"level": "ERROR", "CorrelationId": "c-42", "callsite": "Shop.Orders.Process", "message": "failed hard"},
    ),
    (
        "${time} [${threadname}] ${level} ${event-properties:item=UserId} - ${message}",
        "nlog",
        "10:00:00.1234 [Main Thread] Info u1 - Hello",
        {"time": "10:00:00.1234", "thread": "Main Thread", "level": "Info", "UserId": "u1", "message": "Hello"},
    ),
    (
        "${date} ${pad:padding=5:inner=${level}} ${literal:text=>>} ${foo-bar} ${message}",
        "nlog",
        "2026/11/13 10:00:00.123  Info >> x1 msg",
        {"time": "2026/11/13 10:00:00.123", "level": "Info", "foo_bar": "x1", "message": "msg"},
    ),
    (
        "${shortdate} ${date:format=HH:mm:ss}|${processid}|${machinename}|${message}",
        "nlog",
        "2026-11-13 10:00:00|4242|HOST-1|ok",
        {"date": "2026-11-13", "time": "10:00:00", "pid": "4242", "host": "HOST-1", "message": "ok"},
    ),
    # ---- Serilog ----
    (
        "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {Message:lj}{NewLine}{Exception}",
        "serilog",
        "2026-11-13 10:00:00.123 +01:00 [INF] Starting {not a hole}",
        {"time": "2026-11-13 10:00:00.123 +01:00", "level": "INF", "message": "Starting {not a hole}"},
    ),
    (
        "[{Timestamp:HH:mm:ss} {Level:u3}] {SourceContext}: {Message:lj}{NewLine}{Exception}",
        "serilog",
        "[10:00:00 WRN] Shop.Api.Orders: Slow: 1200 ms",
        {"time": "10:00:00", "level": "WRN", "logger": "Shop.Api.Orders", "message": "Slow: 1200 ms"},
    ),
    (
        "{Timestamp:o} {Level,-11} {ThreadId} {RequestId} {Message}{NewLine}",
        "serilog",
        "2026-11-13T10:00:00.1234567+01:00 Information 12 req-9 Done",
        {"time": "2026-11-13T10:00:00.1234567+01:00", "level": "Information", "thread": "12", "RequestId": "req-9"},
    ),
    (
        "{{app}} {Timestamp:yyyy-MM-dd} {@Message} {Properties:j}",
        "serilog",
        '{app} 2026-11-13 Hello world {"a": 1, "b": "x"}',
        {"time": "2026-11-13", "message": "Hello world", "properties": '{"a": 1, "b": "x"}'},
    ),
    (
        "{Timestamp} {Level,5} {Message}",
        "serilog",
        "11/13/2026 10:00:00 AM +01:00  Warn careful",
        {"time": "11/13/2026 10:00:00 AM +01:00", "level": "Warn", "message": "careful"},
    ),
]


@pytest.mark.parametrize(("pattern", "style", "line", "expected"), ROUND_TRIPS)
def test_layout_round_trip(pattern: str, style: LayoutStyle, line: str, expected: dict[str, str]) -> None:
    fmt = compile_layout(pattern, style=style)
    fields = fmt.parse(line)
    assert fields is not None, fmt.regex.pattern if fmt.regex else ""
    assert {key: fields.get(key) for key in expected} == expected
    assert fmt.multiline
    auto = compile_layout(pattern)  # auto-detection gives the same fields for these patterns
    assert auto.fields == fmt.fields


def test_layout_roles_and_metadata() -> None:
    fmt = compile_layout("%date [%thread] %-5level %logger - %message%newline", name="mine", display_name="Mine")
    assert (fmt.name, fmt.display_name) == ("mine", "Mine")
    assert fmt.fields == ("time", "thread", "level", "logger", "message")
    assert (fmt.time_field, fmt.level_field, fmt.message_field) == ("time", "level", "message")
    assert "log4net" in fmt.description
    assert compile_layout("%d{HH:mm:ss.SSS} %m").description.startswith("log4j")


def test_duplicate_conversions_get_distinct_groups() -> None:
    fmt = compile_layout("%date %date{HH:mm} %message", style="log4net")
    assert fmt.fields == ("time", "time_2", "message")


def test_literal_line_break_ends_the_first_line_and_trailing_blanks_are_optional() -> None:
    # layouts pasted from XML config often carry a real line break instead of %newline
    fmt = compile_layout("%date [%thread] %message ]  \r\n%exception", style="log4net")
    assert fmt.fields == ("time", "thread", "message")
    assert fmt.parse("2026-11-13 10:00:00,123 [1] hello ]") == {
        "time": "2026-11-13 10:00:00,123",
        "thread": "1",
        "message": "hello",
    }


def test_conversion_names_are_read_like_the_libraries_do() -> None:
    # log4j / log4net take the longest known conversion name and treat the rest as literal text
    fmt = compile_layout("%d{HH:mm} %clogger %m", style="log4j")
    assert fmt.fields == ("time", "logger", "message")
    assert fmt.parse("10:00 App.Mainlogger hi") == {"time": "10:00", "logger": "App.Main", "message": "hi"}
    assert compile_layout("%level-%message", style="log4net").fields == ("level", "message")


def test_continuation_lines_join_the_message() -> None:
    fmt = compile_layout("%date [%thread] %-5level %logger - %message%newline%exception")
    lines = [
        "2026-11-13 10:00:00,123 [1] ERROR App - failed",
        "System.Exception: boom",
        "   at App.Main()",
        "2026-11-13 10:00:01,000 [1] INFO  App - next",
    ]
    records = extract_records(fmt, lines)
    assert [r.line_count for r in records] == [3, 1]
    assert records[0].fields["message"] == "failed\nSystem.Exception: boom\n   at App.Main()"


def test_lines_of_other_layouts_do_not_match() -> None:
    fmt = compile_layout("${longdate}|${level}|${logger}|${message}")
    assert fmt.parse("2026-11-13 10:00:00,123 [1] INFO  App - hello") is None
    assert fmt.parse("2026-11-13 10:00:00.1234|INFO|App|hello") is not None


@pytest.mark.parametrize(
    ("pattern", "style", "message"),
    [
        ("%date{yyyy [%thread] %message", "log4net", "unbalanced"),
        ("${longdate} ${level", "nlog", "unbalanced"),
        ("{Timestamp} {Level", "serilog", "unbalanced '{'"),
        ("{Timestamp} Level} {Message}", "serilog", "unbalanced '}'"),
        ("{Not Valid} {Message}", "serilog", "invalid property"),
        ("%date %", "log4net", "missing conversion name"),
        ("%date %-5 x", "log4net", "missing conversion name"),
        ("", "auto", "empty"),
        ("plain text only", "auto", "cannot tell"),
        ("%n", "log4net", "no fields"),
        ("literal ${newline}${message}", "nlog", "no fields"),
        ("${}", "nlog", "empty"),
        ("%d{yyyy 'T} %m", "log4j", "unterminated"),
        ("%m", "log5j", "unknown layout style"),
    ],
)
def test_layout_errors(pattern: str, style: LayoutStyle, message: str) -> None:
    with pytest.raises(LayoutError, match=message):
        compile_layout(pattern, style=style)


def test_layout_error_position() -> None:
    with pytest.raises(LayoutError) as caught:
        compile_layout("%date %level %", style="log4net")
    assert caught.value.position == 13
    assert "position 13" in str(caught.value)


def test_nesting_is_bounded() -> None:
    pattern = "%highlight{" * (MAX_NESTING + 2) + "%m" + "}" * (MAX_NESTING + 2)
    with pytest.raises(LayoutError, match="nested too deeply"):
        compile_layout(pattern, style="log4j")


@pytest.mark.parametrize(
    ("pattern", "style"),
    [
        ("%date [%thread] %-5level %logger - %message", "log4net"),
        ("%d{HH:mm:ss.SSS} [%t] %-5level %logger{36} - %msg%n", "log4j"),
        ("${longdate}|${level}|${message}", "nlog"),
        ("[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}", "serilog"),
    ],
)
def test_detect_layout_style(pattern: str, style: str) -> None:
    assert detect_layout_style(pattern) == style


# ---- date formats ----------------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("fmt", "dialect", "text"),
    [
        ("yyyy-MM-dd HH:mm:ss,fff", "dotnet", "2026-11-13 10:00:00,123"),
        ("dd/MM/yyyy hh:mm:ss tt", "dotnet", "13/11/2026 10:00:00 AM"),
        ("ddd, dd MMM yyyy HH':'mm':'ss zzz", "dotnet", "Fri, 13 Nov 2026 10:00:00 +01:00"),
        ("dddd d MMMM yyyy H:m:s.FFF", "dotnet", "Friday 3 November 2026 9:5:7.1"),
        (r"yyyy\-MM\-dd\THH:mm:ssK", "dotnet", "2026-11-13T10:00:00Z"),
        ("o", "dotnet", "2026-11-13T10:00:00.1234567+01:00"),
        ("s", "dotnet", "2026-11-13T10:00:00"),
        ("u", "dotnet", "2026-11-13 10:00:00Z"),
        ("G", "dotnet", "11/13/2026 10:00:00 AM"),
        ("yyyy-MM-dd'T'HH:mm:ss.SSSXXX", "java", "2026-11-13T10:00:00.123+01:00"),
        ("yyyy-MM-dd'T'HH:mm:ss.SSSXXX", "java", "2026-11-13T10:00:00.123Z"),
        ("EEE MMM dd HH:mm:ss z yyyy", "java", "Fri Nov 13 10:00:00 CET 2026"),
        ("dd-MMM-yyyy hh:mm:ss a Z", "java", "13-Nov-2026 10:00:00 AM +0100"),
        ("yyyyMMdd''HHmmss", "java", "20261113'100000"),
        ("", "dotnet", "2026-11-13 10:00:00.123Z"),
    ],
)
def test_date_format_regex(fmt: str, dialect: DateDialect, text: str) -> None:
    regex = date_format_regex(fmt, dialect=dialect)
    assert re.fullmatch(regex, text), regex


def test_date_format_regex_rejects_other_shapes() -> None:
    assert not re.fullmatch(date_format_regex("yyyy-MM-dd HH:mm:ss,fff"), "2026-11-13 10:00:00.123")
    assert not re.fullmatch(date_format_regex("HH:mm:ss.SSS", dialect="java"), "10:00:00")


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("ISO8601", "2026-11-13 10:00:00,123"),
        ("ISO8601", "2026-11-13T10:00:00,123"),
        ("ISO8601_OFFSET_DATE_TIME_HHCMM", "2026-11-13T10:00:00,123+01:00"),
        ("DEFAULT", "2026-11-13 10:00:00,123"),
        ("ABSOLUTE", "10:00:00,123"),
        ("DATE", "13 Nov 2026 10:00:00,123"),
        ("COMPACT", "20261113100000123"),
        ("ISO8601_BASIC", "20261113T100000,123"),
        ("UNIX_MILLIS", "1763024400000"),
    ],
)
def test_named_date_formats(name: str, text: str) -> None:
    regex = named_date_regex(name)
    assert regex is not None
    assert re.fullmatch(regex, text)


def test_format_strings_are_not_named_formats() -> None:
    assert named_date_regex("yyyy-MM-dd") is None
    assert named_date_regex("HH") is None
    assert named_date_regex("") is None
