"""Format detection, field extraction, multi-line records, level mapping, facets and user formats (synthetic lines)."""

from __future__ import annotations

import json
import re
import time
from datetime import UTC, datetime

import pytest

from loglens.core.formats import (
    ALL_FORMATS,
    CANONICAL_LEVELS,
    GENERIC,
    CustomFormat,
    CustomFormatError,
    LogFormat,
    canonical_level,
    detect_format,
    extract_fields,
    extract_records,
    facets,
    format_by_name,
    level_facets,
    score_format,
)
from loglens.core.formats.builtin import LOG4NET, SETUPAPI, W3C
from loglens.core.winevent.models import EventRecord

# ---- synthetic samples (same shape as the real formats, made-up content) ---------------------------------------------
LOG4NET_LINES = [
    "2026-11-13 10:00:00,123 [1] INFO  Shop.Program - Starting service",
    "2026-11-13 10:00:00,456 [Worker 7] WARN  Shop.Cache - Cache miss for key 42",
    "2026-11-13 10:00:01,001 [7] ERROR Shop.Orders - Order failed",
    "System.InvalidOperationException: Sequence contains no elements",
    r"   at Shop.Orders.Process() in C:\src\Orders.cs:line 10",
    "2026-11-13 10:00:02,000 [1] DEBUG Shop.Program - Done",
]
LOG4J_LINES = [
    "2026-11-13 10:00:00 INFO  Main:42 - Application started",
    "2026-11-13 10:00:01 ERROR Repo:87 - Query failed",
    "java.sql.SQLException: timeout",
    "\tat com.example.Repo.find(Repo.java:87)",
    "2026-11-13 10:00:02 WARN  Main:50 - Slow response",
]
LOG4J2_LINES = [
    "10:00:00.123 [main] INFO  com.example.App - Started",
    "10:00:00.456 [pool-1-thread-2] ERROR com.example.Worker - Job failed",
    "java.lang.IllegalStateException: boom",
    "\tat com.example.Worker.run(Worker.java:10)",
    "10:00:01.000 [main] DEBUG com.example.App - Tick",
]
NLOG_LINES = [
    "2026-11-13 10:00:00.1234|INFO|Shop.Program|Starting",
    "2026-11-13 10:00:00.5678|WARN|Shop.Cache|Cache is cold",
    "2026-11-13 10:00:01.0000|ERROR|Shop.Db|Connection lost System.TimeoutException: timed out",
]
SERILOG_LINES = [
    "2026-11-13 10:00:00.123 +01:00 [INF] Starting web host",
    "2026-11-13 10:00:00.456 +01:00 [WRN] Slow request /api/items took 1200 ms",
    "2026-11-13 10:00:01.000 +01:00 [ERR] Unhandled exception",
    "System.NullReferenceException: Object reference not set to an instance of an object.",
    "   at Api.Controllers.ItemsController.Get()",
]
SERILOG_CONSOLE_LINES = [
    "[10:00:00 INF] Starting web host",
    "[10:00:01 WRN] Slow request",
    "[10:00:02 ERR] Unhandled exception",
    "System.Exception: boom",
    "   at Api.Worker.Run()",
]
CLEF_LINES = [
    '{"@t":"2026-11-13T09:00:00.1234567Z","@mt":"Started {App} in {Elapsed} ms","App":"Shop","Elapsed":120}',
    '{"@t":"2026-11-13T09:00:01.0000000Z","@l":"Error","@mt":"Order {OrderId} failed","OrderId":42,'
    '"@x":"System.Exception: boom"}',
    '{"@t":"2026-11-13T09:00:02.0000000Z","@l":"Warning","@m":"Disk almost full","Drive":"C:"}',
]
JSON_LINES = [
    '{"timestamp":"2026-11-13T09:00:00Z","level":"info","msg":"listening","port":8080}',
    '{"timestamp":"2026-11-13T09:00:01Z","level":"error","msg":"request failed","http":{"method":"GET","status":500}}',
    '{"timestamp":"2026-11-13T09:00:02Z","level":"warn","msg":"slow","took_ms":1500,"tags":["a","b"]}',
]
LOGFMT_LINES = [
    'time=2026-11-13T09:00:00Z level=info msg="server started" port=8080',
    'time=2026-11-13T09:00:01Z level=error msg="db timeout \\"primary\\"" duration=5s',
    "time=2026-11-13T09:00:02Z level=debug msg=tick",
]
W3C_LINES = [
    "#Software: Example HTTP Server 1.0",
    "#Version: 1.0",
    "#Date: 2026-11-13 09:00:00",
    "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port c-ip cs(User-Agent) sc-status time-taken",
    "2026-11-13 09:00:00 10.0.0.1 GET /index.html - 80 10.0.0.9 Mozilla/5.0+(Windows+NT+10.0) 200 15",
    "2026-11-13 09:00:01 10.0.0.1 POST /api/orders id=4 443 10.0.0.9 curl/8.4.0 500 230",
    "2026-11-13 09:00:02 10.0.0.1 GET /api/orders - 443 10.0.0.8 curl/8.4.0 200 12",
    "#Fields: date time cs-method cs-uri-stem sc-status",
    "2026-11-13 09:05:00 GET /health 200",
]
APACHE_COMBINED_LINES = [
    '192.0.2.10 - alice [13/Nov/2026:10:00:00 +0100] "GET /index.html HTTP/1.1" 200 5120 "https://example.com/" '
    '"Mozilla/5.0 (X11; Linux x86_64)"',
    '198.51.100.7 - - [13/Nov/2026:10:00:01 +0100] "POST /api/login HTTP/1.1" 401 32 "-" "curl/8.4.0"',
    '198.51.100.7 - - [13/Nov/2026:10:00:02 +0100] "GET /favicon.ico HTTP/1.1" 404 - "-" "curl/8.4.0"',
]
APACHE_COMMON_LINES = [
    '192.0.2.10 - alice [13/Nov/2026:10:00:00 +0100] "GET /index.html HTTP/1.0" 200 5120',
    '198.51.100.7 - - [13/Nov/2026:10:00:01 +0100] "GET /missing HTTP/1.0" 404 -',
    '198.51.100.7 - - [13/Nov/2026:10:00:02 +0100] "GET /a HTTP/1.0" 200 10',
]
SYSLOG_3164_LINES = [
    "<34>Nov 13 10:00:00 web01 sshd[2211]: Failed password for invalid user admin from 192.0.2.5 port 50022",
    "Nov 13 10:00:05 web01 CRON[3001]: (root) CMD (run-parts /etc/cron.hourly)",
    "<13>Nov 13 10:00:09 web01 app: started",
]
SYSLOG_5424_LINES = [
    '<165>1 2026-11-13T10:00:00.003Z host1.example.org evntslog 1234 ID47 [exampleSDID@32473 iut="3"] An event',
    "<34>1 2026-11-13T10:00:01Z host1 su - ID47 - 'su root' failed for user1 on /dev/pts/8",
    "<14>1 2026-11-13T10:00:02Z host1 app 77 - - started",
]
CMTRACE_LINES = [
    '<![LOG[Starting deployment]LOG]!><time="10:00:00.123+000" date="11-13-2026" component="Setup" context="" '
    'type="1" thread="1234" file="setup.cpp:10">',
    "<![LOG[Could not find file",
    'second line of message]LOG]!><time="10:00:01.000+000" date="11-13-2026" component="Setup" context="" '
    'type="3" thread="1234" file="setup.cpp:20">',
    '<![LOG[Retrying]LOG]!><time="10:00:02.000+000" date="11-13-2026" component="Setup" context="" type="2" '
    'thread="1234" file="">',
]
SETUPAPI_LINES = [
    "[Device Install Log]",
    "     OS Version = 10.0.26100",
    "     Architecture = amd64",
    "",
    "[BeginLog]",
    "",
    "[Boot Session: 2026/11/13 09:58:12.500]",
    "",
    r">>>  [Device Install (Hardware initiated) - USB\VID_1234&PID_5678\0001]",
    ">>>  Section start 2026/11/13 10:00:00.123",
    "     ump: Creating Install Process: DrvInst.exe 10:00:00.125",
    "     ndv: Retrieving device info...",
    "     dvi: {Build Driver List} 10:00:00.140",
    "!    dvi: Device not started: Device has problem: 0x1c.",
    "!!!  dvi: Default installer: failed!",
    "<<<  Section end 2026/11/13 10:00:01.500",
    "<<<  [Exit status: FAILURE(0xe0000219)]",
]
CBS_LINES = [
    "2026-11-13 10:00:00, Info                  CBS    Starting the servicing stack initialization.",
    "2026-11-13 10:00:01, Warning               CBS    Failed to get session package state [HRESULT = 0x80070490]",
    "2026-11-13 10:00:02, Error                 DISM   DISM Package Manager: PID=1234 TID=5678 Failed finalizing.",
    "2026-11-13 10:00:03, Info                  CSI    00000001 Shim considered [l:123] : got STATUS_SUCCESS",
]
WINDOWS_UPDATE_LINES = [
    "2026/11/13 10:00:00.1234567 1234  5678  Agent           * START *   Finding updates CallerId = Orchestrator",
    "2026/11/13 10:00:01.2345678 1234  5678  ComApi          Search ClientId = Orchestrator",
    "2026/11/13 10:00:02.0000000 1234  9012  Handler         Download completed",
]
SPRING_LINES = [
    "2026-11-13T10:00:00.123+01:00  INFO 12345 --- [           main] c.e.shop.ShopApplication                 : "
    "Started ShopApplication in 2.1 seconds",
    "2026-11-13T10:00:01.456+01:00 ERROR 12345 --- [nio-8080-exec-1] c.e.shop.web.OrderController             : "
    "Request failed",
    "java.lang.NullPointerException: null",
    "\tat com.example.shop.web.OrderController.get(OrderController.java:20)",
]
PYTHON_LINES = [
    "2026-11-13 10:00:00,123 - myapp.db - INFO - connected",
    "2026-11-13 10:00:01,456 - myapp.api - ERROR - request failed",
    "Traceback (most recent call last):",
    '  File "app.py", line 10, in <module>',
    "ValueError: bad",
]
MEL_LINES = [
    "info: Shop.Hosting.Lifetime[14]",
    "      Now listening on: http://localhost:5000",
    "warn: Shop.Api.Controllers.OrdersController[0]",
    "      Slow request",
    "fail: Shop.Api.Startup[1000]",
    "      Unhandled exception",
]
CSV_LINES = [
    "Timestamp,Severity,Source,Message",
    '2026-11-13 10:00:00,Information,Api,"Started, listening on 8080"',
    "2026-11-13 10:00:01,Error,Db,Connection lost",
    "2026-11-13 10:00:02,Warning,Api,Slow request",
]
TSV_LINES = [
    "time\tlevel\tcomponent\tmessage",
    "2026-11-13 10:00:00\tINFO\tapi\tstarted",
    "2026-11-13 10:00:01\tERROR\tdb\tconnection lost",
    "2026-11-13 10:00:02\tWARN\tapi\tslow",
]
GENERIC_LINES = [
    "2026-11-13 10:00:00 [main] ERROR Something broke",
    "2026-11-13 10:00:01 WARNING disk low",
    "[2026-11-13 10:00:02] info: hello",
    "2026-11-13 10:00:03 just text",
]
PLAIN_LINES = ["Hello world", "This is a readme", "nothing to see here", "- a bullet", "", "The end."]


def _event_lines() -> list[str]:
    stamp = datetime(2026, 11, 13, 9, 0, tzinfo=UTC)
    return [
        EventRecord(
            "System", "Service Control Manager", 7031, 2, stamp, record_id=1, message="Service stopped."
        ).to_line(),
        EventRecord("Application", "Demo Source", 1000, 4, stamp, message="Hello").to_line(),
        EventRecord("Security", "Audit Source", 4625, 0, stamp, keywords=0x10000000000000, message="Logon").to_line(),
    ]


SAMPLES: dict[str, list[str]] = {
    "log4net": LOG4NET_LINES,
    "log4j": LOG4J_LINES,
    "log4j2": LOG4J2_LINES,
    "nlog": NLOG_LINES,
    "serilog": SERILOG_LINES,
    "serilog_console": SERILOG_CONSOLE_LINES,
    "clef": CLEF_LINES,
    "json": JSON_LINES,
    "logfmt": LOGFMT_LINES,
    "w3c": W3C_LINES,
    "apache_combined": APACHE_COMBINED_LINES,
    "apache_common": APACHE_COMMON_LINES,
    "syslog_rfc3164": SYSLOG_3164_LINES,
    "syslog_rfc5424": SYSLOG_5424_LINES,
    "cmtrace": CMTRACE_LINES,
    "setupapi": SETUPAPI_LINES,
    "cbs": CBS_LINES,
    "windows_update": WINDOWS_UPDATE_LINES,
    "windows_events": _event_lines(),
    "spring_boot": SPRING_LINES,
    "python_logging": PYTHON_LINES,
    "mel_console": MEL_LINES,
    "csv": CSV_LINES,
    "tsv": TSV_LINES,
    "generic": GENERIC_LINES,
}


def _fmt(name: str) -> LogFormat:
    fmt = format_by_name(name)
    assert fmt is not None, name
    return fmt


# ---- catalog ---------------------------------------------------------------------------------------------------------
def test_catalog_names_are_unique_and_every_builtin_has_a_sample() -> None:
    names = [fmt.name for fmt in ALL_FORMATS]
    assert len(names) == len(set(names))
    assert set(names) == set(SAMPLES)
    assert format_by_name("nope") is None
    assert ALL_FORMATS[-1] is GENERIC  # the fallback is last


def test_formats_are_hashable_value_objects() -> None:
    assert len({fmt: fmt.name for fmt in ALL_FORMATS}) == len(ALL_FORMATS)


# ---- detection -------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("name", list(SAMPLES))
def test_detects_each_builtin_format(name: str) -> None:
    detection = detect_format(SAMPLES[name])
    assert detection.format.name == name, [(f.name, s) for f, s in detection.alternatives]
    assert detection.confidence >= 0.25
    assert all(fmt.name != name for fmt, _ in detection.alternatives)


def test_plain_text_falls_back_to_generic_with_zero_confidence() -> None:
    detection = detect_format(PLAIN_LINES)
    assert detection.format is GENERIC
    assert detection.confidence == 0.0
    assert detect_format([]).format is GENERIC


def test_specific_format_beats_generic_fallback() -> None:
    detection = detect_format(LOG4NET_LINES)
    assert detection.format.name == "log4net"
    assert any(fmt is GENERIC for fmt, _ in detection.alternatives)


def test_more_specific_format_wins_ties() -> None:
    # CLEF lines are JSON lines too; CLEF knows more about them.
    detection = detect_format(CLEF_LINES)
    assert detection.format.name == "clef"
    assert detection.alternatives[0][0].name == "json"
    assert detection.alternatives[0][1] == detection.confidence


def test_filename_hint_breaks_near_ties() -> None:
    # One W3C data line among unparseable junk: content alone is weak, the u_ex*.log name tips it.
    lines = ["#Fields: date time cs-method cs-uri-stem sc-status", "2026-11-13 09:00:00 GET / 200"]
    assert detect_format(lines, filename=r"C:\logs\W3SVC1\u_ex261113.log").format.name == "w3c"


def test_continuation_lines_are_not_failures() -> None:
    with_trace = score_format(LOG4NET, LOG4NET_LINES)
    records = 4
    assert with_trace == pytest.approx(records / (records + 1))
    # a line with a timestamp that doesn't fit the layout is a failure
    assert score_format(LOG4NET, [*LOG4NET_LINES, "2026-11-13 10:00:03 something else"]) < with_trace


def test_orphan_lines_before_the_first_record_count_as_failures() -> None:
    assert score_format(LOG4NET, ["just text", *LOG4NET_LINES]) < score_format(LOG4NET, LOG4NET_LINES)


def test_user_format_competes_and_wins_ties() -> None:
    custom = CustomFormat(
        "Pipes", regex=r"(?P<time>[\d-]+ [\d:.]+)\|(?P<level>\w+)\|(?P<logger>[^|]+)\|(?P<message>.*)"
    )
    detection = detect_format(NLOG_LINES, candidates=[*ALL_FORMATS, custom.to_format()])
    assert detection.format.name == "custom:Pipes"


_CLOCK = re.compile(r"10:00:0\d")


def _unique_lines(lines: list[str], count: int = 2_000) -> list[str]:
    """``count`` lines cycling through ``lines`` with distinct clock times (real files don't repeat lines)."""
    return [
        _CLOCK.sub(f"{10 + i // 3600:02d}:{i // 60 % 60:02d}:{i % 60:02d}", lines[i % len(lines)]) for i in range(count)
    ]


@pytest.mark.parametrize("name", ["log4net", "clef", "w3c", "cmtrace", "apache_combined", "syslog_rfc3164"])
def test_detection_is_fast_on_two_thousand_lines(name: str) -> None:
    sample = _unique_lines(SAMPLES[name])
    assert detect_format(sample).format.name == name
    best = min(_timed(sample) for _ in range(3))
    assert best < 0.1, f"{best * 1000:.0f} ms"


def test_detection_is_fast_on_plain_and_very_long_lines() -> None:
    for sample in [(PLAIN_LINES * 400)[:2_000], [f"{'x' * 5_000} {i}" for i in range(2_000)]]:
        assert min(_timed(sample) for _ in range(3)) < 0.1


def _timed(sample: list[str]) -> float:
    start = time.perf_counter()
    detect_format(sample)
    return time.perf_counter() - start


def test_detection_is_deterministic() -> None:
    first = detect_format(GENERIC_LINES)
    assert all(detect_format(GENERIC_LINES) == first for _ in range(3))


# ---- field extraction ------------------------------------------------------------------------------------------------
def test_log4net_fields_and_multiline_records() -> None:
    records = extract_records(LOG4NET, LOG4NET_LINES, first_line=100)
    assert [r.line for r in records] == [100, 101, 102, 105]
    assert [r.line_count for r in records] == [1, 1, 3, 1]
    assert records[1].fields == {
        "time": "2026-11-13 10:00:00,456",
        "thread": "Worker 7",
        "level": "WARN",
        "logger": "Shop.Cache",
        "message": "Cache miss for key 42",
    }
    message = records[2].fields["message"]
    assert message.startswith("Order failed\nSystem.InvalidOperationException")
    assert message.endswith(r"C:\src\Orders.cs:line 10")


def test_lines_before_the_first_record_are_kept_unparsed() -> None:
    records = extract_records(LOG4NET, ["   at Orphan.Frame()", *LOG4NET_LINES[:2]])
    assert not records[0].parsed
    assert records[0].fields == {"message": "   at Orphan.Frame()"}
    assert records[1].parsed


def test_single_line_format_keeps_unparsed_lines() -> None:
    records = extract_records(_fmt("apache_common"), [*APACHE_COMMON_LINES[:1], "garbage", ""])
    assert [r.parsed for r in records] == [True, False]


@pytest.mark.parametrize(
    ("name", "index", "expected"),
    [
        ("log4j", 0, {"time": "2026-11-13 10:00:00", "level": "INFO", "logger": "Main", "line": "42"}),
        ("log4j2", 1, {"time": "10:00:00.456", "thread": "pool-1-thread-2", "logger": "com.example.Worker"}),
        (
            "nlog",
            2,
            {"level": "ERROR", "logger": "Shop.Db", "message": "Connection lost System.TimeoutException: timed out"},
        ),
        ("serilog", 1, {"time": "2026-11-13 10:00:00.456 +01:00", "level": "WRN"}),
        ("serilog_console", 0, {"time": "10:00:00", "level": "INF", "message": "Starting web host"}),
        ("clef", 0, {"level": "Information", "message": "Started Shop in 120 ms", "App": "Shop", "Elapsed": "120"}),
        ("clef", 1, {"level": "Error", "exception": "System.Exception: boom", "OrderId": "42"}),
        (
            "json",
            1,
            {"time": "2026-11-13T09:00:01Z", "level": "error", "message": "request failed", "http.status": "500"},
        ),
        ("json", 2, {"took_ms": "1500", "tags": '["a","b"]'}),
        ("logfmt", 1, {"time": "2026-11-13T09:00:01Z", "level": "error", "message": 'db timeout "primary"'}),
        ("apache_combined", 0, {"host": "192.0.2.10", "user": "alice", "method": "GET", "path": "/index.html"}),
        ("apache_combined", 2, {"status": "404", "size": "-", "agent": "curl/8.4.0"}),
        ("apache_common", 1, {"time": "13/Nov/2026:10:00:01 +0100", "status": "404", "protocol": "HTTP/1.0"}),
        ("syslog_rfc3164", 0, {"level": "crit", "facility": "auth", "host": "web01", "app": "sshd", "pid": "2211"}),
        (
            "syslog_rfc3164",
            1,
            {"level": "", "facility": "", "app": "CRON", "message": "(root) CMD (run-parts /etc/cron.hourly)"},
        ),
        ("syslog_rfc5424", 0, {"level": "notice", "facility": "local4", "msgid": "ID47", "message": "An event"}),
        ("syslog_rfc5424", 1, {"app": "su", "procid": "", "structured_data": ""}),
        ("cbs", 2, {"time": "2026-11-13 10:00:02", "level": "Error", "component": "DISM"}),
        ("windows_update", 0, {"pid": "1234", "tid": "5678", "component": "Agent"}),
        ("spring_boot", 0, {"level": "INFO", "pid": "12345", "thread": "main", "logger": "c.e.shop.ShopApplication"}),
        ("python_logging", 0, {"logger": "myapp.db", "level": "INFO", "message": "connected"}),
        ("mel_console", 1, {"level": "warn", "category": "Shop.Api.Controllers.OrdersController", "event_id": "0"}),
        ("csv", 0, {"time": "2026-11-13 10:00:00", "level": "Information", "Source": "Api"}),
        ("tsv", 1, {"time": "2026-11-13 10:00:01", "level": "ERROR", "component": "db", "message": "connection lost"}),
        (
            "generic",
            0,
            {"time": "2026-11-13 10:00:00", "level": "ERROR", "context": "main", "message": "Something broke"},
        ),
        ("generic", 2, {"time": "2026-11-13 10:00:02", "level": "info", "message": "hello"}),
        ("generic", 3, {"level": "", "message": "just text"}),
    ],
)
def test_field_values(name: str, index: int, expected: dict[str, str]) -> None:
    records = [r for r in extract_records(_fmt(name), SAMPLES[name]) if r.parsed]
    fields = records[index].fields
    assert {key: fields.get(key) for key in expected} == expected


def test_csv_quoted_delimiter_and_header_names() -> None:
    fields = extract_fields(_fmt("csv"), CSV_LINES)
    assert list(fields[0]) == ["time", "level", "message", "Source"]  # time / level / message first
    assert fields[0]["message"] == "Started, listening on 8080"
    assert len(fields) == 3


def test_csv_without_header_or_with_wrong_column_count() -> None:
    assert score_format(_fmt("csv"), CSV_LINES[1:]) == 0.0  # no header: nothing to name the columns
    records = extract_records(_fmt("csv"), [*CSV_LINES, "2026-11-13 10:00:03,Error,Db"])
    assert not records[-1].parsed


def test_decimal_comma_of_a_timestamp_is_not_a_csv_column() -> None:
    # A first line that looks like a 2-column header, then lines whose only comma is the timestamp's decimal comma.
    lines = ["Starting, please wait", *LOG4NET_LINES]
    assert detect_format(lines).format.name == "log4net"
    assert score_format(_fmt("csv"), lines) == 0.0
    # a timestamp column followed by a numeric column is still CSV
    fields = extract_fields(_fmt("csv"), ["Time,Count,Note", "2026-11-13 10:00:00,5,ok"])
    assert fields == [{"time": "2026-11-13 10:00:00", "Count": "5", "Note": "ok"}]


def test_semicolon_csv_and_trailing_delimiter() -> None:
    fields = extract_fields(_fmt("csv"), ["Date;Level;Text;", "2026-11-13;Info;hello;"])
    assert fields == [{"time": "2026-11-13", "level": "Info", "message": "hello"}]


def test_w3c_fields_change_mid_file() -> None:
    records = extract_records(W3C, W3C_LINES)
    assert len(records) == 4
    first = records[0].fields
    assert first["time"] == "2026-11-13 09:00:00"
    assert "date" not in first
    assert first["cs-uri-query"] == ""  # "-" = no value
    assert first["cs(User-Agent)"] == "Mozilla/5.0+(Windows+NT+10.0)"
    assert records[3].fields == {
        "time": "2026-11-13 09:05:00",
        "cs-method": "GET",
        "cs-uri-stem": "/health",
        "sc-status": "200",
    }
    assert records[3].line == 8


def test_w3c_needs_its_directive_as_context_mid_file() -> None:
    tail = W3C_LINES[5:7]
    assert all(not r.parsed for r in extract_records(W3C, tail))
    records = extract_records(W3C, tail, first_line=5, context=[W3C_LINES[3]])
    assert [r.fields["cs-method"] for r in records] == ["POST", "GET"]
    assert records[0].line == 5


def test_w3c_time_only_uses_date_directive() -> None:
    lines = ["#Date: 2026-11-13 00:00:00", "#Fields: time cs-method sc-status", "09:00:00 GET 200"]
    assert extract_fields(W3C, lines) == [{"time": "2026-11-13 09:00:00", "cs-method": "GET", "sc-status": "200"}]


def test_cmtrace_joined_multiline_record() -> None:
    records = extract_records(_fmt("cmtrace"), CMTRACE_LINES)
    assert [r.line_count for r in records] == [1, 2, 1]
    second = records[1].fields
    assert second["message"] == "Could not find file\nsecond line of message"
    assert second["time"] == "2026-11-13 10:00:01.000"
    assert second["component"] == "Setup"
    assert second["file"] == "setup.cpp:20"


def test_setupapi_sections_and_times() -> None:
    records = extract_records(SETUPAPI, SETUPAPI_LINES)
    by_message = {r.fields["message"]: r.fields for r in records}
    failed = by_message["Default installer: failed!"]
    assert failed["section"].startswith("Device Install (Hardware initiated)")
    assert failed["category"] == "dvi"
    assert failed["time"] == "2026/11/13 10:00:00.140"  # latest time seen in the section
    assert by_message["Retrieving device info..."]["time"] == "2026/11/13 10:00:00.125"
    assert by_message["[Boot Session: 2026/11/13 09:58:12.500]"]["time"] == "2026/11/13 09:58:12.500"
    assert by_message["[Exit status: FAILURE(0xe0000219)]"]["section"]  # still inside the section
    assert all(r.parsed for r in records)


def test_message_below_its_header_line_is_dedented() -> None:
    records = extract_records(_fmt("mel_console"), MEL_LINES)
    messages = [r.fields["message"] for r in records]
    assert messages == ["Now listening on: http://localhost:5000", "Slow request", "Unhandled exception"]
    assert records[0].fields["category"] == "Shop.Hosting.Lifetime"


def test_windows_event_lines_round_trip() -> None:
    records = extract_records(_fmt("windows_events"), _event_lines())
    first = records[0].fields
    assert (first["level"], first["channel"], first["provider"], first["event_id"]) == (
        "Error",
        "System",
        "Service Control Manager",
        "7031",
    )
    assert first["message"] == "Service stopped."
    assert json.loads(first["details"])["record"] == 1
    assert json.loads(records[1].fields["details"]) == {"message": "Hello"}
    assert records[2].fields["level"] == "AuditFailure"


# ---- levels ----------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("name", "index", "level"),
    [
        ("setupapi", "!!!  dvi: Default installer: failed!", "Error"),
        ("setupapi", "!    dvi: Device not started: Device has problem: 0x1c.", "Warning"),
        ("setupapi", "     ndv: Retrieving device info...", ""),
    ],
)
def test_setupapi_levels(name: str, index: str, level: str) -> None:
    fmt = _fmt(name)
    fields = fmt.parse(index)
    assert fields is not None
    assert fmt.level_of(fields) == level


@pytest.mark.parametrize(
    ("name", "levels"),
    [
        ("syslog_rfc3164", {"Critical": 1, "Info": 1}),  # <34> = auth.crit, <13> = user.notice, no PRI = unknown
        ("syslog_rfc5424", {"Info": 2, "Critical": 1}),
        ("cmtrace", {"Info": 1, "Error": 1, "Warning": 1}),
        ("serilog", {"Info": 1, "Warning": 1, "Error": 1}),
        ("clef", {"Info": 1, "Error": 1, "Warning": 1}),  # no @l = Information
        ("mel_console", {"Info": 1, "Warning": 1, "Error": 1}),
        ("cbs", {"Info": 2, "Warning": 1, "Error": 1}),
        ("windows_events", {"Error": 1, "Info": 1, "Warning": 1}),
        ("log4net", {"Info": 1, "Warning": 1, "Error": 1, "Debug": 1}),
    ],
)
def test_level_mapping(name: str, levels: dict[str, int]) -> None:
    fmt = _fmt(name)
    assert dict(level_facets(fmt, extract_records(fmt, SAMPLES[name]))) == levels


def test_canonical_level_tokens() -> None:
    assert canonical_level("OFF") == "Info"  # log4net OFF = always printed
    assert canonical_level("FTL") == "Critical"
    assert canonical_level("Verbose") == "Trace"
    assert canonical_level(" warn ") == "Warning"
    assert canonical_level("50", _fmt("json").level_map) == "Error"  # pino / bunyan numeric levels
    assert canonical_level("banana") == ""
    assert canonical_level("") == ""
    tokens = ("fatal", "error", "warn", "info", "debug", "trace")
    assert {canonical_level(t) for t in tokens} == set(CANONICAL_LEVELS)


# ---- facets ----------------------------------------------------------------------------------------------------------
def test_facets_count_values_most_common_first() -> None:
    records = extract_records(W3C, W3C_LINES)
    assert facets(records, "cs-method") == [("GET", 3), ("POST", 1)]
    assert facets(records, "sc-status", top=1) == [("200", 3)]
    assert facets([r.fields for r in records], "missing") == []
    assert facets([{"a": "x"}, {"a": "y"}, {"a": "x"}, {"a": ""}], "a", top=None) == [("x", 2), ("y", 1)]


# ---- custom formats --------------------------------------------------------------------------------------------------
def test_custom_regex_format_round_trips_through_json() -> None:
    custom = CustomFormat(
        "My app",
        regex=r"(?P<ts>\S+ \S+) (?P<sev>[A-Z]) (?P<message>.*)",
        multiline=True,
        time_field="ts",
        level_field="sev",
        filename_hints=("myapp*.log",),
        level_map=(("E", "Error"), ("W", "Warning")),
    )
    data = json.loads(json.dumps(custom.to_dict()))
    assert CustomFormat.from_dict(data) == custom
    fmt = custom.to_format()
    assert fmt.name == "custom:My app"
    assert fmt.multiline
    fields = fmt.parse("2026-11-13 10:00:00 E broken")
    assert fields == {"ts": "2026-11-13 10:00:00", "sev": "E", "message": "broken"}
    assert fmt.level_of(fields) == "Error"


def test_custom_layout_format() -> None:
    custom = CustomFormat("Layout", layout="%date %-5level %logger - %message", style="log4net")
    restored = CustomFormat.from_dict(custom.to_dict())
    fmt = restored.to_format()
    assert fmt.multiline
    assert (fmt.time_field, fmt.level_field, fmt.message_field) == ("time", "level", "message")
    assert fmt.parse("2026-11-13 10:00:00,1 INFO  App - hi") is not None


def test_custom_format_guesses_roles() -> None:
    fmt = CustomFormat("x", regex=r"(?P<Timestamp>\S+) (?P<Severity>\w+) (?P<msg>.*)").to_format()
    assert (fmt.time_field, fmt.level_field, fmt.message_field) == ("Timestamp", "Severity", "msg")


@pytest.mark.parametrize(
    ("custom", "error"),
    [
        (CustomFormat("x", regex=r"(\d+) (.*)"), "named group"),
        (CustomFormat("x", regex=r"(?P<a>[unclosed"), "regex"),
        (CustomFormat("x", regex=r"(?P<message>.*)", time_field="time"), "time field"),
        (CustomFormat("x", regex=r"(?P<message>.*)", level_field="lvl"), "level field"),
        (CustomFormat("x"), "either a regex or a layout"),
        (CustomFormat("x", regex=r"(?P<message>.*)", layout="%m"), "either a regex or a layout"),
        (CustomFormat("  ", regex=r"(?P<message>.*)"), "name"),
        (CustomFormat("x", layout="%date{yyyy [%thread]"), "layout"),
        (CustomFormat("x", regex=r"(?P<message>.*)", level_map=(("E", "Bad"),)), "must be one of"),
    ],
)
def test_custom_format_validation(custom: CustomFormat, error: str) -> None:
    with pytest.raises(CustomFormatError, match=error):
        custom.validate()


@pytest.mark.parametrize(
    "data",
    [
        {"name": 3, "regex": "(?P<m>.*)"},
        {"name": "x", "regex": "(?P<m>.*)", "multiline": "yes"},
        {"name": "x", "layout": "%m", "style": "log5j"},
        {"name": "x", "regex": "(?P<m>.*)", "filename_hints": "a.log"},
        {"name": "x", "regex": "(?P<m>.*)", "level_map": {"E": 1}},
        {"name": "x", "regex": "(?P<m>.*)", "version": 99},
    ],
)
def test_custom_format_from_dict_rejects_malformed_data(data: dict[str, object]) -> None:
    with pytest.raises(CustomFormatError):
        CustomFormat.from_dict(data)
