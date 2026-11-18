"""Windows events (XML parsing, one-line form, live read), knowledge base matching and line-time parsing."""

from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta

import pytest

from loglens.core.kb import KnowledgeBase
from loglens.core.kb.codes import describe_code, find_codes
from loglens.core.timeparse import parse_line_time
from loglens.core.winevent.models import EVENT_LINE, EventRecord, parse_event_xml, record_from_line
from loglens.core.winevent.reader import EventQuery, read_events

EVENT_XML = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
<System><Provider Name='Application Error'/><EventID Qualifiers='0'>1000</EventID><Level>2</Level>
<Keywords>0x80000000000000</Keywords><TimeCreated SystemTime='2026-11-13T06:49:20.6053364Z'/>
<EventRecordID>641097</EventRecordID><Execution ProcessID='20980' ThreadID='55372'/>
<Channel>Application</Channel><Computer>pc1</Computer></System>
<EventData><Data>w3wp.exe</Data><Data>10.0.1</Data><Data>0xc0000005</Data></EventData></Event>"""


def test_parse_event_xml_and_line_form() -> None:
    event = parse_event_xml(EVENT_XML, "Faulting application name: w3wp.exe\r\nException code: 0xc0000005")
    assert (event.provider, event.event_id, event.level_name, event.channel) == (
        "Application Error",
        1000,
        "Error",
        "Application",
    )
    assert event.time_created == datetime(2026, 11, 13, 6, 49, 20, 605336, UTC)
    assert event.process_id == 20980 and event.data == {
        "param1": "w3wp.exe",
        "param2": "10.0.1",
        "param3": "0xc0000005",
    }
    line = event.to_line()
    assert "\n" not in line and line.endswith("}")
    match = EVENT_LINE.match(line)
    assert match is not None and match["provider"] == "Application Error" and match["event_id"] == "1000"
    # local time + offset round-trips to the same instant (at the millisecond precision shown in the line)
    assert parse_line_time(line) == event.time_created.replace(microsecond=605000)


def test_event_without_message_uses_data() -> None:
    event = parse_event_xml(EVENT_XML)
    assert event.text() == "param1=w3wp.exe; param2=10.0.1; param3=0xc0000005"


def test_query_xpath() -> None:
    since = datetime(2026, 11, 13, 10, 0, tzinfo=UTC)
    query = EventQuery(levels=(2, 4), since=since, until=since + timedelta(minutes=10))
    assert query.xpath() == (
        "*[System[(Level=0 or Level=2 or Level=4) and TimeCreated[@SystemTime>='2026-11-13T10:00:00.000Z'] "
        "and TimeCreated[@SystemTime<='2026-11-13T10:10:00.000Z']]]"
    )
    assert EventQuery().xpath() == "*"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Event Log")
def test_read_local_application_log() -> None:
    events = list(read_events(EventQuery("Application", max_events=3)))
    assert len(events) <= 3
    for event in events:
        assert event.channel == "Application" and event.provider and EVENT_LINE.match(event.to_line())


# ---- knowledge base ------------------------------------------------------------------------------------------------
@pytest.fixture(scope="module")
def kb() -> KnowledgeBase:
    return KnowledgeBase.builtin()


def test_builtin_kb_is_valid(kb: KnowledgeBase) -> None:
    assert len(kb.entries) > 60
    ids = [e.id for e in kb.entries]
    assert len(ids) == len(set(ids)), "duplicate KB ids"
    for entry in kb.entries:
        assert entry.title and entry.explanation and (entry.event_ids or entry.codes or entry.patterns), entry.id


def test_event_and_code_findings(kb: KnowledgeBase) -> None:
    line = parse_event_xml(EVENT_XML, "Faulting application name: w3wp.exe, Exception code: 0xc0000005").to_line()
    findings = kb.explain(line)
    assert [f.kind for f in findings][:2] == ["event", "code"]
    assert findings[0].title == "An application crashed" and "access violation" in findings[1].title


def test_provider_prefix_and_noise(kb: KnowledgeBase) -> None:
    assert kb.lookup_event("Microsoft-Windows-Kernel-Power", 41)
    assert kb.lookup_event("ASP.NET 4.0.30319.0", 1309)  # version suffix
    dcom = kb.lookup_event("Microsoft-Windows-DistributedCOM", 10016)
    assert dcom and dcom[0].noise == "benign"


def test_wildcard_application_events(kb: KnowledgeBase) -> None:
    assert [e.id for e in kb.lookup_event("Some Vendor App", 0)] == ["event-application-defined"]
    assert [e.id for e in kb.lookup_event("Service Control Manager", 7031)] == ["event-scm-7031"]
    assert kb.lookup_event("Some Vendor App", 16) == []


def test_text_patterns(kb: KnowledgeBase) -> None:
    titles = [f.title for f in kb.explain("ERROR Transaction (Process ID 61) was deadlocked on lock resources")]
    assert "SQL Server deadlock (error 1205)" in titles
    assert any("HTTP 5xx" in f.title for f in kb.explain("returned an error: (502) Bad Gateway."))
    assert kb.explain("INFO all good") == []


def test_codes() -> None:
    assert find_codes("hr:0x800f081f pid 0x0000215c addr 0x00007ff8a1b2c3d4 again 0x800F081F") == [0x800F081F]
    if sys.platform == "win32":
        assert describe_code(0x80070005) == "Access is denied."
        message = describe_code(0xC0000005)
        assert message is not None and "%" not in message


# ---- line time parsing ----------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("line", "expected_utc"),
    [
        ("2026-11-13T10:15:02.123Z x", datetime(2026, 11, 13, 10, 15, 2, 123000, UTC)),
        ("2026-11-13 10:15:02,123 +04:00 [INF] x", datetime(2026, 11, 13, 6, 15, 2, 123000, UTC)),
        ('127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /"', datetime(2000, 10, 10, 20, 55, 36, tzinfo=UTC)),
    ],
)
def test_parse_line_time_with_zone(line: str, expected_utc: datetime) -> None:
    assert parse_line_time(line) == expected_utc


def test_parse_line_time_local_and_missing() -> None:
    local = parse_line_time("11/13/2026 4:53:45 PM Warning disk")
    assert local is not None and local.tzinfo is not None and (local.hour, local.minute) == (16, 53)
    assert parse_line_time("   at Foo.Bar()") is None


def test_record_round_trips_through_its_line() -> None:
    event = EventRecord(
        "Application", "Application Error", 1000, 2, datetime(2026, 11, 13, 9, 0, 1, 250000, tzinfo=UTC),
        record_id=77, process_id=12, message="Faulting application name: shop.exe",
        data={"AppName": "shop.exe", "ExceptionCode": "c0000005"},
    )  # fmt: skip
    again = record_from_line(event.to_line())
    assert again is not None
    assert (again.provider, again.event_id, again.level, again.record_id) == ("Application Error", 1000, 2, 77)
    assert again.time_created == event.time_created and again.data == event.data
    assert record_from_line("2026-11-13 10:00:00 INFO plain line") is None
