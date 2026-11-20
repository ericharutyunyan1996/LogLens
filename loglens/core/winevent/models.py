"""Event records parsed from the Windows event XML schema, and their one-line log representation."""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import UTC, datetime

from ..timeparse import to_local

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
LEVEL_NAMES = {0: "Information", 1: "Critical", 2: "Error", 3: "Warning", 4: "Information", 5: "Verbose"}
AUDIT_FAILURE, AUDIT_SUCCESS = 0x10000000000000, 0x20000000000000
MAX_LINE_MESSAGE = 600  # characters of the message shown in the one-line form (full text is in the JSON part)

# "2026-11-13 10:15:02.123 +04:00 Error [System] Service Control Manager (7031) — message ‖ {json}"
EVENT_LINE = re.compile(
    r"^\S+ \S+ [+-]\d\d:\d\d (?P<level>\w+) \[(?P<channel>[^\]]+?)(?: @ (?P<server>[^\]]+))?\] "
    r"(?P<provider>.+?) \((?P<event_id>\d+)\) — "
)


@dataclass(frozen=True, slots=True)
class EventRecord:
    channel: str
    provider: str
    event_id: int
    level: int
    time_created: datetime  # aware, UTC
    record_id: int = 0
    computer: str = ""
    process_id: int = 0
    thread_id: int = 0
    keywords: int = 0
    user_sid: str = ""
    message: str = ""
    data: dict[str, str] = field(default_factory=dict)
    server: str = ""  # the LogLens server profile it was read from ("" = this computer)

    @property
    def level_name(self) -> str:
        if self.keywords & AUDIT_FAILURE:
            return "AuditFailure"
        if self.keywords & AUDIT_SUCCESS:
            return "AuditSuccess"
        return LEVEL_NAMES.get(self.level, f"Level{self.level}")

    def text(self) -> str:
        """Message, or the event data when the publisher's message templates are unavailable."""
        if self.message:
            return self.message
        return "; ".join(f"{k}={v}" if k else v for k, v in self.data.items()) or "(no message)"

    def to_line(self) -> str:
        """One log line: local timestamp with offset, level, channel, provider (id) — message ‖ {details}."""
        local = to_local(self.time_created)
        stamp = local.strftime("%Y-%m-%d %H:%M:%S.") + f"{local.microsecond // 1000:03d} " + _offset(local)
        flat = " ".join(self.text().split())
        if len(flat) > MAX_LINE_MESSAGE:
            flat = flat[:MAX_LINE_MESSAGE] + " …"
        details = {
            "message": self.text(),
            "data": self.data,
            "record": self.record_id,
            "pid": self.process_id,
            "tid": self.thread_id,
            "computer": self.computer,
            "user": self.user_sid,
        }
        payload = json.dumps({k: v for k, v in details.items() if v not in ("", 0, {})}, ensure_ascii=False)
        where = f"{self.channel} @ {self.server}" if self.server else self.channel
        return f"{stamp} {self.level_name} [{where}] {self.provider} ({self.event_id}) — {flat} ‖ {payload}"


def _offset(moment: datetime) -> str:
    delta = moment.utcoffset()
    minutes = int(delta.total_seconds() // 60) if delta else 0
    sign = "+" if minutes >= 0 else "-"
    return f"{sign}{abs(minutes) // 60:02d}:{abs(minutes) % 60:02d}"


def _int(text: str | None, default: int = 0) -> int:
    if not text:
        return default
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return default


def _parse_time(value: str | None) -> datetime:
    if not value:
        return datetime.fromtimestamp(0, UTC)
    # SystemTime has up to 7 fractional digits; datetime accepts at most 6
    match = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?", value)
    if not match:
        return datetime.fromtimestamp(0, UTC)
    fraction = (match.group(2) or "0")[:6].ljust(6, "0")
    return datetime.fromisoformat(f"{match.group(1)}.{fraction}+00:00")


def parse_event_xml(xml: str, message: str = "") -> EventRecord:
    """Build an EventRecord from the XML rendered by EvtRender."""
    root = ET.fromstring(xml)
    system = root.find("e:System", NS)
    if system is None:
        raise ValueError("not an event XML document")

    def attr(path: str, name: str) -> str:
        element = system.find(path, NS)
        return element.get(name, "") if element is not None else ""

    def text(path: str) -> str:
        element = system.find(path, NS)
        return (element.text or "") if element is not None else ""

    data: dict[str, str] = {}
    for index, element in enumerate(root.findall("e:EventData/e:Data", NS)):
        data[element.get("Name") or f"param{index + 1}"] = (element.text or "").strip()
    user_data = root.find("e:UserData", NS)
    if user_data is not None:
        for element in user_data.iter():
            value = (element.text or "").strip()
            if len(element) == 0 and value:
                data[element.tag.split("}")[-1]] = value

    return EventRecord(
        channel=text("e:Channel"),
        provider=attr("e:Provider", "Name") or attr("e:Provider", "EventSourceName"),
        event_id=_int(text("e:EventID")) & 0xFFFF,
        level=_int(text("e:Level")),
        time_created=_parse_time(attr("e:TimeCreated", "SystemTime")),
        record_id=_int(text("e:EventRecordID")),
        computer=text("e:Computer"),
        process_id=_int(attr("e:Execution", "ProcessID")),
        thread_id=_int(attr("e:Execution", "ThreadID")),
        keywords=_int(text("e:Keywords")),
        user_sid=attr("e:Security", "UserID"),
        message=(message or "").strip(),
        data=data,
    )


_LINE_STAMP = re.compile(r"^(\S+ \S+ [+-]\d\d:\d\d) ")
_DETAILS_SEPARATOR = " ‖ "


def record_from_line(line: str) -> EventRecord | None:
    """The event behind a line written by :meth:`EventRecord.to_line` (None for any other line)."""
    match = EVENT_LINE.match(line)
    stamp = _LINE_STAMP.match(line)
    if match is None or stamp is None:
        return None
    try:
        moment = datetime.strptime(stamp.group(1), "%Y-%m-%d %H:%M:%S.%f %z").astimezone(UTC)
    except ValueError:
        return None
    _, _, payload = line.partition(_DETAILS_SEPARATOR)
    try:
        details = json.loads(payload) if payload else {}
    except ValueError:
        details = {}
    if not isinstance(details, dict):
        details = {}
    level = next((number for number, name in LEVEL_NAMES.items() if name == match["level"]), 0)
    data = details.get("data")
    return EventRecord(
        channel=match["channel"],
        provider=match["provider"],
        event_id=int(match["event_id"]),
        level=level,
        time_created=moment,
        record_id=int(details.get("record", 0) or 0),
        computer=str(details.get("computer", "")),
        process_id=int(details.get("pid", 0) or 0),
        thread_id=int(details.get("tid", 0) or 0),
        user_sid=str(details.get("user", "")),
        message=str(details.get("message", "")),
        data={str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {},
        server=match["server"] or "",
    )
