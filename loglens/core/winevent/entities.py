"""Structured facts from Windows events: which app, service, account, product or code an event is about.

``extract(event)`` runs the parser registered for the event's provider and id. Every parser looks for a value in
three places, in order: the event's named data (manifest providers), a regex over the rendered message, and the
positional ``param<N>`` data of classic providers (used when the message template is missing, e.g. an .evtx from
another machine). Unknown events still get the generic facts any event can carry: failure codes and file paths.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field, fields, replace
from datetime import datetime
from functools import cache
from typing import Any

from ..kb.codes import describe_code, find_codes
from .models import EventRecord
from .wer import CRASH_EVENT_TYPES, HANG_EVENT_TYPES, map_signature, parse_hex

MAX_PATHS = 10  # file paths kept per event; messages rarely name more, and more would only be noise
MAX_STACK_FRAMES = 25  # stack lines kept from .NET / ASP.NET events (the top frames carry the signal)
DIRECTIONAL_MARKS = dict.fromkeys(map(ord, "\u200e\u200f\u202a\u202b\u202c\u202d\u202e"))  # in rendered dates
EMPTY_VALUES = frozenset({"", "-", "(null)", "null", "n/a"})  # how event data spells "nothing"
INSERTION_PREFIX = "%%"  # SCM writes "%%1053" for "the message text of Win32 error 1053"
MSI_SUCCESS_CODES = frozenset({0, 1641, 3010})  # success, success + reboot initiated, success + reboot required
WER_PARAMETERS = 10  # P1…P10 of the "Windows Error Reporting 1001" event

LOGON_TYPES: dict[int, str] = {
    2: "interactive",
    3: "network",
    4: "batch",
    5: "service",
    7: "unlock",
    8: "network cleartext",
    9: "new credentials",
    10: "remote interactive (RDP)",
    11: "cached interactive",
    12: "cached remote interactive",
    13: "cached unlock",
}
# NTSTATUS codes in the Status / Sub Status fields of a failed logon (4625)
LOGON_FAILURE_REASONS: dict[int, str] = {
    0xC0000064: "user name does not exist",
    0xC000006A: "wrong password",
    0xC000006D: "bad user name or password",
    0xC000006E: "account restriction",
    0xC000006F: "logon outside allowed hours",
    0xC0000070: "logon from this workstation not allowed",
    0xC0000071: "password expired",
    0xC0000072: "account disabled",
    0xC0000133: "clock out of sync with the domain controller",
    0xC000015B: "logon type not granted",
    0xC000018C: "trust relationship failed",
    0xC0000192: "Netlogon service not started",
    0xC0000193: "account expired",
    0xC0000224: "password must be changed",
    0xC0000234: "account locked out",
    0xC0000413: "machine not allowed by authentication firewall",
}

_PATH = re.compile(
    # drive or UNC root, directory components that may contain a few spaces ("Program Files (x86)"), then a final
    # component without spaces — so prose after a path ("… on behalf of user X\Y") is not swallowed
    r"(?:\b[A-Za-z]:\\|\\\\[\w.$-]+\\)"
    r"(?:[^\\/:*?\"<>|\r\n\s]+(?: [^\\/:*?\"<>|\r\n\s]+){0,2}\\)*"
    r"[^\\/:*?\"<>|\r\n\s,;']*"
)
_ISO_TIME = re.compile(r"(\d{4}-\d\d-\d\d)[T ](\d\d:\d\d:\d\d)(?:\.(\d+))?")
_STACK_LINE = re.compile(r"^\s*at (.+?)\s*$", re.MULTILINE)  # "   at Namespace.Type.Method(args)"


@dataclass(frozen=True, slots=True)
class EventFacts:
    """What an event is about. Empty strings / None mean "not stated"; ``extra`` holds parser-specific details."""

    kind: str = "generic"  # parser family: app-crash, service, logon-failure, installer, … (see PARSERS)
    app_name: str = ""
    app_version: str = ""
    app_path: str = ""
    faulting_module: str = ""
    module_version: str = ""
    exception_code: int | None = None
    exception_type: str = ""
    exception_message: str = ""
    stack: tuple[str, ...] = ()
    fault_offset: str = ""
    process_id: int | None = None
    report_id: str = ""
    service_name: str = ""
    service_state: str = ""  # service or app-pool state/outcome ("terminated unexpectedly", "disabled", …)
    app_pool: str = ""
    error_code: int | None = None
    error_text: str = ""
    user: str = ""  # DOMAIN\name when the domain is known
    logon_type: int | None = None
    source_ip: str = ""
    workstation: str = ""
    status: int | None = None
    sub_status: int | None = None
    failure_reason: str = ""
    product_name: str = ""
    product_version: str = ""
    update_title: str = ""
    shutdown_reason: str = ""
    shutdown_initiator: str = ""
    url: str = ""
    paths: tuple[str, ...] = ()
    codes: tuple[int, ...] = ()  # failure codes (0x8…/0xC…) found anywhere in the event
    extra: dict[str, str] = field(default_factory=dict)

    @property
    def subject(self) -> str:
        """The main thing the event is about (application, service, app pool, product, update or account)."""
        for value in (
            self.app_name,
            self.service_name,
            self.app_pool,
            self.product_name,
            self.update_title,
            self.user,
            self.faulting_module,
        ):
            if value:
                return value
        return ""

    @property
    def logon_type_name(self) -> str:
        if self.logon_type is None:
            return ""
        return LOGON_TYPES.get(self.logon_type, str(self.logon_type))

    def items(self) -> list[tuple[str, str]]:
        """Non-empty facts as (field name, display text) pairs, for detail views."""
        result: list[tuple[str, str]] = []
        for spec in fields(self):
            value = getattr(self, spec.name)
            if spec.name in ("kind", "extra") or value in (None, "", ()):
                continue
            if spec.name in _INT_FIELDS and isinstance(value, int):
                text = f"0x{value:08X}" if value > 0xFFFF or spec.name in _HEX_FIELDS else str(value)
            elif isinstance(value, tuple):
                text = ", ".join(f"0x{v:08X}" if isinstance(v, int) else str(v) for v in value)
            else:
                text = str(value)
            result.append((spec.name, text))
        result.extend(self.extra.items())
        return result


_INT_FIELDS = frozenset({"exception_code", "process_id", "error_code", "logon_type", "status", "sub_status"})
_HEX_FIELDS = frozenset({"exception_code", "status", "sub_status"})


# ---- value helpers ---------------------------------------------------------------------------------------------------
@cache
def normalize_provider(name: str) -> str:
    """Provider name for matching: lower case, without "Microsoft-Windows-"; all ASP.NET versions → "asp.net"."""
    norm = name.strip().lower().removeprefix("microsoft-windows-")
    return "asp.net" if norm.startswith("asp.net") else norm


def event_key(event: EventRecord) -> tuple[str, int]:
    """(normalized provider, event id) — the key parsers and recipes match on."""
    return normalize_provider(event.provider), event.event_id


def clean(value: str) -> str:
    """Strip whitespace and direction marks; event data's "-" / "(NULL)" placeholders become ""."""
    text = value.translate(DIRECTIONAL_MARKS).strip()
    return "" if text.lower() in EMPTY_VALUES else text


def to_int(text: str, *, hexadecimal: bool = False) -> int | None:
    """Parse "1053", "%%1053", "0x80070005" or "-1073741819" (→ 0xC0000005); bare hex digits if ``hexadecimal``."""
    value = clean(text).removeprefix(INSERTION_PREFIX)
    if not value:
        return None
    if hexadecimal or value.lower().startswith("0x"):
        return parse_hex(value)
    try:
        number = int(value)
    except ValueError:
        return None
    return number & 0xFFFFFFFF if number < 0 else number


def parse_iso_time(text: str) -> datetime | None:
    """``2026-11-13T05:50:16.1857599Z`` (any number of fraction digits, direction marks allowed) → aware UTC."""
    match = _ISO_TIME.search(clean(text))
    if match is None:
        return None
    fraction = (match.group(3) or "0")[:6].ljust(6, "0")
    try:
        return datetime.fromisoformat(f"{match.group(1)}T{match.group(2)}.{fraction}+00:00")
    except ValueError:
        return None


def _text(event: EventRecord) -> str:
    """Rendered message, or the data values when the publisher's message template is unavailable."""
    if event.message:
        return event.message.translate(DIRECTIONAL_MARKS)
    return "\n".join(value for value in event.data.values() if value).translate(DIRECTIONAL_MARKS)


def _account(event: EventRecord, name_key: str, domain_key: str) -> str:
    name = clean(event.data.get(name_key, ""))
    domain = clean(event.data.get(domain_key, ""))
    return f"{domain}\\{name}" if name and domain else name


def _stack(text: str) -> tuple[str, ...]:
    return tuple(match.group(1) for match in _STACK_LINE.finditer(text))[:MAX_STACK_FRAMES]


def _short_text(text: str) -> str:
    """First sentence of a Windows message."""
    return " ".join(text.split()).split(". ")[0].rstrip(".")


# ---- declarative parsers ---------------------------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class _Field:
    names: tuple[str, ...] = ()  # named data, tried first
    pattern: re.Pattern[str] | None = None  # regex over the message (group 1)
    position: int = 0  # 1-based positional data (``param<N>``) for classic providers

    def pick(self, event: EventRecord, text: str) -> str:
        for name in self.names:
            value = clean(event.data.get(name, ""))
            if value:
                return value
        if self.pattern is not None:
            match = self.pattern.search(text)
            if match is not None and clean(match.group(1)):
                return clean(match.group(1))
        return clean(event.data.get(f"param{self.position}", "")) if self.position else ""


def _f(*names: str, rx: str = "", pos: int = 0) -> _Field:
    return _Field(names, re.compile(rx, re.IGNORECASE | re.MULTILINE) if rx else None, pos)


Parser = Callable[[EventRecord, str], EventFacts]


@dataclass(frozen=True, slots=True)
class _Spec:
    """Facts read field by field. ``fixed`` / ``fixed_extra`` are constants for the event id; ``post`` refines."""

    kind: str
    values: dict[str, _Field]
    extra: dict[str, _Field] = field(default_factory=dict)
    fixed: dict[str, str] = field(default_factory=dict)
    fixed_extra: dict[str, str] = field(default_factory=dict)
    hex_fields: frozenset[str] = _HEX_FIELDS
    post: Callable[[EventFacts, EventRecord, str], EventFacts] | None = None

    def __call__(self, event: EventRecord, text: str) -> EventFacts:
        values = {name: spec.pick(event, text) for name, spec in self.values.items()}
        extra = {name: value for name, spec in self.extra.items() if (value := spec.pick(event, text))}
        facts = build_facts(
            self.kind, {**values, **self.fixed}, {**extra, **self.fixed_extra}, hex_fields=self.hex_fields
        )
        return self.post(facts, event, text) if self.post is not None else facts


def build_facts(
    kind: str, values: dict[str, str], extra: dict[str, str] | None = None, *, hex_fields: frozenset[str] = _HEX_FIELDS
) -> EventFacts:
    """EventFacts from text values: integer fields are parsed, empty values dropped, offsets normalised."""
    kwargs: dict[str, Any] = {}
    for name, text in values.items():
        if not text:
            continue
        if name in _INT_FIELDS:
            number = to_int(text, hexadecimal=name in hex_fields)
            if number is not None:
                kwargs[name] = number
        elif name == "fault_offset":
            offset = parse_hex(text)
            kwargs[name] = f"0x{offset:x}" if offset is not None else text
        else:
            kwargs[name] = text
    return EventFacts(kind=kind, extra=dict(extra or {}), **kwargs)


def _with_error_text(facts: EventFacts, _event: EventRecord | None = None, _text: str = "") -> EventFacts:
    """Fill ``error_text`` from Windows' message table when the event only gave the code (usable as a post hook).

    A text that is itself an unresolved insertion string ("%%2149884192") counts as missing.
    """
    if (facts.error_text and not facts.error_text.startswith(INSERTION_PREFIX)) or not facts.error_code:
        return facts
    return replace(facts, error_text=_short_text(describe_code(facts.error_code) or ""))


# ---- crashes ---------------------------------------------------------------------------------------------------------
_APP_CRASH = _Spec(
    "app-crash",
    {
        "app_name": _f("AppName", rx=r"^Faulting application name: ([^,\r\n]+)", pos=1),
        "app_version": _f("AppVersion", rx=r"^Faulting application name: [^,\r\n]+, version: ([^,\r\n]+)", pos=2),
        "faulting_module": _f("ModuleName", rx=r"^Faulting module name: ([^,\r\n]+)", pos=4),
        "module_version": _f("ModuleVersion", rx=r"^Faulting module name: [^,\r\n]+, version: ([^,\r\n]+)", pos=5),
        "exception_code": _f("ExceptionCode", rx=r"^Exception code: (0x[0-9a-f]+)", pos=7),
        "fault_offset": _f("FaultingOffset", rx=r"^Fault offset: (0x[0-9a-f]+)", pos=8),
        "process_id": _f("ProcessId", rx=r"^Faulting process id: (0x[0-9a-f]+)", pos=9),
        "app_path": _f("AppPath", rx=r"^Faulting application path: ([^\r\n]+)", pos=11),
        "report_id": _f("IntegratorReportId", rx=r"^Report Id: ([0-9a-f-]{36})", pos=13),
    },
    extra={"module_path": _f("ModulePath", rx=r"^Faulting module path: ([^\r\n]+)", pos=12)},
)
_APP_HANG = _Spec(
    "app-hang",
    {
        "app_name": _f("AppName", rx=r"The program (\S+) version", pos=1),
        "app_version": _f("AppVersion", rx=r"The program \S+ version (\S+)", pos=2),
        "process_id": _f("ProcessId", rx=r"^\s*Process ID: ((?:0x)?[0-9a-f]+)", pos=3),
        "app_path": _f("ExeFileName", rx=r"^\s*Application Path: ([^\r\n]+)", pos=6),
        "report_id": _f("ReportId", rx=r"^\s*Report Id: ([0-9a-f-]{36})", pos=7),
    },
    extra={"hang_type": _f("HangType", rx=r"^\s*Hang type: ([^\r\n]+)", pos=10)},
    hex_fields=frozenset({"process_id"}),  # Application Hang writes the PID in hex, with or without 0x
)
_WER_EVENT_NAME = _f("EventName", rx=r"^Event Name: (\S+)", pos=3)
_WER_PARAMETERS = tuple(_f(f"P{i}", rx=rf"^P{i}: ([^\r\n]*)", pos=5 + i) for i in range(1, WER_PARAMETERS + 1))
_WER_REPORT_ID = _f("ReportId", rx=r"^Report Id: ([0-9a-f-]{36})", pos=20)
_WER_STORE = _f("StorePath", rx=r"These files may be available here:\s*([^\r\n]+)", pos=17)


def _wer_event(event: EventRecord, text: str) -> EventFacts:
    """Windows Error Reporting 1001: the problem signature P1…P10 is laid out per event name (APPCRASH, CLR20r3 …)."""
    event_name = _WER_EVENT_NAME.pick(event, text)
    values = map_signature(event_name, [spec.pick(event, text) for spec in _WER_PARAMETERS])
    values["report_id"] = _WER_REPORT_ID.pick(event, text)
    extra = {"wer_event": event_name, "report_path": _WER_STORE.pick(event, text).removeprefix("\\\\?\\")}
    kind = "wer-report"
    if event_name.lower() in CRASH_EVENT_TYPES:
        kind = "wer-crash"
    elif event_name.lower() in HANG_EVENT_TYPES:
        kind = "wer-hang"
    return build_facts(kind, values, {k: v for k, v in extra.items() if v})


_DOTNET_APP = re.compile(r"^Application: (.+?)\s*$", re.MULTILINE)
_DOTNET_RUNTIME = re.compile(r"^(?:Framework Version|CoreCLR Version|\.NET Version): (.+?)\s*$", re.MULTILINE)
_DOTNET_DESCRIPTION = re.compile(r"^Description: (.+?)\s*$", re.MULTILINE)
_DOTNET_EXCEPTION = re.compile(r"^Exception Info: ([\w.`+<>\[\],]+?)(?::\s*(.*?))?\s*$", re.MULTILINE)
_DOTNET_EXIT_CODE = re.compile(r"exit code ((?:0x)?[0-9a-f]{8})\b", re.IGNORECASE)


def _dotnet_crash(event: EventRecord, text: str) -> EventFacts:
    """.NET Runtime 1026: application, runtime version, exception type/message and stack of an unhandled exception."""
    exceptions = list(_DOTNET_EXCEPTION.finditer(text))
    first = exceptions[0] if exceptions else None  # .NET Framework lists the innermost (root cause) exception first
    values = {
        "app_name": _group(_DOTNET_APP, text),
        "exception_type": first.group(1) if first else "",
        "exception_message": (first.group(2) or "") if first else "",
        "failure_reason": _group(_DOTNET_DESCRIPTION, text),
        "error_code": _group(_DOTNET_EXIT_CODE, text),
    }
    extra = {"runtime_version": _group(_DOTNET_RUNTIME, text)}
    if len(exceptions) > 1:
        extra["exception_chain"] = " ← ".join(match.group(1) for match in exceptions)
    facts = build_facts(
        "dotnet-crash", values, {k: v for k, v in extra.items() if v}, hex_fields=frozenset({"error_code"})
    )
    return replace(facts, stack=_stack(text))


def _group(pattern: re.Pattern[str], text: str) -> str:
    match = pattern.search(text)
    return clean(match.group(1)) if match is not None else ""


def _aspnet_post(facts: EventFacts, _event: EventRecord, text: str) -> EventFacts:
    """IIS application pool from the "IIS APPPOOL\\<pool>" account, plus the stack trace."""
    pool = facts.user.split("\\", 1)[1] if facts.user.upper().startswith("IIS APPPOOL\\") else ""
    return replace(facts, app_pool=pool, stack=_stack(text))


_ASPNET = _Spec(
    "aspnet-error",
    {
        "exception_type": _f(rx=r"^\s*Exception type: (\S+)", pos=18),
        "exception_message": _f(rx=r"^\s*Exception message: ([^\r\n]+)", pos=19),
        "url": _f(rx=r"^\s*Request URL: (\S+)", pos=20),
        "app_path": _f(rx=r"^\s*Application Path: ([^\r\n]+?)\s*$", pos=12),
        "process_id": _f(rx=r"^\s*Process ID: (\d+)", pos=15),
        "app_name": _f(rx=r"^\s*Process name: (\S+)", pos=16),
        "user": _f(rx=r"^\s*Account name: ([^\r\n]+?)\s*$", pos=17),
        "source_ip": _f(rx=r"^\s*User host address: (\S+)", pos=22),
    },
    extra={
        "event_code": _f(rx=r"^\s*Event code: (\d+)", pos=1),
        "virtual_path": _f(rx=r"^\s*Application Virtual Path: (\S+)", pos=11),
    },
    post=_aspnet_post,
)


# ---- services --------------------------------------------------------------------------------------------------------
def _scm(state: str, service: _Field, **more: _Field) -> _Spec:
    """Service Control Manager event: service name, a fixed state, and optional error / extra fields."""
    values = {"service_name": service}
    extra: dict[str, _Field] = {}
    for name, spec in more.items():
        (values if name in ("error_code", "error_text", "app_path", "user") else extra)[name] = spec
    return _Spec("service", values, extra, fixed={"service_state": state}, post=_with_error_text)


_SCM_ERROR_TEXT = _f(rx=r"following (?:service-specific )?error:\s*([^\r\n]+)")
_SCM: dict[int, _Spec] = {
    7000: _scm(
        "failed to start",
        _f("param1", rx=r"^The (.+?) service failed to start"),
        error_code=_f("param2"),
        error_text=_SCM_ERROR_TEXT,
    ),
    7001: _scm(
        "dependency failed to start",
        _f("param1", rx=r"^The (.+?) service depends on"),
        error_code=_f("param3"),
        error_text=_SCM_ERROR_TEXT,
        depends_on=_f("param2", rx=r"depends on the (.+?) service which failed"),
    ),
    7009: _scm(
        "start timed out",
        _f("param2", rx=r"waiting for the (.+?) service to connect"),
        timeout_ms=_f("param1", rx=r"timeout was reached \((\d+) milliseconds\)"),
    ),
    7011: _scm(
        "did not respond to a control request",
        _f("param2", rx=r"transaction response from the (.+?) service"),
        timeout_ms=_f("param1", rx=r"timeout \((\d+) milliseconds\)"),
    ),
    7022: _scm("hung on starting", _f("param1", rx=r"^The (.+?) service hung on starting")),
    7023: _scm(
        "terminated with an error",
        _f("param1", rx=r"^The (.+?) service terminated with the following error"),
        error_code=_f("param2"),
        error_text=_SCM_ERROR_TEXT,
    ),
    7024: _scm(
        "terminated with a service-specific error",
        _f("param1", rx=r"^The (.+?) service terminated with the following service-specific error"),
        error_code=_f("param2"),
        error_text=_SCM_ERROR_TEXT,
    ),
    7026: _scm("driver failed to load", _f("param1", rx=r"did not load:\s*(.+?)\s*$")),
    7031: _scm(
        "terminated unexpectedly",
        _f("param1", rx=r"^The (.+?) service terminated unexpectedly"),
        times=_f("param2", rx=r"It has done this (\d+) time"),
        recovery_action=_f("param5", rx=r"will be taken in \d+ milliseconds: ([^\r\n]+?)\.?\s*$"),
    ),
    7034: _scm(
        "terminated unexpectedly",
        _f("param1", rx=r"^The (.+?) service terminated unexpectedly"),
        times=_f("param2", rx=r"It has done this (\d+) time"),
    ),
    7040: _scm(
        "start type changed",
        _f("param1", rx=r"^The start type of the (.+?) service was changed"),
        start_type_from=_f("param2", rx=r"was changed from (.+?) to "),
        start_type_to=_f("param3", rx=r"was changed from .+? to (.+?)\.?\s*$"),
    ),
    7045: _scm(
        "installed",
        _f("ServiceName", rx=r"^Service Name:\s+([^\r\n]+)"),
        app_path=_f("ImagePath", rx=r"^Service File Name:\s+([^\r\n]+)"),
        user=_f("AccountName", rx=r"^Service Account:\s+([^\r\n]+)"),
        start_type=_f("StartType", rx=r"^Service Start Type:\s+([^\r\n]+)"),
        service_type=_f("ServiceType", rx=r"^Service Type:\s+([^\r\n]+)"),
    ),
}
_SERVICE_STATE = _Spec(  # 7036: "The X service entered the running state."
    "service",
    {
        "service_name": _f("param1", rx=r"^The (.+?) service entered the"),
        "service_state": _f("param2", rx=r"entered the (.+?) state"),
    },
)


# ---- IIS application pools (WAS) ---------------------------------------------------------------------------------
def _was(state: str, *, exit_code: bool = False) -> _Spec:
    values = {
        "app_pool": _f("AppPoolID", "AppPoolId", rx=r"application pool '([^']+)'", pos=1),
        "process_id": _f("ProcessID", "ProcessId", rx=r"process id (?:was|of) '(\d+)'", pos=2),
    }
    if exit_code:
        values["error_code"] = _f("ExitCode", rx=r"exit code was '([^']+)'", pos=3)
    return _Spec("app-pool", values, fixed={"service_state": state})


_WAS: dict[int, _Spec] = {
    5002: _Spec(
        "app-pool",
        {"app_pool": _f("AppPoolID", "AppPoolId", rx=r"application pool '([^']+)'", pos=1)},
        fixed={"service_state": "disabled after repeated failures (rapid-fail protection)"},
    ),
    5009: _was("worker process terminated unexpectedly", exit_code=True),
    5010: _was("worker process failed to respond to a ping"),
    5011: _was("worker process had a fatal communication error"),
    5013: _was("worker process exceeded the shutdown time limit"),
    5186: _Spec(
        "app-pool",
        {
            "app_pool": _f("AppPoolID", "AppPoolId", rx=r"application pool '([^']+)'", pos=2),
            "process_id": _f("ProcessID", "ProcessId", rx=r"process id of '(\d+)'", pos=1),
        },
        extra={"idle_minutes": _f("Minutes", rx=r"set to (\d+) minutes", pos=3)},
        fixed={"service_state": "worker process shut down after being idle"},
    ),
}


# ---- power, boot and shutdown ----------------------------------------------------------------------------------------
def _kernel_power(event: EventRecord, _text: str) -> EventFacts:
    """Kernel-Power 41: the system rebooted without a clean shutdown; a bug check code means a blue screen."""
    data = event.data
    bugcheck = to_int(data.get("BugcheckCode", "")) or 0
    extra: dict[str, str] = {}
    if bugcheck:
        extra["bugcheck_code"] = f"0x{bugcheck:08X}"
        parameters = [clean(data.get(f"BugcheckParameter{i}", "")) for i in range(1, 5)]
        extra["bugcheck_parameters"] = ", ".join(p for p in parameters if p)
        reason = f"blue screen (bug check 0x{bugcheck:08X})"
    elif clean(data.get("LongPowerButtonPressDetected", "")).lower() == "true":
        reason = "power button held down"
    elif to_int(data.get("PowerButtonTimestamp", "")):
        reason = "power button pressed"
    else:
        reason = "no bug check recorded: power loss, hard reset, or the system stopped responding"
    if clean(data.get("SleepInProgress", "")) not in ("", "0", "false"):
        extra["sleep_in_progress"] = clean(data["SleepInProgress"])
    return EventFacts(kind="unexpected-shutdown", error_code=bugcheck or None, failure_reason=reason, extra=extra)


def _previous_shutdown(facts: EventFacts, event: EventRecord, text: str) -> EventFacts:
    """6008: "The previous system shutdown at <time> on <date> was unexpected." → extra["previous_shutdown"]."""
    match = re.search(r"shutdown at (.+?) on (.+?) was unexpected", text)
    if match is not None:
        when = f"{clean(match.group(2))} {clean(match.group(1))}"
    else:
        when = f"{clean(event.data.get('param2', ''))} {clean(event.data.get('param1', ''))}".strip()
    extra = {**facts.extra, "previous_shutdown": when} if when else facts.extra
    return replace(facts, failure_reason="the previous shutdown was unexpected", extra=extra)


def _planned_shutdown(facts: EventFacts, _event: EventRecord, _text: str) -> EventFacts:
    """1074: drop the "(COMPUTER)" suffix after the initiating process."""
    initiator = re.sub(r"\s*\([^)]*\)$", "", facts.shutdown_initiator)
    return replace(facts, shutdown_initiator=initiator)


_EVENTLOG: dict[int, _Spec] = {
    6005: _Spec("eventlog", {}, fixed={"service_name": "EventLog", "service_state": "started"}),
    6006: _Spec("eventlog", {}, fixed={"service_name": "EventLog", "service_state": "stopped"}),
    6008: _Spec("unexpected-shutdown", {}, post=_previous_shutdown),
    6013: _Spec("eventlog", {}, extra={"uptime_seconds": _f(rx=r"uptime is (\d+) seconds", pos=5)}),
}
_USER32_SHUTDOWN = _Spec(
    "planned-shutdown",
    {
        "shutdown_initiator": _f(rx=r"^The process (.+?) has initiated", pos=1),
        "user": _f(rx=r"on behalf of user (.+?) for the following reason", pos=7),
        "shutdown_reason": _f(rx=r"for the following reason: ([^\r\n]+)", pos=3),
    },
    extra={
        "reason_code": _f(rx=r"Reason Code: (0x[0-9a-f]+)", pos=4),
        "shutdown_type": _f(rx=r"Shutdown Type: (\S+)", pos=5),
        "comment": _f(rx=r"Comment: ([^\r\n]+)", pos=6),
    },
    post=_planned_shutdown,
)


# ---- time changes ----------------------------------------------------------------------------------------------------
def _time_change(event: EventRecord, text: str) -> EventFacts:
    """4616 (Security) and Kernel-General 1: the system clock was changed; ``extra["delta_seconds"]`` is the jump."""
    data = event.data
    old = parse_iso_time(f"{data.get('PreviousDate', '')} {data.get('PreviousTime', '')}") or parse_iso_time(
        data.get("OldTime", "")
    )
    new = parse_iso_time(f"{data.get('NewDate', '')} {data.get('NewTime', '')}") or parse_iso_time(
        data.get("NewTime", "")
    )
    extra = {"old_time": old.isoformat() if old else "", "new_time": new.isoformat() if new else ""}
    if old is not None and new is not None:
        extra["delta_seconds"] = f"{(new - old).total_seconds():g}"
    else:
        delta_ms = to_int(data.get("TimeDeltaInMs", ""))
        if delta_ms is not None:  # written as an unsigned 32-bit number: a small step back reads as ~49.7 days
            signed = delta_ms - (1 << 32) if delta_ms >= 1 << 31 else delta_ms
            extra["delta_seconds"] = f"{signed / 1000:g}"
    extra["change_reason"] = _group(re.compile(r"Change Reason: ([^\r\n]+)"), text)
    values = {
        "user": _account(event, "SubjectUserName", "SubjectDomainName"),
        "app_path": clean(data.get("ProcessName", "")),
        "process_id": clean(data.get("ProcessId", "") or data.get("ProcessID", "")),
    }
    return build_facts("time-change", values, {k: v for k, v in extra.items() if v})


def time_change_seconds(facts: EventFacts) -> float | None:
    """Size of a clock change in seconds (positive = forward), if the event stated it."""
    value = facts.extra.get("delta_seconds")
    try:
        return float(value) if value else None
    except ValueError:
        return None


# ---- security --------------------------------------------------------------------------------------------------------
_IP = _f("IpAddress", rx=r"Source Network Address:\s+(\S+)")
_LOGON_TYPE = _f("LogonType", rx=r"Logon Type:\s+(\d+)")
_WORKSTATION = _f("WorkstationName", rx=r"Workstation Name:\s+(\S+)")


def _logon(event: EventRecord, text: str) -> EventFacts:
    """4624 successful logon / 4625 failed logon (with the reason from Status / Sub Status)."""
    values = {
        "user": _account(event, "TargetUserName", "TargetDomainName"),
        "logon_type": _LOGON_TYPE.pick(event, text),
        "source_ip": _IP.pick(event, text),
        "workstation": _WORKSTATION.pick(event, text),
        "app_path": clean(event.data.get("ProcessName", "")),
        "status": clean(event.data.get("Status", "")),
        "sub_status": clean(event.data.get("SubStatus", "")),
    }
    extra = {"auth_package": clean(event.data.get("AuthenticationPackageName", ""))}
    failed = event.event_id == 4625
    facts = build_facts("logon-failure" if failed else "logon", values, {k: v for k, v in extra.items() if v})
    if failed:
        facts = replace(facts, failure_reason=_logon_failure_reason(facts, text))
    return facts


def _logon_failure_reason(facts: EventFacts, text: str) -> str:
    for code in (facts.sub_status, facts.status):
        if code and code in LOGON_FAILURE_REASONS:
            return LOGON_FAILURE_REASONS[code]
    return _group(re.compile(r"Failure Reason:\s+([^\r\n]+)"), text)


def _lockout(event: EventRecord, _text: str) -> EventFacts:
    """4740: TargetUserName was locked out; TargetDomainName holds the *caller computer* that sent the bad passwords."""
    return build_facts(
        "lockout",
        {
            "user": clean(event.data.get("TargetUserName", "")),
            "workstation": clean(event.data.get("TargetDomainName", "")),
        },
    )


def _explicit_logon(event: EventRecord, text: str) -> EventFacts:
    """4648: a process logged on with explicit credentials (runas, mapped drive with other credentials, …)."""
    values = {
        "user": _account(event, "SubjectUserName", "SubjectDomainName"),
        "source_ip": _IP.pick(event, text),
        "app_path": clean(event.data.get("ProcessName", "")),
    }
    extra = {
        "target_user": _account(event, "TargetUserName", "TargetDomainName"),
        "target_server": clean(event.data.get("TargetServerName", "")),
    }
    return build_facts("explicit-logon", values, {k: v for k, v in extra.items() if v})


def _special_logon(event: EventRecord, _text: str) -> EventFacts:
    """4672: an administrator-equivalent logon (special privileges assigned)."""
    privileges = " ".join(clean(event.data.get("PrivilegeList", "")).split())
    return build_facts(
        "special-logon",
        {"user": _account(event, "SubjectUserName", "SubjectDomainName")},
        {"privileges": privileges} if privileges else None,
    )


def _log_cleared(event: EventRecord, text: str) -> EventFacts:
    """1102 (Security log cleared) and 104 (any other log cleared — the channel is in the data)."""
    channel = clean(event.data.get("Channel", "")) or _group(re.compile(r"The (.+?) log file was cleared"), text)
    if not channel and event.event_id == 1102:
        channel = event.channel or "Security"
    return build_facts(
        "log-cleared",
        {"user": _account(event, "SubjectUserName", "SubjectDomainName")},
        {"channel": channel} if channel else None,
    )


# ---- installs and updates --------------------------------------------------------------------------------------------
def _msi_status(facts: EventFacts, _event: EventRecord, _text: str) -> EventFacts:
    """1033/1034/1035: outcome from the installer status (0, 1641 and 3010 are successes)."""
    if facts.error_code in MSI_SUCCESS_CODES:
        return replace(facts, extra={**facts.extra, "outcome": "success"})
    return replace(_with_error_text(facts), extra={**facts.extra, "outcome": "failed"})


def _msi_summary(action: str) -> _Spec:
    """ "Windows Installer installed the product. Product Name: X. Product Version: Y. … status: 0." (1033 …)."""
    return _Spec(
        "installer",
        {
            "product_name": _f(rx=r"Product Name: (.+?)\. Product Version:", pos=1),
            "product_version": _f(rx=r"Product Version: (.+?)\. Product Language:", pos=2),
            "error_code": _f(rx=r"success or error status: (-?\d+)", pos=4),
        },
        extra={"manufacturer": _f(rx=r"Manufacturer: (.+?)\. \w+ success or error status", pos=5)},
        fixed_extra={"action": action},
        post=_msi_status,
    )


def _msi_result(action: str, outcome: str) -> _Spec:
    """ "Product: X -- Installation failed." (11707/11708, 11724/11725, 11728/11729)."""
    return _Spec(
        "installer",
        {"product_name": _f(rx=r"Product: (.+?) -- ", pos=1)},
        fixed_extra={"action": action, "outcome": outcome},
    )


_MSI: dict[int, _Spec] = {
    1033: _msi_summary("install"),
    1034: _msi_summary("removal"),
    1035: _msi_summary("reconfiguration"),
    11707: _msi_result("install", "success"),
    11708: _msi_result("install", "failed"),
    11724: _msi_result("removal", "success"),
    11725: _msi_result("removal", "failed"),
    11728: _msi_result("reconfiguration", "success"),
    11729: _msi_result("reconfiguration", "failed"),
}


def _update(action: str, outcome: str) -> _Spec:
    """WindowsUpdateClient 19/20/43: "… the following update[ with error 0x…]: <title>"."""
    return _Spec(
        "update",
        {
            "update_title": _f("updateTitle", rx=r"following update(?: with error 0x[0-9a-f]+)?: ([^\r\n]+?)\.?\s*$"),
            "error_code": _f("errorCode", rx=r"with error (0x[0-9a-f]+)"),
        },
        fixed_extra={"action": action, "outcome": outcome},
        post=_with_error_text,
    )


def _servicing_post(facts: EventFacts, _event: EventRecord, _text: str) -> EventFacts:
    outcome = "success" if not facts.error_code else "failed"
    return replace(_with_error_text(facts), extra={**facts.extra, "outcome": outcome})


_SERVICING = _Spec(  # Setup channel: "Package KB5031356 was successfully changed to the Installed state."
    "update",
    {
        "update_title": _f("PackageIdentifier", rx=r"Package (\S+) was"),
        "error_code": _f("ErrorCode", rx=r"error code (0x[0-9a-f]+)"),
    },
    extra={"state": _f("IntendedPackageStateTextized", rx=r"changed to the (\w+) state")},
    post=_servicing_post,
)
_KERNEL_GENERAL: dict[int, Parser] = {
    1: _time_change,
    12: _Spec("boot", {}, extra={"start_time": _f("StartTime", rx=r"started at system time (\S+)")}),
    13: _Spec("os-shutdown", {}, extra={"stop_time": _f("StopTime", rx=r"shutting down at system time (\S+)")}),
}

# ---- registry --------------------------------------------------------------------------------------------------------
PARSERS: dict[tuple[str, int], Parser] = {
    ("application error", 1000): _APP_CRASH,
    ("application error", 1002): _APP_HANG,
    ("application hang", 1002): _APP_HANG,
    ("windows error reporting", 1001): _wer_event,
    (".net runtime", 1026): _dotnet_crash,
    ("asp.net", 1309): _ASPNET,
    ("service control manager", 7036): _SERVICE_STATE,
    **{("service control manager", event_id): spec for event_id, spec in _SCM.items()},
    **{("was", event_id): spec for event_id, spec in _WAS.items()},
    ("kernel-power", 41): _kernel_power,
    **{("eventlog", event_id): spec for event_id, spec in _EVENTLOG.items()},
    ("eventlog", 104): _log_cleared,
    ("eventlog", 1102): _log_cleared,
    ("user32", 1074): _USER32_SHUTDOWN,
    ("security-auditing", 4624): _logon,
    ("security-auditing", 4625): _logon,
    ("security-auditing", 4740): _lockout,
    ("security-auditing", 4648): _explicit_logon,
    ("security-auditing", 4672): _special_logon,
    ("security-auditing", 4616): _time_change,
    **{("msiinstaller", event_id): spec for event_id, spec in _MSI.items()},
    ("windowsupdateclient", 19): _update("install", "success"),
    ("windowsupdateclient", 20): _update("install", "failed"),
    ("windowsupdateclient", 43): _update("install started", "pending"),
    ("servicing", 2): _SERVICING,
    **{("kernel-general", event_id): parser for event_id, parser in _KERNEL_GENERAL.items()},
}


def has_parser(provider: str, event_id: int) -> bool:
    return (normalize_provider(provider), event_id) in PARSERS


def extract(event: EventRecord) -> EventFacts:
    """Facts for one event: the specific parser's fields plus failure codes and file paths found anywhere in it."""
    text = _text(event)
    parser = PARSERS.get(event_key(event))
    facts = parser(event, text) if parser is not None else EventFacts()
    blob = "\n".join((text, *event.data.values())) if event.message else text
    codes = tuple(find_codes(blob))
    found = (match.group(0).rstrip(".") for match in _PATH.finditer(blob))
    paths = tuple(dict.fromkeys(path for path in found if len(path) > len("C:\\")))[:MAX_PATHS]
    # only unknown events take the first code as "the" error; specific parsers know which value is the error
    error_code = codes[0] if facts.kind == "generic" and codes else facts.error_code
    return replace(facts, codes=codes, paths=paths, error_code=error_code)
