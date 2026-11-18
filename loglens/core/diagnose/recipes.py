"""Guided diagnosis recipes over Windows events: crashes, unexpected restarts, failing services, … with next steps.

A recipe selects the few events it understands (``event_filter``), correlates them (same application, service,
account or source address, within a time window) and returns ``DiagnosisFinding``s: what happened, how sure we are,
the evidence events and what to do next. Recipes are pure functions over ``EventRecord`` lists, so they work the same
on live channels and on exported .evtx files. ``run_all`` runs every registered recipe.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal

from ..kb.codes import describe_code
from ..timeparse import to_local
from ..winevent.entities import EventFacts, event_key, extract, time_change_seconds, to_int
from ..winevent.models import EventRecord
from ..winevent.wer import exception_label

Severity = Literal["critical", "error", "warning", "info"]
Confidence = Literal["high", "medium", "low"]
EventFilter = Callable[[EventRecord], bool]
Analyzer = Callable[[list[EventRecord]], list["DiagnosisFinding"]]
EventKey = tuple[str, int]
Pair = tuple[EventRecord, EventFacts]

SEVERITY_RANK: dict[str, int] = {"critical": 0, "error": 1, "warning": 2, "info": 3}
CHANNEL_ORDER = ("Application", "System", "Security", "Setup")

CRASH_CHAIN_WINDOW = timedelta(minutes=2)  # .NET 1026 → Application Error 1000 → WER 1001 of one crash: seconds apart
REPEATED_CRASHES = 3  # crashes of one application in the analysed period that make it a crash loop
SERVICE_LOOP_COUNT = 3  # unexpected terminations of one service within SERVICE_LOOP_WINDOW = restart loop
SERVICE_LOOP_WINDOW = timedelta(hours=1)
UNCLEAN_PAIR_WINDOW = timedelta(minutes=10)  # Kernel-Power 41 and EventLog 6008 of one crash are logged at one boot
BOOT_MARKER_WINDOW = timedelta(minutes=5)  # Kernel-General 12, EventLog 6009 and 6005 of the same boot
HUNG_SHUTDOWN_WINDOW = timedelta(minutes=30)  # a restart requested this soon before an unclean one probably hung
PLANNED_DEDUP_WINDOW = timedelta(minutes=5)  # some initiators log 1074 twice for one restart
LOCKOUT_LOOKBACK = timedelta(minutes=30)  # failed logons before a lockout that count towards it (default AD window)
BRUTE_FORCE_ATTEMPTS = 10  # failed logons from one address within BRUTE_FORCE_WINDOW — far beyond mistyping
BRUTE_FORCE_WINDOW = timedelta(minutes=5)
SPRAY_ACCOUNTS = 5  # distinct accounts tried from one address = password spraying, not one stale password
BRUTE_FORCE_SUCCESS_WINDOW = timedelta(hours=1)  # a successful logon from the attacking address this soon after
TIME_JUMP_MIN_SECONDS = 60.0  # clock corrections below a minute are routine time synchronisation
MAX_LISTED = 6  # items named in one summary before "… and N more"
NON_SOURCE_ADDRESSES = frozenset({"", "-", "::1", "127.0.0.1"})  # local logons have no meaningful source address
LEVELS_PROBLEM = frozenset({1, 2, 3})  # critical, error, warning

BOOT_KEYS: frozenset[EventKey] = frozenset({("eventlog", 6005), ("eventlog", 6009), ("kernel-general", 12)})
STOP_KEYS: frozenset[EventKey] = frozenset({("eventlog", 6006), ("kernel-general", 13)})
UNCLEAN_KEYS: frozenset[EventKey] = frozenset({("kernel-power", 41), ("eventlog", 6008)})
LOG_CLEARED_KEYS: frozenset[EventKey] = frozenset({("eventlog", 1102), ("eventlog", 104)})
TIME_CHANGE_KEYS: frozenset[EventKey] = frozenset({("security-auditing", 4616), ("kernel-general", 1)})
PLANNED_SHUTDOWN_KEY: EventKey = ("user32", 1074)


@dataclass(frozen=True, slots=True)
class DiagnosisFinding:
    """One diagnosed problem (or notable change) with its evidence. ``time``: when it happened (latest occurrence)."""

    recipe_id: str
    title: str
    severity: Severity
    summary: str
    evidence: tuple[EventRecord, ...]
    confidence: Confidence
    next_steps: tuple[str, ...]
    time: datetime


@dataclass(frozen=True, slots=True)
class Recipe:
    """A guided check: which channels it needs, which events it looks at, and how it turns them into findings."""

    id: str
    title: str
    description: str
    channels: tuple[str, ...]
    event_filter: EventFilter
    analyze: Analyzer

    def run(self, events: Iterable[EventRecord]) -> list[DiagnosisFinding]:
        selected = sorted((event for event in events if self.event_filter(event)), key=_chronological)
        return self.analyze(selected) if selected else []


# ---- shared helpers --------------------------------------------------------------------------------------------------
def format_time(moment: datetime) -> str:
    """Local time as shown in findings: ``2026-11-13 10:15:02``."""
    return to_local(moment).strftime("%Y-%m-%d %H:%M:%S")


def format_duration(delta: timedelta) -> str:
    """The two most significant units: ``2 d 3 h``, ``3 h 20 min``, ``45 s``."""
    seconds = int(abs(delta.total_seconds()))
    parts: list[str] = []
    for unit, size in (("d", 86_400), ("h", 3_600), ("min", 60), ("s", 1)):
        value, seconds = divmod(seconds, size)
        if value:
            parts.append(f"{value} {unit}")
        if parts and (len(parts) == 2 or not value):
            break
    return " ".join(parts) or "0 s"


def is_time_jump(facts: EventFacts) -> bool:
    """A clock change large enough to matter (not a routine time-sync correction)."""
    delta = time_change_seconds(facts)
    return delta is not None and abs(delta) >= TIME_JUMP_MIN_SECONDS


def _chronological(event: EventRecord) -> tuple[datetime, int]:
    return event.time_created, event.record_id


def _accept_keys(keys: Iterable[EventKey], accept: EventFilter | None = None) -> EventFilter:
    wanted = frozenset(keys)

    def matches(event: EventRecord) -> bool:
        return event_key(event) in wanted and (accept is None or accept(event))

    return matches


def _listing(items: Sequence[str]) -> str:
    shown = ", ".join(items[:MAX_LISTED])
    return f"{shown} and {len(items) - MAX_LISTED} more" if len(items) > MAX_LISTED else shown


def _times(count: int) -> str:
    return "once" if count == 1 else f"{count} times"


def _span(events: Sequence[EventRecord]) -> str:
    first, last = format_time(events[0].time_created), format_time(events[-1].time_created)
    return f"at {first}" if first == last else f"between {first} and {last}"


def _clusters(events: Sequence[EventRecord], window: timedelta) -> list[list[EventRecord]]:
    """Consecutive events no more than ``window`` apart (input sorted by time)."""
    groups: list[list[EventRecord]] = []
    for event in events:
        if groups and event.time_created - groups[-1][-1].time_created <= window:
            groups[-1].append(event)
        else:
            groups.append([event])
    return groups


def _max_in_window(times: Sequence[datetime], window: timedelta) -> int:
    """Largest number of ``times`` (sorted) that fit in one ``window``."""
    best, left = 0, 0
    for right, moment in enumerate(times):
        while moment - times[left] > window:
            left += 1
        best = max(best, right - left + 1)
    return best


def _first_sentence(text: str) -> str:
    return " ".join(text.split()).split(". ")[0].rstrip(".")


def _code_text(code: int | None, text: str = "") -> str:
    """``1053 (The service did not respond …)`` / ``0x80070005 (Access is denied)``."""
    if code is None:
        return text
    label = f"0x{code:08X}" if code > 0xFFFF else str(code)
    description = text or _first_sentence(describe_code(code) or "")
    return f"{label} ({description})" if description else label


def _finding(
    recipe_id: str,
    title: str,
    severity: Severity,
    summary: str,
    evidence: Sequence[EventRecord],
    *,
    confidence: Confidence = "high",
    steps: Iterable[str] = (),
) -> DiagnosisFinding:
    return DiagnosisFinding(
        recipe_id=recipe_id,
        title=title,
        severity=severity,
        summary=summary,
        evidence=tuple(evidence),
        confidence=confidence,
        next_steps=tuple(step for step in steps if step),
        time=evidence[-1].time_created,
    )


# ---- application crashes and hangs ---------------------------------------------------------------------------------
WER_KEY: EventKey = ("windows error reporting", 1001)
CRASH_KEYS: frozenset[EventKey] = frozenset(
    {("application error", 1000), ("application error", 1002), ("application hang", 1002), (".net runtime", 1026)}
)
_CRASH_CODE_STEPS: dict[int, str] = {
    0xC0000005: "Access violation: a bug or memory corruption in {module} — update the application and the product "
    "that ships {module}.",
    0xC0000374: "Heap corruption: the culprit is often a different component than {module} — enable full PageHeap "
    "(gflags /p /enable <exe> /full) to catch it in the act.",
    0xC0000409: "Fail-fast / stack buffer overrun: the process stopped itself after detecting corruption — update the "
    "application and the product that ships {module}.",
    0xC00000FD: "Stack overflow, usually endless recursion — the vendor needs a crash dump.",
    0xC0000135: "A DLL the application needs is missing: repair or reinstall the application and its runtime "
    "(Visual C++ redistributable, .NET).",
    0xC06D007E: "A DLL the application needs is missing: repair or reinstall the application and its runtime "
    "(Visual C++ redistributable, .NET).",
    0xC0000142: "A DLL failed to initialise — often a broken runtime or desktop-heap exhaustion; repair the runtime.",
    0xE06D7363: "Unhandled C++ exception: the application's own log usually states the error it threw.",
    0xE0434352: "Unhandled .NET exception: the matching '.NET Runtime 1026' event in the Application log has the "
    "exception type and stack.",
}


@dataclass(frozen=True, slots=True)
class _Crash:
    """One crash or hang of an application, merged from the events it produced."""

    hang: bool
    app: str
    version: str
    module: str
    code: int | None
    exception: str  # .NET exception type (+ message)
    report_id: str


def _is_crash_event(event: EventRecord) -> bool:
    key = event_key(event)
    if key == WER_KEY:
        return extract(event).kind in ("wer-crash", "wer-hang")
    return key in CRASH_KEYS


# Store-app package full name "Name_Version_Arch_ResourceId_PublisherId": group all versions of one package together
_PACKAGE_FULL_NAME = re.compile(r"^(?P<name>[^_]+)_\d+(?:\.\d+){3}_[^_]*_[^_]*_[a-z0-9]{13}$", re.IGNORECASE)


def _app_key(facts: EventFacts) -> str:
    name = (facts.app_name or facts.app_path.rsplit("\\", 1)[-1] or "unknown application").lower()
    package = _PACKAGE_FULL_NAME.match(name)
    return package["name"] if package is not None else name


def _is_hang(facts: EventFacts) -> bool:
    return facts.kind in ("app-hang", "wer-hang")


def _incident_key(event: EventRecord, facts: EventFacts) -> tuple[EventKey, str]:
    return event_key(event), facts.extra.get("wer_event", "").lower()


def _crash_incidents(pairs: list[Pair]) -> list[list[Pair]]:
    """Split one application's events into crashes: a new one starts after a pause or when an event repeats."""
    incidents: list[list[Pair]] = []
    for event, facts in pairs:
        current = incidents[-1] if incidents else None
        if (
            current is None
            or event.time_created - current[-1][0].time_created > CRASH_CHAIN_WINDOW
            or any(_incident_key(*other) == _incident_key(event, facts) for other in current)
        ):
            incidents.append([(event, facts)])
        else:
            current.append((event, facts))
    return incidents


def _crash_groups(pairs: list[Pair]) -> list[list[Pair]]:
    """Events per application. A WER report filed under another name (a store app's package instead of its .exe)
    joins the application whose crash or hang event is closest in time."""
    groups: dict[str, list[Pair]] = defaultdict(list)
    direct = [pair for pair in pairs if event_key(pair[0]) != WER_KEY]
    for event, facts in direct:
        groups[_app_key(facts)].append((event, facts))
    for event, facts in pairs:
        if event_key(event) != WER_KEY:
            continue
        key = _app_key(facts)
        if not any(_near_crash(event, other) for other, _ in groups.get(key, [])):
            partners = [
                (abs(other.time_created - event.time_created), _app_key(other_facts))
                for other, other_facts in direct
                if _near_crash(event, other) and _is_hang(other_facts) == _is_hang(facts)
            ]
            key = min(partners)[1] if partners else key
        groups[key].append((event, facts))
    return [sorted(group, key=lambda pair: _chronological(pair[0])) for group in groups.values()]


def _near_crash(event: EventRecord, other: EventRecord) -> bool:
    return abs(event.time_created - other.time_created) <= CRASH_CHAIN_WINDOW


def _merge_crash(incident: list[Pair]) -> _Crash:
    facts = [item for _, item in incident]

    def first(attribute: str) -> str:
        return next((str(getattr(f, attribute)) for f in facts if getattr(f, attribute)), "")

    exception = first("exception_type")
    message = first("exception_message").rstrip(".")
    return _Crash(
        hang=all(_is_hang(f) for f in facts),
        app=first("app_name") or "unknown application",
        version=first("app_version"),
        module=first("faulting_module"),
        code=next((f.exception_code for f in facts if f.exception_code is not None), None),
        exception=f"{exception}: {message}" if exception and message else exception,
        report_id=first("report_id"),
    )


def _crash_cause(crash: _Crash) -> str:
    if crash.hang:
        return ""
    if crash.exception:
        return f"Unhandled .NET exception {crash.exception}."
    parts = []
    if crash.code is not None:
        parts.append(f"exception {exception_label(crash.code)}")
    if crash.module:
        parts.append(f"in {crash.module}")
    return ("Cause: " + " ".join(parts) + ".") if parts else ""


def _crash_steps(crash: _Crash, count: int, last_time: datetime) -> list[str]:
    steps: list[str] = []
    if crash.hang:
        steps.append(
            "Next time it hangs, capture a dump (Task Manager → Create dump file, or ProcDump -h -ma) to see what it "
            "is waiting for."
        )
    elif crash.exception:
        steps.append(
            "Read the full exception and stack in the .NET Runtime event, then the application's own log just "
            f"before {format_time(last_time)}."
        )
    if not crash.hang and crash.code is not None and crash.code in _CRASH_CODE_STEPS and not crash.exception:
        steps.append(_CRASH_CODE_STEPS[crash.code].format(module=crash.module or "the faulting module"))
    if crash.report_id:
        steps.append(
            f"Reliability Monitor (perfmon /rel) shows WER report {crash.report_id}; its Report.wer in the WER "
            "ReportArchive folder lists the loaded modules."
        )
    if count >= REPEATED_CRASHES:
        steps.append("It keeps happening: check 'What changed' for an update or install just before the first crash.")
    if not crash.hang:
        steps.append(
            "For the vendor: enable WER LocalDumps for this executable (or run ProcDump -e -ma) to get a dump."
        )
    return steps


def _crash_finding(pairs: list[Pair]) -> DiagnosisFinding:
    crashes = [_merge_crash(incident) for incident in _crash_incidents(pairs)]
    latest, count = crashes[-1], len(crashes)
    events = [event for event, _ in pairs]
    hang = all(crash.hang for crash in crashes)
    verb = "stopped responding" if hang else "crashed"
    # name the application as its own crash events do (a WER report may use a package name instead)
    name = next((f.app_name for e, f in reversed(pairs) if f.app_name and event_key(e) != WER_KEY), latest.app)
    version = latest.version if name == latest.app else ""
    app = " ".join(part for part in (name, version) if part)
    summary = f"{app} {verb} {_times(count)} {_span(events)}. {_crash_cause(latest)}".strip()
    causes = sorted({_crash_cause(crash) for crash in crashes if not crash.hang} - {""})
    if len(causes) > 1:
        summary += f" Earlier crashes had {len(causes) - 1} other cause(s) — the problem may not be one single bug."
    if hang:
        severity: Severity = "error" if count >= REPEATED_CRASHES else "warning"
    else:
        severity = "critical" if count >= REPEATED_CRASHES else "error"
    direct = any(event_key(event) != WER_KEY for event in events)
    return _finding(
        "crashes",
        f"{name} {verb}" + ("" if count == 1 else f" {count} times"),
        severity,
        summary,
        events,
        confidence="high" if direct else "medium",
        steps=_crash_steps(latest, count, events[-1].time_created),
    )


def _analyze_crashes(events: list[EventRecord]) -> list[DiagnosisFinding]:
    return [_crash_finding(group) for group in _crash_groups([(event, extract(event)) for event in events])]


# ---- unexpected restarts ---------------------------------------------------------------------------------------------
def _unclean_steps(power: EventFacts | None) -> list[str]:
    reason = power.failure_reason if power is not None else ""
    if power is not None and power.extra.get("bugcheck_code"):
        return [
            "Open the memory dump (C:\\Windows\\MEMORY.DMP or C:\\Windows\\Minidump) in WinDbg and run !analyze -v to "
            "find the driver responsible.",
            "Update or roll back that driver and the firmware/BIOS; repeated different bug checks point to hardware "
            "(memory, overheating).",
        ]
    if "power button" in reason:
        return ["The power button was used — check who had physical or remote (iLO, iDRAC, hypervisor) access."]
    return [
        "Check the power path (UPS, power supply, cables) and, for a virtual machine, the host for a forced reset.",
        "Look at the events just before the previous shutdown time for warnings (disk, driver, temperature, memory).",
        "If it happens again, configure a complete memory dump and turn off automatic restart to catch a hard hang.",
    ]


def _unclean_finding(group: list[EventRecord], planned: list[EventRecord]) -> DiagnosisFinding:
    by_id = {event.event_id: extract(event) for event in group}
    power, previous = by_id.get(41), by_id.get(6008)
    boot = group[0].time_created
    summary = f"Windows started at {format_time(boot)} without having shut down cleanly."
    if previous is not None and previous.extra.get("previous_shutdown"):
        summary += f" The previous shutdown at {previous.extra['previous_shutdown']} was unexpected."
    if power is not None:
        summary += f" Kernel-Power recorded: {power.failure_reason}."
    hung = [event for event in planned if boot - HUNG_SHUTDOWN_WINDOW <= event.time_created <= boot]
    if hung:
        facts = extract(hung[-1])
        summary += (
            f" A restart had been requested at {format_time(hung[-1].time_created)} by "
            f"{facts.shutdown_initiator or 'a process'} — the system probably hung while shutting down."
        )
    bugcheck = power.extra.get("bugcheck_code") if power is not None else ""
    title = f"Unexpected restart — blue screen {bugcheck}" if bugcheck else "Unexpected restart or power loss"
    return _finding("restarts", title, "critical", summary, [*hung, *group], steps=_unclean_steps(power))


def _inferred_unclean(boundaries: list[EventRecord], unclean: list[EventRecord]) -> list[DiagnosisFinding]:
    """Two boots with no shutdown logged in between, and no 41/6008 for it: an unclean restart Windows did not flag."""
    findings: list[DiagnosisFinding] = []
    previous_boot: EventRecord | None = None
    previous_was_boot = False
    for event in boundaries:
        if event_key(event) not in BOOT_KEYS:
            previous_was_boot = False
            continue
        if previous_boot is not None and event.time_created - previous_boot.time_created <= BOOT_MARKER_WINDOW:
            continue  # another marker of the same boot
        flagged = any(abs(other.time_created - event.time_created) <= UNCLEAN_PAIR_WINDOW for other in unclean)
        if previous_was_boot and previous_boot is not None and not flagged:
            summary = (
                f"Windows started at {format_time(event.time_created)}, but no shutdown was logged after the previous "
                f"start at {format_time(previous_boot.time_created)}: the system was probably reset or lost power."
            )
            findings.append(
                _finding(
                    "restarts",
                    "Restart without a logged shutdown",
                    "error",
                    summary,
                    [previous_boot, event],
                    confidence="medium",
                    steps=("Check the last events before this restart for warnings (disk, driver, power, hangs).",),
                )
            )
        previous_boot, previous_was_boot = event, True
    return findings


def _planned_finding(group: list[EventRecord]) -> DiagnosisFinding:
    facts = extract(group[0])
    kind = facts.extra.get("shutdown_type") or "restart"
    user = facts.user or "an unknown user"
    summary = f"{facts.shutdown_initiator or 'A process'} requested a {kind} on behalf of {user}"
    summary += f": {facts.shutdown_reason}" if facts.shutdown_reason else ""
    summary += f" (reason code {facts.extra['reason_code']})" if facts.extra.get("reason_code") else ""
    summary += f'. Comment: "{facts.extra["comment"]}"' if facts.extra.get("comment") else "."
    return _finding(
        "restarts",
        f"{kind.capitalize()} requested by {user}",
        "info",
        summary,
        group,
        steps=(f"Expected for maintenance or updates; otherwise ask {user} or check what ran the initiating process.",),
    )


def _analyze_restarts(events: list[EventRecord]) -> list[DiagnosisFinding]:
    unclean = [event for event in events if event_key(event) in UNCLEAN_KEYS]
    planned = [event for event in events if event_key(event) == PLANNED_SHUTDOWN_KEY]
    boundaries = [event for event in events if event_key(event) in BOOT_KEYS | STOP_KEYS]
    findings = [_unclean_finding(group, planned) for group in _clusters(unclean, UNCLEAN_PAIR_WINDOW)]
    findings.extend(_inferred_unclean(boundaries, unclean))
    findings.extend(_planned_finding(group) for group in _clusters(planned, PLANNED_DEDUP_WINDOW))
    return findings


# ---- services --------------------------------------------------------------------------------------------------------
SCM = "service control manager"
SERVICE_CRASH_IDS = frozenset({7031, 7034})
SERVICE_START_IDS = frozenset({7000, 7001, 7009, 7011, 7022})
SERVICE_ERROR_EXIT_IDS = frozenset({7023, 7024})
_SERVICE_ERROR_STEPS: dict[int, str] = {
    2: "The service executable (or a file it needs) is missing — check its path (sc qc <service>) and reinstall.",
    3: "The service executable's folder is missing — check its path (sc qc <service>) and reinstall.",
    5: "Access denied — check the service account's rights on its files, folders and registry keys.",
    1053: "The service did not report 'running' in time (30 s by default): check its own log for slow start-up work, "
    "its dependencies, and disk/CPU load at boot.",
    1058: "The service is disabled — change its start type in services.msc if it is needed.",
    1067: "Its process ended unexpectedly — look for an Application Error 1000 for the service executable.",
    1068: "A service it depends on did not start — fix that service first.",
    1069: "Logon failure — the service account's password is wrong or expired, or it lacks 'Log on as a service'.",
    1075: "A dependency does not exist or is marked for deletion — check the service's dependencies (sc qc <service>).",
}


def _service_name(pairs: Sequence[Pair]) -> str:
    return pairs[0][1].service_name or "unknown service"


def _service_crash_finding(pairs: list[Pair]) -> DiagnosisFinding:
    name, events = _service_name(pairs), [event for event, _ in pairs]
    reported = max((to_int(facts.extra.get("times", "")) or 0 for _, facts in pairs), default=0)
    burst = _max_in_window([event.time_created for event in events], SERVICE_LOOP_WINDOW)
    looping = max(burst, reported) >= SERVICE_LOOP_COUNT
    summary = f"'{name}' terminated unexpectedly {_times(len(events))} {_span(events)}."
    if reported > 1:
        summary += f" Service Control Manager counted {reported} failures in a row."
    action = pairs[-1][1].extra.get("recovery_action")
    summary += f" Recovery action: {action}." if action else " No recovery action is configured."
    return _finding(
        "services",
        f"Service '{name}' keeps crashing" if looping else f"Service '{name}' terminated unexpectedly",
        "error" if looping else "warning",
        summary,
        events,
        steps=(
            "Look for a crash of the service's executable at the same times (Application Error 1000 / .NET Runtime "
            "1026) — the application crash finding has the exception details.",
            "Check the service's own log for its last messages before each termination.",
            "Review its recovery settings (services.msc → Recovery) so a crash loop does not go unnoticed.",
        ),
    )


def _service_start_finding(pairs: list[Pair]) -> DiagnosisFinding:
    name, events = _service_name(pairs), [event for event, _ in pairs]
    latest = pairs[-1][1]
    # 7011 (no answer to a control request) can happen at any time, the others while starting
    verb = "failed to start" if any(e.event_id != 7011 for e in events) else "did not respond to a control request"
    summary = f"'{name}' {verb} {_times(len(events))} {_span(events)}"
    summary += f" (last: {latest.service_state})" if latest.service_state not in (verb, "failed to start") else ""
    error = _code_text(latest.error_code, latest.error_text)
    summary += f" — error {error}." if error else "."
    if latest.extra.get("depends_on"):
        summary += f" It depends on '{latest.extra['depends_on']}', which failed."
    steps = [_SERVICE_ERROR_STEPS.get(latest.error_code or 0, "")]
    if latest.extra.get("timeout_ms") or latest.service_state == "hung on starting":
        steps.append(_SERVICE_ERROR_STEPS[1053])
    steps.append("Check the service's own log and the Application log at the same time for the underlying error.")
    return _finding("services", f"Service '{name}' {verb}", "error", summary, events, steps=steps)


def _service_exit_finding(pairs: list[Pair]) -> DiagnosisFinding:
    name, events = _service_name(pairs), [event for event, _ in pairs]
    latest = pairs[-1][1]
    error = _code_text(latest.error_code, latest.error_text)
    summary = f"'{name}' stopped with an error {_times(len(events))} {_span(events)}" + (
        f": {error}." if error else "."
    )
    return _finding(
        "services",
        f"Service '{name}' stopped with an error",
        "warning",
        summary,
        events,
        steps=("If it should keep running, check the service's own log for why it stopped.",),
    )


def _analyze_services(events: list[EventRecord]) -> list[DiagnosisFinding]:
    by_service: dict[str, list[Pair]] = defaultdict(list)
    for event in events:
        facts = extract(event)
        by_service[facts.service_name.lower()].append((event, facts))
    findings: list[DiagnosisFinding] = []
    for pairs in by_service.values():
        groups = (
            (SERVICE_CRASH_IDS, _service_crash_finding),
            (SERVICE_START_IDS, _service_start_finding),
            (SERVICE_ERROR_EXIT_IDS, _service_exit_finding),
        )
        for ids, build in groups:
            selected = [pair for pair in pairs if pair[0].event_id in ids]
            if selected:
                findings.append(build(selected))
    return findings


# ---- installer and update failures -----------------------------------------------------------------------------------
MSI = "msiinstaller"
INSTALL_FAILURE_KEYS: frozenset[EventKey] = frozenset(
    {
        *((MSI, event_id) for event_id in (1033, 1034, 1035, 11708, 11725, 11729)),
        ("windowsupdateclient", 20),
        ("servicing", 2),
    }
)
_MSI_STATUS_STEPS: dict[int, str] = {
    1602: "The installation was cancelled by the user.",
    1603: "Fatal error during installation: run it again with a verbose log (msiexec /i <package> /l*v install.log) "
    "and look just above the first 'Return value 3' for the failing action.",
    1612: "The installation source is unavailable — repair from the original package or media.",
    1618: "Another installation was already running — wait for it to finish (or restart) and retry.",
    1619: "The package could not be opened — check that it exists and is readable (path, network share, rights).",
    1625: "System policy forbids this installation — check Group Policy / AppLocker / software restriction rules.",
    1638: "Another version of the product is already installed — remove it first or use the vendor's upgrade package.",
}
_UPDATE_ERROR_STEPS: dict[int, str] = {
    0x80073D02: "The app was in use during the update — close it and let the update retry.",
    0x80070070: "Not enough disk space — free space on the system drive and retry.",
    0x80070005: "Access denied — check security software and the Windows Update service account.",
}


def _failed(event: EventRecord) -> bool:
    return extract(event).extra.get("outcome") == "failed"


def _install_finding(pairs: list[Pair]) -> DiagnosisFinding:
    events = [event for event, _ in pairs]
    facts = next((f for _, f in reversed(pairs) if f.error_code is not None), pairs[-1][1])
    code = facts.error_code
    if facts.kind == "installer":
        product = " ".join(part for part in (facts.product_name, facts.product_version) if part) or "a product"
        action = facts.extra.get("action", "install")
        noun = {"install": "Installation", "removal": "Removal"}.get(action, action.capitalize())
        summary = f"Windows Installer could not {action} {product} ({_times(len(events))}, {_span(events)})."
        summary += f" Status {_code_text(code, facts.error_text)}." if code is not None else ""
        steps = [
            _MSI_STATUS_STEPS.get(code or 0, ""),
            "Check the Application log around that time for the installer's other MsiInstaller messages.",
        ]
        return _finding("installers", f"{noun} of {product} failed", "error", summary, events, steps=steps)
    title = facts.update_title or "an update"
    summary = f"{title} failed to install {_times(len(events))} {_span(events)}"
    summary += f" with error {_code_text(code, facts.error_text)}." if code is not None else "."
    steps = [
        _UPDATE_ERROR_STEPS.get(code or 0, ""),
        "If it keeps failing, run Get-WindowsUpdateLog and search for the error code.",
    ]
    return _finding("installers", f"Update failed: {title}", "warning", summary, events, steps=steps)


def _analyze_installers(events: list[EventRecord]) -> list[DiagnosisFinding]:
    by_subject: dict[str, list[Pair]] = defaultdict(list)
    for event in events:
        facts = extract(event)
        by_subject[f"{facts.kind}:{facts.subject.lower()}"].append((event, facts))
    return [_install_finding(pairs) for pairs in by_subject.values()]


# ---- account lockouts and password guessing --------------------------------------------------------------------------
LOGON_SUCCESS_KEY: EventKey = ("security-auditing", 4624)
LOGON_FAILURE_KEY: EventKey = ("security-auditing", 4625)
LOCKOUT_KEY: EventKey = ("security-auditing", 4740)


def _account_name(user: str) -> str:
    """``CONTOSO\\bob`` / ``bob@contoso.com`` → ``bob`` (lockouts and logon failures spell domains differently)."""
    return user.rsplit("\\", 1)[-1].split("@", 1)[0].lower()


def _lockout_finding(lockouts: list[Pair], failures: list[Pair]) -> DiagnosisFinding:
    account = lockouts[-1][1].user
    name = _account_name(account)
    callers = sorted({facts.workstation for _, facts in lockouts if facts.workstation})
    related = [
        (event, facts)
        for event, facts in failures
        if _account_name(facts.user) == name
        and any(lock.time_created - LOCKOUT_LOOKBACK <= event.time_created <= lock.time_created for lock, _ in lockouts)
    ]
    sources = sorted({facts.source_ip or facts.workstation for _, facts in related} - {""})
    reasons = sorted({facts.failure_reason for _, facts in related} - {""})
    summary = f"Account '{account}' was locked out {_times(len(lockouts))} {_span([e for e, _ in lockouts])}"
    summary += f" (caller computer: {_listing(callers)})." if callers else "."
    if related:
        summary += f" {len(related)} failed logon(s) in the {format_duration(LOCKOUT_LOOKBACK)} before"
        summary += f" from {_listing(sources)}" if sources else ""
        summary += f"; reason: {_listing(reasons)}." if reasons else "."
    evidence = sorted([e for e, _ in related] + [e for e, _ in lockouts], key=_chronological)
    caller = callers[0] if callers else "the caller computer"
    return _finding(
        "account-lockout",
        f"Account '{account}' locked out",
        "error",
        summary,
        evidence,
        confidence="high" if related or callers else "medium",
        steps=(
            f"Find what on {caller} still uses an old password for '{account}': mapped drives, services or scheduled "
            "tasks running as the account, saved RDP / mail / phone credentials.",
            "Once the source is fixed, unlock the account (Active Directory Users and Computers or Unlock-ADAccount).",
        ),
    )


def _analyze_lockouts(events: list[EventRecord]) -> list[DiagnosisFinding]:
    pairs = [(event, extract(event)) for event in events]
    failures = [pair for pair in pairs if event_key(pair[0]) == LOGON_FAILURE_KEY]
    by_account: dict[str, list[Pair]] = defaultdict(list)
    for event, facts in pairs:
        if event_key(event) == LOCKOUT_KEY:
            by_account[_account_name(facts.user)].append((event, facts))
    return [_lockout_finding(lockouts, failures) for lockouts in by_account.values()]


def _burst_members(times: Sequence[datetime]) -> set[int]:
    """Indexes of the events that belong to any BRUTE_FORCE_WINDOW holding at least BRUTE_FORCE_ATTEMPTS of them."""
    members: set[int] = set()
    left = 0
    for right, moment in enumerate(times):
        while moment - times[left] > BRUTE_FORCE_WINDOW:
            left += 1
        if right - left + 1 >= BRUTE_FORCE_ATTEMPTS:
            members.update(range(left, right + 1))
    return members


def _brute_force_finding(address: str, attempts: list[Pair], successes: list[Pair]) -> DiagnosisFinding:
    events = [event for event, _ in attempts]
    accounts = sorted({facts.user for _, facts in attempts if facts.user})
    first, last = events[0].time_created, events[-1].time_created
    after = [
        (event, facts)
        for event, facts in successes
        if facts.source_ip == address and first <= event.time_created <= last + BRUTE_FORCE_SUCCESS_WINDOW
    ]
    spraying = len(accounts) >= SPRAY_ACCOUNTS
    summary = (
        f"{len(events)} failed logons from {address} {_span(events)} against {len(accounts)} account(s): "
        f"{_listing(accounts)}."
    )
    if spraying:
        summary += " Many different accounts from one address looks like password spraying."
    steps = [
        f"If {address} is not a known system, block it at the firewall.",
        "Do not expose RDP/SMB directly to the internet; require a VPN, NLA and an account lockout policy.",
    ]
    if after:
        hijacked = _listing(sorted({facts.user for _, facts in after if facts.user}))
        summary += f" It was followed by a successful logon from the same address as {hijacked}."
        steps.insert(0, f"Treat {hijacked} as compromised: reset the password and review what the account did.")
    return _finding(
        "brute-force",
        f"Password guessing from {address}" + (" followed by a successful logon" if after else ""),
        "critical" if after else "error",
        summary,
        sorted(events + [event for event, _ in after], key=_chronological),
        steps=steps,
    )


def _analyze_brute_force(events: list[EventRecord]) -> list[DiagnosisFinding]:
    by_address: dict[str, list[Pair]] = defaultdict(list)
    successes: list[Pair] = []
    for event in events:
        facts = extract(event)
        if event_key(event) == LOGON_SUCCESS_KEY:
            successes.append((event, facts))
        elif facts.source_ip not in NON_SOURCE_ADDRESSES:
            by_address[facts.source_ip].append((event, facts))
    findings: list[DiagnosisFinding] = []
    for address, attempts in by_address.items():
        members = _burst_members([event.time_created for event, _ in attempts])
        if members:
            burst = [pair for index, pair in enumerate(attempts) if index in members]
            findings.append(_brute_force_finding(address, burst, successes))
    return findings


# ---- IIS application pools -------------------------------------------------------------------------------------------
APP_POOL_EVENTS: dict[int, tuple[str, Severity]] = {
    5002: ("pool disabled by rapid-fail protection", "critical"),
    5009: ("worker process crashed", "error"),
    5011: ("worker process lost contact with WAS", "error"),
    5010: ("worker process did not answer a ping (hung)", "warning"),
    5013: ("worker process exceeded the shutdown time limit", "warning"),
}


def _app_pool_finding(pairs: list[Pair]) -> DiagnosisFinding:
    pool = pairs[0][1].app_pool or "unknown pool"
    events = [event for event, _ in pairs]
    counts: dict[int, int] = defaultdict(int)
    for event in events:
        counts[event.event_id] += 1
    parts = [f"{APP_POOL_EVENTS[event_id][0]} {_times(count)}" for event_id, count in sorted(counts.items())]
    severity = min((APP_POOL_EVENTS[event_id][1] for event_id in counts), key=SEVERITY_RANK.__getitem__)
    exits = sorted({facts.error_code for _, facts in pairs if facts.error_code is not None})
    summary = f"Application pool '{pool}' {_span(events)}: {_listing(parts)}."
    if exits:
        summary += f" Exit codes: {_listing([exception_label(code) for code in exits])}."
    steps = [
        "Correlate with Application Error 1000 / .NET Runtime 1026 / ASP.NET 1309 events for w3wp.exe at the same "
        "times — they hold the exception that killed the worker process.",
    ]
    if 5010 in counts or 5013 in counts:
        steps.append("For hangs, capture a dump of the w3wp.exe process while it hangs (ProcDump -ma, DebugDiag).")
    if 5002 in counts:
        steps.append(
            "The pool stays stopped until started again: fix the cause, then start it in IIS Manager "
            "(Rapid-Fail Protection settings are in the pool's advanced settings)."
        )
    return _finding("app-pools", f"IIS application pool '{pool}' failing", severity, summary, events, steps=steps)


def _analyze_app_pools(events: list[EventRecord]) -> list[DiagnosisFinding]:
    by_pool: dict[str, list[Pair]] = defaultdict(list)
    for event in events:
        facts = extract(event)
        by_pool[facts.app_pool.lower()].append((event, facts))
    return [_app_pool_finding(pairs) for pairs in by_pool.values()]


# ---- disks and file systems ------------------------------------------------------------------------------------------
STORAGE_EVENTS: dict[EventKey, tuple[str, Severity]] = {
    ("disk", 7): ("bad block", "critical"),
    ("disk", 11): ("controller error", "error"),
    ("disk", 51): ("error during a paging operation", "error"),
    ("disk", 52): ("failure predicted by the drive (SMART)", "critical"),
    ("disk", 153): ("I/O operation retried", "warning"),
    ("ntfs", 55): ("file system corruption", "critical"),
    ("ntfs", 98): ("volume needs repair (chkdsk)", "error"),
}
VOLSNAP = "volsnap"
_VOLSNAP_PROBLEM: tuple[str, Severity] = ("shadow copy problem", "warning")
_DEVICE_PATTERNS = (
    re.compile(r"\\Device\\Harddisk\d+\\DR\d+", re.IGNORECASE),
    re.compile(r"\\Device\\[\w\\]+"),
    re.compile(r"\bDisk \d+\b"),
    re.compile(r"\b[A-Z]:(?=[\s)\\.,]|$)"),
)
_STORAGE_STEPS: dict[str, tuple[str, ...]] = {
    "hardware": (
        "Back up the data on this disk now.",
        "Check the drive's health (Get-PhysicalDisk | Get-StorageReliabilityCounter, or the vendor's tool) and "
        "replace it if it reports errors; check cables, controller drivers and firmware (or the host's storage for "
        "a virtual machine).",
    ),
    "retry": ("Occasional retries are tolerated; frequent ones point to a failing disk, cable or storage path.",),
    "filesystem": (
        "Run chkdsk <drive>: /scan (online) and schedule chkdsk /f if it reports errors.",
        "Back up first if the same disk also logs bad blocks or controller errors.",
    ),
    "shadow": (
        "Shadow copies (restore points, backups) were lost or not created — usually too little shadow storage: "
        "check vssadmin list shadowstorage and increase it or free space.",
    ),
}


def _storage_kind(event: EventRecord) -> tuple[str, Severity] | None:
    key = event_key(event)
    if key[0] == VOLSNAP:
        return _VOLSNAP_PROBLEM if event.level in LEVELS_PROBLEM else None
    if key == ("ntfs", 98) and event.level not in LEVELS_PROBLEM:
        return None  # "volume is healthy"
    return STORAGE_EVENTS.get(key)


def _device(event: EventRecord) -> str:
    for name in ("DriveName", "VolumeName", "DeviceName"):  # "C:" beats "\Device\HarddiskVolumeShadowCopy12"
        value = event.data.get(name, "").strip()
        if value:
            return value
    text = event.text()
    for pattern in _DEVICE_PATTERNS:
        match = pattern.search(text)
        if match is not None:
            return match.group(0)
    return "unknown device"


def _storage_steps(event: EventRecord) -> tuple[str, ...]:
    key = event_key(event)
    if key[0] == VOLSNAP:
        return _STORAGE_STEPS["shadow"]
    if key[0] == "ntfs":
        return _STORAGE_STEPS["filesystem"]
    return _STORAGE_STEPS["retry"] if key == ("disk", 153) else _STORAGE_STEPS["hardware"]


def _analyze_storage(events: list[EventRecord]) -> list[DiagnosisFinding]:
    groups: dict[tuple[str, Severity, str], list[EventRecord]] = defaultdict(list)
    for event in events:
        kind = _storage_kind(event)
        if kind is not None:
            groups[(*kind, _device(event))].append(event)
    findings: list[DiagnosisFinding] = []
    for (label, severity, device), grouped in groups.items():
        title = f"{label[:1].upper()}{label[1:]} on {device}"  # not str.capitalize(): keep "I/O", "SMART"
        summary = f"{title}, reported {_times(len(grouped))} {_span(grouped)}."
        findings.append(_finding("storage", title, severity, summary, grouped, steps=_storage_steps(grouped[0])))
    return findings


# ---- what changed ----------------------------------------------------------------------------------------------------
CHANGE_KEYS: frozenset[EventKey] = frozenset(
    {
        (SCM, 7045),
        (SCM, 7040),
        (MSI, 11707),
        (MSI, 1033),
        (MSI, 11724),
        (MSI, 1034),
        ("windowsupdateclient", 19),
        ("servicing", 2),
        *TIME_CHANGE_KEYS,
        PLANNED_SHUTDOWN_KEY,
    }
)
CHANGE_CATEGORIES: dict[str, tuple[str, Severity]] = {
    "service-installed": ("New services installed", "info"),
    "start-type": ("Service start types changed", "info"),
    "installed": ("Software installed", "info"),
    "removed": ("Software removed", "info"),
    "update": ("Updates installed", "info"),
    "clock": ("System clock changed", "warning"),
    "user-restart": ("Restarts or shutdowns by a user", "info"),
}
SERVICING_CHANGE_STATES = frozenset({"installed", "absent"})  # servicing states that are a real change


def _is_user(user: str) -> bool:
    """A person's account, not the system acting on its own (NT AUTHORITY\\SYSTEM, machine accounts)."""
    lowered = user.lower()
    return (
        bool(lowered) and not lowered.startswith("nt authority\\") and lowered != "system" and not lowered.endswith("$")
    )


Change = tuple[str, str, str]  # (category, item key, item text)


def _service_change(event: EventRecord, facts: EventFacts) -> Change | None:
    key = event_key(event)
    if key == (SCM, 7045):
        return "service-installed", facts.service_name, f"{facts.service_name} ({facts.app_path or 'unknown path'})"
    if key == (SCM, 7040):
        transition = f"{facts.extra.get('start_type_from', '?')} → {facts.extra.get('start_type_to', '?')}"
        return "start-type", facts.service_name, f"{facts.service_name}: {transition}"
    return None


def _software_change(event: EventRecord, facts: EventFacts) -> Change | None:
    if facts.extra.get("outcome") != "success":
        return None
    if facts.kind == "installer":
        category = "installed" if facts.extra.get("action") == "install" else "removed"
        product = " ".join(part for part in (facts.product_name, facts.product_version) if part)
        return category, facts.product_name, product
    state = facts.extra.get("state", "installed").lower()
    if facts.kind != "update" or (event_key(event) == ("servicing", 2) and state not in SERVICING_CHANGE_STATES):
        return None
    return "update", facts.update_title, facts.update_title + (" (removed)" if state == "absent" else "")


def _clock_change(event: EventRecord, facts: EventFacts) -> Change | None:
    if facts.kind != "time-change" or not is_time_jump(facts):
        return None
    delta = time_change_seconds(facts) or 0.0
    sign = "+" if delta >= 0 else "−"
    who = facts.user or facts.app_path or "unknown"
    text = f"{sign}{format_duration(timedelta(seconds=delta))} at {format_time(event.time_created)} by {who}"
    # 4616 and Kernel-General 1 report the same change: same size, same minute → one item
    return "clock", f"{round(delta)}@{event.time_created:%Y%m%d%H%M}", text


def _user_restart(event: EventRecord, facts: EventFacts) -> Change | None:
    if event_key(event) != PLANNED_SHUTDOWN_KEY or not _is_user(facts.user):
        return None
    kind = facts.extra.get("shutdown_type") or "restart"
    return "user-restart", facts.user, f"{facts.user}: {kind} via {facts.shutdown_initiator or 'unknown process'}"


_CHANGE_DETECTORS = (_service_change, _software_change, _clock_change, _user_restart)


def _change(event: EventRecord, facts: EventFacts) -> Change | None:
    """(category, item key, item text) for an event that records a change, else None."""
    return next((change for detect in _CHANGE_DETECTORS if (change := detect(event, facts)) is not None), None)


def _is_change(event: EventRecord) -> bool:
    return _change(event, extract(event)) is not None


def _analyze_changes(events: list[EventRecord]) -> list[DiagnosisFinding]:
    by_category: dict[str, list[EventRecord]] = defaultdict(list)
    items: dict[str, dict[str, tuple[str, int]]] = defaultdict(dict)
    for event in events:
        change = _change(event, extract(event))
        if change is None:
            continue
        category, item_key, text = change
        by_category[category].append(event)
        _, seen = items[category].get(item_key.lower(), ("", 0))
        items[category][item_key.lower()] = (text, seen + 1)  # latest text, running count
    findings: list[DiagnosisFinding] = []
    for category, grouped in by_category.items():
        title, severity = CHANGE_CATEGORIES[category]
        listed = [text if count == 1 else f"{text} ({count}×)" for text, count in items[category].values()]
        summary = f"{title} {_span(grouped)}: {_listing(listed)}."
        steps = ["Compare these times with when the problem started — a change just before it is the first suspect."]
        if category == "clock":
            steps.insert(0, "Event order around a clock change can mislead; check what changed the time and why.")
        findings.append(_finding("changes", f"{title} ({len(listed)})", severity, summary, grouped, steps=steps))
    return findings


# ---- registry --------------------------------------------------------------------------------------------------------
def _storage_filter(event: EventRecord) -> bool:
    return _storage_kind(event) is not None


RECIPES: dict[str, Recipe] = {
    recipe.id: recipe
    for recipe in (
        Recipe(
            "crashes",
            "Application crashes and hangs",
            "Groups Application Error 1000, Application Hang 1002, .NET Runtime 1026 and WER 1001 per application "
            "and counts repeated crashes.",
            ("Application",),
            _is_crash_event,
            _analyze_crashes,
        ),
        Recipe(
            "restarts",
            "Unexpected restarts",
            "Kernel-Power 41 / EventLog 6008 (unclean) versus User32 1074 (planned), with boot and shutdown markers.",
            ("System",),
            _accept_keys(UNCLEAN_KEYS | BOOT_KEYS | STOP_KEYS | {PLANNED_SHUTDOWN_KEY}),
            _analyze_restarts,
        ),
        Recipe(
            "services",
            "Service failures",
            "Services that crash repeatedly (7031/7034), fail to start (7000/7001/7009/7011/7022) or stop with errors.",
            ("System",),
            _accept_keys(
                (SCM, event_id) for event_id in SERVICE_CRASH_IDS | SERVICE_START_IDS | SERVICE_ERROR_EXIT_IDS
            ),
            _analyze_services,
        ),
        Recipe(
            "installers",
            "Failed installations and updates",
            "Windows Installer failures (11708/11725/11729, 1033/1034/1035 with an error status) and failed updates.",
            ("Application", "System", "Setup"),
            _accept_keys(INSTALL_FAILURE_KEYS, _failed),
            _analyze_installers,
        ),
        Recipe(
            "account-lockout",
            "Account lockouts",
            "Each locked-out account (4740) with the failed logons (4625) that led to it.",
            ("Security",),
            _accept_keys({LOCKOUT_KEY, LOGON_FAILURE_KEY}),
            _analyze_lockouts,
        ),
        Recipe(
            "brute-force",
            "Password guessing",
            f"At least {BRUTE_FORCE_ATTEMPTS} failed logons from one address within "
            f"{format_duration(BRUTE_FORCE_WINDOW)}, and any successful logon from it afterwards.",
            ("Security",),
            _accept_keys({LOGON_FAILURE_KEY, LOGON_SUCCESS_KEY}),
            _analyze_brute_force,
        ),
        Recipe(
            "app-pools",
            "IIS application pool failures",
            "WAS events for crashing, hanging or disabled application pools (5002/5009/5010/5011/5013).",
            ("System",),
            _accept_keys(("was", event_id) for event_id in APP_POOL_EVENTS),
            _analyze_app_pools,
        ),
        Recipe(
            "storage",
            "Disk and file system problems",
            "Bad blocks, controller and paging errors, I/O retries (disk), corruption (Ntfs) and shadow copy problems.",
            ("System",),
            _storage_filter,
            _analyze_storage,
        ),
        Recipe(
            "changes",
            "What changed",
            "Services installed or reconfigured, software and updates installed or removed, clock changes and "
            "restarts by users.",
            CHANNEL_ORDER,
            _accept_keys(CHANGE_KEYS, _is_change),
            _analyze_changes,
        ),
    )
}


def run_all(events: Iterable[EventRecord], *, recipes: Iterable[Recipe] | None = None) -> list[DiagnosisFinding]:
    """Run ``recipes`` (default: all) over ``events``; findings sorted by severity, then time (oldest first)."""
    pool = list(events)
    chosen = RECIPES.values() if recipes is None else recipes
    findings = [finding for recipe in chosen for finding in recipe.run(pool)]
    findings.sort(key=lambda finding: (SEVERITY_RANK[finding.severity], finding.time))
    return findings


def channels_needed(recipes: Iterable[Recipe] | None = None) -> tuple[str, ...]:
    """Channels to read for ``recipes`` (default: all), well-known channels first."""
    wanted = {channel for recipe in (RECIPES.values() if recipes is None else recipes) for channel in recipe.channels}
    return tuple(c for c in CHANNEL_ORDER if c in wanted) + tuple(sorted(wanted - set(CHANNEL_ORDER)))
