"""Coverage warnings: reasons the events being analysed may not tell the whole story.

Logs get cleared, wrap when they are full, cannot be read without administrator rights, or have holes when the clock
jumps or the event log service is stopped. These checks turn such conditions into short sentences shown next to the
diagnosis, so that "no problems found" is not mistaken for "nothing happened".
"""

from __future__ import annotations

from bisect import bisect_left, bisect_right
from collections.abc import Collection, Mapping, Sequence
from datetime import datetime, timedelta
from itertools import pairwise

from ..winevent.entities import event_key, extract, time_change_seconds
from ..winevent.models import EventRecord
from .recipes import (
    BOOT_KEYS,
    LOG_CLEARED_KEYS,
    STOP_KEYS,
    TIME_CHANGE_KEYS,
    format_duration,
    format_time,
    is_time_jump,
)

LOG_START_SLACK = timedelta(hours=1)  # oldest event this close to the requested start = the log covers the period
LARGE_GAP = timedelta(hours=6)  # Windows logs something every few hours while running; longer silence is suspicious
BOUNDARY_SLACK = timedelta(minutes=5)  # events can be logged a little after a boot marker / before a stop marker
CLOCK_DEDUP_WINDOW = timedelta(minutes=1)  # 4616 and Kernel-General 1 describe the same clock change
# Windows' own channels that receive events every few hours while it runs: only for these does "the oldest event is
# much later than the requested start" mean the log wrapped (a quiet channel like Setup simply had nothing to log)
BUSY_CHANNELS = ("Application", "System", "Security")
SYSTEM_CHANNEL = "System"  # holds the boot / shutdown / sleep markers that gap detection needs

# a silence that starts at one of these (shutdown, sleep) or ends at one of these (boot, wake) is expected
DOWN_KEYS = STOP_KEYS | {("kernel-power", 42), ("kernel-power", 109), ("kernel-power", 506)}
UP_KEYS = BOOT_KEYS | {("kernel-power", 107), ("kernel-power", 507), ("power-troubleshooter", 1)}
EVENTLOG_STOPPED = ("eventlog", 6006)


def coverage_warnings(
    events_by_channel: Mapping[str, Sequence[EventRecord]],
    requested_start: datetime,
    requested_end: datetime,
    access_errors: Mapping[str, str],
    *,
    truncated_channels: Collection[str] = (),
) -> list[str]:
    """Plain-language warnings about missing or unreliable coverage of [requested_start, requested_end].

    ``access_errors`` maps channels that could not be read to the reason; ``truncated_channels`` are channels where the
    reader stopped at its event limit (so their oldest event says nothing about the log itself).
    """
    timeline = sorted((e for events in events_by_channel.values() for e in events), key=lambda e: e.time_created)
    warnings = [f"The {channel} log could not be read: {reason}" for channel, reason in access_errors.items()]
    warnings += _cleared(timeline)
    warnings += _start_coverage(events_by_channel, timeline, requested_start, access_errors, truncated_channels)
    warnings += _empty_channels(events_by_channel, access_errors)
    warnings += _clock_changes(timeline)
    if any(event.channel == SYSTEM_CHANNEL for event in timeline):
        warnings += _gaps(timeline)
    warnings += _eventlog_stopped(timeline, requested_end)
    return warnings


def _cleared(timeline: Sequence[EventRecord]) -> list[str]:
    warnings: list[str] = []
    for event in timeline:
        if event_key(event) in LOG_CLEARED_KEYS:
            facts = extract(event)
            channel = facts.extra.get("channel") or event.channel
            who = f" by {facts.user}" if facts.user else ""
            warnings.append(
                f"The {channel} log was cleared at {format_time(event.time_created)}{who} — earlier events are gone."
            )
    return warnings


def _start_coverage(
    events_by_channel: Mapping[str, Sequence[EventRecord]],
    timeline: Sequence[EventRecord],
    requested_start: datetime,
    access_errors: Mapping[str, str],
    truncated: Collection[str],
) -> list[str]:
    """Channels whose oldest event is well after the requested start: log wrapped (too small) or read limit hit."""
    boots = [event.time_created for event in timeline if event_key(event) in BOOT_KEYS]
    warnings: list[str] = []
    for channel, events in events_by_channel.items():
        if channel in access_errors or not events:
            continue
        oldest = min(event.time_created for event in events)
        if channel in truncated:
            warnings.append(
                f"Only the newest {len(events)} {channel} events were read (back to {format_time(oldest)}) — "
                "older events in the period were not analysed."
            )
        elif (
            channel in BUSY_CHANNELS
            and oldest - requested_start > LOG_START_SLACK
            and not _near(oldest, boots, LOG_START_SLACK)  # the system was simply off until it booted
        ):
            warnings.append(
                f"The {channel} log only goes back to {format_time(oldest)} (requested from "
                f"{format_time(requested_start)}): older events were overwritten because the log is full — increase "
                "its maximum size — or the log was cleared."
            )
    return warnings


def _empty_channels(
    events_by_channel: Mapping[str, Sequence[EventRecord]], access_errors: Mapping[str, str]
) -> list[str]:
    return [
        f"No {channel} events at all in the requested period — the log may have been cleared or the system was off."
        for channel, events in events_by_channel.items()
        if not events and channel not in access_errors and channel in BUSY_CHANNELS
    ]


def _near(moment: datetime, sorted_times: Sequence[datetime], slack: timedelta) -> bool:
    index = bisect_left(sorted_times, moment - slack)
    return index < len(sorted_times) and sorted_times[index] <= moment + slack


def _clock_changes(timeline: Sequence[EventRecord]) -> list[str]:
    warnings: list[str] = []
    last: tuple[datetime, int] | None = None
    for event in timeline:
        if event_key(event) not in TIME_CHANGE_KEYS:
            continue
        facts = extract(event)
        if not is_time_jump(facts):
            continue
        delta = time_change_seconds(facts) or 0.0
        if last is not None and event.time_created - last[0] <= CLOCK_DEDUP_WINDOW and last[1] == round(delta):
            continue
        last = (event.time_created, round(delta))
        direction = "forward" if delta > 0 else "back"
        who = facts.user or facts.app_path
        warnings.append(
            f"The system clock was set {direction} by {format_duration(timedelta(seconds=delta))} at "
            f"{format_time(event.time_created)}" + (f" by {who}" if who else "") + " — events around it may appear "
            "out of order."
        )
    return warnings


def _gaps(timeline: Sequence[EventRecord]) -> list[str]:
    """Long silences across all channels that no shutdown, sleep, boot or wake explains."""
    downs = [event.time_created for event in timeline if event_key(event) in DOWN_KEYS]
    ups = [event.time_created for event in timeline if event_key(event) in UP_KEYS]
    warnings: list[str] = []
    for before, after in pairwise(timeline):
        gap = after.time_created - before.time_created
        if gap < LARGE_GAP:
            continue
        went_down = bisect_right(downs, before.time_created) > bisect_left(downs, before.time_created - BOUNDARY_SLACK)
        came_up = bisect_right(ups, after.time_created + BOUNDARY_SLACK) > bisect_left(ups, after.time_created)
        if went_down or came_up:
            continue
        warnings.append(
            f"No events at all between {format_time(before.time_created)} and {format_time(after.time_created)} "
            f"({format_duration(gap)}) although no shutdown or sleep was logged — the event log service may have "
            "been stopped, events removed, or the system frozen."
        )
    return warnings


def _eventlog_stopped(timeline: Sequence[EventRecord], requested_end: datetime) -> list[str]:
    """A 6006 (event log service stopped) with no start marker after it: nothing after that time is covered."""
    stops = [event for event in timeline if event_key(event) == EVENTLOG_STOPPED]
    if not stops:
        return []
    last_stop = stops[-1]
    if any(event_key(e) in BOOT_KEYS and e.time_created >= last_stop.time_created for e in timeline):
        return []
    return [
        f"The event log service stopped at {format_time(last_stop.time_created)} and no restart was logged before "
        f"{format_time(requested_end)} — the system was shut down or logging stopped; nothing later is covered."
    ]
