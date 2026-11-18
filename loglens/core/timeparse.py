"""Turn the timestamp at the start of a log line into an aware datetime (for correlation across logs).

Timestamps without an offset are taken as *local* time (how most application logs are written); ``Z`` / ``+hh:mm``
are honoured. Formats without a year (syslog, Android) get the latest year that does not put them in the future.

Numeric dates such as ``05/11/2026`` are ambiguous: dot-separated dates are read day first (European style), others
month first unless the first number can't be a month. A file's order is better decided once from a sample
(:func:`infer_day_first`) and passed as ``day_first`` (``LineClock.day_first``), so ``12/11`` and ``13/11`` of the
same log agree.

Only moments in :data:`EARLIEST` … :data:`LATEST` are returned: Windows can't convert other instants to local time
(``astimezone()`` raises ``OSError``), and dates like 0001-01-01, 1601-01-01 or 1900-01-01 in a log are "no time"
placeholders, not real moments.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone, tzinfo
from itertools import islice

from .timestamps import TimestampMatch, find_timestamp

_MONTH_NAMES = ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec")
_MONTHS = {name: number for number, name in enumerate(_MONTH_NAMES, start=1)}
_OFFSET = re.compile(r"(Z|[+-]\d{2}:?\d{2})$")

# Instants LogLens works with. Windows' C runtime converts to local time only from 1970-01-01 to 3000-12-31 (UTC);
# a day of margin on each side keeps every derived local time (histogram midnights, zone changes) inside that.
EARLIEST = datetime(1970, 1, 2, tzinfo=UTC)
LATEST = datetime(3000, 12, 30, tzinfo=UTC)
_ZONE_MARGIN = timedelta(days=1)  # > any UTC offset: a naive time this far inside the range is inside in any zone
_NAIVE_EARLIEST = EARLIEST.replace(tzinfo=None) + _ZONE_MARGIN
_NAIVE_LATEST = LATEST.replace(tzinfo=None) - _ZONE_MARGIN
# A year-less date up to this far ahead of now is clock skew between machines / zones, not last year's.
FUTURE_TOLERANCE = timedelta(days=1)
MAX_YEAR_ROLLBACK = 9  # years tried back from next year: Feb 29 recurs within 8 years (2096 → 2104, 2100 isn't leap)
DAY_FIRST_SAMPLE = 5_000  # lines examined by infer_day_first (bounded work on any file)

_ISO = re.compile(r"(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d):(\d\d)(?:[.,](\d+))?\s?(Z|[+-]\d\d:?\d\d)?")
_SLASHED = re.compile(r"(\d{4})/(\d\d)/(\d\d)[ :](\d\d):(\d\d):(\d\d)(?:[.,](\d+))?")
_DMY = re.compile(r"(\d{1,2})([/.-])(\d{1,2})[/.-](\d{4}),? (\d{1,2}):(\d\d):(\d\d)(?:[.,](\d+))?\s?([AP]M)?")
_CLF = re.compile(r"(\d\d)/([A-Za-z]{3})/(\d{4}):(\d\d):(\d\d):(\d\d)(?: ([+-]\d{4}))?")
_CTIME = re.compile(r"[A-Za-z]{3} ([A-Za-z]{3}) +(\d{1,2}) (\d\d):(\d\d):(\d\d)(?:\.(\d+))? (\d{4})")
_SYSLOG = re.compile(r"([A-Za-z]{3}) +(\d{1,2}) (\d\d):(\d\d):(\d\d)")
_COMPACT = re.compile(r"(\d\d)(\d\d)(\d\d) (\d\d)(\d\d)(\d\d)")
_YMD_COMPACT = re.compile(r"(\d{4})(\d\d)(\d\d)-(\d\d):(\d\d):(\d\d)(?:[:.](\d+))?")
_MD_TIME = re.compile(r"(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)\.(\d+)")


@dataclass(frozen=True, slots=True)
class _Options:
    day_first: bool | None
    now: datetime | None  # naive local "now" for year-less formats; None = the real clock


def _fraction(text: str | None) -> int:
    return int((text or "0")[:6].ljust(6, "0"))


def _matched(regex: re.Pattern[str], text: str) -> re.Match[str]:
    m = regex.match(text)
    if m is None:
        raise ValueError(text)
    return m


def in_range(moment: datetime) -> bool:
    """Whether an aware ``moment`` is one LogLens can show and convert to local time (see :data:`EARLIEST`)."""
    return EARLIEST <= moment <= LATEST


def to_local(moment: datetime) -> datetime:
    """An aware ``moment`` in this computer's zone for display; outside what Windows can convert (before 1970,
    after 3000 — e.g. a placeholder date typed by the user or found in a report) it stays in its own zone."""
    try:
        return moment.astimezone()
    except (OSError, OverflowError, ValueError):
        return moment


def _local(moment: datetime) -> datetime:
    """Naive wall time → aware local time; ``ValueError`` outside the supported range."""
    if not _NAIVE_EARLIEST <= moment <= _NAIVE_LATEST:
        raise ValueError(f"{moment} is outside the supported time range")
    try:
        return moment.astimezone()
    except (OSError, OverflowError):  # the C runtime can't resolve it after all: use the zone's current offset
        return moment.replace(tzinfo=datetime.now().astimezone().tzinfo)


def _with_zone(moment: datetime, zone: str | None) -> datetime:
    if not zone:
        return _local(moment)
    if zone == "Z":
        return moment.replace(tzinfo=UTC)
    sign = 1 if zone[0] == "+" else -1
    digits = zone[1:].replace(":", "")
    offset = timedelta(hours=int(digits[:2]), minutes=int(digits[2:]))
    return moment.replace(tzinfo=timezone(sign * offset))


def _recent(month: int, day: int, clock: tuple[int, int, int, int], now: datetime | None) -> datetime:
    """Naive moment of a year-less date: the latest year that is at most :data:`FUTURE_TOLERANCE` ahead of now
    (a log read in January keeps its December lines in last year; Feb 29 goes back to the last leap year)."""
    current = now if now is not None else datetime.now()
    limit = current + FUTURE_TOLERANCE
    for year in range(current.year + 1, current.year - MAX_YEAR_ROLLBACK, -1):
        try:
            moment = datetime(year, month, day, *clock)
        except ValueError:  # Feb 29 of a common year
            continue
        if moment <= limit:
            return moment
    raise ValueError(f"no recent year has {month:02d}-{day:02d}")


def _iso(text: str, _options: _Options) -> datetime:
    m = _matched(_ISO, text)
    y, mo, d, h, mi, s = (int(g) for g in m.groups()[:6])
    return _with_zone(datetime(y, mo, d, h, mi, s, _fraction(m.group(7))), m.group(8))


def _slashed(text: str, _options: _Options) -> datetime:
    m = _matched(_SLASHED, text)
    y, mo, d, h, mi, s = (int(g) for g in m.groups()[:6])
    return _with_zone(datetime(y, mo, d, h, mi, s, _fraction(m.group(7))), None)


def _dmy_or_mdy(text: str, options: _Options) -> datetime:
    m = _matched(_DMY, text)
    a, separator, b = int(m[1]), m[2], int(m[3])
    y, h, mi, s = int(m[4]), int(m[5]), int(m[6]), int(m[7])
    day_first = options.day_first
    if day_first is None:  # no file-level decision: dots are European (day first); else US unless impossible
        day_first = separator == "." or a > 12
    month, day = (b, a) if day_first else (a, b)
    if month > 12:  # this line contradicts the file's order: the other order is the only possible reading
        month, day = day, month
    if m[9]:
        h = h % 12 + (12 if m[9] == "PM" else 0)
    return _with_zone(datetime(y, month, day, h, mi, s, _fraction(m[8])), None)


def _clf(text: str, _options: _Options) -> datetime:
    m = _matched(_CLF, text)
    moment = datetime(int(m[3]), _MONTHS[m[2].lower()], int(m[1]), int(m[4]), int(m[5]), int(m[6]))
    return _with_zone(moment, m[7])


def _ctime(text: str, _options: _Options) -> datetime:
    m = _matched(_CTIME, text)
    moment = datetime(int(m[7]), _MONTHS[m[1].lower()], int(m[2]), int(m[3]), int(m[4]), int(m[5]), _fraction(m[6]))
    return _with_zone(moment, None)


def _syslog(text: str, options: _Options) -> datetime:
    m = _matched(_SYSLOG, text)
    moment = _recent(_MONTHS[m[1].lower()], int(m[2]), (int(m[3]), int(m[4]), int(m[5]), 0), options.now)
    return _with_zone(moment, None)


def _compact(text: str, _options: _Options) -> datetime:  # yymmdd HHMMSS
    m = _matched(_COMPACT, text)
    y, mo, d, h, mi, s = (int(g) for g in m.groups())
    return _with_zone(datetime(2000 + y, mo, d, h, mi, s), None)


def _ymd_compact(text: str, _options: _Options) -> datetime:  # yyyymmdd-HH:MM:SS[:mmm]
    m = _matched(_YMD_COMPACT, text)
    y, mo, d, h, mi, s = (int(g) for g in m.groups()[:6])
    return _with_zone(datetime(y, mo, d, h, mi, s, _fraction(m.group(7))), None)


def _md_time(text: str, options: _Options) -> datetime:  # MM-DD HH:MM:SS.mmm (no year)
    m = _matched(_MD_TIME, text)
    mo, d, h, mi, s = (int(g) for g in m.groups()[:5])
    return _with_zone(_recent(mo, d, (h, mi, s, _fraction(m.group(6))), options.now), None)


def _epoch(text: str, _options: _Options) -> datetime:
    value = float(text)
    return datetime.fromtimestamp(value / 1000 if value > 1e11 else value, UTC)


_PARSERS: dict[str, Callable[[str, _Options], datetime]] = {
    "iso8601": _iso,
    "slashed-ymd": _slashed,
    "dmy-or-mdy": _dmy_or_mdy,
    "clf": _clf,
    "ctime": _ctime,
    "syslog": _syslog,
    "compact": _compact,
    "ymd-compact-time": _ymd_compact,
    "md-time": _md_time,
    "epoch": _epoch,
}


def parse_match(
    match: TimestampMatch, *, day_first: bool | None = None, now: datetime | None = None
) -> datetime | None:
    """Aware datetime of a found timestamp, or None if it can't be parsed or is outside :data:`EARLIEST` …
    :data:`LATEST`. ``day_first`` fixes the order of numeric day/month dates (None: decided per line); ``now``
    (naive local time, default the real clock) dates year-less formats."""
    parser = _PARSERS.get(match.pattern.name)
    if parser is None:
        return None
    try:
        moment = parser(match.text, _Options(day_first, now))
    except (ValueError, KeyError, OverflowError, OSError):  # OSError: the C runtime rejects the date (Windows)
        return None
    return moment if in_range(moment) else None


def parse_line_time(line: str) -> datetime | None:
    """Aware datetime of the timestamp at the start of ``line``, or None if there is none / it can't be parsed."""
    match = find_timestamp(line)
    return parse_match(match) if match is not None else None


def infer_day_first(lines: Iterable[str]) -> bool | None:
    """Day/month order of a file's numeric dates, decided once from (up to :data:`DAY_FIRST_SAMPLE`) sample lines.

    True: day first (``13/11/2026``); False: month first (``11/13/2026``); None: no evidence either way (every
    date could be read both ways) or a tie — then each line is read on its own (see :func:`parse_match`).
    """
    votes = {True: 0, False: 0}
    for line in islice(lines, DAY_FIRST_SAMPLE):
        match = find_timestamp(line)
        if match is None or match.pattern.name != "dmy-or-mdy":
            continue
        m = _DMY.match(match.text)
        if m is None:
            continue
        first, second = int(m[1]), int(m[3])
        if first > 12 >= second:
            votes[True] += 1
        elif second > 12 >= first:
            votes[False] += 1
    if votes[True] == votes[False]:
        return None
    return votes[True] > votes[False]


@dataclass(frozen=True, slots=True)
class LineClock:
    """How one log's timestamps map to real time.

    ``zone`` re-interprets timestamps that carry no offset (None = this computer's local time, the default for
    application logs); explicit offsets and epoch values are never re-interpreted. ``shift`` corrects a writer whose
    clock was off. ``day_first`` is the file's day/month order for numeric dates (see :func:`infer_day_first`; None
    decides per line).
    """

    zone: tzinfo | None = None
    shift: timedelta = timedelta(0)
    day_first: bool | None = None

    @property
    def is_default(self) -> bool:
        """No user correction (zone / shift); ``day_first`` describes the file, not a correction."""
        return self.zone is None and not self.shift

    def __call__(self, line: str) -> datetime | None:
        match = find_timestamp(line)
        if match is None:
            return None
        moment = parse_match(match, day_first=self.day_first)
        if moment is None:
            return None
        if self.is_default:
            return moment
        try:
            if self.zone is not None and not _has_explicit_zone(match):
                moment = moment.replace(tzinfo=self.zone)  # same wall time, other zone
            moment = moment + self.shift
        except OverflowError:
            return None
        return moment if in_range(moment) else None

    def describe(self) -> str:
        parts = []
        if self.zone is not None:
            parts.append(f"times without offset are {self.zone.tzname(None) or self.zone}")
        if self.shift:
            seconds = int(self.shift.total_seconds())
            sign = "+" if seconds >= 0 else "-"
            parts.append(f"shifted {sign}{abs(seconds) // 3600:02d}:{abs(seconds) % 3600 // 60:02d}")
        return ", ".join(parts) or "local time"


def _has_explicit_zone(match: TimestampMatch) -> bool:
    return match.pattern.name == "epoch" or _OFFSET.search(match.text.rstrip()) is not None or "UTC" in match.text
