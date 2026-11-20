"""HTTP access-log analytics and request/response transactions for any log that mentions HTTP requests.

Lines are recognised by *shape*, never by product. Parsers are tried in order:

1. **W3C extended** — ``#Fields:`` directive lines followed by space-separated values. The field list may change
   mid-file (a new ``#Fields:`` line), so only the stateful :class:`HttpLogParser` understands these lines.
2. **Common / Combined Log Format** — ``host ident user [time] "METHOD target proto" status bytes "ref" "ua"``,
   optionally followed by a request time.
3. **JSON objects** with the usual field names (``method``, ``path``/``url``, ``status``/``statusCode``,
   ``duration``/``elapsed`` …). Keys are matched ignoring case and punctuation; nested objects are flattened.
4. **Application text** — an HTTP method followed by a path or URL anywhere in the line; status and duration are
   picked from the usual phrasings (``status=500``, ``StatusCode: 404``, ``responded 200``, ``took 120ms`` …).
5. **key=value** lines (logfmt and friends) with the same field names as JSON.

:func:`summarize` aggregates records (status classes, endpoints with latency percentiles, requests per minute,
slowest requests). :func:`pair_transactions` correlates request lines with the response lines answering them, by
request id / trace id / GUID, falling back to the thread id in brackets.

Everything is bounded by the caps below; the unit heuristics for durations are named constants as well.
"""

from __future__ import annotations

import heapq
import json
import math
import random
import re
import string
from array import array
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import lru_cache
from typing import Literal

import numpy as np

from .timeparse import parse_line_time

# ---- caps ------------------------------------------------------------------------------------------------------------
MAX_RECORDS = 1_000_000  # parse_lines() stops here: exact statistics for any realistic file, bounded memory
MAX_TRANSACTIONS = 100_000  # pair_transactions() opens no new transactions beyond this
MAX_OPEN_REQUESTS = 10_000  # unanswered requests waiting for a response; beyond it the oldest is given up (unpaired)
MAX_TRANSACTION_LINES = 200  # line numbers kept per transaction (request and response lines always included)
MAX_KEYS_PER_LINE = 4  # correlation keys taken from one line (request id, trace id, a couple of GUIDs)
FORM_SCAN_CHARS = 4_000  # how much of a line the key=value / marker / verb+id detectors look at
THREAD_HEADER_CHARS = 160  # a thread id in brackets sits in the line header, not deep in the message
MAX_DURATION_SAMPLES = 1_000_000  # latencies kept for percentiles (8 MB); beyond it a uniform reservoir sample
MAX_ENDPOINT_SAMPLES = 10_000  # per-endpoint reservoir: percentiles of 10k samples are within ~1 % of exact
MAX_TRACKED_ENDPOINTS = 5_000  # distinct endpoints counted; later newcomers (ids normalisation missed) go to OTHER
MAX_REPORTED_ENDPOINTS = 500  # endpoints returned by summarize(), busiest first
MAX_TRACKED_CLIENTS = 50_000  # distinct clients counted; later newcomers go to OTHER
MAX_MINUTE_BUCKETS = 262_144  # ~6 months of per-minute buckets; minutes beyond it are left out of the series
MAX_FILLED_MINUTES = 7 * 24 * 60  # a series spanning up to a week gets its empty minutes filled in (gap-free charts)
JSON_MAX_DEPTH = 4  # nested objects flattened this deep (request.headers.user-agent)
NORMALIZE_CACHE = 65_536  # distinct raw paths remembered by normalize_path()
TIME_CACHE = 4_096  # access logs repeat the same timestamp text for every request in that second

# ---- defaults & heuristics -------------------------------------------------------------------------------------------
TOP_N = 20  # default length of the top-status / top-client lists
SLOWEST_N = 50  # default number of slowest requests kept
ERROR_STATUS_MIN = 500  # default: an error is a server failure (5xx); 4xx are usually the client's doing
PERCENTILES = (50.0, 95.0, 99.0)
RESERVOIR_SEED = 20_261_113  # fixed seed: the same input always gives the same (sampled) percentiles
DEFAULT_DURATION_MS = 1.0  # a duration without a unit is taken as milliseconds (the most common convention)
TRAILING_DECIMAL_MS = 1000.0  # a bare decimal after a CLF line is a request time in seconds ("0.123")
TRAILING_INTEGER_MS = 0.001  # a bare integer after a CLF line is a request time in microseconds ("123456")
W3C_DECIMAL_MS = 1000.0  # W3C time-taken with a decimal point is seconds, as the W3C draft specifies ...
W3C_INTEGER_MS = 1.0  # ... while an integer time-taken is milliseconds (the common server convention)
ID_PLACEHOLDER = "{id}"
OTHER = "(other)"

HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT")
# Structured fields (JSON, W3C, CLF) may also carry WebDAV methods; free text only matches the core methods.
_STRUCTURED_METHODS = frozenset((*HTTP_METHODS, "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"))
# Registered status codes (RFC 9110 and friends): a bare 3-digit number only counts as a status if it is one of these.
_STANDARD_STATUSES = frozenset(
    {100, 101, 102, 103, 226, 428, 429, 431, 451, 510, 511}.union(
        range(200, 209), range(300, 309), range(400, 419), range(421, 427), range(500, 509)
    )
)


# ---- value objects ---------------------------------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class HttpRecord:
    """One HTTP request as seen in a log line; fields the line doesn't carry are empty / None."""

    line: int  # 0-based line number
    time: datetime | None
    method: str
    path: str  # without the query string
    query: str = ""
    status: int | None = None
    duration_ms: float | None = None
    client: str = ""
    bytes_sent: int | None = None
    user_agent: str = ""
    request_id: str = ""

    @property
    def status_class(self) -> str:
        """``"2xx"`` … ``"5xx"``, or ``""`` without a status."""
        return f"{self.status // 100}xx" if self.status is not None else ""

    @property
    def endpoint(self) -> str:
        """Method and normalised path, e.g. ``GET /users/{id}``."""
        return endpoint_key(self.method, self.path)


@dataclass(frozen=True, slots=True)
class EndpointStats:
    method: str
    path: str  # normalised (ids replaced by ID_PLACEHOLDER)
    count: int
    errors: int
    p50_ms: float | None
    p95_ms: float | None
    p99_ms: float | None
    max_ms: float | None
    top_statuses: tuple[tuple[int, int], ...]  # (status, count), most common first

    @property
    def endpoint(self) -> str:
        return f"{self.method} {self.path}".strip()

    @property
    def error_rate(self) -> float:
        return self.errors / self.count if self.count else 0.0


@dataclass(frozen=True, slots=True)
class HttpSummary:
    """Aggregate view of HTTP records (see :func:`summarize`)."""

    total: int  # requests counted
    incomplete: int  # request-start lines left out because other lines carry the outcome of the requests
    errors: int  # status >= error_status_min
    error_status_min: int
    status_classes: tuple[tuple[str, int], ...]  # ("1xx".."5xx", count) in order, then ("unknown", n) without status
    top_statuses: tuple[tuple[int, int], ...]
    p50_ms: float | None
    p95_ms: float | None
    p99_ms: float | None
    max_ms: float | None
    endpoints: tuple[EndpointStats, ...]  # busiest first
    top_clients: tuple[tuple[str, int], ...]
    per_minute: tuple[tuple[datetime, int, int], ...]  # (minute, requests, errors), chronological
    slowest: tuple[HttpRecord, ...]  # slowest first

    @property
    def error_rate(self) -> float:
        return self.errors / self.total if self.total else 0.0

    def class_count(self, name: str) -> int:
        """Requests in status class ``name`` (``"5xx"``)."""
        return next((count for label, count in self.status_classes if label == name), 0)


@dataclass(frozen=True, slots=True)
class Transaction:
    """A request line and the response line answering it (``response_line`` is None when none was found)."""

    key: str  # correlation key (request id, trace id, GUID), "" when paired by thread or self-contained
    request_line: int
    response_line: int | None
    method: str
    path: str
    status: int | None
    duration_ms: float | None
    all_lines: tuple[int, ...]  # request, related lines, response (capped at MAX_TRANSACTION_LINES)
    thread: str = ""  # thread id used for pairing lines without a key
    match: str = ""  # how the response was found: key | thread | target | inline | orphan ("" = unanswered)
    confidence: str = "high"  # high: shared id / self-contained; medium: same thread; low: same target only
    form: str = "http"  # http | operation (a [START]/[END] pair of a command or query, not an HTTP call)

    @property
    def paired(self) -> bool:
        """A request with its response (an orphan response has no request, so it is not "paired")."""
        return self.response_line is not None and self.match != "orphan"

    @property
    def orphan(self) -> bool:
        """A response whose request could not be identified (kept so it can still be inspected)."""
        return self.match == "orphan"

    @property
    def uncertain(self) -> bool:
        """The association rests on weak evidence (same thread / same target): shown, but flagged."""
        return self.paired and self.confidence != "high"


# ---- shared patterns -------------------------------------------------------------------------------------------------
# Speed: keyword patterns run on the lower-cased line (no IGNORECASE) and start with a literal alternation instead of
# \b, so the regex engine can jump between candidate first characters (3-5x faster); the word boundary in front of a
# match is checked by _words(). Lookbehinds sit after the first character for the same reason.
_TEXT_REQUEST = re.compile(
    r"(?P<method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE)\s+\"?"
    r"(?P<target>(?:https?|wss?)://[^\s\"'<>]+|/[^\s\"'<>]*)"
)
_URL_PREFIX = re.compile(r"^[A-Za-z][\w+.-]*://[^/?#]*")
_GUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
_ID_SEGMENT = re.compile(
    r"\d+"  # numeric ids
    rf"|\{{?{_GUID}\}}?"  # GUIDs / UUIDs, optionally braced
    r"|(?=.*\d)[0-9a-fA-F]{8,}"  # hex ids, hashes, object ids (a digit is required, so plain words stay)
    r"|(?=.*\d)(?=.*[A-Za-z])[\w-]{20,}"  # long opaque tokens (base64url, ULIDs, slugs with numbers)
)
# A number followed by one of these is a duration/size/count, never a status.
_NOT_UNIT = r"(?!\s?(?:ms|msecs?|s|secs?|seconds?|us|µs|μs|ns|mins?|minutes?|b|bytes?|kb|mb|items?|records?|rows?)\b)"
_STATUS_AFTER_TARGET = re.compile(
    r"\"?\s+(?:http/\d(?:\.\d)?\"?\s+)?(?:[-=>|:]+\s*)?(?P<status>[1-5]\d\d)(?!\w)(?!\.\d)" + _NOT_UNIT
)
_STATUS_FIELD = re.compile(
    r"(?:status(?:[ _-]?code)?|http[ _-]?status(?:[ _-]?code)?|response(?:[ _-]?(?:code|status))?)\b"
    r"[\"']?\s*(?:[:=]|is|of)?\s*[\"']?(?P<status>[1-5]\d\d)(?!\w)(?!\.\d)"
)
_STATUS_VERB = re.compile(
    r"(?:responded|returned|returning|replied)(?:\s+with)?\s*[:=]?\s*(?P<status>[1-5]\d\d)(?!\w)(?!\.\d)" + _NOT_UNIT
)
_STATUS_REASON = re.compile(
    r"(?P<status>[1-5](?<![\w.,:/-][1-5])\d\d)\s+(?:ok|created|accepted|no content|partial content|"
    r"moved permanently|found|see other|not modified|temporary redirect|permanent redirect|bad request|unauthorized|"
    r"forbidden|not found|method not allowed|not acceptable|request timeout|conflict|gone|payload too large|"
    r"unsupported media type|unprocessable entity|too many requests|internal server error|not implemented|"
    r"bad gateway|service unavailable|gateway timeout)\b"
)
_STATUS_PAREN = re.compile(r"\((?P<status>[1-5]\d\d)\)\s+[a-z]")  # .NET WebException: "(502) Bad Gateway"
_STATUS_BARE = re.compile(r"(?P<status>[1-5](?<![\w.,:/\[\]#-][1-5])\d\d)(?![\w:/\]-])(?!\.\d)" + _NOT_UNIT)
_DURATION_UNIT = (
    r"ms|msecs?|millis(?:econds?)?|us|µs|μs|usecs?|micros(?:econds?)?|ns|nanos(?:econds?)?|s|secs?|seconds?|mins?|"
    r"minutes?"
)
_KEY_UNIT = r"ms|millis(?:econds)?|us|micros(?:econds)?|ns|nanos(?:econds)?|s|secs?|seconds"
_DURATION = re.compile(
    r"(?P<key>took|in|after|elapsed(?:[ _-]?time)?|duration|latency|time[ _-]?taken|response[ _-]?time|"
    r"request[ _-]?time|processing[ _-]?time|execution[ _-]?time)"
    rf"(?:[ _-]?(?P<key_unit>{_KEY_UNIT}))?"
    r"[\"']?\s*[:=]?\s*[\"']?"
    r"(?P<value>\d+:\d\d:\d\d(?:\.\d+)?|\d+(?:\.\d+)?)"
    rf"(?:\s?(?P<unit>{_DURATION_UNIT}))?(?![\w.])"
)
_DURATION_VALUE = re.compile(
    rf"\s*(?P<value>\d+:\d\d:\d\d(?:\.\d+)?|\d+(?:\.\d+)?)\s*(?P<unit>{_DURATION_UNIT})?\s*", re.IGNORECASE
)
_BARE_MS = re.compile(r"(?P<value>\d(?<![\w.]\d)\d*(?:\.\d+)?)\s?ms\b")
_CLIENT_TEXT = re.compile(
    r"(?:client(?:[ _-]?ip)?|remote(?:[ _-]?(?:addr|address|ip))?|from|ip)\b\s*[=:]?\s*"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})(?![\d.])"
)
_RESPONSE_WORDS = re.compile(
    r"(?:response|responded|reply|replied|completed?|finished|ended|end|done|returned|failed|timed out)\b"
)
_REQUEST_WORDS = re.compile(
    r"\b(?:incoming|sending|start(?:ed|ing)?|begin(?:ning)?|receiv(?:ed|ing))\W+(?:\w+\W+){0,3}?request\b"
    r"|\brequest\W+(?:start(?:ed|ing)?|begin|received|incoming)\b"
)
# Forms that are not "METHOD /path" text (the logger names and words are irrelevant: only the shape counts):
#   key=value:  "Request, Method=GET, Url=https://h/p"      "Response, Status=404 (NotFound), Method=GET, Url=…"
#   markers:    "[START] GetUser [43b4badd] {json}"          "[END] GetUser [43b4badd]; Execution time=7ms"
#   verb + id:  "Requesting [00000001] https://h/p"          "Received JSON: [00000001]"   "Request failed … (500) …"
_KV_METHOD = re.compile(r"\bmethod\s*[=:]\s*[\"']?(?P<method>get|post|put|delete|patch|head|options|trace)\b")
_KV_TARGET = re.compile(
    r"\b(?:url|uri|path|endpoint|request[ _-]?uri|request[ _-]?url)\s*[=:]\s*[\"']?"
    r"(?P<target>(?:https?|wss?)://[^\s\"'<>,]+|/[^\s\"'<>,]*)"
)
_KV_STATUS = re.compile(r"\b(?:status(?:[ _-]?code)?|code)\s*[=:]\s*[\"']?(?P<status>[1-5]\d\d)(?!\w)")
_BEGIN_MARK = re.compile(
    r"\[(?:start|begin|started|enter|entering)\]\s+(?P<name>[^\s\[\]]+)\s+\[(?P<id>[\w.:-]{2,64})\]"
)
_END_MARK = re.compile(
    r"\[(?:end|finish|finished|exit|complete|completed|done|stop|stopped)\]\s+(?P<name>[^\s\[\]]+)\s+\[(?P<id>[\w.:-]{2,64})\]"
)
_CALL_OUT = re.compile(
    r"\b(?:requesting|calling|fetching|querying|invoking|posting|getting|sending)\s+(?:\[(?P<id>[\w.:-]{2,64})\]\s+)?"
    r"(?P<target>(?:https?|wss?)://[^\s\"'<>]+)"
)
_CALL_BACK = re.compile(r"\b(?:received|got|response|reply|result)\b[^\[\]]{0,40}\[(?P<id>[\w.:-]{2,64})\]")
_CALL_FAILED = re.compile(r"\b(?:request|call|http request|operation)\s+(?:failed|timed out)\b|\bfailed after\b")
_TRAILING_PUNCT = ".,;:!?'\""
_CLOSERS = {")": "(", "]": "[", "}": "{"}
_ASCII_LOWER = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)


# ---- small helpers ---------------------------------------------------------------------------------------------------
def _lower(text: str) -> str:
    """Lower-cased ``text`` with the same length (so match positions map back to ``text``)."""
    low = text.lower()
    return low if len(low) == len(text) else text.translate(_ASCII_LOWER)


def _words(pattern: re.Pattern[str], text: str) -> Iterator[re.Match[str]]:
    """Non-overlapping matches of ``pattern`` that start at a word boundary (see the speed note above)."""
    pos = 0
    while (m := pattern.search(text, pos)) is not None:
        start = m.start()
        before = text[start - 1] if start else " "
        if before.isalnum() or before == "_":
            pos = start + 1
            continue
        yield m
        pos = max(m.end(), start + 1)


def _find_request(text: str) -> re.Match[str] | None:
    """``METHOD /path`` or ``METHOD http://host/path`` in ``text``."""
    return next(_words(_TEXT_REQUEST, text), None)


@lru_cache(maxsize=TIME_CACHE)
def _cached_time(text: str) -> datetime | None:
    return parse_line_time(text)


def _split_target(target: str) -> tuple[str, str]:
    """Request target (path, ``/p?q``, or absolute URL) → (path, query)."""
    target = target.rstrip(_TRAILING_PUNCT)
    while target and target[-1] in _CLOSERS and target.count(_CLOSERS[target[-1]]) < target.count(target[-1]):
        target = target[:-1].rstrip(_TRAILING_PUNCT)  # "(GET /x)" — but keep balanced "/odata/Items(1)"
    target = _URL_PREFIX.sub("", target, count=1).partition("#")[0]
    path, _, query = target.partition("?")
    return path or "/", query


@lru_cache(maxsize=NORMALIZE_CACHE)
def normalize_path(path: str) -> str:
    """``/users/42/orders/3f2504e0-4f89-…`` → ``/users/{id}/orders/{id}``: ids in path segments become a placeholder.

    Ids are numbers, GUIDs, hex strings with a digit (8+ chars) and long opaque tokens with letters and digits.
    A trailing slash is dropped so ``/a/`` and ``/a`` are one endpoint.
    """
    if len(path) > 1:
        path = path.rstrip("/") or "/"
    return "/".join(ID_PLACEHOLDER if _ID_SEGMENT.fullmatch(part) else part for part in path.split("/"))


def endpoint_key(method: str, path: str) -> str:
    """``"GET /users/{id}"`` — the grouping key used by :func:`summarize`."""
    return f"{method} {normalize_path(path)}".strip()


def _unit_factor(unit: str) -> float:
    """Milliseconds per ``unit`` (one of the duration unit spellings above)."""
    unit = unit.lower()
    if unit.startswith(("ms", "milli")):
        return 1.0
    if unit in ("us", "µs", "μs") or unit.startswith(("usec", "micro")):
        return 0.001
    if unit == "ns" or unit.startswith("nano"):
        return 0.000_001
    if unit.startswith("min"):
        return 60_000.0
    return 1000.0  # s / sec / seconds


def _duration_ms(value: str, factor: float) -> float:
    """``"12.5"`` × factor, or a ``h:mm:ss.fff`` time span in milliseconds."""
    if ":" in value:
        hours, minutes, seconds = value.split(":")
        return (int(hours) * 3600 + int(minutes) * 60 + float(seconds)) * 1000.0
    return float(value) * factor


def _status_value(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    status = _int_value(value)
    return status if status is not None and 100 <= status <= 599 else None


def _int_value(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, float) and not math.isfinite(value):  # NaN / Infinity are valid in Python's json
        return None
    if isinstance(value, int | float):
        return int(value)
    if isinstance(value, str) and value.strip().isdigit():
        return int(value)
    return None


def _find_status(low: str, *, after: int | None, loose: bool) -> int | None:  # noqa: PLR0911 - one rule per spelling
    """Status code in lower-cased ``low``: right after the request target, by keyword, by reason phrase, or bare
    (only when ``loose``, i.e. the line reads like a response, and only registered codes)."""
    if after is not None:
        m = _STATUS_AFTER_TARGET.match(low, after)
        if m is not None and int(m["status"]) in _STANDARD_STATUSES:
            return int(m["status"])
    m = next(_words(_STATUS_FIELD, low), None)
    if m is not None:
        return int(m["status"])
    m = next(_words(_STATUS_VERB, low), None)
    if m is not None and int(m["status"]) in _STANDARD_STATUSES:
        return int(m["status"])
    m = _STATUS_REASON.search(low)
    if m is not None:
        return int(m["status"])
    m = _STATUS_PAREN.search(low)
    if m is not None and int(m["status"]) in _STANDARD_STATUSES:
        return int(m["status"])
    if loose:
        for bare in _STATUS_BARE.finditer(low):
            if int(bare["status"]) in _STANDARD_STATUSES:
                return int(bare["status"])
    return None


def _find_duration(low: str) -> float | None:
    """Duration in ms in lower-cased ``low``: ``took 120ms``, ``in 12.3 ms``, ``elapsed=1.2s``, ``duration_ms=7``,
    ``elapsed: 00:00:01.5``, else a bare ``54.3ms``."""
    for m in _words(_DURATION, low):
        explicit = m["unit"]
        if m["key"] in ("in", "after") and not explicit:
            continue  # "in 2026", "after 3 attempts": only a duration with a unit
        unit = explicit or m["key_unit"]
        return _duration_ms(m["value"], _unit_factor(unit) if unit else DEFAULT_DURATION_MS)
    bare = _BARE_MS.search(low)
    return float(bare["value"]) if bare is not None else None


# ---- text lines ------------------------------------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class _Scan:
    method: str
    target: str
    status: int | None
    duration_ms: float | None
    responded: bool  # response wording ("responded", "completed", …) outside the request target


def _without_target(text: str, request: re.Match[str] | None) -> tuple[str, int | None]:
    """The line minus its request target (ids or words inside the path must not count) and where the target was."""
    if request is None:
        return text, None
    start, end = request.span("target")
    return text[:start] + text[end:], start


def _scan(request: re.Match[str] | None, low: str, after: int | None) -> _Scan:
    """Outcome of a line; ``low`` is the lower-cased line without its target, which stood at ``after``."""
    responded = next(_words(_RESPONSE_WORDS, low), None) is not None
    status = _find_status(low, after=after, loose=responded)
    duration = _find_duration(low) if request is not None or responded or status is not None else None
    method, target = (request["method"], request["target"]) if request is not None else ("", "")
    return _Scan(method, target, status, duration, responded)


def _parse_text(text: str, line: int) -> HttpRecord | None:
    request = _find_request(text)
    if request is None:
        return None
    rest, after = _without_target(text, request)
    low = _lower(rest)
    scan = _scan(request, low, after)
    path, query = _split_target(scan.target)
    client = next(_words(_CLIENT_TEXT, low), None)
    keys = _explicit_keys(rest, low)
    return HttpRecord(
        line=line,
        time=parse_line_time(text),
        method=scan.method,
        path=path,
        query=query,
        status=scan.status,
        duration_ms=scan.duration_ms,
        client=client["ip"] if client is not None else "",
        request_id=keys[0] if keys else "",
    )


# ---- Common / Combined Log Format ------------------------------------------------------------------------------------
_CLF = re.compile(
    r"(?P<client>\S+) \S+ (?P<user>\"[^\"]*\"|\S+) \[(?P<time>[^\]]+)\] "
    r"\"(?P<request>(?:[^\"\\]|\\.)*)\" (?P<status>\d{3}|-) (?P<bytes>\d+|-)"
    r"(?: \"(?P<referer>(?:[^\"\\]|\\.)*)\" \"(?P<agent>(?:[^\"\\]|\\.)*)\")?"
)
_QUOTED = re.compile(r"\"(?:[^\"\\]|\\.)*\"")
_BARE_NUMBER = re.compile(r"(?<![\w.:/-])(?P<value>\d+(?:\.\d+)?)(?![\w.:/-])")


def _trailing_duration(rest: str) -> float | None:
    """Request time appended after the combined format: ``rt=0.123``, ``123ms``, a bare ``0.123`` or ``123456``."""
    rest = _lower(_QUOTED.sub(" ", rest))
    explicit = _find_duration(rest)
    if explicit is not None:
        return explicit
    m = _BARE_NUMBER.search(rest)
    if m is None:
        return None
    value = m["value"]
    return float(value) * (TRAILING_DECIMAL_MS if "." in value else TRAILING_INTEGER_MS)


def _parse_clf(text: str, line: int) -> HttpRecord | None:
    if '] "' not in text:
        return None
    m = _CLF.search(text)
    if m is None:
        return None
    parts = m["request"].split()
    method, target = (parts[0], parts[1]) if len(parts) >= 2 and parts[0] in _STRUCTURED_METHODS else ("", "")
    path, query = _split_target(target) if target else ("", "")
    agent = m["agent"] or ""
    return HttpRecord(
        line=line,
        time=_cached_time(m["time"]),
        method=method,
        path=path,
        query=query,
        status=_status_value(m["status"]),
        duration_ms=_trailing_duration(text[m.end() :]),
        client=m["client"] if m["client"] != "-" else "",
        bytes_sent=_int_value(m["bytes"]),
        user_agent=agent if agent != "-" else "",
    )


# ---- structured lines (JSON, key=value) ------------------------------------------------------------------------------
_NON_ALNUM = re.compile(r"[^a-z0-9]")
_JSON_HINT = re.compile(r"\"(?:get|post|put|delete|patch|head|options)\b", re.IGNORECASE)
_KV_HINT = re.compile(r"(?:method|verb)[\"']?\s*[=:]")  # on the lower-cased line
_KV_PAIR = re.compile(
    r"(?P<key>[A-Za-z_@][\w.@-]*)[\"']?\s*[=:]\s*"
    r"(?:\"(?P<dq>[^\"]*)\"|'(?P<sq>[^']*)'|(?P<bare>[^\s,;\"'\])}]+))"
)
# Field aliases after normalisation (lower case, punctuation removed), most specific first.
_METHOD_KEYS = ("method", "httpmethod", "requestmethod", "httprequestmethod", "verb", "csmethod")
_TARGET_KEYS = (
    "path", "requestpath", "urlpath", "csuristem", "uri", "requesturi", "url", "requesturl", "urloriginal",
    "httpurl", "target", "httptarget", "endpoint",
)  # fmt: skip
_REQUEST_LINE_KEYS = ("request", "requestline", "httprequest")
_QUERY_KEYS = ("query", "querystring", "urlquery", "csuriquery")
_STATUS_KEYS = (
    "status", "statuscode", "httpstatus", "httpstatuscode", "responsestatus", "responsestatuscode",
    "httpresponsestatuscode", "scstatus", "responsecode",
)  # fmt: skip
_CLIENT_KEYS = (
    "clientip", "client", "remoteaddr", "remoteip", "remoteaddress", "clientaddress", "cip", "sourceip", "srcip", "ip",
)  # fmt: skip
_BYTES_KEYS = (
    "bytessent", "bodybytessent", "scbytes", "responsebytes", "responsesize", "responsebodybytes",
    "responsecontentlength", "bytes", "size",
)  # fmt: skip
_AGENT_KEYS = ("useragent", "httpuseragent", "csuseragent", "useragentoriginal", "ua")
_REQUEST_ID_KEYS = (
    "requestid", "xrequestid", "reqid", "correlationid", "xcorrelationid", "traceid", "operationid", "activityid",
    "transactionid",
)  # fmt: skip
_TIME_KEYS = ("timestamp", "time", "ts", "datetime", "date", "logtime", "eventtime")
_DURATION_KEY = re.compile(
    r"(?:duration|elapsed(?:time)?|latency|took|timetaken|responsetime|requesttime|processingtime|executiontime)"
    rf"(?P<unit>{_KEY_UNIT})?"
)


def _norm_key(key: str) -> str:
    return _NON_ALNUM.sub("", key.lower())


def _flatten(obj: dict[str, object], prefix: str, out: dict[str, object], depth: int) -> None:
    """Nested JSON → {normalised dotted path: scalar}; leaves are also reachable by their own (normalised) name."""
    for key, value in obj.items():
        name = _norm_key(str(key))
        if isinstance(value, dict):
            if depth < JSON_MAX_DEPTH:
                _flatten(value, prefix + name, out, depth + 1)
            continue
        item = value
        if isinstance(item, list):  # header values are often lists: take the first scalar
            item = item[0] if item and not isinstance(item[0], dict | list) else None
        if item is None:
            continue
        out.setdefault(prefix + name, item)
        if prefix:
            out.setdefault(name, item)


def _lookup(fields: dict[str, object], keys: tuple[str, ...]) -> object | None:
    for key in keys:
        value = fields.get(key)
        if value is not None and value not in ("", "-"):
            return value
    return None


def _lookup_text(fields: dict[str, object], keys: tuple[str, ...]) -> str:
    value = _lookup(fields, keys)
    return "" if value is None or isinstance(value, bool) else str(value)


def _is_target(value: str) -> bool:
    return value.startswith("/") or "://" in value


def _structured_request(fields: dict[str, object]) -> tuple[str, str]:
    """(method, target) from structured fields, or ("", "")."""
    method = _lookup_text(fields, _METHOD_KEYS).upper()
    if method in _STRUCTURED_METHODS:
        for key in _TARGET_KEYS:
            value = fields.get(key)
            if isinstance(value, str) and _is_target(value):
                return method, value
    request = _lookup_text(fields, _REQUEST_LINE_KEYS)  # "GET /x HTTP/1.1" in one field
    m = _find_request(request) if request else None
    return (m["method"], m["target"]) if m is not None else ("", "")


def _structured_duration(fields: dict[str, object]) -> float | None:
    for key, value in fields.items():
        m = _DURATION_KEY.fullmatch(key)
        if m is None or isinstance(value, bool):
            continue
        factor = _unit_factor(m["unit"]) if m["unit"] else DEFAULT_DURATION_MS
        if isinstance(value, int | float):
            return float(value) * factor
        if isinstance(value, str) and (v := _DURATION_VALUE.fullmatch(value)) is not None:
            return _duration_ms(v["value"], _unit_factor(v["unit"]) if v["unit"] else factor)
    return None


def _structured_time(fields: dict[str, object], text: str) -> datetime | None:
    value = _lookup(fields, _TIME_KEYS)
    moment = parse_line_time(str(value)) if isinstance(value, str | int | float) else None
    return moment if moment is not None else parse_line_time(text)


def _from_fields(fields: dict[str, object], text: str, line: int) -> HttpRecord | None:
    method, target = _structured_request(fields)
    if not method:
        return None
    path, query = _split_target(target)
    return HttpRecord(
        line=line,
        time=_structured_time(fields, text),
        method=method,
        path=path,
        query=query or _lookup_text(fields, _QUERY_KEYS).lstrip("?"),
        status=_status_value(_lookup(fields, _STATUS_KEYS)),
        duration_ms=_structured_duration(fields),
        client=_lookup_text(fields, _CLIENT_KEYS),
        bytes_sent=_int_value(_lookup(fields, _BYTES_KEYS)),
        user_agent=_lookup_text(fields, _AGENT_KEYS),
        request_id=_lookup_text(fields, _REQUEST_ID_KEYS),
    )


def _parse_json(text: str, line: int) -> HttpRecord | None:
    brace = text.find("{")
    if brace < 0 or not text.rstrip().endswith("}") or _JSON_HINT.search(text) is None:
        return None
    try:
        obj = json.loads(text[brace:])
    except (ValueError, RecursionError):
        return None
    if not isinstance(obj, dict):
        return None
    fields: dict[str, object] = {}
    _flatten(obj, "", fields, 0)
    return _from_fields(fields, text, line)


def _parse_kv(text: str, line: int) -> HttpRecord | None:
    if ("method" not in (low := _lower(text)) and "verb" not in low) or _KV_HINT.search(low) is None:
        return None
    fields: dict[str, object] = {}
    for m in _KV_PAIR.finditer(text):
        value = next(v for v in (m["dq"], m["sq"], m["bare"]) if v is not None)
        fields.setdefault(_norm_key(m["key"]), value)
    return _from_fields(fields, text, line)


def parse_line(text: str, line: int) -> HttpRecord | None:
    """HTTP request in one line (CLF, JSON, application text, key=value), or None. W3C needs :class:`HttpLogParser`."""
    return _parse_clf(text, line) or _parse_json(text, line) or _parse_text(text, line) or _parse_kv(text, line)


# ---- W3C extended ----------------------------------------------------------------------------------------------------
_W3C_DIRECTIVE = re.compile(
    r"#(?P<name>Fields|Date|Software|Version|Remark|Start-Date|End-Date)\s*:\s*(?P<value>.*)", re.IGNORECASE
)
_W3C_TOKEN = re.compile(r"\"[^\"]*\"|\S+")
_W3C_ROLES = {
    "date": "date",
    "time": "time",
    "cs-method": "method",
    "cs-uri-stem": "path",
    "cs-uri-query": "query",
    "cs-uri": "uri",
    "sc-status": "status",
    "time-taken": "duration",
    "c-ip": "client",
    "sc-bytes": "bytes",
    "cs(user-agent)": "agent",
}
_W3C_ID_FIELD = re.compile(r"(?:request|correlation|trace)[-_]?id", re.IGNORECASE)


class W3CParser:
    """State of a W3C extended log: the current ``#Fields:`` list (it may change mid-file) and the ``#Date:``."""

    __slots__ = ("_date", "_fields", "_roles")

    def __init__(self) -> None:
        self._fields: tuple[str, ...] = ()
        self._roles: dict[str, int] = {}
        self._date = ""

    @property
    def fields(self) -> tuple[str, ...]:
        return self._fields

    @property
    def is_http(self) -> bool:
        """True once a ``#Fields:`` list with a request path has been seen."""
        return "path" in self._roles or "uri" in self._roles

    def directive(self, text: str) -> bool:
        """Consume a ``#Directive:`` line (remembering fields / date); False if ``text`` isn't one."""
        m = _W3C_DIRECTIVE.match(text)
        if m is None:
            return False
        name, value = m["name"].lower(), m["value"].strip()
        if name == "fields":
            self._fields = tuple(value.split())
            self._roles = {}
            for index, field in enumerate(self._fields):
                role = _W3C_ROLES.get(field.lower()) or ("request_id" if _W3C_ID_FIELD.search(field) else "")
                if role:
                    self._roles.setdefault(role, index)
        elif name in ("date", "start-date") and value:
            self._date = value.split()[0]
        return True

    def parse(self, text: str, line: int) -> HttpRecord | None:
        """Record for a data line matching the current field list, or None."""
        if not self.is_http:
            return None
        tokens = _W3C_TOKEN.findall(text) if '"' in text else text.split()
        if len(tokens) != len(self._fields):
            return None

        def get(role: str) -> str:
            index = self._roles.get(role)
            value = tokens[index].strip('"') if index is not None else ""
            return "" if value == "-" else value

        path, query = get("path"), get("query")
        if not path and get("uri"):
            path, query = _split_target(get("uri"))
        if not path:
            return None
        date, clock = get("date") or self._date, get("time")
        taken = get("duration")
        duration = None
        if taken.replace(".", "", 1).isdigit():
            duration = float(taken) * (W3C_DECIMAL_MS if "." in taken else W3C_INTEGER_MS)
        return HttpRecord(
            line=line,
            time=_cached_time(f"{date}T{clock}Z") if date and clock else None,  # W3C times are UTC
            method=get("method").upper(),
            path=path,
            query=query,
            status=_status_value(get("status")),
            duration_ms=duration,
            client=get("client"),
            bytes_sent=_int_value(get("bytes")),
            user_agent=get("agent").replace("+", " "),  # W3C writers encode spaces in values as '+'
            request_id=get("request_id"),
        )


class HttpLogParser:
    """Stateful line parser: W3C directives set the field list for the data lines after them."""

    __slots__ = ("_w3c",)

    def __init__(self) -> None:
        self._w3c = W3CParser()

    def feed(self, line_number: int, text: str) -> HttpRecord | None:
        """Record for this line (directive lines and non-HTTP lines give None)."""
        if text.startswith("#") and self._w3c.directive(text):
            return None
        if self._w3c.is_http:
            record = self._w3c.parse(text, line_number)
            if record is not None:
                return record
        return parse_line(text, line_number)


def parse_lines(lines: Iterable[tuple[int, str]], *, limit: int = MAX_RECORDS) -> list[HttpRecord]:
    """Records of ``(line number, text)`` pairs, in order, at most ``limit``."""
    parser = HttpLogParser()
    records: list[HttpRecord] = []
    for number, text in lines:
        record = parser.feed(number, text)
        if record is not None:
            records.append(record)
            if len(records) >= limit:
                break
    return records


# ---- summary ---------------------------------------------------------------------------------------------------------
class _Samples:
    """Durations for percentiles: all of them up to ``cap``, then a uniform reservoir sample; exact maximum."""

    __slots__ = ("_cap", "_rng", "_seen", "maximum", "values")

    def __init__(self, cap: int) -> None:
        self._cap = cap
        self._seen = 0
        self._rng: random.Random | None = None
        self.values: array[float] = array("d")
        self.maximum: float | None = None

    def add(self, value: float) -> None:
        self._seen += 1
        if self.maximum is None or value > self.maximum:
            self.maximum = value
        if len(self.values) < self._cap:
            self.values.append(value)
            return
        if self._rng is None:
            self._rng = random.Random(RESERVOIR_SEED)
        slot = self._rng.randrange(self._seen)
        if slot < self._cap:
            self.values[slot] = value

    def percentiles(self) -> tuple[float | None, float | None, float | None]:
        if not self.values:
            return None, None, None
        p50, p95, p99 = np.percentile(np.frombuffer(self.values, dtype=np.float64), PERCENTILES)
        return float(p50), float(p95), float(p99)


class _EndpointTally:
    __slots__ = ("count", "errors", "samples", "statuses")

    def __init__(self) -> None:
        self.count = 0
        self.errors = 0
        self.statuses: Counter[int] = Counter()
        self.samples = _Samples(MAX_ENDPOINT_SAMPLES)

    def stats(self, method: str, path: str, top: int) -> EndpointStats:
        p50, p95, p99 = self.samples.percentiles()
        return EndpointStats(
            method=method,
            path=path,
            count=self.count,
            errors=self.errors,
            p50_ms=p50,
            p95_ms=p95,
            p99_ms=p99,
            max_ms=self.samples.maximum,
            top_statuses=tuple(self.statuses.most_common(top)),
        )


class _Tally:
    """Streaming aggregation of records; memory bounded by the caps, not by the number of records."""

    def __init__(self, error_status_min: int, slowest: int) -> None:
        self.total = 0
        self.errors = 0
        self._error_min = error_status_min
        self._slowest_n = slowest
        self._statuses: Counter[int] = Counter()
        self._durations = _Samples(MAX_DURATION_SAMPLES)
        self._endpoints: dict[tuple[str, str], _EndpointTally] = {}
        self._clients: Counter[str] = Counter()
        self._minutes: dict[datetime, list[int]] = {}
        self._slowest: list[tuple[float, int, HttpRecord]] = []  # min-heap (duration, sequence, record)

    def add(self, record: HttpRecord) -> None:
        self.total += 1
        error = record.status is not None and record.status >= self._error_min
        self.errors += error
        if record.status is not None:
            self._statuses[record.status] += 1
        tally = self._endpoint(record.method, normalize_path(record.path) if record.path else "")
        tally.count += 1
        tally.errors += error
        if record.status is not None:
            tally.statuses[record.status] += 1
        if record.duration_ms is not None:
            tally.samples.add(record.duration_ms)
            self._durations.add(record.duration_ms)
            self._keep_if_slow(record, record.duration_ms)
        if record.client:
            known = record.client in self._clients or len(self._clients) < MAX_TRACKED_CLIENTS
            self._clients[record.client if known else OTHER] += 1
        if record.time is not None:
            self._count_minute(record.time, error)

    def _endpoint(self, method: str, path: str) -> _EndpointTally:
        key = (method, path)
        tally = self._endpoints.get(key)
        if tally is None:
            if len(self._endpoints) >= MAX_TRACKED_ENDPOINTS:
                key = ("", OTHER)
            tally = self._endpoints.setdefault(key, _EndpointTally())
        return tally

    def _keep_if_slow(self, record: HttpRecord, duration: float) -> None:
        if self._slowest_n <= 0:
            return
        item = (duration, -self.total, record)  # earlier records win ties; the sequence keeps records uncompared
        if len(self._slowest) < self._slowest_n:
            heapq.heappush(self._slowest, item)
        elif item[:2] > self._slowest[0][:2]:
            heapq.heapreplace(self._slowest, item)

    def _count_minute(self, moment: datetime, error: bool) -> None:
        if moment.tzinfo is None:
            moment = moment.astimezone()  # naive → local, as timeparse does
        if self._minutes:
            moment = moment.astimezone(next(iter(self._minutes)).tzinfo)  # one zone for the whole series
        minute = moment.replace(second=0, microsecond=0)
        bucket = self._minutes.get(minute)
        if bucket is None:
            if len(self._minutes) >= MAX_MINUTE_BUCKETS:
                return
            bucket = self._minutes[minute] = [0, 0]
        bucket[0] += 1
        bucket[1] += error

    def _series(self) -> tuple[tuple[datetime, int, int], ...]:
        if not self._minutes:
            return ()
        minutes = sorted(self._minutes)
        span = int((minutes[-1] - minutes[0]).total_seconds() // 60) + 1
        if span <= MAX_FILLED_MINUTES:
            minutes = [minutes[0] + timedelta(minutes=offset) for offset in range(span)]
        series: list[tuple[datetime, int, int]] = []
        for minute in minutes:
            count, errors = self._minutes.get(minute, (0, 0))
            series.append((minute, count, errors))
        return tuple(series)

    def _status_classes(self) -> tuple[tuple[str, int], ...]:
        classes: Counter[str] = Counter()
        for status, count in self._statuses.items():
            classes[f"{status // 100}xx"] += count
        result = [(name, classes[name]) for name in ("1xx", "2xx", "3xx", "4xx", "5xx") if classes[name]]
        unknown = self.total - sum(classes.values())
        return (*result, ("unknown", unknown)) if unknown else tuple(result)

    def build(self, *, incomplete: int, top: int) -> HttpSummary:
        p50, p95, p99 = self._durations.percentiles()
        busiest = sorted(self._endpoints.items(), key=lambda item: (-item[1].count, item[0]))[:MAX_REPORTED_ENDPOINTS]
        return HttpSummary(
            total=self.total,
            incomplete=incomplete,
            errors=self.errors,
            error_status_min=self._error_min,
            status_classes=self._status_classes(),
            top_statuses=tuple(self._statuses.most_common(top)),
            p50_ms=p50,
            p95_ms=p95,
            p99_ms=p99,
            max_ms=self._durations.maximum,
            endpoints=tuple(tally.stats(method, path, top) for (method, path), tally in busiest),
            top_clients=tuple(self._clients.most_common(top)),
            per_minute=self._series(),
            slowest=tuple(record for _, _, record in sorted(self._slowest, key=lambda item: item[:2], reverse=True)),
        )


def summarize(
    records: Iterable[HttpRecord],
    *,
    top: int = TOP_N,
    slowest: int = SLOWEST_N,
    error_status_min: int = ERROR_STATUS_MIN,
) -> HttpSummary:
    """Status classes, endpoints, latency percentiles, requests per minute and slowest requests of ``records``.

    Records carrying neither status nor duration are request-start lines when other records carry the outcome
    (``Request starting GET /x`` … ``Request finished GET /x 200``); they are then left out (``incomplete``) so
    requests aren't counted twice. If no record has an outcome, all of them are counted.
    """
    complete = _Tally(error_status_min, slowest)
    bare = _Tally(error_status_min, slowest)
    for record in records:
        (complete if record.status is not None or record.duration_ms is not None else bare).add(record)
    if complete.total:
        return complete.build(incomplete=bare.total, top=top)
    return bare.build(incomplete=0, top=top)


# ---- transactions ----------------------------------------------------------------------------------------------------
# On the lower-cased line: "request id", "requestId", "x-request-id", "traceId", "correlation_id", … and "req=".
_EXPLICIT_KEY = re.compile(
    r"(?:request|req|correlation|corr|trace|transaction|txn|operation|activity)(?:[ _-]?id\b|(?<=req)(?=\s*[=:]))"
    r"[\"']?\s*[:=#]?\s*[\"']?(?P<value>\w[\w.:/+-]*)"
)
_BRACKET_KEY = re.compile(r"\[(?P<value>(?:req|request|trace|corr|correlation|txn|tx)[-_:][\w.:-]+)\]", re.IGNORECASE)
_GUID_RE = re.compile(rf"\b{_GUID}\b")
_BRACKET_TOKEN = re.compile(r"\[([^\[\]\s]{1,64})\]")
_TIME_LIKE = re.compile(r"\d:\d\d|\d{4}-\d\d-\d\d")
_LEVEL_WORDS = frozenset((
    "TRACE", "DEBUG", "INFO", "INFORMATION", "NOTICE", "WARN", "WARNING", "ERROR", "FATAL", "CRITICAL", "SEVERE",
    "ALERT", "EMERG", "EMERGENCY", "VERBOSE", "FINE", "FINER", "FINEST", "CONFIG", "TRC", "DBG", "INF", "WRN", "ERR",
    "FTL", "CRT", "VRB",
))  # fmt: skip
_JUNK_KEYS = frozenset(("null", "none", "nil", "undefined", "unknown", "empty", "n/a"))
_KEY_TRIM = ".:,;/+-"


def _add_key(found: list[str], value: str) -> None:
    value = value.rstrip(_KEY_TRIM)
    folded = value.lower()
    if (
        folded not in _JUNK_KEYS
        and (len(value) >= 8 or any(ch.isdigit() for ch in value))
        and value.strip("0-")  # all-zero ids are placeholders, not correlation keys
        and all(folded != known.lower() for known in found)
    ):
        found.append(value)


def _explicit_keys(text: str, low: str) -> list[str]:
    """Values (original case) of ``requestId=…`` / ``traceId: …`` / ``X-Request-ID …`` / ``[req-…]`` in ``text``;
    ``low`` is ``text`` lower-cased."""
    found: list[str] = []
    for m in _words(_EXPLICIT_KEY, low):
        _add_key(found, text[m.start("value") : m.end("value")])
    if "[" in text:
        for m in _BRACKET_KEY.finditer(text):
            _add_key(found, m["value"])
    return found


def _correlation_keys(text: str, low: str) -> list[str]:
    """Explicit keys, then GUIDs (original case, at most MAX_KEYS_PER_LINE)."""
    found = _explicit_keys(text, low)
    if text.count("-") >= 4:  # a GUID has four dashes
        for m in _GUID_RE.finditer(text):
            if len(found) >= MAX_KEYS_PER_LINE:
                break
            _add_key(found, m[0])
    return found[:MAX_KEYS_PER_LINE]


def _thread_of(text: str) -> str:
    """First bracketed header token that isn't a level, a time or a correlation key: ``[14]``, ``[worker-3]``."""
    for m in _BRACKET_TOKEN.finditer(text, 0, THREAD_HEADER_CHARS):
        token = m[1]
        if (
            token.upper() in _LEVEL_WORDS
            or _TIME_LIKE.search(token)
            or _GUID_RE.fullmatch(token)
            or _BRACKET_KEY.fullmatch(m[0])
        ):
            continue
        return token
    return ""


@dataclass(frozen=True, slots=True)
class _LineInfo:
    kind: Literal["request", "response", "other"]
    method: str
    path: str
    status: int | None
    duration_ms: float | None
    keys: tuple[str, ...]  # lower-cased, for matching
    label: str  # first key in its original case, for display
    thread: str
    form: str = "http"  # http | operation
    explicit: bool = False  # recognised by an unmistakable shape (marker / key=value / verb + id)
    style: str = ""  # "kv": key=value pairs (their trace steps also log Status=, which is not the answer)


def _id_info(kind: Literal["request", "response", "other"], text: str, low: str, **fields: object) -> _LineInfo:
    """A _LineInfo for a form-recognised line whose own id (``[43b4badd]``) is its correlation key."""
    ident = str(fields.pop("ident", "") or "")
    keys = (ident.lower(),) if ident else ()
    return _LineInfo(
        kind,
        str(fields.get("method", "")),
        str(fields.get("path", "")),
        fields.get("status"),  # type: ignore[arg-type]
        fields.get("duration_ms"),  # type: ignore[arg-type]
        keys,
        ident,
        _thread_of(text),
        str(fields.get("form", "http")),
        True,
        str(fields.get("style", "")),
    )


def _classify_forms(text: str) -> _LineInfo | None:  # noqa: PLR0911 - one return per recognised shape
    """Request/response shapes that are not ``METHOD /path`` text: key=value pairs, [START]/[END] markers, and a
    verb followed by an id and a URL ("Requesting [id] https://…" … "Received JSON: [id]"). Generic by shape."""
    body = text.lstrip()[:2]
    if body[:1] in ("{", "<") or body in ("[{", '["', "[["):  # a JSON / XML body line: payload, not a request
        return None
    if len(text) > FORM_SCAN_CHARS:  # the shape sits in the line header; never scan a multi-megabyte body for it
        text = text[:FORM_SCAN_CHARS]
    low = _lower(text)

    if "[" in text:
        m = _BEGIN_MARK.search(low)
        if m is not None:
            ident = text[m.start("id") : m.end("id")]
            return _id_info(
                "request", text, low, ident=ident, path=text[m.start("name") : m.end("name")], form="operation"
            )
        m = _END_MARK.search(low)
        if m is not None:
            ident = text[m.start("id") : m.end("id")]
            return _id_info(
                "response", text, low, ident=ident, path=text[m.start("name") : m.end("name")],
                duration_ms=_find_duration(low), status=None, form="operation",
            )  # fmt: skip
    method = _KV_METHOD.search(low)
    if method is not None:
        target = _KV_TARGET.search(text) or _KV_TARGET.search(low)
        if target is not None:
            rest = text[: target.start("target")] + text[target.end("target") :]
            status = _KV_STATUS.search(_lower(rest))
            path = _split_target(target["target"])[0]
            keys = _correlation_keys(rest, _lower(rest))
            ident = keys[0] if keys else ""
            kind: Literal["request", "response", "other"] = "response" if status is not None else "request"
            return _id_info(
                kind, text, low, ident=ident, method=method["method"].upper(), path=path,
                status=int(status["status"]) if status is not None else None,
                duration_ms=_find_duration(_lower(rest)) if status is not None else None, style="kv",
            )  # fmt: skip
    if "[" in text:
        out = _CALL_OUT.search(low)
        if out is not None and out["id"]:
            ident = text[out.start("id") : out.end("id")]
            return _id_info(
                "request", text, low, ident=ident, path=_split_target(text[out.start("target") : out.end("target")])[0]
            )
        back = _CALL_BACK.search(low)
        if back is not None:
            ident = text[back.start("id") : back.end("id")]
            return _id_info(
                "response",
                text,
                low,
                ident=ident,
                status=_find_status(low, after=None, loose=True),
                duration_ms=_find_duration(low),
            )
    if _CALL_FAILED.search(low):  # a failure line without an id: answered by the call open on its thread
        return _id_info(
            "response", text, low, status=_find_status(low, after=None, loose=True), duration_ms=_find_duration(low)
        )
    return None


def _classify(text: str) -> _LineInfo | None:
    """What a line contributes to transactions; None when it can't contribute (no request, key or thread)."""
    request = _find_request(text)
    if request is None:
        formed = _classify_forms(text)
        if formed is not None:
            return formed
    rest, after = _without_target(text, request)
    low = _lower(rest)
    keys = _correlation_keys(rest, low)
    thread = _thread_of(text)
    if request is None and not keys and not thread:
        return None
    scan = _scan(request, low, after)
    path = _split_target(scan.target)[0] if request is not None else ""
    if scan.status is not None or (scan.responded and (request is not None or scan.duration_ms is not None or keys)):
        kind: Literal["request", "response", "other"] = "response"
    elif request is not None or (keys and _REQUEST_WORDS.search(low)):
        kind = "request"
    else:
        kind = "other"
    label = keys[0] if keys else ""
    folded = tuple(key.lower() for key in keys)
    return _LineInfo(kind, scan.method, path, scan.status, scan.duration_ms, folded, label, thread)


class _OpenRequest:
    __slots__ = ("form", "keys", "label", "lines", "method", "path", "seq", "style", "thread", "time", "worker")

    def __init__(self, seq: int, line: int, info: _LineInfo, time: datetime | None) -> None:
        self.seq = seq
        self.keys = info.keys
        self.label = info.label
        self.thread = info.thread if not info.keys else ""  # keyed requests are paired by key first
        self.worker = info.thread  # the thread it ran on: answers without a key are matched on it (medium confidence)
        self.form = info.form
        self.style = info.style
        self.method = info.method
        self.path = info.path
        self.time = time
        self.lines = [line]


def _push[K](stacks: dict[K, list[_OpenRequest]], key: K, request: _OpenRequest) -> None:
    stacks.setdefault(key, []).append(request)


def _pull[K](stacks: dict[K, list[_OpenRequest]], key: K, request: _OpenRequest) -> None:
    stack = stacks.get(key)
    if stack is not None and request in stack:
        stack.remove(request)
        if not stack:
            del stacks[key]


class _Pairer:
    """Open requests, found again by correlation key, by the thread they ran on, or (weakest) by method + path.

    Stacks everywhere, so nested calls pair inside out. A response is matched with, in order of trust:
    1. a shared key (request id, trace id, GUID, ``[id]``)       → high confidence;
    2. the call open on its thread, when the response carries no key → medium (flagged uncertain);
    3. the only open call to the same method + path, no key/thread  → low (flagged uncertain).
    A response that names a key nobody opened is never guessed onto another request: it is kept as an orphan.
    """

    def __init__(self, limit: int) -> None:
        self._limit = limit
        self._seq = 0
        self._by_key: dict[str, list[_OpenRequest]] = {}
        self._by_thread: dict[str, list[_OpenRequest]] = {}  # requests without a key, paired by thread
        self._by_worker: dict[str, list[_OpenRequest]] = {}  # every request, by the thread it ran on
        self._by_target: dict[tuple[str, str], list[_OpenRequest]] = {}
        self._open: dict[int, _OpenRequest] = {}  # insertion order = age
        self._done: list[Transaction] = []

    def feed(self, line: int, text: str) -> None:
        info = _classify(text)
        if info is None:
            return
        if info.kind == "request":
            self._request(line, text, info)
        elif info.kind == "response":
            self._response(line, text, info)
        else:
            request, _how, _confidence = self._find(info)
            if request is not None and len(request.lines) < MAX_TRANSACTION_LINES - 1:  # room for the response
                request.lines.append(line)

    def finish(self) -> list[Transaction]:
        for request in list(self._open.values()):
            self._close(request, None, "", None, ("", "high"))
        return sorted(self._done, key=lambda t: (t.request_line, t.response_line or 0))

    def _full(self) -> bool:
        return len(self._done) + len(self._open) >= self._limit

    def _find(self, info: _LineInfo) -> tuple[_OpenRequest | None, str, str]:
        """The open request answered by (or owning) a line, how it was found, and how far to trust that."""
        for key in info.keys:
            stack = self._by_key.get(key)
            if stack:
                return stack[-1], "key", "high"
        if info.keys:  # it names an id nobody opened: don't guess another request for it
            return None, "", ""
        if info.thread:
            stack = self._by_thread.get(info.thread) or self._by_worker.get(info.thread)
            if stack:
                return stack[-1], "thread", "medium"
        if info.method and info.path:
            candidates = self._by_target.get((info.method, info.path), [])
            if len(candidates) == 1:  # several look alike → ambiguous → no guess
                return candidates[0], "target", "low"
        return None, "", ""

    def _request(self, line: int, text: str, info: _LineInfo) -> None:
        if self._full():
            return
        if len(self._open) >= MAX_OPEN_REQUESTS:
            self._close(next(iter(self._open.values())), None, "", None, ("", "high"))
        self._seq += 1
        request = _OpenRequest(self._seq, line, info, parse_line_time(text))
        self._open[request.seq] = request
        for key in request.keys:
            _push(self._by_key, key, request)
        if request.thread:
            _push(self._by_thread, request.thread, request)
        if request.worker:
            _push(self._by_worker, request.worker, request)
        if request.method and request.path:
            _push(self._by_target, (request.method, request.path), request)

    def _response(self, line: int, text: str, info: _LineInfo) -> None:
        request, how, confidence = self._find(info)
        if request is not None and request.style == "kv" and how != "key" and not (info.method and info.path):
            if len(request.lines) < MAX_TRANSACTION_LINES - 1:  # a trace step (Operation=…, Status=200) of the call
                request.lines.append(line)
            return
        conflict = (
            request is not None
            and how != "key"
            and bool(request.method and info.method)
            and (request.method, request.path) != (info.method, info.path)
        ) or (
            request is not None
            and how == "key"
            and bool(request.method and info.method)
            and (request.method, request.path) != (info.method, info.path)
        )
        if request is not None and not conflict:
            self._close(request, line, text, info, (how, confidence))
        elif info.method and not self._full() and info.kind == "response" and request is None and not info.keys:
            # self-contained: "GET /x responded 200 in 5 ms"
            self._done.append(
                Transaction(info.label, line, line, info.method, info.path, info.status, info.duration_ms, (line,),
                            info.thread, "inline", "high", info.form)
            )  # fmt: skip
        elif ((info.method and info.path) or info.keys or info.explicit) and not self._full():
            # a response whose request is unknown (rotated away, other file, logged without an id): keep it visible
            self._done.append(
                Transaction(info.label, line, line, info.method, info.path, info.status, info.duration_ms, (line,),
                            info.thread, "orphan", "low", info.form)
            )  # fmt: skip

    def _close(
        self, request: _OpenRequest, line: int | None, text: str, info: _LineInfo | None, matched: tuple[str, str]
    ) -> None:
        how, confidence = matched
        del self._open[request.seq]
        for key in request.keys:
            _pull(self._by_key, key, request)
        if request.thread:
            _pull(self._by_thread, request.thread, request)
        if request.worker:
            _pull(self._by_worker, request.worker, request)
        if request.method and request.path:
            _pull(self._by_target, (request.method, request.path), request)
        duration = info.duration_ms if info is not None else None
        if line is not None:
            request.lines.append(line)
            if duration is None and request.time is not None:
                answered = parse_line_time(text)
                if answered is not None and answered >= request.time:
                    duration = (answered - request.time).total_seconds() * 1000.0
        self._done.append(
            Transaction(
                key=request.label,
                request_line=request.lines[0],
                response_line=line,
                method=request.method or (info.method if info is not None else ""),
                path=request.path or (info.path if info is not None else ""),
                status=info.status if info is not None else None,
                duration_ms=duration,
                all_lines=tuple(request.lines),
                thread=request.worker,
                match=how if line is not None else "",
                confidence=confidence if line is not None else "high",
                form=request.form,
            )
        )


def pair_transactions(lines: Iterable[tuple[int, str]], *, limit: int = MAX_TRANSACTIONS) -> list[Transaction]:
    """Pair request lines with the response lines answering them, ordered by request line.

    Lines are correlated by a key they share (``requestId=…``, ``traceId``, ``X-Request-ID``, ``[req-…]``, or a GUID
    outside the request path). Lines without a key pair with the next response on the same ``[thread]``; requests
    that can't be paired are returned unpaired. A line holding method, path and outcome with nothing open to answer
    is a self-contained transaction. The duration is the logged one, else the time between the two lines.
    """
    pairer = _Pairer(limit)
    for number, text in lines:
        pairer.feed(number, text)
    return pairer.finish()
