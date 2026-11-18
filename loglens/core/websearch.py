"""Build a useful web-search query from log line(s) and the URL for a search engine.

Logs are full of values that make a search useless or leak data: timestamps, thread ids, GUIDs, IPs, user names,
domain accounts, internal host names, paths. We keep what other people would have in *their* logs too — exception
type, error message, error codes, event source/id — and drop the rest.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from urllib.parse import quote_plus

from .ai.config import Redact
from .ai.redaction import Redactor
from .timestamps import find_timestamp
from .winevent.models import EVENT_LINE

ENGINES: dict[str, str] = {
    "Google": "https://www.google.com/search?q={}",
    "Bing": "https://www.bing.com/search?q={}",
    "DuckDuckGo": "https://duckduckgo.com/?q={}",
    "Stack Overflow": "https://stackoverflow.com/search?q={}",
    "Microsoft Learn": "https://learn.microsoft.com/en-us/search/?terms={}",
}
MAX_QUERY_CHARS = 200  # engines ignore very long queries (Google: 32 words)

# A type name ending in Exception/Error with something before the suffix ("WebException", "ValueError",
# "System.Net.WebException") — not the bare word "Error"; optional "(0x80131904)" before the ": message".
_EXCEPTION = re.compile(
    r"\b((?:[A-Za-z_]\w*\.)*[A-Z]\w+(?:Exception|Error))\b(?:\s*\([^)]*\))?(?::\s*([^\r\n]{0,160}))?"
)
_CODE = re.compile(r"(?<![\w.])0x[0-9a-fA-F]{8}(?![0-9a-fA-F])")
# Personal / internal names, removed before anything else: (pattern, replacement).
_PERSONAL: list[tuple[re.Pattern[str], str]] = [
    # user 'jdoe', Login failed for user "CONTOSO\jdoe", username: 'x' → keep the word, drop the name
    (
        re.compile(
            r"(?i)\b(?P<key>user(?:[ _-]?name)?|account(?:[ _-]?name)?|log[io]n(?:[ _-]?name)?)"
            r"[\"']?\s*[:=]?\s*(?P<q>[\"'])[^\"'\r\n]{1,64}(?P=q)"
        ),
        r"\g<key>",
    ),
    (re.compile(r"(?<![\w\\/.$-])[\w.-]+\\{1,2}[\w.$-]+(?![\w\\/$-])"), " "),  # DOMAIN\user (any case)
    # Host names: 3+ labels in lower case (db01.corp.example.com), or a name in an internal-only zone written in one
    # case (DC01.CONTOSO.LOCAL, web.contoso.corp). Mixed-case dotted names are code (System.Net.Http, Foo.Internal).
    (re.compile(r"(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.){2,}[a-z]{2,63}(?![\w.-])"), " "),
    (re.compile(r"(?<![\w.-])(?:[A-Za-z0-9-]+\.)+(?:local|corp|lan|internal|LOCAL|CORP|LAN|INTERNAL)(?![\w-])"), " "),
]
_NOISE = [
    re.compile(r"\[[^\]]{0,40}\]"),  # [thread] [INF] [req=…]
    re.compile(r"\b[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b"),  # GUIDs
    re.compile(r"(?<![\w.])0x[0-9a-fA-F]{9,}\b"),  # addresses / offsets
    re.compile(r"\b[0-9a-fA-F]{16,}\b"),  # long hex ids
    re.compile(r"https?://\S+"),  # URLs (host/paths are specific to this system)
    re.compile(r"(?:[A-Za-z]:)?(?:[\\/][\w.$ -]+){2,}[\\/]?"),  # file paths
    re.compile(r"\b\w+=\S*"),  # key=value tokens (PID=123, req=abc)
    re.compile(r"\b\d{4,}\b"),  # big numbers: ids, ports, durations, counts
    re.compile(r"\b(?:TRACE|DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL|CRITICAL|VERBOSE)\b"),  # level words
    re.compile(r"\s[-|:]+\s"),  # separators
]
_REDACT = (Redact.SECRETS, Redact.EMAILS, Redact.IP_ADDRESSES, Redact.USER_PATHS)


def _strip_header(line: str) -> str:
    stamp = find_timestamp(line)
    return line[stamp.end :] if stamp is not None else line


def _clean(text: str) -> str:
    for pattern, replacement in _PERSONAL:
        text = pattern.sub(replacement, text)
    text = Redactor(_REDACT).redact(text).text
    text = re.sub(r"<[A-Z]+_\d+>", " ", text)  # drop redaction placeholders entirely
    for pattern in _NOISE:
        text = pattern.sub(" ", text)
    return " ".join(text.split())


@dataclass(frozen=True, slots=True)
class QueryPart:
    """One piece of a suggested query; the UI lets the user switch parts on/off."""

    kind: str  # "event" | "exception" | "message" | "code" | "text"
    label: str  # short name for the toggle
    text: str  # what goes into the query


def query_parts(lines: Sequence[str]) -> list[QueryPart]:
    """Suggested parts for the selected line(s): event source+id, exception type, message, error codes, or text."""
    joined = "\n".join(lines)
    parts: list[QueryPart] = []
    event = EVENT_LINE.match(joined)
    if event is not None:
        parts.append(
            QueryPart("event", f"Event {event['event_id']}", f'"{event["provider"]}" event {event["event_id"]}')
        )
    exception = _EXCEPTION.search(joined)
    if exception is not None:
        parts.append(QueryPart("exception", exception.group(1).rsplit(".", 1)[-1], exception.group(1)))
        message = _clean(exception.group(2) or "")[:120]
        if message:
            parts.append(QueryPart("message", "Message", message))
    elif event is None:
        first = next((line for line in lines if line.strip()), "")
        text = _clean(_strip_header(first))
        if text:
            parts.append(QueryPart("text", "Text", text))
    seen = " ".join(p.text for p in parts).lower()
    parts.extend(
        QueryPart("code", code, code) for code in dict.fromkeys(_CODE.findall(joined)) if code.lower() not in seen
    )
    return parts


def compose(parts: Sequence[QueryPart], exact_message: bool = True) -> str:
    """Join parts into a query; a message of 3+ words is quoted as an exact phrase when ``exact_message``."""
    texts = []
    for part in parts:
        quoted = part.kind == "message" and exact_message and len(part.text.split()) >= 3
        texts.append(f'"{part.text}"' if quoted else part.text)
    return " ".join(t for t in texts if t)[:MAX_QUERY_CHARS].strip()


def build_query(lines: Sequence[str]) -> str:
    """The default query: all suggested parts, message as an exact phrase."""
    return compose(query_parts(lines))


def search_url(engine: str, query: str) -> str:
    return ENGINES.get(engine, ENGINES["Google"]).format(quote_plus(query))
