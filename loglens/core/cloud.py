"""Log platforms as sources: Grafana Loki and Elasticsearch / OpenSearch, read through their HTTP APIs.

A query is limited by time and size, the result becomes ordinary log lines (``<ISO time> <labels> <message>``) in a
file LogLens opens. A token is optional and is passed in by the caller (the app keeps it in Windows Credential
Manager, never in settings).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime, timedelta
from typing import Any

TIMEOUT_S = 60.0
MAX_LINES = 50_000
MAX_RESPONSE = 64 * 1024 * 1024


class CloudError(Exception):
    """The platform could not be queried; the message says why in plain words."""


def _check_url(url: str) -> urllib.parse.ParseResult:
    parsed = urllib.parse.urlparse(url)
    local = parsed.hostname in ("localhost", "127.0.0.1", "::1")
    if parsed.scheme not in ("http", "https") or not parsed.netloc or (parsed.scheme == "http" and not local):
        raise CloudError("The address must start with https:// (http is only allowed for localhost).")
    return parsed


def _get(url: str, headers: dict[str, str], body: bytes | None = None) -> Any:
    method = "POST" if body is not None else "GET"
    request = urllib.request.Request(url, data=body, headers=headers, method=method)  # scheme checked by callers
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_S) as response:
            data = response.read(MAX_RESPONSE + 1)
    except urllib.error.HTTPError as exc:
        hint = " Check the token." if exc.code in (401, 403) else ""
        raise CloudError(f"The service answered {exc.code} {exc.reason}.{hint}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise CloudError(f"The service could not be reached: {getattr(exc, 'reason', exc)}.") from exc
    if len(data) > MAX_RESPONSE:
        raise CloudError("The answer is too large: narrow the time range or the query.")
    try:
        return json.loads(data)
    except ValueError as exc:
        raise CloudError("The service did not answer with JSON.") from exc


def _headers(token: str) -> dict[str, str]:
    if token:
        return {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    return {"Accept": "application/json"}


def _iso(nanoseconds: str) -> str:
    try:
        moment = datetime.fromtimestamp(int(nanoseconds) / 1e9, UTC)
    except (ValueError, OverflowError, OSError):
        return ""
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def loki_lines(
    base_url: str, query: str, *, since: timedelta = timedelta(hours=1), limit: int = 5000, token: str = ""
) -> list[str]:
    """Lines of a LogQL ``query`` (oldest first) from Grafana Loki."""
    _check_url(base_url)
    if not query.strip():
        raise CloudError('Enter a LogQL query, like {app="shop"} |= "error".')
    end = datetime.now(UTC)
    params = urllib.parse.urlencode(
        {
            "query": query,
            "start": int((end - since).timestamp() * 1e9),
            "end": int(end.timestamp() * 1e9),
            "limit": max(1, min(limit, MAX_LINES)),
            "direction": "forward",
        }
    )
    data = _get(f"{base_url.rstrip('/')}/loki/api/v1/query_range?{params}", _headers(token))
    if data.get("status") != "success":
        raise CloudError(f"Loki refused the query: {data.get('error', data.get('status'))}")
    rows: list[tuple[int, str]] = []
    for stream in data.get("data", {}).get("result", []):
        labels = ",".join(f"{k}={v}" for k, v in sorted(stream.get("stream", {}).items()))
        for stamp, text in stream.get("values", []):
            rows.append((int(stamp), f"{_iso(stamp)} [{labels}] {' '.join(str(text).splitlines())}"))
    return [line for _t, line in sorted(rows)][:MAX_LINES]


def elastic_lines(
    base_url: str,
    index: str,
    query: str = "*",
    *,
    since: timedelta = timedelta(hours=1),
    limit: int = 5000,
    token: str = "",
) -> list[str]:
    """Documents of an Elasticsearch / OpenSearch index matching a query-string ``query`` (oldest first)."""
    _check_url(base_url)
    if not index.strip() or any(c in index for c in " /\\?#") or index.startswith(("_", "-", "+")):
        raise CloudError("Enter an index name or pattern, like logs-* (no spaces or slashes).")
    body = json.dumps(
        {
            "size": max(1, min(limit, 10_000)),
            "sort": [{"@timestamp": "asc"}],
            "query": {
                "bool": {
                    "must": [{"query_string": {"query": query or "*"}}],
                    "filter": [{"range": {"@timestamp": {"gte": f"now-{int(since.total_seconds())}s"}}}],
                }
            },
        }
    ).encode()
    headers = {**_headers(token), "Content-Type": "application/json"}
    data = _get(f"{base_url.rstrip('/')}/{urllib.parse.quote(index, safe='*,-_.')}/_search", headers, body)
    lines = []
    for hit in data.get("hits", {}).get("hits", []):
        doc = hit.get("_source", {})
        stamp = str(doc.get("@timestamp", ""))
        message = doc.get("message")
        text = str(message) if message is not None else json.dumps(doc, separators=(",", ":"))
        lines.append(f"{stamp} {' '.join(text.splitlines())}".strip())
    return lines
