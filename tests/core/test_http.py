"""HTTP access-log parsing, summaries and request/response transactions (synthetic lines of common shapes)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import numpy as np
import pytest

from loglens.core import http
from loglens.core.http import (
    ID_PLACEHOLDER,
    HttpLogParser,
    HttpRecord,
    endpoint_key,
    normalize_path,
    pair_transactions,
    parse_line,
    parse_lines,
    summarize,
)

# ---- W3C extended ----------------------------------------------------------------------------------------------------
W3C_LOG = [
    "#Software: Some Web Server 10.0",
    "#Version: 1.0",
    "#Date: 2026-11-13 10:00:00",
    "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port c-ip cs(User-Agent) sc-status time-taken",
    "2026-11-13 10:00:01 10.0.0.1 GET /api/orders/42 expand=items 443 10.0.0.9 Mozilla/5.0+(Windows+NT) 200 15",
    "2026-11-13 10:00:02 10.0.0.1 POST /api/orders - 443 10.0.0.8 curl/8.0 500 1234",
    "#Software: Some Web Server 10.0",
    "#Fields: time c-ip cs-method cs-uri-stem sc-status sc-bytes time-taken x-request-id",
    "10:05:00 10.0.0.7 DELETE /api/orders/42 204 0 0.250 abc-123",
]


def test_w3c_fields_change_mid_file() -> None:
    parser = HttpLogParser()
    records = [parser.feed(number, text) for number, text in enumerate(W3C_LOG)]
    assert records[:4] == [None, None, None, None]  # directives are not records
    first, second = records[4], records[5]
    assert first is not None and second is not None
    assert (first.method, first.path, first.query, first.status, first.duration_ms) == (
        "GET",
        "/api/orders/42",
        "expand=items",
        200,
        15.0,
    )
    assert first.client == "10.0.0.9" and first.user_agent == "Mozilla/5.0 (Windows NT)"
    assert first.time == datetime(2026, 11, 13, 10, 0, 1, tzinfo=UTC)  # W3C times are UTC
    assert (second.query, second.status, second.duration_ms) == ("", 500, 1234.0)
    assert records[6] is None and records[7] is None
    third = records[8]
    assert third is not None
    assert (third.method, third.path, third.status, third.bytes_sent) == ("DELETE", "/api/orders/42", 204, 0)
    assert third.duration_ms == pytest.approx(250.0)  # decimal time-taken is seconds
    assert third.request_id == "abc-123"
    assert third.time == datetime(2026, 11, 13, 10, 5, tzinfo=UTC)  # date from the #Date directive


def test_w3c_without_http_fields_is_ignored() -> None:
    parser = HttpLogParser()
    assert parser.feed(0, "#Fields: date time action protocol src-ip dst-ip") is None
    assert parser.feed(1, "2026-11-13 10:00:00 ALLOW TCP 10.0.0.1 10.0.0.2") is None


# ---- Common / Combined Log Format ------------------------------------------------------------------------------------
def test_common_log_format() -> None:
    record = parse_line('127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326', 3)
    assert record is not None
    assert (record.line, record.client, record.method, record.path, record.status, record.bytes_sent) == (
        3,
        "127.0.0.1",
        "GET",
        "/apache_pb.gif",
        200,
        2326,
    )
    assert record.time == datetime(2000, 10, 10, 13, 55, 36, tzinfo=UTC) + timedelta(hours=7)
    assert record.duration_ms is None and record.user_agent == ""


def test_combined_log_format_with_request_time() -> None:
    line = (
        '10.1.1.1 - - [13/Nov/2026:10:00:00 +0000] "POST /api/items?page=2 HTTP/1.1" 502 - '
        '"https://example.com/" "Mozilla/5.0 (X11)" 0.123'
    )
    record = parse_line(line, 0)
    assert record is not None
    assert (record.method, record.path, record.query, record.status) == ("POST", "/api/items", "page=2", 502)
    assert record.bytes_sent is None and record.user_agent == "Mozilla/5.0 (X11)"
    assert record.duration_ms == pytest.approx(123.0)  # trailing decimal = seconds
    integer = parse_line(line.replace(" 0.123", " 4500"), 0)
    assert integer is not None and integer.duration_ms == pytest.approx(4.5)  # trailing integer = microseconds


def test_clf_with_unparseable_request_line() -> None:
    record = parse_line('10.0.0.1 - - [13/Nov/2026:10:00:00 +0000] "-" 408 0', 0)
    assert record is not None and (record.method, record.path, record.status) == ("", "", 408)


# ---- application text and key=value lines ----------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("line", "expected"),
    [
        (
            "2026-11-13 10:15:02,123 [14] INFO Api - GET /api/x?y=1 status=500 took 120ms",
            ("GET", "/api/x", "y=1", 500, 120.0),
        ),
        (
            "2018-07-06 09:02:17.148 +10:00 [INF] HTTP GET /api/orders/42 responded 200 in 12.3456 ms",
            ("GET", "/api/orders/42", "", 200, 12.3456),
        ),
        (
            "info: Hosting[1] Request starting HTTP/1.1 POST http://localhost:5000/api/items application/json 42",
            ("POST", "/api/items", "", None, None),
        ),
        (
            "info: Hosting[2] Request finished HTTP/1.1 GET http://localhost/api/items - 200 - text/plain 54.3216ms",
            ("GET", "/api/items", "", 200, 54.3216),
        ),
        ("Sending HTTP request GET https://example.com/v1/data#frag", ("GET", "/v1/data", "", None, None)),
        (
            "Received response for GET https://example.com/v1/data?k=v StatusCode: 404 elapsed=1.2s",
            ("GET", "/v1/data", "k=v", 404, 1200.0),
        ),
        ("GET /health 503 Service Unavailable duration_ms=7", ("GET", "/health", "", 503, 7.0)),
        ('"PUT /api/x HTTP/1.1" 201 (Elapsed: 00:00:01.500)', ("PUT", "/api/x", "", 201, 1500.0)),
        ("(DELETE /odata/Items(7)) returned 404 after 3 s", ("DELETE", "/odata/Items(7)", "", 404, 3000.0)),
        ("GET /api/report 200 ms", ("GET", "/api/report", "", None, 200.0)),  # a duration, not a status
        ("Query returned 300 rows for GET /api/report", ("GET", "/api/report", "", None, None)),
        ("PATCH /a/b?c=1, done in 2026", ("PATCH", "/a/b", "c=1", None, None)),  # "in 2026" has no unit
        (
            "level=info method=POST path=/api/login status=401 duration=35ms client=10.1.2.3",
            ("POST", "/api/login", "", 401, 35.0),
        ),
        ('verb="GET" url="https://h/p?q=1" StatusCode=301 latency_us=1500', ("GET", "/p", "q=1", 301, 1.5)),
    ],
)
def test_generic_text_lines(line: str, expected: tuple[str, str, str, int | None, float | None]) -> None:
    record = parse_line(line, 0)
    assert record is not None
    method, path, query, status, duration = expected
    assert (record.method, record.path, record.query, record.status) == (method, path, query, status)
    assert record.duration_ms == (pytest.approx(duration) if duration is not None else None)


def test_keyword_must_start_a_word() -> None:
    record = parse_line("POST /a http_status=503 xstatus=200 superelapsed=99ms", 0)
    assert record is not None and record.status == 503
    assert record.duration_ms == 99.0  # no keyword at a word start, so the bare "99ms" is used
    assert parse_line("FORGET /x", 0) is None


def test_non_ascii_line_keeps_positions() -> None:
    # "İ".lower() is two characters; matching must still line up with the original text.
    record = parse_line("İİİ GET /api/şehir?q=İ 404 Not Found requestId=AbC-1", 0)
    assert record is not None
    assert (record.path, record.query, record.status, record.request_id) == ("/api/şehir", "q=İ", 404, "AbC-1")


def test_text_line_time_client_and_request_id() -> None:
    record = parse_line("2026-11-13T10:00:00Z GET /x from 192.168.1.20 requestId=r-77 status=200", 5)
    assert record is not None
    assert record.time == datetime(2026, 11, 13, 10, 0, tzinfo=UTC)
    assert (record.client, record.request_id, record.line) == ("192.168.1.20", "r-77", 5)


@pytest.mark.parametrize(
    "line",
    [
        "Started service",
        "The values are GET and POST",
        "GET request failed",
        "method=parseConfig took 12ms",
        '{"method":"GET"}',
        '{"method": "doWork", "path": "/x"}',
        "{broken json GET",
        "",
    ],
)
def test_non_http_lines(line: str) -> None:
    assert parse_line(line, 0) is None


# ---- JSON lines ------------------------------------------------------------------------------------------------------
def test_json_lines() -> None:
    flat = parse_line(
        '{"time":"2026-11-13T10:00:00Z","method":"GET","path":"/a","status":200,"duration_ms":12.5,"requestId":"q1"}',
        0,
    )
    assert flat is not None
    assert (flat.method, flat.path, flat.status, flat.duration_ms, flat.request_id) == ("GET", "/a", 200, 12.5, "q1")
    assert flat.time == datetime(2026, 11, 13, 10, 0, tzinfo=UTC)

    nested = parse_line(
        '{"ts":1763028000.5,"request":{"method":"POST","uri":"/b?x=1","remote_ip":"1.2.3.4",'
        '"headers":{"User-Agent":["curl/8"]}},"status":201,"duration":"1.5s","size":10}',
        1,
    )
    assert nested is not None
    assert (nested.method, nested.path, nested.query, nested.status) == ("POST", "/b", "x=1", 201)
    assert (nested.duration_ms, nested.client, nested.user_agent, nested.bytes_sent) == (
        1500.0,
        "1.2.3.4",
        "curl/8",
        10,
    )
    assert nested.time == datetime.fromtimestamp(1763028000.5, UTC)

    mixed_case = parse_line('{"Method":"delete","Url":"https://h/c/1","StatusCode":"204","ElapsedMilliseconds":3}', 2)
    assert mixed_case is not None
    assert (mixed_case.method, mixed_case.path, mixed_case.status, mixed_case.duration_ms) == ("DELETE", "/c/1", 204, 3)

    request_line = parse_line('{"request":"GET /d HTTP/1.1","status":"404","Elapsed":"00:00:00.250"}', 3)
    assert request_line is not None
    assert (request_line.path, request_line.status, request_line.duration_ms) == ("/d", 404, 250.0)


def test_json_after_a_text_prefix() -> None:
    record = parse_line('2026-11-13 10:00:00,000 INFO access {"method":"GET","url":"/z","status":302}', 0)
    assert record is not None and (record.path, record.status) == ("/z", 302)
    assert record.time is not None and record.time.hour == 10


# ---- endpoint normalisation ------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("path", "normalized"),
    [
        ("/users/42/orders/3f2504e0-4f89-11d3-9a0c-0305e82c3301", "/users/{id}/orders/{id}"),
        ("/items/{3F2504E0-4F89-11D3-9A0C-0305E82C3301}", "/items/{id}"),
        ("/x/507f1f77bcf86cd799439011/y", "/x/{id}/y"),
        ("/files/9b74c9897bac770ffc029102a200c5de", "/files/{id}"),
        ("/t/01ARZ3NDEKTSV4RRFFQ69G5FAV", "/t/{id}"),
        ("/v1/items/", "/v1/items"),
        ("/api/deadbeef/facade", "/api/deadbeef/facade"),  # hex-looking words without digits stay
        ("/", "/"),
        ("", ""),
    ],
)
def test_normalize_path(path: str, normalized: str) -> None:
    assert normalize_path(path) == normalized


def test_endpoint_key() -> None:
    assert endpoint_key("GET", "/a/12") == f"GET /a/{ID_PLACEHOLDER}"
    assert HttpRecord(0, None, "PUT", "/b/7/c").endpoint == "PUT /b/{id}/c"


# ---- summary ---------------------------------------------------------------------------------------------------------
def _record(line: int, path: str, status: int | None, duration: float | None, *, second: int = 0) -> HttpRecord:
    moment = datetime(2026, 11, 13, 10, 0, tzinfo=UTC) + timedelta(seconds=second)
    return HttpRecord(line, moment, "GET", path, status=status, duration_ms=duration, client=f"10.0.0.{line % 3}")


def test_summary_percentiles_and_status_classes() -> None:
    durations = [float(d) for d in range(1, 101)]
    statuses = [200] * 90 + [404] * 5 + [500] * 3 + [503] * 2
    records = [
        _record(i, f"/items/{i}", status, duration, second=i * 7)
        for i, (status, duration) in enumerate(zip(statuses, durations, strict=True))
    ]
    summary = summarize(records, top=3, slowest=5)
    assert summary.total == 100 and summary.incomplete == 0
    assert summary.status_classes == (("2xx", 90), ("4xx", 5), ("5xx", 5))
    assert summary.class_count("5xx") == 5 and summary.class_count("3xx") == 0
    assert summary.top_statuses == ((200, 90), (404, 5), (500, 3))
    assert (summary.errors, summary.error_rate) == (5, 0.05)
    expected = np.percentile(durations, [50, 95, 99])
    assert (summary.p50_ms, summary.p95_ms, summary.p99_ms) == pytest.approx(tuple(expected))
    assert summary.max_ms == 100.0
    assert [r.duration_ms for r in summary.slowest] == [100.0, 99.0, 98.0, 97.0, 96.0]

    (endpoint,) = summary.endpoints  # every /items/<n> is one endpoint
    assert (endpoint.endpoint, endpoint.count, endpoint.errors) == ("GET /items/{id}", 100, 5)
    assert endpoint.p95_ms == pytest.approx(expected[1]) and endpoint.max_ms == 100.0
    assert endpoint.error_rate == pytest.approx(0.05)
    assert sum(count for _, count in summary.top_clients) == 100 and len(summary.top_clients) == 3


def test_summary_per_minute_series_fills_gaps() -> None:
    records = [
        _record(0, "/a", 200, 1.0),
        _record(1, "/a", 500, 1.0, second=30),
        _record(2, "/a", 200, 1.0, second=185),
    ]
    series = summarize(records).per_minute
    start = datetime(2026, 11, 13, 10, 0, tzinfo=UTC)
    assert [(minute - start, count, errors) for minute, count, errors in series] == [
        (timedelta(0), 2, 1),
        (timedelta(minutes=1), 0, 0),
        (timedelta(minutes=2), 0, 0),
        (timedelta(minutes=3), 1, 0),
    ]


def test_summary_skips_request_start_echoes() -> None:
    lines = [
        "Request starting HTTP/1.1 GET http://localhost/api/a",
        "Request finished HTTP/1.1 GET http://localhost/api/a - 200 - text/plain 5.0ms",
        "Request starting HTTP/1.1 POST http://localhost/api/b",
        "Request finished HTTP/1.1 POST http://localhost/api/b - 500 - text/plain 9.0ms",
    ]
    summary = summarize(parse_lines(enumerate(lines)))
    assert (summary.total, summary.incomplete, summary.errors) == (2, 2, 1)
    only_requests = summarize(parse_lines(enumerate(lines[::2])))
    assert (only_requests.total, only_requests.incomplete) == (2, 0)
    assert only_requests.status_classes == (("unknown", 2),) and only_requests.p50_ms is None


def test_summary_of_nothing() -> None:
    summary = summarize([])
    assert (summary.total, summary.error_rate, summary.endpoints, summary.per_minute) == (0, 0.0, (), ())


def test_error_threshold_is_configurable() -> None:
    records = [_record(0, "/a", 404, None), _record(1, "/a", 500, None)]
    assert summarize(records).errors == 1
    assert summarize(records, error_status_min=400).errors == 2


def test_summary_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(http, "MAX_TRACKED_ENDPOINTS", 2)
    monkeypatch.setattr(http, "MAX_TRACKED_CLIENTS", 1)
    monkeypatch.setattr(http, "MAX_DURATION_SAMPLES", 500)
    records = [
        HttpRecord(i, None, "GET", f"/r{i % 4}", status=200, duration_ms=float(i), client=f"c{i % 3}")
        for i in range(10_000)
    ]
    summary = summarize(records)
    assert {e.endpoint for e in summary.endpoints} == {"GET /r0", "GET /r1", http.OTHER}
    assert dict(summary.top_clients) == {"c0": 3334, http.OTHER: 6666}
    assert summary.max_ms == 9999.0  # exact even when percentiles come from a sample
    assert summary.p50_ms == pytest.approx(5000.0, rel=0.15)


def test_parse_lines_limit() -> None:
    lines = enumerate([f"GET /a/{i} status=200" for i in range(10)])
    assert [r.line for r in parse_lines(lines, limit=3)] == [0, 1, 2]


# ---- transactions ----------------------------------------------------------------------------------------------------
def test_pair_by_request_id_interleaved() -> None:
    lines = [
        "2026-11-13 10:00:00,000 [1] INFO Incoming GET /api/orders requestId=a1",
        "2026-11-13 10:00:00,010 [2] INFO Incoming POST /api/pay requestId=b2",
        "2026-11-13 10:00:00,050 [2] DEBUG validating card requestId=b2",
        "2026-11-13 10:00:00,120 [2] INFO Completed status=201 requestId=b2",
        "2026-11-13 10:00:00,250 [1] INFO Completed 200 in 245.5 ms requestId=a1",
        "2026-11-13 10:00:00,300 [3] INFO unrelated line",
    ]
    first, second = pair_transactions(enumerate(lines))
    assert (first.key, first.request_line, first.response_line, first.method, first.path) == (
        "a1",
        0,
        4,
        "GET",
        "/api/orders",
    )
    assert (first.status, first.duration_ms) == (200, 245.5)  # logged duration wins
    assert (second.key, second.request_line, second.response_line, second.status) == ("b2", 1, 3, 201)
    assert second.duration_ms == pytest.approx(110.0)  # from the timestamps
    assert second.all_lines == (1, 2, 3) and second.paired


def test_pair_by_guid_outside_the_path() -> None:
    order = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
    corr_a, corr_b = "7c9e6679-7425-40de-944b-e07fc1f90ae7", "16fd2706-8baf-433b-82eb-8c7fada847da"
    lines = [
        f"2026-11-13 10:00:00.000 INFO GET /api/orders/{order} ({corr_a})",
        f"2026-11-13 10:00:00.010 INFO PUT /api/orders/{order} ({corr_b})",
        f"2026-11-13 10:00:00.100 INFO Response 409 ({corr_b})",
        f"2026-11-13 10:00:00.250 INFO Response 200 ({corr_a})",
    ]
    get, put = pair_transactions(enumerate(lines))
    assert (get.key, get.response_line, get.status, get.method) == (corr_a, 3, 200, "GET")
    assert get.duration_ms == pytest.approx(250.0)
    assert (put.key, put.response_line, put.status, put.method) == (corr_b, 2, 409, "PUT")


@pytest.mark.parametrize(
    ("request_suffix", "response_suffix"),
    [
        ("traceId=4bf92f3577b34da6a3ce929d0e0e4736", "traceId=4bf92f3577b34da6a3ce929d0e0e4736"),
        ("X-Request-ID: 9f86d081", "X-Request-ID: 9f86d081"),
        ("[req-1f3a]", "[req-1f3a]"),
        ("correlationId=c-42", '"correlationId":"c-42"'),
        ("RequestId:0HMQ8VQ:00000001", "RequestId:0HMQ8VQ:00000001"),
        ("req=77", "req=77"),
    ],
)
def test_correlation_key_shapes(request_suffix: str, response_suffix: str) -> None:
    lines = [
        f"2026-11-13 10:00:00,000 INFO GET /a {request_suffix}",
        "2026-11-13 10:00:00,001 INFO GET /b reqId=zz-other",
        f"2026-11-13 10:00:00,020 INFO request completed status=200 {response_suffix}",
    ]
    transactions = pair_transactions(enumerate(lines))
    paired = [t for t in transactions if t.paired]
    assert [(t.path, t.response_line) for t in paired] == [("/a", 2)]


def test_unpaired_request() -> None:
    lines = [
        "2026-11-13 10:00:00,000 INFO GET /slow requestId=s1",
        "2026-11-13 10:00:01,000 INFO GET /fast requestId=f1",
        "2026-11-13 10:00:01,005 INFO done status=200 requestId=f1",
    ]
    slow, fast = pair_transactions(enumerate(lines))
    assert (slow.key, slow.response_line, slow.status, slow.duration_ms, slow.paired) == ("s1", None, None, None, False)
    assert slow.all_lines == (0,)
    assert fast.paired and fast.duration_ms == pytest.approx(5.0)


def test_pair_by_thread_without_keys() -> None:
    lines = [
        "2026-11-13 10:00:00,000 [7] INFO Api - GET /a",
        "2026-11-13 10:00:00,005 [8] INFO Api - POST /b",
        "2026-11-13 10:00:00,020 [8] INFO Api - saving",
        "2026-11-13 10:00:00,050 [8] INFO Api - finished with status=500",
        "2026-11-13 10:00:00,090 [7] INFO Api - returned 200",
        "2026-11-13 10:00:00,095 GET /orphan",  # no key, no thread: stays unpaired
        "2026-11-13 10:00:00,099 [9] ERROR Api - Response 502",  # nothing open on thread 9: bare status, nothing to identify it by: ignored
    ]
    a, b, unanswered = pair_transactions(enumerate(lines))
    assert (a.thread, a.response_line, a.status, a.duration_ms) == ("7", 4, 200, pytest.approx(90.0))
    assert (b.thread, b.all_lines, b.status) == ("8", (1, 2, 3), 500)
    assert (unanswered.request_line, unanswered.paired) == (5, False)


def test_self_contained_lines_and_mismatched_responses() -> None:
    lines = [
        "2026-11-13 10:00:00,000 [4] INFO GET /never-answered",
        "2026-11-13 10:00:00,100 [4] INFO HTTP POST /api/x responded 201 in 12.5 ms",
    ]
    open_request, single = pair_transactions(enumerate(lines))
    assert (open_request.path, open_request.paired) == ("/never-answered", False)
    assert (single.request_line, single.response_line, single.method, single.status, single.duration_ms) == (
        1,
        1,
        "POST",
        201,
        12.5,
    )


def test_nested_calls_with_the_same_key_pair_inside_out() -> None:
    lines = [
        "2026-11-13 10:00:00,000 INFO GET /outer requestId=n1",
        "2026-11-13 10:00:00,010 INFO calling GET https://backend/inner requestId=n1",
        "2026-11-13 10:00:00,040 INFO backend responded 200 requestId=n1",
        "2026-11-13 10:00:00,060 INFO request completed status=200 requestId=n1",
    ]
    outer, inner = pair_transactions(enumerate(lines))
    assert (outer.path, outer.response_line) == ("/outer", 3)
    assert (inner.path, inner.response_line, inner.duration_ms) == ("/inner", 2, pytest.approx(30.0))


def test_transaction_key_keeps_its_case() -> None:
    lines = [
        "info: Hosting[1] => RequestId:0HMQ8VQ:00000001 Request starting HTTP/1.1 GET http://localhost/api/a",
        "info: Hosting[2] => RequestId:0HMQ8VQ:00000001 Request finished HTTP/1.1 GET http://localhost/api/a - 200",
    ]
    (transaction,) = pair_transactions(enumerate(lines))
    assert (transaction.key, transaction.response_line, transaction.status) == ("0HMQ8VQ:00000001", 1, 200)


def test_transaction_limit() -> None:
    lines = [f"2026-11-13 10:00:00,000 INFO GET /a/{i} requestId=k{i}" for i in range(20)]
    assert len(pair_transactions(enumerate(lines), limit=5)) == 5


def test_open_requests_are_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(http, "MAX_OPEN_REQUESTS", 3)
    lines = [f"GET /a/{i} requestId=k{i}" for i in range(5)] + ["done status=200 requestId=k0"]
    transactions = pair_transactions(enumerate(lines))
    assert len(transactions) == 6 and not any(t.paired for t in transactions)  # k0 was given up before its answer ...
    assert next(t for t in transactions if t.orphan).key == "k0"  # ... so its answer is kept as an orphan response
