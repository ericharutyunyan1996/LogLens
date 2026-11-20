"""Request/response detection beyond "METHOD /path" text: key=value traces, [START]/[END] markers, verb + id calls.

Everything is matched by the *shape* of the line; the logger names below are made up and mean nothing to the code.
"""

from __future__ import annotations

import pytest

from loglens.core.http import Transaction, pair_transactions

TS = "2026-11-13 10:00:00,000"


def pair(lines: list[str]) -> list[Transaction]:
    return pair_transactions(enumerate(lines))


# ---- key=value traces ("Request, Method=GET, Url=…" / "Response, Status=404 (NotFound), Method=GET, Url=…") ---------
def test_key_value_request_and_response_pair_by_thread() -> None:
    (tx,) = pair(
        [
            f"{TS} [8] TRACE Api - Request, Method=GET, Url=https://h/api/v1/items/42?x=1, Message='https://h/api/v1/items/42?x=1'",
            f"{TS} [8] TRACE Api - Response, Status=404 (NotFound), Method=GET, Url=https://h/api/v1/items/42?x=1, Message='-'",
        ]
    )
    assert (tx.method, tx.path, tx.status, tx.paired) == ("GET", "/api/v1/items/42", 404, True)
    assert (tx.match, tx.confidence, tx.uncertain) == ("thread", "medium", True)


def test_trace_steps_with_a_status_do_not_end_a_key_value_call() -> None:
    """ "Operation=X, Status=200" lines are steps of the call, not its response: they attach to it."""
    (tx,) = pair(
        [
            f"{TS} [8] TRACE Api - Request, Method=POST, Url=https://h/api/orders",
            f"{TS} [8] TRACE Api - Operation=Handler.Send, Status=200 (OK)",
            f"{TS} [8] TRACE Api - Operation=Filter.Run, Status=200 (OK)",
            f"{TS} [8] TRACE Api - Response, Status=201 (Created), Method=POST, Url=https://h/api/orders",
        ]
    )
    assert (tx.response_line, tx.status) == (3, 201)
    assert tx.all_lines == (0, 1, 2, 3)  # the steps stay with their call


def test_concurrent_key_value_calls_on_different_threads_do_not_mix() -> None:
    a, b = pair(
        [
            f"{TS} [1] TRACE Api - Request, Method=GET, Url=https://h/a",
            f"{TS} [2] TRACE Api - Request, Method=GET, Url=https://h/b",
            f"{TS} [2] TRACE Api - Response, Status=500 (Error), Method=GET, Url=https://h/b",
            f"{TS} [1] TRACE Api - Response, Status=200 (OK), Method=GET, Url=https://h/a",
        ]
    )
    assert (a.path, a.status, a.response_line) == ("/a", 200, 3)
    assert (b.path, b.status, b.response_line) == ("/b", 500, 2)


def test_response_for_another_target_is_never_forced_onto_an_open_call() -> None:
    open_call, other = pair(
        [
            f"{TS} [1] TRACE Api - Request, Method=GET, Url=https://h/a",
            f"{TS} [1] TRACE Api - Response, Status=200 (OK), Method=GET, Url=https://h/zzz",
        ]
    )
    assert not open_call.paired and open_call.path == "/a"  # unanswered requests stay visible
    assert other.orphan and other.path == "/zzz"  # the stray response stays inspectable


# ---- [START] / [END] markers ----------------------------------------------------------------------------------------
def test_markers_pair_by_id_even_across_threads_and_out_of_order() -> None:
    a, b = pair(
        [
            f"{TS} [1] DEBUG Bus - [START] GetUser [aa11bb22] {{...}}",
            f"{TS} [2] DEBUG Bus - [START] SaveOrder [cc33dd44] {{...}}",
            f"{TS} [9] DEBUG Bus - [END] SaveOrder [cc33dd44]; Execution time=12ms",
            f"{TS} [7] DEBUG Bus - [END] GetUser [aa11bb22]; Execution time=3ms",
        ]
    )
    assert (a.path, a.response_line, a.duration_ms, a.match, a.confidence, a.form) == (
        "GetUser",
        3,
        3.0,
        "key",
        "high",
        "operation",
    )
    assert (b.path, b.response_line, b.duration_ms) == ("SaveOrder", 2, 12.0)


def test_end_without_a_start_and_duplicate_end_are_kept_as_orphans() -> None:
    first, duplicate, lone = pair(
        [
            f"{TS} [1] DEBUG Bus - [START] Job [aa11bb22]",
            f"{TS} [1] DEBUG Bus - [END] Job [aa11bb22]; Execution time=1ms",
            f"{TS} [1] DEBUG Bus - [END] Job [aa11bb22]; Execution time=1ms",  # duplicate log entry
            f"{TS} [1] DEBUG Bus - [END] Other [99887766]; Execution time=1ms",  # its START was rotated away
        ]
    )
    assert first.paired and not first.orphan
    assert duplicate.orphan and lone.orphan and not duplicate.paired


def test_start_without_end_stays_visible_as_unanswered() -> None:
    (tx,) = pair([f"{TS} [1] DEBUG Bus - [START] Slow [aa11bb22]"])
    assert not tx.paired and not tx.orphan and tx.response_line is None


# ---- verb + id calls ("Requesting [id] url" / "Received JSON: [id]" / "Request failed … (500)") ----------------------
def test_verb_and_id_call_with_a_multi_line_body() -> None:
    lines = [
        f"{TS} [3] DEBUG Client - Requesting [00000001] https://h/api/users.list?limit=10",
        f"{TS} [3] TRACE Client - Received JSON: [00000001] ",
        '{"ok":true,"users":[{"id":"U1"}]}',
        f"{TS} [3] DEBUG Other - unrelated",
    ]
    (tx,) = pair(lines)
    assert (tx.key, tx.path, tx.response_line, tx.match, tx.confidence) == (
        "00000001",
        "/api/users.list",
        1,
        "key",
        "high",
    )


def test_keyed_responses_pair_with_their_own_request_when_calls_interleave() -> None:
    a, b = pair(
        [
            f"{TS} [1] DEBUG Client - Requesting [00000001] https://h/a",
            f"{TS} [2] DEBUG Client - Requesting [00000002] https://h/a",  # same endpoint, concurrent
            f"{TS} [2] TRACE Client - Received JSON: [00000002] ",
            f"{TS} [1] TRACE Client - Received JSON: [00000001] ",
        ]
    )
    assert (a.key, a.response_line) == ("00000001", 3)
    assert (b.key, b.response_line) == ("00000002", 2)


def test_failure_line_without_an_id_pairs_by_thread_and_is_flagged_uncertain() -> None:
    (tx,) = pair(
        [
            f"{TS} [7] DEBUG Client - Requesting [00000007] https://h/x",
            f"{TS} [7] WARN  Client - Request failed. Reason: The remote server returned an error: (500) Internal Server Error.",
        ]
    )
    assert (tx.status, tx.match, tx.confidence, tx.uncertain) == (500, "thread", "medium", True)


def test_failure_line_on_another_thread_is_not_guessed() -> None:
    call, stray = pair(
        [
            f"{TS} [7] DEBUG Client - Requesting [00000007] https://h/x",
            f"{TS} [8] WARN  Client - Request failed after 12ms",
        ]
    )
    assert not call.paired
    assert stray.orphan


# ---- plain text requests: methods, retries, ids ----------------------------------------------------------------------
@pytest.mark.parametrize("method", ["GET", "POST", "PUT", "DELETE", "PATCH"])
def test_every_common_method_is_paired_by_request_id(method: str) -> None:
    (tx,) = pair(
        [
            f"{TS} INFO {method} /items/5 requestId=abc12345",
            f"{TS} INFO done status=200 requestId=abc12345 took 7ms",
        ]
    )
    assert (tx.method, tx.path, tx.status, tx.duration_ms, tx.match) == (method, "/items/5", 200, 7.0, "key")


def test_retries_with_the_same_id_pair_in_order() -> None:
    first, second = pair(
        [
            f"{TS} INFO GET /a requestId=rid00001",
            f"{TS} INFO done status=503 requestId=rid00001",
            f"{TS} INFO GET /a requestId=rid00001",  # retry
            f"{TS} INFO done status=200 requestId=rid00001",
        ]
    )
    assert (first.status, first.response_line) == (503, 1)
    assert (second.status, second.response_line) == (200, 3)


def test_trace_id_matches_when_there_is_no_request_id() -> None:
    (tx,) = pair(
        [
            f"{TS} INFO POST /pay traceId=4bf92f3577b34da6a3ce929d0e0e4736",
            f"{TS} INFO responded 402 traceId=4bf92f3577b34da6a3ce929d0e0e4736",
        ]
    )
    assert (tx.status, tx.match) == (402, "key")


def test_a_request_with_a_missing_response_and_an_answer_with_a_missing_request() -> None:
    waiting, orphan = pair(
        [
            f"{TS} INFO GET /lost requestId=rid00009",
            f"{TS} INFO done status=200 requestId=rid00042",  # answers a request that is not in this log
        ]
    )
    assert not waiting.paired and not waiting.orphan
    assert orphan.orphan and orphan.key == "rid00042" and orphan.status == 200


# ---- large and awkward input -------------------------------------------------------------------------------------------
def test_very_large_bodies_do_not_break_pairing() -> None:
    body = '{"data":"' + "x" * 2_000_000 + '"}'  # 2 MB on one line
    (tx,) = pair(
        [
            f"{TS} [3] DEBUG Client - Requesting [00000001] https://h/big",
            body,
            f"{TS} [3] TRACE Client - Received JSON: [00000001] ",
            body,
        ]
    )
    assert tx.paired and tx.response_line == 2


def test_lines_kept_per_transaction_are_bounded() -> None:
    lines = [f"{TS} [4] INFO Api - Request, Method=GET, Url=https://h/a"]
    lines += [f"{TS} [4] TRACE Api - Operation=Step{i}, Status=200 (OK)" for i in range(5000)]
    lines += [f"{TS} [4] INFO Api - Response, Status=200 (OK), Method=GET, Url=https://h/a"]
    (tx,) = pair(lines)
    assert tx.paired and len(tx.all_lines) <= 200
    assert tx.response_line == len(lines) - 1  # the response line itself is always kept


def test_lines_that_start_with_a_bracketed_timestamp_are_still_recognised() -> None:
    (tx,) = pair(
        [
            "[2026-11-13 10:00:00,000] [1] DEBUG Bus - [START] GetUser [aa11bb22]",
            "[2026-11-13 10:00:00,004] [1] DEBUG Bus - [END] GetUser [aa11bb22]; Execution time=4ms",
        ]
    )
    assert tx.paired and tx.duration_ms == 4.0


def test_json_and_xml_body_lines_are_never_taken_for_requests() -> None:
    lines = [
        f"{TS} [1] DEBUG Bus - [START] Job [aa11bb22]",
        '{"note":"[END] Job [aa11bb22]; Execution time=1ms"}',  # a body that merely quotes an end marker
        '[{"x":"[END] Job [aa11bb22]"}]',
        f"{TS} [1] DEBUG Bus - [END] Job [aa11bb22]; Execution time=9ms",
    ]
    (tx,) = pair(lines)
    assert tx.response_line == 3 and tx.duration_ms == 9.0


def test_pairing_a_large_log_stays_fast() -> None:
    """100,000 marker pairs plus bodies: pairing must not become quadratic or regex-bound."""
    import time

    lines: list[str] = []
    for i in range(100_000):
        lines.append(f"{TS} [{i % 50}] DEBUG Bus - [START] Op{i % 7} [id{i:08x}] " + f'{{"n":{i}}}')
        lines.append(f"{TS} [{i % 50}] DEBUG Bus - [END] Op{i % 7} [id{i:08x}]; Execution time={i % 9}ms")
        if i % 1000 == 0:
            lines.append('{"body":"' + "x" * 200_000 + '"}')  # an occasional huge body line
    started = time.perf_counter()
    transactions = pair(lines)
    elapsed = time.perf_counter() - started
    assert len(transactions) == 100_000 and all(t.paired for t in transactions)
    assert elapsed < 20.0, f"pairing took {elapsed:.1f}s"
