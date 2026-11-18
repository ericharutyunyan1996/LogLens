"""Payload formatters: JSON, XML, JWT, URL/query, SQL, fields, base64, header blocks — and their combination."""

from __future__ import annotations

import base64
import json

import pytest

from loglens.core.payloads import analyze, pretty_text
from loglens.core.payloads.json_payload import JsonFormatter, is_payload
from loglens.core.payloads.sql_payload import format_sql

LOG_PREFIX = "2026-11-10 18:51:55,949 [11] TRACE Http.Trace - "


def kinds(text: str) -> list[str]:
    return [s.kind for s in analyze(text).located]


def b64url(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


# ---- JSON -----------------------------------------------------------------------------------------------------------
def test_json_after_log_prefix_with_json_looking_tokens() -> None:
    """``[11]`` (a thread id) is valid JSON but not a payload; the real body comes later."""
    line = LOG_PREFIX + '[Response] [00000002] Content : {"version":"1.1","total":0,"items":[]}'
    out = pretty_text(line)
    assert out.startswith(LOG_PREFIX.strip() + " [Response] [00000002] Content :")
    assert '── JSON ──\n{\n  "version": "1.1",' in out


def test_json_array_payload_and_several_payloads_per_line() -> None:
    assert kinds('[3] Content : [{"id":1},{"id":2}]') == ["JSON"]
    out = pretty_text('req={"a":1} resp={"b":2} done')
    assert out.index('"a": 1') < out.index("resp=") < out.index('"b": 2') and out.endswith("done")


def test_json_derived_sections() -> None:
    token = base64.b64encode(b'{"scrollId":"abc","page":2}').decode()
    line = json.dumps({"status": 200, "body": '{"user":{"id":7}}', "error": "boom\n   at A.B()", "next": token})
    out = pretty_text(line)
    assert "── body (embedded JSON) ──" in out and '"id": 7' in out
    assert "── error (text) ──\nboom\n   at A.B()" in out
    assert "── next (base64 → JSON) ──" in out and '"scrollId": "abc"' in out


def test_json_decoration_is_not_payload() -> None:
    assert not is_payload([11]) and not is_payload([1, 2, 3]) and not is_payload("x")
    assert is_payload({}) and is_payload([{"a": 1}]) and is_payload(["a", "b"])
    assert JsonFormatter().find("[12] INFO numbers [1, 2, 3] only") == []


# ---- XML ------------------------------------------------------------------------------------------------------------
def test_xml_after_placeholder_tokens() -> None:
    out = pretty_text("Sender: <NULL> payload <order id='5'><item>x</item></order> end")
    assert "── XML ──" in out and '<order id="5">' in out and out.endswith("end")


def test_soap_envelope_with_namespaces() -> None:
    soap = (
        '<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>'
        '<GetUser xmlns="urn:x"><Id>5</Id></GetUser></s:Body></s:Envelope>'
    )
    assert kinds("Request body: " + soap) == ["XML"]
    assert "<s:Body>" in pretty_text("Request body: " + soap)


def test_broken_xml_is_left_alone() -> None:
    line = "value <NULL> and <2588330> and a < b > c"
    assert pretty_text(line) == line


# ---- JWT ------------------------------------------------------------------------------------------------------------
def test_jwt_decoded_with_times() -> None:
    token = f"{b64url({'alg': 'RS256', 'typ': 'JWT'})}.{b64url({'sub': 'u1', 'exp': 1794000000})}.c2lnbmF0dXJl"
    out = pretty_text(f"Authorization: Bearer {token}")
    assert "── JWT ──" in out and '"sub": "u1"' in out and "exp = 2026-" in out
    assert "signature not verified" in out


# ---- URL / query string ---------------------------------------------------------------------------------------------
def test_url_with_query_is_decoded() -> None:
    out = pretty_text("GET https://api.example.com/v1/search?q=hello%20world&page=2&tags=a%2Cb returned 200")
    assert "── URL ──\nhttps://api.example.com\npath: /v1/search" in out
    assert "q    = hello world" in out and "tags = a,b" in out and out.endswith("returned 200")


def test_plain_url_and_bare_query_string() -> None:
    assert kinds("see https://example.com/docs/page for details") == []
    assert kinds("form data: user=alice&role=admin&active=true") == ["Query string"]


# ---- SQL ------------------------------------------------------------------------------------------------------------
def test_sql_statement_is_split_into_clauses() -> None:
    sql = (
        "SELECT o.Id, c.Name FROM Orders o INNER JOIN Customers c ON c.Id = o.CustomerId WHERE o.Total > 10 AND "
        "c.Name = 'A AND B' ORDER BY o.Id"
    )
    out = format_sql(sql)
    assert out.splitlines() == [
        "SELECT o.Id, c.Name",
        "FROM Orders o",
        "INNER JOIN Customers c",
        "ON c.Id = o.CustomerId",
        "WHERE o.Total > 10",
        "    AND c.Name = 'A AND B'",
        "ORDER BY o.Id",
    ]
    assert kinds("Executing: " + sql) == ["SQL"]


def test_prose_is_not_sql() -> None:
    assert kinds("Please select a file from the list") == []


# ---- key=value / fields ---------------------------------------------------------------------------------------------
def test_logfmt_fields() -> None:
    out = pretty_text('at=info method=GET path=/ status=200 msg="request done" duration=12ms')
    assert "── Fields ──" in out and "msg      = request done" in out


def test_colon_fields_and_minimum_counts() -> None:
    out = pretty_text("New instance created. DisplayName: Archive, Id: 8c3563ec-5f64-4228-9f54-fd7bd347def3.")
    assert "DisplayName = Archive" in out and "Id          = 8c3563ec" in out
    assert kinds("only a=1 b=2 here") == []  # fewer than 3 key=value pairs


# ---- base64 ---------------------------------------------------------------------------------------------------------
def test_base64_text_decoded_but_hex_ids_ignored() -> None:
    token = base64.b64encode(b"Hello from a base64 encoded message body!").decode()
    assert "Hello from a base64" in pretty_text(f"payload={token}")
    assert kinds("hash 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08") == []


# ---- header blocks (multi-line records) -----------------------------------------------------------------------------
def test_header_block_in_multiline_record() -> None:
    record = (
        "[ResponseHeader] [00000002] Connection : keep-alive\nContent-Type : application/json\n"
        "Content-Length : 4445\nServer : nginx"
    )
    out = pretty_text(record)
    assert "── Headers ──" in out and "Content-Length : 4445" in out


# ---- combination ----------------------------------------------------------------------------------------------------
def test_overlap_priority_url_inside_json_stays_json() -> None:
    line = 'event {"callback":"https://h.example/cb?x=1&y=2","ok":true}'
    assert kinds(line) == ["JSON"]


def test_plain_text_unchanged_and_giant_lines_skipped() -> None:
    assert pretty_text("just a normal log line") == "just a normal log line"
    assert pretty_text("plain line {not json") == "plain line {not json"


def test_malformed_bracketed_host_is_not_a_url_payload() -> None:
    """Regression: urlsplit raises "Invalid IPv6 URL" for an unclosed bracket; the line must still be analysed."""
    text = 'GET http://[fe80::1%eth0/x?a=1 then {"ok": true}'
    analysis = analyze(text)
    assert "URL" not in analysis.kinds
    assert "JSON" in analysis.kinds


def test_a_failing_formatter_does_not_hide_the_others(caplog: pytest.LogCaptureFixture) -> None:
    class Broken:
        kind = "Broken"

        def find(self, text: str) -> list:
            raise RuntimeError("bug")

    analysis = analyze('{"ok": true}', (Broken(), JsonFormatter()))
    assert analysis.kinds == ["JSON"]
    assert "Broken formatter failed" in caplog.text
