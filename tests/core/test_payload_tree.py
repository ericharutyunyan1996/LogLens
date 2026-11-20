"""JSON / XML payload detection and the lazy tree model: raw text is never altered, malformed input never raises,
huge payloads are paged, and XML declarations that could load or expand entities are refused."""

from __future__ import annotations

import json
import time

import pytest

from loglens.core.payload_tree import PAGE_SIZE, Node, find_payloads, parse


def keys(parsed, node: Node, start: int = 0, limit: int = 1000) -> list[str]:
    return [child.key for child in parsed.children(node, start, limit)]


# ---- detection -------------------------------------------------------------------------------------------------------
def test_json_after_a_log_prefix_keeps_the_exact_raw_slice() -> None:
    body = '{"user":{"id":7,"tags":["a","b"]},  "ok":true}'  # odd spacing must survive
    text = f"2026-11-13 10:00:00,000 [4] DEBUG Api - Response: {body} (took 5ms)"
    (found,) = find_payloads(text)
    assert (found.kind, found.raw) == ("json", body)
    assert text[found.start : found.end] == body


def test_several_payloads_and_plain_brackets_are_told_apart() -> None:
    text = 'thread [11] saw {"a":1} then [{"b":2}] and "[ERROR]" plus {not json}'
    assert [s.raw for s in find_payloads(text)] == ['{"a":1}', '[{"b":2}]']


def test_xml_with_namespaces_and_attributes_is_found() -> None:
    text = 'Body: <s:Envelope xmlns:s="http://x/soap"><s:Body id="1"><Ping>hi</Ping></s:Body></s:Envelope> end'
    (found,) = find_payloads(text)
    assert found.kind == "xml" and found.raw.startswith("<s:Envelope") and found.raw.endswith("</s:Envelope>")


def test_escaped_json_logged_as_a_string_is_recovered() -> None:
    text = r'payload="{\"id\":5,\"name\":\"a b\"}" sent'
    (found,) = find_payloads(text)
    assert found.derived and json.loads(found.raw) == {"id": 5, "name": "a b"}


@pytest.mark.parametrize(
    "text", ["", "no payload here", "{", "<NULL>", "a < b > c", "[]", "{broken: json}", "<a><b></a>"]
)
def test_non_payloads_are_not_reported(text: str) -> None:
    assert find_payloads(text) == []


# ---- JSON tree -------------------------------------------------------------------------------------------------------
def test_small_json_tree_and_formatted_text() -> None:
    raw = '{"a":1,"b":[true,null,"x"],"c":{"d":2.5}}'
    parsed = parse(raw)
    assert parsed.ok and parsed.raw == raw and parsed.root is not None
    assert keys(parsed, parsed.root) == ["a", "b", "c"]
    b = parsed.children(parsed.root)[1]
    assert (b.kind, b.size, b.preview) == ("array", 3, "[3 items]")
    assert [(n.kind, n.preview) for n in parsed.children(b)] == [("boolean", "true"), ("null", "null"), ("string", "x")]
    assert json.loads(parsed.formatted()) == json.loads(raw)
    assert parsed.raw == raw  # parsing and formatting did not touch the original


def test_deeply_nested_json_is_expanded_lazily() -> None:
    depth = 900
    raw = '{"n":' * depth + "1" + "}" * depth
    parsed = parse(raw)
    assert parsed.ok
    node = parsed.root
    for _ in range(depth):  # walks level by level: no recursion in the model
        assert node is not None
        (node,) = parsed.children(node)
    assert node is not None and node.preview == "1"


def test_large_array_is_paged_not_materialised() -> None:
    parsed = parse(json.dumps(list(range(300_000))))
    assert parsed.root is not None and parsed.root.size == 300_000
    first = parsed.children(parsed.root)
    assert len(first) == PAGE_SIZE and first[0].key == "[0]"
    last = parsed.children(parsed.root, 299_990, 100)
    assert [n.key for n in last][-1] == "[299999]" and len(last) == 10


def test_large_object_children_pages_in_order() -> None:
    parsed = parse(json.dumps({f"k{i}": i for i in range(5_000)}))
    assert parsed.root is not None
    assert keys(parsed, parsed.root, 0, 3) == ["k0", "k1", "k2"]
    assert keys(parsed, parsed.root, 4_998, 10) == ["k4998", "k4999"]


def test_search_finds_keys_and_values_in_document_order_and_navigates() -> None:
    parsed = parse('{"user":{"name":"Ada","mail":"ada@example.org"},"items":[{"name":"AdaX"},{"name":"Bob"}]}')
    hits = parsed.search("ada")
    assert [parsed.node_at(h).key for h in hits] == ["name", "mail", "name"]  # type: ignore[union-attr]
    assert parsed.search("nothing-like-this") == []
    assert parsed.search("ADA", case_sensitive=True) == []


def test_search_over_a_big_payload_is_fast_enough() -> None:
    parsed = parse(json.dumps([{"id": i, "v": f"value-{i}"} for i in range(60_000)]))
    started = time.perf_counter()
    hits = parsed.search("value-59999")
    assert len(hits) == 1
    assert time.perf_counter() - started < 5.0


def test_string_value_holding_json_offers_its_parsed_form() -> None:
    parsed = parse(json.dumps({"payload": '{"inner":[1,2,3]}'}))
    assert parsed.root is not None
    payload = parsed.children(parsed.root)[0]
    assert payload.kind == "string" and payload.expandable
    (inner,) = parsed.children(payload)
    assert keys(parsed, inner) == ["inner"]


# ---- malformed / empty ------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("raw", ['{"a": }', "{", '{"a":1,}', "[1,2", "not json", ""])
def test_malformed_json_gives_an_error_and_keeps_the_raw_text(raw: str) -> None:
    parsed = parse(raw, "json")
    assert not parsed.ok and parsed.error.startswith("Not valid JSON") and parsed.raw == raw
    assert parsed.formatted() == raw  # the viewer can still show it


@pytest.mark.parametrize("raw", ["<a><b></a>", "<a>", "<<>>", ""])
def test_malformed_xml_gives_an_error_and_keeps_the_raw_text(raw: str) -> None:
    parsed = parse(raw, "xml")
    assert not parsed.ok and parsed.error.startswith("Not valid XML") and parsed.raw == raw


def test_empty_containers_are_valid_and_empty() -> None:
    for raw in ("{}", "[]"):
        parsed = parse(raw)
        assert parsed.ok and parsed.root is not None and parsed.root.size == 0 and parsed.children(parsed.root) == []


# ---- XML tree ------------------------------------------------------------------------------------------------------------
def test_xml_tree_shows_attributes_namespaces_text_and_children() -> None:
    raw = '<s:Envelope xmlns:s="http://x/soap" v="2"><s:Body><Ping id="9">hello</Ping><Empty/></s:Body></s:Envelope>'
    parsed = parse(raw)
    assert parsed.ok and parsed.root is not None
    top = parsed.children(parsed.root)
    assert [n.key for n in top][:2] == ["@xmlns:s", "@v"]  # namespace declarations and attributes are visible
    body = next(n for n in top if n.key == "<s:Body>")
    ping, empty = parsed.children(body)
    assert (ping.key, ping.expandable) == ("<Ping>", True)  # has an attribute
    assert [(n.key, n.preview) for n in parsed.children(ping)] == [("@id", "9"), ("#text", "hello")]
    assert empty.key == "<Empty>" and not empty.expandable
    assert parsed.raw == raw


def test_xml_formatted_text_is_indented() -> None:
    parsed = parse("<a><b>1</b><c><d/></c></a>")
    assert parsed.formatted().splitlines()[0] == "<a>" and "  <b>1</b>" in parsed.formatted()


@pytest.mark.parametrize(
    "raw",
    [
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///c:/windows/win.ini">]><r>&x;</r>',
        '<!DOCTYPE r [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;">]><r>&b;&b;</r>',  # entity expansion bomb
        '<!doctype r SYSTEM "http://127.0.0.1:9/evil.dtd"><r/>',
    ],
)
def test_xml_with_dtd_or_entities_is_refused_never_expanded(raw: str) -> None:
    parsed = parse(raw, "xml")
    assert not parsed.ok and "security" in parsed.error and parsed.raw == raw


def test_large_xml_is_parsed_and_paged() -> None:
    raw = "<r>" + "".join(f'<i n="{i}">v{i}</i>' for i in range(40_000)) + "</r>"
    parsed = parse(raw)
    assert parsed.ok and parsed.root is not None and parsed.root.size == 40_000
    page = parsed.children(parsed.root, 39_990, 100)
    assert [n.key for n in page] == ["<i>"] * 10


def test_a_bracketed_body_that_fails_to_parse_is_reported_not_ignored() -> None:
    from loglens.core.payload_tree import find_malformed

    text = (
        '2026-11-13 10:00:00,000 [7] DEBUG Client - Received JSON:\n{"a": [1, 2,, }\n<a><b></a>\nplain {not json} line'
    )
    assert [(s.kind, s.raw) for s in find_malformed(text)] == [("json", '{"a": [1, 2,, }'), ("xml", "<a><b></a>")]
    assert find_payloads(text) == []  # ...while the valid-payload finder keeps skipping them
