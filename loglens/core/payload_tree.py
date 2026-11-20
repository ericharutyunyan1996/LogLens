"""Structured, lazily expandable views of JSON and XML payloads (no Qt).

``find_payloads`` locates JSON / XML in any text and keeps the exact original slice (``raw``): parsing and
formatting never replace it. ``parse`` builds a :class:`ParsedPayload` whose nodes are produced on demand, a page at a
time, so a payload with millions of nodes is never turned into a million widgets: the viewer only asks for the
children of what the user expands. Parsing itself can be slow for huge payloads — callers run it off the UI thread.

Security: XML is parsed with the standard expat parser, which resolves no external entities; on top of that any
``<!DOCTYPE`` / ``<!ENTITY`` declaration is refused (no entity expansion, no external resources). Malformed input is
reported as an ``error`` string, never raised, and the raw text stays available.
"""

from __future__ import annotations

import json
import re
from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any
from xml.dom import minidom
from xml.parsers.expat import ExpatError

PAGE_SIZE = 500  # children produced per request; a node with more shows "… N more" and loads the next page on demand
MAX_STRUCTURED_CHARS = 256_000_000  # beyond this only the raw text is offered (stated to the user, never silent)
PREVIEW_CHARS = 120  # characters of a scalar shown in the tree before "…" (the full value is one click / copy away)
COLLAPSE_CHARS = 10_000  # a payload bigger than this is shown collapsed (Inspector card, tree): open on demand
AUTO_EXPAND_NODES = 2_000  # a payload bigger than this opens collapsed; smaller ones expand to a readable depth
MAX_SEARCH_HITS = 2_000

_decoder = json.JSONDecoder()
_ELEMENT_START = re.compile(r"<(?:\?xml|[A-Za-z_][\w.\-]*(?::[\w.\-]+)?[\s>/])")
_DOCTYPE = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)", re.IGNORECASE)
_ESCAPED_JSON = re.compile(r"[{\[]\s*\\\"")  # {\"a\":1} — JSON that was itself logged as an escaped string
_MAX_XML_ATTEMPTS = 20


# ---- finding payloads in text ----------------------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class PayloadSlice:
    """A JSON or XML payload found in a text. ``raw`` is the exact original characters (or, for ``derived`` payloads
    such as escaped JSON, the unescaped text that was parsed)."""

    kind: str  # "json" | "xml"
    raw: str
    start: int = -1
    end: int = -1
    derived: bool = False


def _is_json_payload(value: object) -> bool:
    """A dict, or a list that holds data (not log decoration such as a thread id ``[11]``)."""
    if isinstance(value, dict):
        return True
    if not isinstance(value, list) or not value:
        return False
    return (
        any(isinstance(x, dict | list) for x in value) or len(value) >= 3 or any(isinstance(x, str) for x in value[1:])
    )


def _json_slices(text: str) -> Iterator[PayloadSlice]:
    pos, size = 0, len(text)
    while pos < size:
        starts = [s for s in (text.find("{", pos), text.find("[", pos)) if s >= 0]
        if not starts:
            return
        start = min(starts)
        try:
            value, end = _decoder.raw_decode(text, start)
        except (ValueError, RecursionError):
            pos = start + 1
            continue
        if _is_json_payload(value):
            yield PayloadSlice("json", text[start:end], start, end)
            pos = end
        else:
            pos = start + 1


def _escaped_json_slice(text: str) -> PayloadSlice | None:
    m = _ESCAPED_JSON.search(text)
    if m is None:
        return None
    candidate = text[m.start() :].replace('\\"', '"').replace("\\\\", "\\")
    try:
        value, end = _decoder.raw_decode(candidate)
    except (ValueError, RecursionError):
        return None
    return PayloadSlice("json", candidate[:end], derived=True) if _is_json_payload(value) else None


def _xml_slice(text: str) -> PayloadSlice | None:
    end = text.rfind(">")
    for attempt, m in enumerate(_ELEMENT_START.finditer(text)):
        if attempt >= _MAX_XML_ATTEMPTS or end <= m.start():
            break
        fragment = text[m.start() : end + 1]
        if _DOCTYPE.search(fragment):
            return PayloadSlice("xml", fragment, m.start(), end + 1)  # reported as refused by parse()
        try:
            minidom.parseString(fragment)
        except (ExpatError, ValueError):
            continue
        return PayloadSlice("xml", fragment, m.start(), end + 1)
    return None


def find_payloads(text: str) -> list[PayloadSlice]:
    """JSON and XML payloads in ``text`` (JSON first, in order; then XML; escaped JSON when nothing else matched).

    No size limit: the whole text is searched. Content that merely contains braces or angle brackets but is not valid
    JSON / XML is not returned."""
    found = list(_json_slices(text))
    xml = _xml_slice(text) if "<" in text else None
    if xml is not None and not any(s.start < xml.end and xml.start < s.end for s in found):
        found.append(xml)
    if not found:
        escaped = _escaped_json_slice(text)
        if escaped is not None:
            found.append(escaped)
    return sorted(found, key=lambda s: s.start)


_BRACKETED_LINE = re.compile(r"(?m)^[ \t]*([{\[<][^\n]*[}\]>])[ \t]*$")


def find_malformed(text: str) -> list[PayloadSlice]:
    """Lines that are one bracketed body (``{…}`` / ``[…]`` / ``<…>``) but are not valid JSON / XML.

    ``find_payloads`` skips these (braces alone prove nothing), but a body that looks like a payload and fails to parse
    deserves a clear error next to its untouched raw text instead of silence (``parse`` produces the error)."""
    out: list[PayloadSlice] = []
    for m in _BRACKETED_LINE.finditer(text):
        raw = m.group(1)
        if len(raw) < 4:
            continue
        kind = "xml" if raw.startswith("<") else "json"
        if not parse(raw, kind).ok:
            out.append(PayloadSlice(kind, raw, m.start(1), m.end(1)))
    return out[:5]


# ---- nodes ---------------------------------------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class Node:
    """One entry of the tree. ``value`` is the Python value (JSON) or the DOM node (XML) behind it."""

    key: str  # "name", "[3]", "<tag>", "@attr", "#text"
    kind: str  # object array string number boolean null | element attribute text | embedded
    value: Any
    size: int  # number of children (0 for scalars)
    preview: str  # one-line rendering shown in the tree

    @property
    def expandable(self) -> bool:
        return self.size > 0


def _clip(text: str) -> str:
    one_line = text.replace("\r", "").replace("\n", "\\n")
    return one_line if len(one_line) <= PREVIEW_CHARS else one_line[:PREVIEW_CHARS] + f"… ({len(text):,} chars)"


def _embedded(value: str) -> list[PayloadSlice]:
    """A string value that is itself a JSON / XML document (logged as an escaped string)."""
    stripped = value.strip()
    if len(stripped) < 2 or stripped[0] not in "{[<":
        return []
    return find_payloads(stripped)


def _json_node(key: str, value: Any) -> Node:
    if isinstance(value, dict):
        return Node(key, "object", value, len(value), f"{{{len(value):,} {'key' if len(value) == 1 else 'keys'}}}")
    if isinstance(value, list):
        return Node(key, "array", value, len(value), f"[{len(value):,} {'item' if len(value) == 1 else 'items'}]")
    if isinstance(value, bool):
        return Node(key, "boolean", value, 0, "true" if value else "false")
    if value is None:
        return Node(key, "null", value, 0, "null")
    if isinstance(value, int | float):
        return Node(key, "number", value, 0, str(value))
    text = str(value)
    inner = _embedded(text) if len(text) > 1 else []
    return Node(key, "string", text, 1 if inner else 0, _clip(text))


def _xml_nodes(parent: Any) -> Iterator[Node]:
    attributes = parent.attributes
    if attributes is not None:
        for name, value in attributes.items():
            yield Node(f"@{name}", "attribute", value, 0, _clip(value))
    for child in parent.childNodes:
        if child.nodeType == child.ELEMENT_NODE:
            count = len(child.childNodes) + (child.attributes.length if child.attributes is not None else 0)
            only_text = len(child.childNodes) == 1 and child.firstChild.nodeType == child.TEXT_NODE
            if only_text and not child.attributes.length:
                yield Node(f"<{child.tagName}>", "element", child, 0, _clip(child.firstChild.data.strip()))
            else:
                yield Node(f"<{child.tagName}>", "element", child, count, f"{count:,} nodes")
        elif child.nodeType in (child.TEXT_NODE, child.CDATA_SECTION_NODE) and child.data.strip():
            yield Node("#text", "text", child.data, 0, _clip(child.data.strip()))
        elif child.nodeType == child.COMMENT_NODE:
            yield Node("#comment", "text", child.data, 0, _clip(child.data))


@dataclass(slots=True)
class ParsedPayload:
    kind: str
    raw: str  # exactly what was found / given; never modified
    root: Node | None = None
    error: str = ""  # why there is no structured view ("" when parsed)
    document: Any = field(default=None, repr=False)

    @property
    def ok(self) -> bool:
        return self.root is not None

    @property
    def size_chars(self) -> int:
        return len(self.raw)

    def children(self, node: Node, start: int = 0, limit: int = PAGE_SIZE) -> list[Node]:
        """``limit`` children of ``node`` from index ``start`` (produced on demand, never the whole subtree)."""
        stop = start + limit
        if node.kind == "object":
            items = _slice_items(node.value.items(), start, stop)
            return [_json_node(str(k), v) for k, v in items]
        if node.kind == "array":
            return [_json_node(f"[{start + i}]", v) for i, v in enumerate(node.value[start:stop])]
        if node.kind == "string":  # a string holding JSON / XML: offer its parsed form as the single child
            parsed = [parse(s.raw, s.kind) for s in _embedded(node.value)[:1]]
            return [p.root for p in parsed if p.root is not None]
        if self.kind == "xml" and node.kind == "element":
            return list(_slice_items(_xml_nodes(node.value), start, stop))
        return []

    def iter_children(self, node: Node) -> Iterator[Node]:
        """All children of ``node`` one at a time (so counting / searching a huge container never builds a list)."""
        if node.kind == "object":
            for key, value in node.value.items():
                yield _json_node(str(key), value)
        elif node.kind == "array":
            for index, value in enumerate(node.value):
                yield _json_node(f"[{index}]", value)
        elif node.kind == "string":
            yield from self.children(node)
        elif self.kind == "xml" and node.kind == "element":
            yield from _xml_nodes(node.value)

    def _container(self, node: Node) -> bool:
        return node.kind in ("object", "array") or (self.kind == "xml" and node.kind == "element")

    def formatted(self) -> str:
        """Readable text of the whole payload (can be large: copy / export only, never rendered widget by widget)."""
        if not self.ok or self.root is None:
            return self.raw
        if self.kind == "json":
            return json.dumps(self.root.value, indent=2, ensure_ascii=False)
        lines = self.document.toprettyxml(indent="  ").splitlines()
        return "\n".join(x for x in lines if x.strip() and not x.startswith("<?xml"))

    def count_nodes(self, cap: int = 5_000_000) -> int:
        """Nodes in the whole tree (stops at ``cap``): used to decide whether to open expanded."""
        if self.root is None:
            return 0
        total, queue = 0, deque([self.root])
        while queue and total < cap:
            node = queue.popleft()
            total += 1
            if self._container(node):
                for child in self.iter_children(node):
                    queue.append(child)
                    if total + len(queue) >= cap:
                        return cap
        return total

    def search(self, query: str, limit: int = MAX_SEARCH_HITS, case_sensitive: bool = False) -> list[tuple[int, ...]]:
        """Paths (child indices from the root) of nodes whose key or value contains ``query``, in document order.

        Depth-first with one generator per open container: memory stays proportional to the depth, whatever the size."""
        if self.root is None or not query:
            return []
        needle = query if case_sensitive else query.lower()
        hits: list[tuple[int, ...]] = []
        stack: list[tuple[tuple[int, ...], Iterator[Node], int]] = []

        def matches(node: Node) -> bool:
            value = node.value if node.kind in ("string", "number", "attribute", "text") else node.preview
            haystack = f"{node.key}\t{value}"
            return needle in (haystack if case_sensitive else haystack.lower())

        if self._container(self.root):
            stack.append(((), self.iter_children(self.root), 0))
        while stack and len(hits) < limit:
            path, children, index = stack.pop()
            child = next(children, None)
            if child is None:
                continue
            stack.append((path, children, index + 1))
            child_path = (*path, index)
            if matches(child):
                hits.append(child_path)
            if self._container(child):
                stack.append((child_path, self.iter_children(child), 0))
        return hits

    def node_at(self, path: tuple[int, ...]) -> Node | None:
        node = self.root
        for index in path:
            if node is None:
                return None
            kids = self.children(node, index, 1)
            node = kids[0] if kids else None
        return node


def _slice_items(items: Any, start: int, stop: int) -> list[Any]:
    out: list[Any] = []
    for i, item in enumerate(items):
        if i >= stop:
            break
        if i >= start:
            out.append(item)
    return out


def parse(raw: str, kind: str | None = None) -> ParsedPayload:  # noqa: PLR0911 - one early return per failure kind
    """Parse ``raw`` as JSON or XML (``kind`` None: whichever it looks like). Never raises: failures set ``error``."""
    text = raw.strip()
    kind = kind or ("xml" if text.startswith("<") else "json")
    if len(raw) > MAX_STRUCTURED_CHARS:
        return ParsedPayload(
            kind, raw, error=f"Too large for the structured view ({len(raw):,} characters): raw text only."
        )
    if kind == "json":
        try:
            value = json.loads(text)
        except (ValueError, RecursionError) as exc:
            return ParsedPayload(kind, raw, error=f"Not valid JSON: {exc}")
        return ParsedPayload(kind, raw, _json_node("root", value), document=value)
    if _DOCTYPE.search(text):
        return ParsedPayload(kind, raw, error="DTD / entity declarations are not processed (security): raw text only.")
    try:
        document = minidom.parseString(text.encode("utf-8"))
    except (ExpatError, ValueError, RecursionError) as exc:
        return ParsedPayload(kind, raw, error=f"Not valid XML: {exc}")
    root = document.documentElement
    if root is None:
        return ParsedPayload(kind, raw, error="Not valid XML: no root element")
    count = len(root.childNodes) + (root.attributes.length if root.attributes is not None else 0)
    return ParsedPayload(
        kind, raw, Node(f"<{root.tagName}>", "element", root, count, f"{count:,} nodes"), document=document
    )
