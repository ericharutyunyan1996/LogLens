"""Signatures: group log lines that say "the same thing", and turn a group into a regex.

``signature_of(line)`` reduces a line to a stable *template*:

* Windows event lines (``EVENT_LINE``) → provider + event id (the template is the masked message);
* exceptions (``System.IO.IOException: …``, ``ValueError: …``) → exception type + masked message;
* anything else → the message without its header (leading timestamp, level word, bracketed thread/ids) with the
  variable parts — numbers, GUIDs, hex, IPs, paths, URLs, e-mails, quoted strings and secrets — replaced by
  placeholders such as ``<NUM>``.

``pattern_for(signature)`` turns a template back into a regex: literals escaped, whitespace flexible, placeholders as
non-greedy wildcards; it is checked against the line the signature came from.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from ..secrets import mask as mask_secrets
from ..timestamps import find_timestamp
from ..winevent.models import EVENT_LINE
from .knowledge import normalize_provider

KIND_EVENT = "event"
KIND_EXCEPTION = "exception"
KIND_TEXT = "text"

MAX_SCAN_CHARS = 2000  # only the start of huge lines (dumped payloads) decides their signature
MAX_TEMPLATE_CHARS = 400  # long enough to tell messages apart; bounded so keys, queues and patterns stay small
MIN_PATTERN_LITERAL_CHARS = 6  # a pattern with less fixed text than this would match almost any line
MAX_HEADER_TOKENS = 6  # level + a few bracketed thread/id fields; more than that is message, not header
HEADER_BRACKET_MAX_CHARS = 64  # a longer [...] block at the start is content, not a thread/id field
KEY_DIGEST_BYTES = 8  # 64-bit template hash: collisions are irrelevant at knowledge-base scale

_EVENT_DETAILS_SEPARATOR = " ‖ "  # event lines end with "‖ {json details}" (record id, pid…) that vary per event
_LEVELS = (
    "TRACE|DEBUG|DBG|INFO|INFORMATION|NOTICE|WARN|WARNING|WRN|ERROR|ERR|FATAL|CRITICAL|CRIT|SEVERE|ALERT|EMERG|"
    "EMERGENCY|VERBOSE|FINE|FINER|FINEST"
)
# What may precede a header timestamp: punctuation/digits ("[", "<34>", "17: ") and optionally a level word.
_HEADER_PREFIX = re.compile(rf"[\W\d_]*(?:(?:{_LEVELS})[\W_]*)?")
_HEADER_TOKEN = re.compile(
    rf"[\s|:,;>\])-]*(?:\[[^\]]{{0,{HEADER_BRACKET_MAX_CHARS}}}\]|\((?:{_LEVELS}|\d+)\)|<(?:{_LEVELS})>|(?:{_LEVELS})\b)"
)
_LEADING_SEPARATORS = re.compile(r"^[\s|:,;>\])-]+")

_EXCEPTION_TYPE = re.compile(r"(?<![\w.$])(?:[A-Za-z_$][\w$]*\.)*[A-Z][\w$]*(?:Exception|Error|Fault)\b(?!\()")
_EXCEPTION_TAIL = re.compile(r"\s*(?:\(\w+\))?\s*:")  # "Type: message" or "Type (10061): message"

# Variable parts of a message, in priority order (earlier alternatives win at the same position).
_VARIABLES = re.compile(
    "|".join(
        (
            r"(?P<SECRET>•+)",  # values already masked by core.secrets
            r"(?P<STR>(?<![\w\\])\"[^\"\r\n]*\"(?!\s*:)|(?<![\w\\])'[^'\r\n]*'(?!\s*:)(?!\w))",  # not JSON keys
            r"(?P<URL>\b[A-Za-z][A-Za-z0-9+.-]*://[^\s\"'<>]+)",
            r"(?P<EMAIL>\b[\w.%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b)",
            r"(?P<PATH>(?:\b[A-Za-z]:\\|\\\\)[^\s\"'<>|]*|(?<![\w.:/])/(?:[\w.@~+-]+/)+[\w.@~+-]*)",
            r"(?P<GUID>\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b)",
            r"(?P<IP>(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?(?![\d.])"
            r"|(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){4,7}[0-9A-Fa-f]{1,4}(?![\w:]))",
            r"(?P<HEX>\b0[xX][0-9A-Fa-f]+\b|\b(?=[0-9A-Fa-f]*\d)(?=[0-9A-Fa-f]*[A-Fa-f])[0-9A-Fa-f]{8,}\b)",
            r"(?P<NUM>(?<![A-Za-z\d])\d+(?:[.,:]\d+)*)",
        )
    )
)
_PLACEHOLDER = re.compile(r"<(SECRET|STR|URL|EMAIL|PATH|GUID|IP|HEX|NUM)>")
_PARTIAL_PLACEHOLDER = re.compile(r"<[A-Z]*$")
# Wildcards per placeholder: token-shaped values never contain spaces; quoted strings and secrets may.
_WILDCARDS = {"STR": ".*?", "SECRET": ".+?"}
_TOKEN_WILDCARD = r"\S+?"


@dataclass(frozen=True, slots=True)
class Signature:
    """What a line "says", independent of its variable parts. ``key`` identifies the group."""

    key: str
    provider: str | None  # event lines only
    event_id: int | None  # event lines only
    template: str  # masked message, e.g. "Timeout after <NUM> ms calling <URL>"
    kind: str = KIND_TEXT  # KIND_EVENT | KIND_EXCEPTION | KIND_TEXT
    sample: str = field(default="", compare=False)  # the line it was made from (for verification)


def _digest(text: str) -> str:
    return hashlib.blake2b(text.encode("utf-8"), digest_size=KEY_DIGEST_BYTES).hexdigest()


def _replace_variable(match: re.Match[str]) -> str:
    kind = match.lastgroup or "NUM"
    if kind == "STR":
        quote = match.group(0)[0]
        return f"{quote}<STR>{quote}"
    return f"<{kind}>"


def mask_template(text: str) -> str:
    """``text`` with secrets and variable parts replaced by placeholders, whitespace collapsed, length bounded."""
    masked = _VARIABLES.sub(_replace_variable, mask_secrets(text[:MAX_SCAN_CHARS]))
    template = " ".join(masked.split())
    if len(template) > MAX_TEMPLATE_CHARS:
        template = _PARTIAL_PLACEHOLDER.sub("", template[:MAX_TEMPLATE_CHARS]).rstrip()
    return template


def strip_header(line: str) -> str:
    """The message part of ``line``: without leading timestamp, level word and bracketed thread/id fields."""
    rest = line
    stamp = find_timestamp(line)
    if stamp is not None and _HEADER_PREFIX.fullmatch(line[: stamp.start]):
        rest = line[stamp.end :]
    for _ in range(MAX_HEADER_TOKENS):
        token = _HEADER_TOKEN.match(rest)
        if token is None:
            break
        rest = rest[token.end() :]
    message = _LEADING_SEPARATORS.sub("", rest).strip()
    return message or line.strip()


def _event_message(line: str, event: re.Match[str]) -> str:
    return line[event.end() :].split(_EVENT_DETAILS_SEPARATOR, 1)[0]


def _find_exception(line: str) -> re.Match[str] | None:
    for match in _EXCEPTION_TYPE.finditer(line, 0, MAX_SCAN_CHARS):
        if "." in match.group(0) or _EXCEPTION_TAIL.match(line, match.end()):
            return match
    return None


def signature_of(line: str) -> Signature:
    """The signature of one log line (see the module docstring for the three kinds)."""
    line = line.rstrip("\r\n")
    event = EVENT_LINE.match(line)
    if event is not None:
        provider, event_id = event["provider"], int(event["event_id"])
        template = mask_template(_event_message(line, event))
        key = f"{KIND_EVENT}:{normalize_provider(provider)}:{event_id}"
        return Signature(key, provider, event_id, template, KIND_EVENT, line)
    exception = _find_exception(line)
    if exception is not None:
        type_name = exception.group(0)
        template = mask_template(type_name + line[exception.end() :])
        key = f"{KIND_EXCEPTION}:{type_name}:{_digest(template)}"
        return Signature(key, None, None, template, KIND_EXCEPTION, line)
    template = mask_template(strip_header(line))
    return Signature(f"{KIND_TEXT}:{_digest(template)}", None, None, template, KIND_TEXT, line)


def _literal_regex(text: str) -> str:
    """Escaped ``text`` where each (collapsed) space may be any run of whitespace in the line."""
    return r"\s+".join(re.escape(word) for word in text.split(" "))


def _pattern_from_template(template: str) -> tuple[str, int]:
    """(regex, number of fixed non-space characters) for ``template``, without leading/trailing wildcards."""
    pieces = _PLACEHOLDER.split(template)  # literal, kind, literal, kind, …, literal
    tokens: list[tuple[bool, str]] = []  # (is_variable, literal text or placeholder kind)
    for index, piece in enumerate(pieces):
        if index % 2:
            tokens.append((True, piece))
        elif piece:
            tokens.append((False, piece))
    while tokens and (tokens[0][0] or not tokens[0][1].strip()):
        tokens.pop(0)
    while tokens and (tokens[-1][0] or not tokens[-1][1].strip()):
        tokens.pop()
    if not tokens:
        return "", 0
    tokens[0] = (False, tokens[0][1].lstrip())
    tokens[-1] = (False, tokens[-1][1].rstrip())
    parts: list[str] = []
    fixed = 0
    for is_variable, text in tokens:
        if is_variable:
            parts.append(_WILDCARDS.get(text, _TOKEN_WILDCARD))
        else:
            parts.append(_literal_regex(text))
            fixed += sum(1 for c in text if not c.isspace())
    return "".join(parts), fixed


def _message_of(signature: Signature) -> str:
    """The raw (unmasked) message part of the signature's sample line, used for the literal fallback pattern."""
    line = signature.sample
    event = EVENT_LINE.match(line)
    if event is not None:
        return _event_message(line, event).strip()
    exception = _find_exception(line)
    if exception is not None:
        return line[exception.start() :].strip()
    return strip_header(line)


def pattern_for(signature: Signature) -> str:
    """A regex (searched case-insensitively, like knowledge-base patterns) matching lines with this template.

    The regex is verified to match ``signature.sample``; if it somehow doesn't, an escaped literal of the sample's
    message is used instead. Raises ``ValueError`` if the template has too little fixed text to make a useful pattern.
    """
    regex, fixed = _pattern_from_template(signature.template)
    if fixed < MIN_PATTERN_LITERAL_CHARS:
        raise ValueError(f"'{signature.template}' has too little fixed text to recognise similar lines")
    if not signature.sample or re.search(regex, signature.sample, re.IGNORECASE):
        return regex
    literal = " ".join(_message_of(signature).split())[:MAX_TEMPLATE_CHARS].rstrip()
    fallback = _literal_regex(literal)
    if len(literal) >= MIN_PATTERN_LITERAL_CHARS and re.search(fallback, signature.sample, re.IGNORECASE):
        return fallback
    raise ValueError(f"could not build a pattern that matches {signature.sample[:80]!r}")
