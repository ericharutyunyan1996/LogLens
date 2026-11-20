"""Find personal data in a log for compliance reviews: e-mail addresses, card numbers, IBANs, phone numbers, ids,
IP addresses and secrets. Findings are reported with masked examples, so the report itself is safe to share.

Names and free-text personal data cannot be found reliably by patterns: the report says what it looked for.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from .secrets import find_secrets

KINDS = {
    "email": "E-mail address",
    "card": "Payment card number",
    "iban": "IBAN (bank account)",
    "phone": "Phone number",
    "ssn": "US social security number",
    "ip": "IP address",
    "secret": "Password, key or token",
}
MAX_EXAMPLES = 5
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}\b")
_CARD = re.compile(r"(?<![\w/.\-])(?:\d[ -]?){12,18}\d(?![\w/.\-])")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b")
_PHONE = re.compile(
    r"(?<![\w.\-/])(?:\+\d{1,3}[ .-]?)?(?:\(\d{2,4}\)[ .-]?|\d{2,4}[ .-])\d{3,4}[ .-]\d{3,4}(?![\w.\-/])"
)
_SSN = re.compile(r"(?<![\d-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\d-])")
_IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.]*\d)")
_TIMESTAMPISH = re.compile(r"^\d{4}[-/]\d{2}[-/]\d{2}")


@dataclass(slots=True)
class Finding:
    kind: str
    count: int = 0
    first_line: int = 0  # 0-based
    lines: int = 0  # lines that contain it
    examples: list[str] = field(default_factory=list)  # masked
    distinct: set[str] = field(default_factory=set)


_BRANDS = (  # (prefix pattern, allowed lengths): a card number starts like a known card brand
    (re.compile(r"4"), (13, 16, 19)),
    (re.compile(r"5[1-5]|2(?:2[2-9]\d|[3-6]\d\d|7[01]\d|720)"), (16,)),
    (re.compile(r"3[47]"), (15,)),
    (re.compile(r"6011|65|64[4-9]"), (16, 19)),
    (re.compile(r"35(?:2[89]|[3-8]\d)"), (16, 19)),
    (re.compile(r"3(?:0[0-5]|[68])"), (14,)),
    (re.compile(r"62"), (16, 17, 18, 19)),
)


def known_brand(digits: str) -> bool:
    return any(p.match(digits) and len(digits) in lengths for p, lengths in _BRANDS)


def luhn_ok(digits: str) -> bool:
    total, flip = 0, False
    for char in reversed(digits):
        n = int(char)
        if flip:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
        flip = not flip
    return total % 10 == 0


def iban_ok(text: str) -> bool:
    iban = text.replace(" ", "")
    if not 15 <= len(iban) <= 34:
        return False
    moved = iban[4:] + iban[:4]
    number = "".join(str(int(c, 36)) for c in moved)
    return int(number) % 97 == 1


def mask_value(kind: str, value: str) -> str:
    """Keep just enough to recognise the kind of value (``j***@example.com``, ``**** 1234``)."""
    if kind == "email":
        name, _, domain = value.partition("@")
        return f"{name[:1]}***@{domain}"
    if kind in ("card", "iban", "ssn", "phone"):
        digits = re.sub(r"\W", "", value)
        return f"****{digits[-4:]}"
    if kind == "ip":
        return ".".join(value.split(".")[:2]) + ".x.x"
    return "***"


def _candidates(line: str) -> Iterable[tuple[str, str]]:
    for m in _EMAIL.finditer(line):
        yield "email", m.group(0)
    for m in _CARD.finditer(line):
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and known_brand(digits) and luhn_ok(digits) and not _TIMESTAMPISH.match(m.group(0)):
            yield "card", digits
    for m in _IBAN.finditer(line):
        if iban_ok(m.group(0)):
            yield "iban", m.group(0).replace(" ", "")
    for m in _SSN.finditer(line):
        yield "ssn", m.group(0)
    for m in _PHONE.finditer(line):
        digits = re.sub(r"\D", "", m.group(0))
        if 8 <= len(digits) <= 15 and not _TIMESTAMPISH.match(m.group(0)) and not _CARD.fullmatch(m.group(0)):
            yield "phone", digits
    for m in _IPV4.finditer(line):
        if m.group(0) not in ("127.0.0.1", "0.0.0.0"):
            yield "ip", m.group(0)
    if "=" in line or ":" in line or "-" in line:
        for secret in find_secrets(line):
            yield "secret", f"{secret.kind}"


def scan(lines: Iterable[tuple[int, str]]) -> dict[str, Finding]:
    """Findings per kind over ``lines`` ((0-based number, text))."""
    found: dict[str, Finding] = {}
    for number, line in lines:
        seen: set[str] = set()
        for kind, value in _candidates(line):
            item = found.setdefault(kind, Finding(kind, first_line=number))
            item.count += 1
            item.distinct.add(value)
            if kind not in seen:
                item.lines += 1
                seen.add(kind)
            if len(item.examples) < MAX_EXAMPLES and mask_value(kind, value) not in item.examples:
                item.examples.append(mask_value(kind, value))
    return found


def render(found: dict[str, Finding], title: str = "Personal data scan") -> str:
    out = [f"# {title}", ""]
    if not found:
        out += ["No e-mail addresses, card numbers, IBANs, phone numbers, ids, IP addresses or secrets were found.", ""]
    else:
        out += [
            "| Kind | Occurrences | Distinct | Lines | First line | Examples (masked) |",
            "|---|---|---|---|---|---|",
        ]
        for kind, item in sorted(found.items(), key=lambda kv: -kv[1].count):
            out.append(
                f"| {KINDS.get(kind, kind)} | {item.count:,} | {len(item.distinct):,} | {item.lines:,} | "
                f"{item.first_line + 1:,} | {', '.join(item.examples)} |"
            )
        out.append("")
    out.append(
        "Names and free-text personal data are not found by this scan. "
        "Use “Save a share-safe copy” to mask what it found."
    )
    return "\n".join(out)
