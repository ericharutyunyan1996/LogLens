"""Redact sensitive values before log text leaves the machine.

Values are replaced by *consistent* placeholders (the same IP is always ``<IP_1>`` within one request), so the
model can still reason about "the same host failed three times" without seeing the host.

Secrets are redacted in three passes: the body lines of private keys logged line by line (the BEGIN line opens a
block, base64-only lines up to the END line are key material, even with the ``L12|>>`` numbering of an AI excerpt),
the broad rules below (deliberately eager — over-redacting before sending is harmless), then everything
:func:`loglens.core.secrets.find_secrets` detects, so AI redaction always covers at least what LogLens flags as a
secret in the viewer.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from ..secrets import SecretKind, find_secrets, private_key_open_after
from .config import Redact


@dataclass(frozen=True, slots=True)
class _Rule:
    category: Redact
    label: str  # placeholder label: <LABEL_n>
    pattern: re.Pattern[str]
    group: int | str = 0  # the group holding the value to replace
    keep: Callable[[re.Match[str], str], bool] | None = None  # True = not sensitive after all: leave the match


_SECRET_KEYS = (
    r"password|passwd|pwd|pass|secret|client_secret|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|token|"
    r"auth|authorization|sig|signature|private[_-]?key|connectionstring|sharedaccesskey|accountkey"
)
_SEP = r"(?:\\{1,2}|/)"  # a path separator, also JSON-escaped (C:\\Users\\name)
# Words that look like user names but name built-in accounts or say "no user".
_KEEP_USERS = frozenset({
    "public", "default", "default user", "all users", "<user>", "system", "localsystem", "local service",
    "network service", "administrator", "administrators", "guest", "everyone", "anonymous", "-", "none", "null",
    "unknown", "n/a",
})  # fmt: skip
# Upper-case "DOMAIN\name" prefixes that are not account domains: built-in principals and registry hives.
_KEEP_DOMAINS = frozenset(
    {"AUTHORITY", "BUILTIN", "APPPOOL", "SERVICE", "MACHINE", "HKLM", "HKCU", "HKCR", "HKCC", "HKU"}
)
_USER_KEY = r"(?:user(?:[ _-]?name)?|account[ _-]?name|log[io]n(?:[ _-]?name)?|upn|samaccountname)"


def _keep_user(_match: re.Match[str], value: str) -> bool:
    return value.lower() in _KEEP_USERS


def _keep_domain_user(match: re.Match[str], value: str) -> bool:
    return match["domain"] in _KEEP_DOMAINS or _keep_user(match, value)


def _keep_ipv6(_match: re.Match[str], value: str) -> bool:
    """Only real (compressed) IPv6 addresses: not "::" separators, C++ scopes or times."""
    if "::" not in value or not value.strip(":"):
        return True
    try:
        ipaddress.IPv6Address(value)
    except ValueError:
        return True
    return False


# Ordered: specific patterns before generic ones.
_RULES: tuple[_Rule, ...] = (
    _Rule(Redact.SECRETS, "JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")),
    _Rule(Redact.SECRETS, "TOKEN", re.compile(r"(?i)\b(?:bearer|basic)\s+([A-Za-z0-9._~+/=-]{12,})"), 1),
    _Rule(Redact.SECRETS, "CREDENTIALS", re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://([^/\s:@]+:[^/\s@]+)@"), 1),
    _Rule(
        Redact.SECRETS,
        "SECRET",
        re.compile(rf"(?i)\b(?:{_SECRET_KEYS})[\"']?\s*[:=]\s*[\"']?([^\s\"'&;,<>]{{3,}})"),
        1,
    ),
    _Rule(
        Redact.SECRETS,
        "KEY",
        re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"),
    ),
    _Rule(Redact.EMAILS, "EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    _Rule(
        Redact.IP_ADDRESSES,
        "IP",
        re.compile(r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])"),
    ),
    _Rule(Redact.IP_ADDRESSES, "IP", re.compile(r"(?i)(?<![\w:])(?:[0-9a-f]{1,4}:){4,7}[0-9a-f]{1,4}(?![\w:])")),
    _Rule(  # compressed IPv6 (fe80::1ff:fe23:4567:890a, 2001:db8::7); candidates are validated
        Redact.IP_ADDRESSES,
        "IP",
        re.compile(r"(?i)(?<![\w:.])[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?![\w:])"),
        keep=_keep_ipv6,
    ),
    _Rule(  # C:\Users\name, C:\\Users\\name (JSON), C:/Users/name, \\server\c$\Users\name, /home/name, /Users/name
        Redact.USER_PATHS,
        "USER",
        re.compile(
            rf"(?i)(?:\b[a-z]:{_SEP}users{_SEP}|\\{{2}}(?:\\{{2}})?[\w.-]+{_SEP}(?:[a-z]\${_SEP})?users{_SEP}"
            r"|/home/|/Users/)([^\\/\s\"']+)"
        ),
        1,
        _keep_user,
    ),
    _Rule(  # CONTOSO\jdoe, CONTOSO\\jdoe (NetBIOS domains are upper case; paths and registry keys are excluded)
        Redact.USER_PATHS,
        "USER",
        re.compile(
            r"(?<![\w\\.$/%-])(?P<domain>[A-Z][A-Z0-9-]{1,14})\\{1,2}(?P<user>[A-Za-z](?:[\w.$-]{0,62}[\w$])?)"
            r"(?![\w$\\/-]|\.\w)"
        ),
        "user",
        _keep_domain_user,
    ),
    _Rule(  # user 'jdoe', Login failed for user "jdoe", "username": "jdoe", Account Name: 'jdoe'
        Redact.USER_PATHS,
        "USER",
        re.compile(rf"(?i)\b{_USER_KEY}[\"']?\s*[:=]?\s*(?P<q>[\"'])(?P<user>[^\"'\s<>]{{1,64}})(?P=q)"),
        "user",
        _keep_user,
    ),
    _Rule(  # user=jdoe, Account Name: jdoe, UserName: jdoe (not followed by a path or domain separator)
        Redact.USER_PATHS,
        "USER",
        re.compile(
            r"(?i)\b(?:user(?:[ _-]?name)?|account[ _-]?name|log[io]n[ _-]?name|upn|samaccountname)\s*[:=][ \t]*"
            r"(?P<user>[A-Za-z](?:[\w.$-]{0,62}[\w$])?)(?![\w$\\/-]|\.\w)"
        ),
        "user",
        _keep_user,
    ),
    _Rule(Redact.GUIDS, "GUID", re.compile(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")),
    _Rule(
        Redact.HOSTNAMES,
        "HOST",
        re.compile(
            r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){2,}(?:com|net|org|io|local|corp|internal|[a-z]{2})\b"
        ),
    ),
)
_LAST_SECRET_RULE = max(i for i, rule in enumerate(_RULES) if rule.category is Redact.SECRETS)
# A base64-only line inside a private key block, with the "L12|" / "L12|>>" numbering of an AI excerpt (or ">>").
_KEY_BODY_LINE = re.compile(r"(?:L\d+\|)?(?:>>)?[ \t]*(?P<value>[A-Za-z0-9+/=]+)[ \t]*\r?")
# Placeholder labels for what core.secrets detects (anything not listed is a SECRET).
_SECRET_LABELS: dict[SecretKind, str] = {
    SecretKind.JWT: "JWT",
    SecretKind.AUTHORIZATION: "TOKEN",
    SecretKind.BEARER_TOKEN: "TOKEN",
    SecretKind.BASIC_CREDENTIALS: "TOKEN",
    SecretKind.URL_PASSWORD: "CREDENTIALS",
    SecretKind.PRIVATE_KEY: "KEY",
    SecretKind.API_KEY: "API_KEY",
    SecretKind.AZURE_STORAGE_KEY: "API_KEY",
    SecretKind.SESSION: "SESSION",
    SecretKind.COOKIE: "SESSION",
    SecretKind.AUTH_CODE: "TOKEN",
}


@dataclass
class RedactionResult:
    text: str
    counts: Counter[str] = field(default_factory=Counter)  # placeholder label -> replacements

    @property
    def total(self) -> int:
        return sum(self.counts.values())


class Redactor:
    """Applies the enabled categories; one instance per request keeps placeholders consistent."""

    def __init__(self, categories: Iterable[Redact]) -> None:
        self._categories = set(categories)
        self._mapping: dict[tuple[str, str], str] = {}
        self._next: Counter[str] = Counter()

    def _placeholder(self, label: str, value: str) -> str:
        key = (label, value)
        if key not in self._mapping:
            self._next[label] += 1
            self._mapping[key] = f"<{label}_{self._next[label]}>"
        return self._mapping[key]

    def redact(self, text: str) -> RedactionResult:
        counts: Counter[str] = Counter()
        if Redact.SECRETS in self._categories:
            text = self._redact_key_bodies(text, counts)
        for index, rule in enumerate(_RULES):
            if rule.category not in self._categories:
                continue

            def replace(m: re.Match[str], rule: _Rule = rule) -> str:
                value = m.group(rule.group)
                if rule.keep is not None and rule.keep(m, value):
                    return m.group(0)
                counts[rule.label] += 1
                start, end = m.start(rule.group) - m.start(), m.end(rule.group) - m.start()
                whole = m.group(0)
                return whole[:start] + self._placeholder(rule.label, value) + whole[end:]

            text = rule.pattern.sub(replace, text)
            if index == _LAST_SECRET_RULE:  # the broad secret rules are done: add what core.secrets detects
                text = self._redact_detected_secrets(text, counts)
        return RedactionResult(text, counts)

    def _redact_key_bodies(self, text: str, counts: Counter[str]) -> str:
        """Base64-only lines after a BEGIN … PRIVATE KEY line, up to the END line or the end of the text."""
        if "-----" not in text:  # no key marker at all: the common case
            return text
        lines = text.split("\n")
        inside = False
        for index, line in enumerate(lines):
            body = _KEY_BODY_LINE.fullmatch(line) if inside else None
            if body is None:
                inside = private_key_open_after(line, inside=inside)
                continue
            counts["KEY"] += 1
            placeholder = self._placeholder("KEY", body["value"])
            lines[index] = line[: body.start("value")] + placeholder + line[body.end("value") :]
        return "\n".join(lines)

    def _redact_detected_secrets(self, text: str, counts: Counter[str]) -> str:
        parts: list[str] = []
        position = 0
        for secret in find_secrets(text):
            label = _SECRET_LABELS.get(secret.kind, "SECRET")
            counts[label] += 1
            parts.append(text[position : secret.start])
            parts.append(self._placeholder(label, text[secret.start : secret.end]))
            position = secret.end
        parts.append(text[position:])
        return "".join(parts)
