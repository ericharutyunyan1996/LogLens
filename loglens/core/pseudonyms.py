"""A share-safe copy of a log: secrets masked, and people / machines replaced by consistent pseudonyms.

"Consistent" is the point: the same user, address or host gets the same pseudonym everywhere in the copy, so the
story of the log stays readable (``user3`` failed to log in from ``ip7``) while the real names stay out of it.
The mapping lives only in memory; saving it next to the copy is the user's explicit choice.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from .secrets import SecretMasker

KINDS = ("email", "ip", "host", "user")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}\b")
_IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.]*\d)")
_IPV6 = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{1,4}:){4,7}[0-9a-fA-F]{1,4}(?![\w:])")
_HOST = re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.){2,}[A-Za-z]{2,24}\b")
_UNC = re.compile(r"(?<![\w\\])\\\\([A-Za-z0-9][\w.\-]{0,62})(?=\\|\b)")
_DOMAIN_USER = re.compile(r"(?<![\w\\/:.])([A-Za-z][\w\-]{1,30})\\([A-Za-z0-9][\w.\-$]{0,40})\b")
_USER_FIELD = re.compile(
    r"(?i)\b(?P<key>user(?:name|_name|id)?|login|account|principal|usr)(?P<sep>\s*[=:]\s*|\s+)"
    r"(?P<q>[\"']?)(?P<value>[A-Za-z0-9][\w.\-$]{1,40})(?P=q)"
)
TLDS = {
    "com",
    "net",
    "org",
    "io",
    "local",
    "internal",
    "corp",
    "lan",
    "edu",
    "gov",
    "int",
    "info",
    "biz",
    "dev",
    "cloud",
    "app",
    "xyz",
    "online",
    "site",
    "tech",
    "home",
    "intra",
    "intranet",
    "test",
    "example",
    "invalid",
    "mil",
}  # fmt: skip - besides two-letter country codes
_KEEP_HOSTS = {"localhost"}
_KEEP_USERS = {
    "unknown",
    "null",
    "none",
    "system",
    "anonymous",
    "guest",
    "admin",
    "root",
    "true",
    "false",
    "n/a",
    "from",
    "failed",
    "logged",
    "is",
    "was",
    "not",
    "has",
    "have",
    "name",
    "id",
    "account",
    "login",
    "with",
    "and",
    "the",
    "in",
    "on",
    "to",
    "for",
    "by",
    "at",
    "a",
    "an",
    "of",
    "denied",
    "locked",
    "created",
    "deleted",
    "disabled",
    "enabled",
    "added",
    "removed",
    "changed",
    "session",
    "authenticated",
    "lockout",
    "sign",
    "signed",
    "logon",
    "logoff",
    "connected",
    "disconnected",
    "attempt",
    "authentication",
    "password",
    "credentials",
    "token",
}  # fmt: skip - values that follow "user" / "login" in prose are words, not people
_FILE_SUFFIXES = {
    "log",
    "txt",
    "xml",
    "json",
    "csv",
    "dll",
    "exe",
    "cs",
    "py",
    "js",
    "ts",
    "java",
    "cpp",
    "h",
    "config",
    "ini",
    "yml",
    "yaml",
    "md",
    "html",
    "htm",
    "evtx",
    "zip",
    "sql",
    "bak",
    "tmp",
    "pdb",
    "so",
    "jar",
    "class",
    "go",
    "rs",
}  # fmt: skip - "Foo.Bar.cs" in a stack trace is a file, not a host


@dataclass(slots=True)
class Pseudonymizer:
    """Replaces what identifies people and machines; call :meth:`line` for every line of one log, in order."""

    kinds: frozenset[str] = frozenset(KINDS)
    secrets: bool = True
    mapping: dict[str, dict[str, str]] = field(default_factory=lambda: {k: {} for k in KINDS})
    _masker: SecretMasker = field(default_factory=SecretMasker)

    def _name(self, kind: str, original: str, make: Callable[[int], str]) -> str:
        table = self.mapping[kind]
        key = original.lower()
        if key not in table:
            table[key] = make(len(table) + 1)
        return table[key]

    def _email(self, m: re.Match[str]) -> str:
        return self._name("email", m.group(0), lambda n: f"person{n}@example.invalid")

    def _ip(self, m: re.Match[str]) -> str:
        text = m.group(0)
        if text in ("0.0.0.0", "127.0.0.1", "255.255.255.255"):
            return text
        return self._name("ip", text, lambda n: f"192.0.2.{n}" if n < 255 else f"198.51.100.{n % 255 or 1}")

    def _ipv6(self, m: re.Match[str]) -> str:
        return self._name("ip", m.group(0), lambda n: f"2001:db8::{n:x}")

    def _host(self, m: re.Match[str]) -> str:
        text = m.group(0)
        last = text.rsplit(".", 1)[1].lower()
        known = last in TLDS or (len(last) == 2 and last not in _FILE_SUFFIXES)
        if not known or text.lower() in _KEEP_HOSTS or text.endswith(".example.invalid"):
            return text
        return self._name("host", text, lambda n: f"host{n}.example.invalid")

    def _unc(self, m: re.Match[str]) -> str:
        return "\\\\" + self._name("host", m.group(1), lambda n: f"host{n}")

    def _user(self, original: str) -> str:
        already = re.fullmatch(r"user\d+", original) is not None  # our own pseudonym: never replaced twice
        if already or original.lower() in _KEEP_USERS or original.endswith("$"):  # well-known and machine accounts stay
            return original
        return self._name("user", original, lambda n: f"user{n}")

    def _domain_user(self, m: re.Match[str]) -> str:
        user = self._user(m.group(2))
        if user == m.group(2) and m.group(2).lower() in _KEEP_USERS:
            return m.group(0)
        return f"{self._name('host', m.group(1), lambda n: f'domain{n}')}\\{user}"

    def _field_user(self, m: re.Match[str]) -> str:
        value = m.group("value")
        replaced = self._user(value)
        if "sep" in m.groupdict():
            return f"{m.group('key')}{m.group('sep')}{m.group('q')}{replaced}{m.group('q')}"
        return f"{m.group('key')} {m.group('q')}{replaced}{m.group('q')}"

    def line(self, text: str) -> str:
        if self.secrets:
            text = self._masker.mask_line(text)
        kinds = self.kinds
        if "email" in kinds and "@" in text:
            text = _EMAIL.sub(self._email, text)
        if "ip" in kinds:
            if "." in text:
                text = _IPV4.sub(self._ip, text)
            if ":" in text:
                text = _IPV6.sub(self._ipv6, text)
        if "user" in kinds:
            if "\\" in text:
                text = _DOMAIN_USER.sub(self._domain_user, text)
            text = _USER_FIELD.sub(self._field_user, text)
        if "host" in kinds:
            if text.startswith("\\\\") or "\\\\" in text:
                text = _UNC.sub(self._unc, text)
            if "." in text:
                text = _HOST.sub(self._host, text)
        return text

    def lines(self, texts: Iterable[str]) -> list[str]:
        return [self.line(t) for t in texts]

    def table(self) -> list[tuple[str, str, str]]:
        """(kind, original, pseudonym) for the mapping file; originals are lower-cased as they were matched."""
        return [(kind, original, pseudo) for kind, items in self.mapping.items() for original, pseudo in items.items()]

    def counts(self) -> dict[str, int]:
        return {kind: len(items) for kind, items in self.mapping.items() if items}
