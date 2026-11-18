"""Find and mask secrets (passwords, tokens, API keys, private keys) in log text.

Detection is shape-based and generic: well-known token formats (JWTs, ``sk-`` / ``AKIA`` / ``ghp_`` / ``xox?-`` /
``AIza`` keys, PEM private keys), credentials in URLs and ``Authorization`` headers, Azure storage keys and SAS
signatures, session cookies and authentication tickets, OAuth authorization codes and SAML responses, values of
secret-ish keys in query strings, ``key=value`` pairs, JSON, XML and connection strings, and long high-entropy tokens
next to secret-ish key names.

A match spans only the secret *value*, so :func:`mask` keeps key names readable (``password=••••••``). Text without
any secret-ish hint (most log lines) is rejected by a cheap substring prefilter before any regex runs.

A private key logged line by line has its BEGIN line and its base64 body on different lines; :class:`SecretMasker`
carries "inside a key block" from line to line so per-line views mask the body lines too.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import re
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum

MASK = "••••••"  # fixed width: a mask never reveals how long the secret was
# Shannon entropy (bits per character) a token needs to count as random. Random base64/hex tokens of
# MIN_ENTROPY_TOKEN_CHARS or more score ~3.6-4.5; identifiers, words and repetitive ids score lower.
ENTROPY_THRESHOLD = 3.5
MIN_ENTROPY_TOKEN_CHARS = 20  # shorter tokens next to a key name are too often ordinary words, ids or counters
MIN_WEAK_VALUE_CHARS = 3  # ambiguous keys (pass=, auth=, sig=) with shorter values are flags/switches, not secrets
MIN_BEARER_TOKEN_CHARS = 16  # "Bearer <word>" in prose is shorter; real opaque tokens are longer
MAX_CONNECTION_PASSWORD_CHARS = 128  # a connection-string password may contain spaces: bound how far it can run
# Session ids are 20-40 random characters (ASP.NET 24, PHP 26-32, Java 32); shorter values of "*session*=" keys are
# counters, timeouts or states (session_timeout=30, sessionState=Active).
MIN_SESSION_ID_CHARS = 12
MIN_COOKIE_VALUE_CHARS = 16  # any cookie value at least this long and random-looking is treated as a credential
MIN_AUTH_CODE_CHARS = 10  # OAuth codes are long; "?code=404" / "?code=1" are status or test values


class SecretKind(StrEnum):
    """What kind of secret a match is."""

    PRIVATE_KEY = "private-key"  # body of a PEM "-----BEGIN … PRIVATE KEY-----" block
    JWT = "jwt"
    API_KEY = "api-key"  # vendor-shaped keys: sk-…, AKIA…, ghp_…, xox?-…, AIza…
    AZURE_STORAGE_KEY = "azure-storage-key"  # AccountKey= / SharedAccessKey=
    SAS_SIGNATURE = "sas-signature"  # sig= of a shared access signature URL
    URL_PASSWORD = "url-password"  # scheme://user:password@host
    AUTHORIZATION = "authorization"  # value of an Authorization header
    BEARER_TOKEN = "bearer-token"
    BASIC_CREDENTIALS = "basic-credentials"  # base64("user:password") after "Basic"
    PASSWORD = "password"  # password= / pwd= / "password": … / <password>… / Password=…;
    SECRET = "secret"  # token= / secret= / apikey= / client_secret= … (any syntax)
    HIGH_ENTROPY = "high-entropy"  # random-looking token next to a secret-ish key name
    SESSION = "session"  # session cookie / authentication ticket: JSESSIONID, ASP.NET_SessionId, .ASPXAUTH, …
    COOKIE = "cookie"  # random-looking value in a Cookie / Set-Cookie header
    AUTH_CODE = "auth-code"  # OAuth authorization code (?code=…) or SAML response (SAMLResponse=…)


@dataclass(frozen=True, slots=True)
class SecretMatch:
    """A secret value at ``text[start:end]``; ``preview`` is safe to display (never contains the secret)."""

    kind: SecretKind
    start: int
    end: int
    preview: str


# ---- value checks ---------------------------------------------------------------------------------------------------
# Values that are clearly not secrets: empty markers, already-masked values, variable references, status words.
_PLACEHOLDER_VALUE = re.compile(
    r"[*•xX#.?_-]+|<[^<>]*>|\$\{[^}]*\}|\$\([^)]*\)|%[\w.-]+%|\{\{?[^{}]*\}?\}|\[[^\[\]]*\]|\(?null\)?"
)
_NOT_SECRET_WORDS = frozenset(
    {
        "null", "none", "nil", "undefined", "empty", "true", "false", "yes", "no", "ok", "n/a", "na", "redacted",
        "hidden", "masked", "removed", "omitted", "filtered", "unset", "notset", "not-set", "set", "present",
        "missing", "required", "invalid", "valid", "expired", "revoked", "refreshed", "failed", "denied", "provided",
        "supplied", "changed", "updated", "bearer", "basic", "negotiate", "ntlm", "digest", "kerberos", "token",
        "secret", "password", "apikey", "sharedkey", "sharedaccesssignature", "hmac",
    }
)  # fmt: skip


def _is_placeholder(value: str) -> bool:
    text = value.strip()
    return (
        not any(c.isalnum() for c in text)
        or text.lower() in _NOT_SECRET_WORDS
        or _PLACEHOLDER_VALUE.fullmatch(text) is not None
    )


def _looks_random(value: str) -> bool:
    """Generated tokens mix letters and digits; words and plain identifiers don't."""
    return any(c.isdigit() for c in value) and any(c.isalpha() for c in value)


def _entropy(value: str) -> float:
    """Shannon entropy in bits per character."""
    if not value:
        return 0.0
    total = len(value)
    return -sum(n / total * math.log2(n / total) for n in Counter(value).values())


def _b64decode(segment: str, *, urlsafe: bool) -> bytes | None:
    padded = segment + "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(padded) if urlsafe else base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None


def _accept_value(_match: re.Match[str], value: str) -> bool:
    return not _is_placeholder(value)


def _accept_random(_match: re.Match[str], value: str) -> bool:
    return _looks_random(value) and not _is_placeholder(value)


def _accept_jwt(_match: re.Match[str], value: str) -> bool:
    raw = _b64decode(value.split(".", 1)[0], urlsafe=True)
    if raw is None:
        return False
    try:
        header = json.loads(raw)
    except ValueError:  # includes UnicodeDecodeError and JSONDecodeError
        return False
    return isinstance(header, dict) and "alg" in header


def _accept_basic(_match: re.Match[str], value: str) -> bool:
    raw = _b64decode(value, urlsafe=False)
    if raw is None:
        return False
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    _user, colon, password = decoded.partition(":")
    return bool(colon and password) and decoded.isprintable()


def _accept_entropy(_match: re.Match[str], value: str) -> bool:
    return _entropy(value) >= ENTROPY_THRESHOLD and _accept_random(_match, value)


# Cookie names that always hold a session id or an authentication ticket, whatever the value looks like.
_KNOWN_SESSION_COOKIE = re.compile(
    r"(?i)jsessionid|phpsessid|asp\.net_sessionid|aspsessionid\w*|\.aspxauth|\.aspnetcore\.[\w.-]+|connect\.sid"
)
_WINDOWS_SID = re.compile(r"(?i)S-1-\d+(?:-\d+)+")  # a security identifier names an account; it is not a credential


def _accept_session(match: re.Match[str], value: str) -> bool:
    if _is_placeholder(value):
        return False
    if _KNOWN_SESSION_COOKIE.fullmatch(match["key"]):
        return len(value) >= MIN_WEAK_VALUE_CHARS
    return len(value) >= MIN_SESSION_ID_CHARS and _looks_random(value) and not _WINDOWS_SID.fullmatch(value)


def _accept_cookie(_match: re.Match[str], value: str) -> bool:
    return len(value) >= MIN_COOKIE_VALUE_CHARS and _accept_random(_match, value)


def _accept_auth_code(_match: re.Match[str], value: str) -> bool:
    return len(value) >= MIN_AUTH_CODE_CHARS and _accept_random(_match, value)


# ---- key names ------------------------------------------------------------------------------------------------------
_PASSWORD_KEYS = r"pass(?:word|wd|phrase)"
# Strong keys: any value after them is a secret, also as the suffix of a compound name (db_password, clientSecret).
_STRONG_KEYS = (
    rf"{_PASSWORD_KEYS}|secret|token|credentials?|api[_-]?key|access[_-]?key|private[_-]?key|account[_-]?key|"
    r"subscription[_-]?key|shared[_-]?access[_-]?key|signing[_-]?key|encryption[_-]?key"
)
# Weak keys: ambiguous short names; only "key=value" with a non-trivial value, and only as a whole word/segment.
_WEAK_KEYS = r"pass|pwd|pw|auth|sig|signature"
_KEY = rf"(?P<key>[\w.-]*?(?:{_STRONG_KEYS})|(?:[\w.-]*[_.-])?(?:{_WEAK_KEYS}))"
_STRONG_KEY = re.compile(rf"(?i)[\w.-]*?(?:{_STRONG_KEYS})")
_PASSWORD_KEY = re.compile(r"(?i)(?:pass(?:word|wd|phrase)?|pwd|pw)$")
_AUTH_SCHEMES = r"bearer|basic|negotiate|ntlm|digest|kerberos|token|apikey|sharedkey|sharedaccesssignature|hmac[\w-]*"


def _accept_key_value(match: re.Match[str], value: str) -> bool:
    if _is_placeholder(value):
        return False
    if _STRONG_KEY.fullmatch(match["key"]):
        return True
    return match["sep"] == "=" and len(value) >= MIN_WEAK_VALUE_CHARS


def _classify_key(match: re.Match[str]) -> SecretKind:
    return SecretKind.PASSWORD if _PASSWORD_KEY.search(match["key"]) else SecretKind.SECRET


# ---- rules ----------------------------------------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class _Rule:
    kind: SecretKind
    pattern: re.Pattern[str]
    accept: Callable[[re.Match[str], str], bool] = _accept_value
    classify: Callable[[re.Match[str]], SecretKind] | None = None
    context: re.Pattern[str] | None = None  # the rule only runs when this also matches somewhere in the text


_VALUE_GROUPS = ("value", "dq", "sq", "esc", "bare")  # whichever participates holds the secret value
_PEM_BEGIN = r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"
_PEM_END = r"-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----"
_B64_RUN = r"(?:[A-Za-z0-9+/=]|\\[rn])+"  # base64, possibly with JSON-escaped line breaks
_B64_WORDS = rf"{_B64_RUN}(?:[ \t]+{_B64_RUN})*"  # unambiguous: runs are separated by required blanks
_CONNECTION_STRING = re.compile(
    r"(?im)(?:^|;)\s*(?:server|data source|host|user id|uid|initial catalog|database|address|endpoint|provider)\s*="
)
_COOKIE_HEADER = re.compile(r"(?i)(?<![\w-])(?:set-)?cookie[\"']?\s*[:=]|\bcs\(cookie\)")
# Session / auth cookie names: *sess* (JSESSIONID, PHPSESSID, ASP.NET_SessionId, session_id), *sid (connect.sid),
# .ASPXAUTH and .AspNetCore.* (ASP.NET authentication and session tickets).
_SESSION_KEY = (
    r"(?P<key>(?:[\w.-]*[_.-])?(?:j|php|asp)?sess(?:ion)?[\w.-]*|\.aspxauth|\.aspnetcore\.[\w.-]+|(?:[\w.-]*[_.-])?sid)"
)

# Ordered from most to least specific: when detections overlap, the earlier rule wins.
_RULES: tuple[_Rule, ...] = (
    _Rule(SecretKind.PRIVATE_KEY, re.compile(rf"{_PEM_BEGIN}(?P<value>[\s\S]*?){_PEM_END}")),
    _Rule(  # a key cut off before its END line: the base64 on the BEGIN line and on the base64-only lines after it
        SecretKind.PRIVATE_KEY,
        re.compile(rf"{_PEM_BEGIN}[ \t]*(?P<value>(?:{_B64_WORDS})?(?:\r?\n[ \t]*{_B64_WORDS}[ \t]*(?=\r?\n|\Z))*)"),
    ),
    _Rule(
        SecretKind.JWT,
        re.compile(r"(?<![\w-])(?P<value>(?P<prefix>eyJ)[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*)"),
        _accept_jwt,
    ),
    _Rule(SecretKind.API_KEY, re.compile(r"(?<![\w-])(?P<value>(?P<prefix>sk-)[A-Za-z0-9_-]{20,})"), _accept_random),
    _Rule(SecretKind.API_KEY, re.compile(r"\b(?P<value>(?P<prefix>AKIA|ASIA)[0-9A-Z]{16})\b")),
    _Rule(SecretKind.API_KEY, re.compile(r"\b(?P<value>(?P<prefix>gh[pousr]_)[A-Za-z0-9]{30,})\b")),
    _Rule(SecretKind.API_KEY, re.compile(r"\b(?P<value>(?P<prefix>github_pat_)[A-Za-z0-9_]{30,})\b")),
    _Rule(SecretKind.API_KEY, re.compile(r"\b(?P<value>(?P<prefix>xox[abprs]-)[A-Za-z0-9-]{10,})")),
    _Rule(SecretKind.API_KEY, re.compile(r"\b(?P<value>(?P<prefix>AIza)[0-9A-Za-z_-]{35})(?![0-9A-Za-z_-])")),
    _Rule(
        SecretKind.AZURE_STORAGE_KEY,
        re.compile(r"(?i)(?<![\w-])(?:account|shared[_-]?access)key\s*=\s*(?P<value>[A-Za-z0-9+/]{20,}={0,2})"),
    ),
    _Rule(SecretKind.SAS_SIGNATURE, re.compile(r"(?i)[?&;]sig=(?P<value>[A-Za-z0-9%+/=_-]{16,})")),
    _Rule(
        SecretKind.URL_PASSWORD,
        re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^/\s:@\"'<>]+:(?P<value>[^/\s@\"'<>]+)@"),
    ),
    _Rule(
        SecretKind.AUTHORIZATION,
        re.compile(
            r"(?i)(?<![\w-])(?:proxy-)?authorization[\"']?\s*[:=]\s*[\"']?"
            rf"(?:(?P<scheme>{_AUTH_SCHEMES})\s+)?(?P<value>[^\s\"',;<>]+)"
        ),
    ),
    _Rule(
        SecretKind.BEARER_TOKEN,
        re.compile(rf"(?i)(?<![\w-])bearer\s+(?P<value>[A-Za-z0-9._~+/=-]{{{MIN_BEARER_TOKEN_CHARS},}})"),
        _accept_random,
    ),
    _Rule(
        SecretKind.BASIC_CREDENTIALS,
        re.compile(r"(?i)(?<![\w-])basic\s+(?P<value>[A-Za-z0-9+/]{6,}={0,2})(?![\w+/=-])"),
        _accept_basic,
    ),
    _Rule(  # JSESSIONID=…; ASP.NET_SessionId=…;+.ASPXAUTH=… (IIS W3C cookie field); .AspNetCore.Session=…
        SecretKind.SESSION,
        re.compile(rf"(?i)(?<![\w.-]){_SESSION_KEY}=(?P<value>[^\s;,&\"'<>]+)"),
        _accept_session,
    ),
    _Rule(  # OAuth authorization code in a redirect URL or token request: ?code=… / &code=… / #code=…
        SecretKind.AUTH_CODE,
        re.compile(r"(?i)[?&#]code=(?P<value>[^&#\s\"'<>]+)"),
        _accept_auth_code,
    ),
    _Rule(  # SAMLResponse=… (a signed assertion is a bearer credential), SAMLart=…
        SecretKind.AUTH_CODE,
        re.compile(r"(?i)(?<![\w.-])saml(?:response|art)[\"']?\s*[:=]\s*[\"']?(?P<value>[^&\s\"'<>]+)"),
    ),
    _Rule(  # Password=…; may contain spaces inside a connection string
        SecretKind.PASSWORD,
        re.compile(
            r"(?im)(?<![\w.-])(?:password|pwd)\s*=\s*"
            rf"(?P<value>[^;\"'\r\n&]{{1,{MAX_CONNECTION_PASSWORD_CHARS}}}?)\s*(?=;|$)"
        ),
        context=_CONNECTION_STRING,
    ),
    _Rule(  # key=value, key: value, "key": "value", \"key\": \"value\" (JSON inside a string), query strings
        SecretKind.SECRET,
        re.compile(
            rf"(?i)(?<![\w.-]){_KEY}(?:\\?[\"'])?\s*(?P<sep>[:=])\s*(?:"
            r"\\\"(?P<esc>(?:[^\\\r\n]|\\(?!\"))*)\\\""
            r"|\"(?P<dq>(?:[^\"\\\r\n]|\\.)*)\""
            r"|'(?P<sq>[^'\r\n]*)'"
            r"|(?P<bare>[^\s\"'&;,<>\\]+(?:\\[^\s\"'&;,<>\\]+)*)"
            r")"
        ),
        _accept_key_value,
        _classify_key,
    ),
    _Rule(  # <password>…</password>
        SecretKind.SECRET,
        re.compile(rf"(?i)<(?P<key>[\w:.-]*?(?:{_STRONG_KEYS}|pwd))(?:\s[^>]*)?>(?P<value>[^<\r\n]+)</"),
        _accept_value,
        _classify_key,
    ),
    _Rule(  # any long random-looking cookie value in a Cookie / Set-Cookie header (custom session cookie names)
        SecretKind.COOKIE,
        re.compile(r"(?<![\w.$-])(?P<key>[\w.$-]+)=(?P<value>[^\s;,\"'<>]+)"),
        _accept_cookie,
        context=_COOKIE_HEADER,
    ),
    _Rule(  # "api key 3f9a…", "token: Zx81…" — long random token right after a secret-ish name
        SecretKind.HIGH_ENTROPY,
        re.compile(
            r"(?i)(?<![A-Za-z0-9])(?:(?:api|access|secret|private|account|auth|signing|encryption|master|client|"
            r"subscription|session|app)[ _.-]?key|apikey|token|secret|password|passwd|credentials?|signature|sas)"
            rf"[\"']?[\s:=(\"']{{1,4}}(?P<value>[A-Za-z0-9+/=_~.-]{{{MIN_ENTROPY_TOKEN_CHARS},}})(?![A-Za-z0-9+/=_~.-])"
        ),
        _accept_entropy,
    ),
)

# Cheap prefilter: every rule needs one of these (lower-cased) substrings somewhere in the text.
_HINTS = (
    "pass", "pw", "secret", "token", "key", "auth", "sig", "credential", "bearer", "basic", "eyj", "://",
    "-----begin", "sk-", "akia", "asia", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "xox", "aiza",
    "sess", "sid=", ".aspnetcore.", "cookie", "code=", "saml",
)  # fmt: skip


def _has_hint(text: str) -> bool:
    lowered = text.lower()
    return any(hint in lowered for hint in _HINTS)


def _value_span(match: re.Match[str]) -> tuple[int, int] | None:
    groups = match.re.groupindex
    for name in _VALUE_GROUPS:
        if name in groups and match.group(name) is not None:
            start, end = match.span(name)
            return (start, end) if end > start else None
    return None


def _detect(rule: _Rule, match: re.Match[str]) -> SecretMatch | None:
    span = _value_span(match)
    if span is None:
        return None
    value = match.string[span[0] : span[1]]
    if not rule.accept(match, value):
        return None
    kind = rule.classify(match) if rule.classify is not None else rule.kind
    prefix = match["prefix"] if "prefix" in match.re.groupindex else ""
    return SecretMatch(kind, span[0], span[1], f"{prefix}… ({len(value)} chars)")


def _scan(text: str, *, first_only: bool) -> list[SecretMatch]:
    found: list[SecretMatch] = []
    if not _has_hint(text):
        return found
    for rule in _RULES:
        if rule.context is not None and rule.context.search(text) is None:
            continue
        for match in rule.pattern.finditer(text):
            secret = _detect(rule, match)
            if secret is None or any(secret.start < f.end and f.start < secret.end for f in found):
                continue
            found.append(secret)
            if first_only:
                return found
    found.sort(key=lambda s: s.start)
    return found


def find_secrets(text: str) -> list[SecretMatch]:
    """Secrets in ``text`` ordered by position; where detections overlap, the most specific kind wins."""
    return _scan(text, first_only=False)


def has_secrets(text: str) -> bool:
    """Whether ``text`` contains any secret (fast for ordinary lines: a substring prefilter runs first)."""
    return bool(_scan(text, first_only=True))


def mask(text: str, *, replacement: str = MASK) -> str:
    """``text`` with every secret value replaced by ``replacement``; key names stay visible. Idempotent."""
    secrets = find_secrets(text)
    if not secrets:
        return text
    parts: list[str] = []
    position = 0
    for secret in secrets:
        parts.append(text[position : secret.start])
        parts.append(replacement)
        position = secret.end
    parts.append(text[position:])
    return "".join(parts)


# ---- private keys logged line by line -------------------------------------------------------------------------------
_PEM_BEGIN_LINE = re.compile(_PEM_BEGIN)
_PEM_END_LINE = re.compile(_PEM_END)
_KEY_BODY_LINE = re.compile(r"[ \t]*(?P<value>[A-Za-z0-9+/=]+)[ \t]*\r?")  # fullmatch: a base64-only line


def private_key_open_after(line: str, *, inside: bool) -> bool:
    """Whether a PEM private key block is open after ``line``; ``inside`` = it was open before the line.

    A BEGIN … PRIVATE KEY marker without a later END marker on the line opens a block; an END marker closes it.
    """
    if "-----" not in line:  # fast path for ordinary lines
        return inside
    last_begin = max((m.start() for m in _PEM_BEGIN_LINE.finditer(line)), default=-1)
    last_end = max((m.start() for m in _PEM_END_LINE.finditer(line)), default=-1)
    if last_begin < 0 and last_end < 0:
        return inside
    return last_begin > last_end


class SecretMasker:
    """Masks secrets line by line like :func:`mask`, plus the body of a private key that was logged line by line.

    After a line with ``-----BEGIN … PRIVATE KEY-----`` (and no END marker after it), every base64-only line is
    masked until a line with the END marker; other lines in between are masked as usual and don't end the block.
    The state carries over between calls, so feed consecutive lines (in one or several calls) and call :meth:`reset`
    before lines that don't follow the previous ones (another file, a jump in the view).
    """

    def __init__(self, *, replacement: str = MASK) -> None:
        self._replacement = replacement
        self._in_key = False

    @property
    def in_private_key(self) -> bool:
        """Whether the last line left a private key block open."""
        return self._in_key

    def reset(self) -> None:
        self._in_key = False

    def mask_line(self, line: str) -> str:
        if self._in_key:
            body = _KEY_BODY_LINE.fullmatch(line)
            if body is not None:
                return line[: body.start("value")] + self._replacement + line[body.end("value") :]
        self._in_key = private_key_open_after(line, inside=self._in_key)
        return mask(line, replacement=self._replacement)

    def mask_lines(self, lines: Sequence[str]) -> list[str]:
        """``lines`` masked, in order (continues the private key state of the previous call)."""
        return [self.mask_line(line) for line in lines]
