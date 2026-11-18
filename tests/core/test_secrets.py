"""Secrets in log text: detection per kind, masking, no false positives, AI redaction coverage.

Synthetic data only: every token below is generated here from a seeded RNG; none is a real credential.
"""

from __future__ import annotations

import base64
import json
import random
import string

import pytest

from loglens.core.ai.config import Redact
from loglens.core.ai.redaction import Redactor
from loglens.core.secrets import MASK, SecretKind, find_secrets, has_secrets, mask

ALNUM = string.ascii_letters + string.digits
URLSAFE = ALNUM + "_-"
BASE64 = ALNUM + "+/"


def fake(alphabet: str, length: int, seed: int) -> str:
    """A random-looking token that always mixes letters and digits (like real generated secrets)."""
    rng = random.Random(seed)
    body = "".join(rng.choices(alphabet, k=length - 2))
    return rng.choice(string.ascii_letters) + rng.choice(string.digits) + body


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


JWT = ".".join(
    (b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()), b64url(b'{"sub":"42"}'), fake(URLSAFE, 43, 1))
)
OPAQUE = fake(ALNUM, 32, 2)
BASIC = base64.b64encode(b"svc-user:" + fake(ALNUM, 14, 3).encode()).decode("ascii")
SK_KEY = "sk-" + fake(URLSAFE, 40, 4)
AWS_KEY = "AKIA" + fake(string.ascii_uppercase + string.digits, 16, 5).upper()
GITHUB_TOKEN = "ghp_" + fake(ALNUM, 36, 6)
SLACK_TOKEN = "xoxb-" + fake(string.digits, 12, 7) + "-" + fake(ALNUM, 24, 8)
GOOGLE_KEY = "AIza" + fake(URLSAFE, 35, 9)
ACCOUNT_KEY = fake(BASE64, 86, 10) + "=="
SAS_SIG = fake(ALNUM, 30, 11) + "%2B" + fake(ALNUM, 10, 12) + "%3D"
PEM_BODY = "\n".join(fake(BASE64, 64, 13 + i) for i in range(3))
HIGH_ENTROPY = fake(ALNUM, 32, 20)

# (line, the secret value in it, expected kind)
CASES: list[tuple[str, str, SecretKind]] = [
    (f"login ok token={JWT}", JWT, SecretKind.JWT),
    (f"Authorization: Bearer {OPAQUE}", OPAQUE, SecretKind.AUTHORIZATION),
    (f"forwarding request with bearer {OPAQUE}", OPAQUE, SecretKind.BEARER_TOKEN),
    (f"proxy header Basic {BASIC}", BASIC, SecretKind.BASIC_CREDENTIALS),
    (f"calling model with {SK_KEY}", SK_KEY, SecretKind.API_KEY),
    (f"aws credentials {AWS_KEY} loaded", AWS_KEY, SecretKind.API_KEY),
    (f"git push using {GITHUB_TOKEN}", GITHUB_TOKEN, SecretKind.API_KEY),
    (f"posting to chat with {SLACK_TOKEN}", SLACK_TOKEN, SecretKind.API_KEY),
    (f"maps request key={GOOGLE_KEY} ok", GOOGLE_KEY, SecretKind.API_KEY),
    (
        f"DefaultEndpointsProtocol=https;AccountName=acct;AccountKey={ACCOUNT_KEY};EndpointSuffix=example.test",
        ACCOUNT_KEY,
        SecretKind.AZURE_STORAGE_KEY,
    ),
    (
        f"GET https://acct.blob.example.test/c/b.txt?sv=2022-11-02&se=2026-12-01&sp=r&sig={SAS_SIG} 200",
        SAS_SIG,
        SecretKind.SAS_SIGNATURE,
    ),
    ("GET /login?user=bob&password=Hunter2x&next=/home 302", "Hunter2x", SecretKind.PASSWORD),
    ("GET /callback?code=1&client_secret=Zq8vWm3k&state=x 200", "Zq8vWm3k", SecretKind.SECRET),
    ("config pwd=Tr0ub4dor loaded", "Tr0ub4dor", SecretKind.PASSWORD),
    ("config apikey=k3yV4lue loaded", "k3yV4lue", SecretKind.SECRET),
    ("startup DB_PASSWORD=abc123def", "abc123def", SecretKind.PASSWORD),
    ('request {"user": "bob", "password": "correct horse battery"}', "correct horse battery", SecretKind.PASSWORD),
    (r'payload="{\"user\":\"bob\",\"password\":\"p4ss word\"}"', "p4ss word", SecretKind.PASSWORD),
    (
        "Server=db01;Database=orders;User Id=app;Password=s3cret value;Encrypt=True",
        "s3cret value",
        SecretKind.PASSWORD,
    ),
    ("<Credentials><Password>Xy9!pass</Password></Credentials>", "Xy9!pass", SecretKind.PASSWORD),
    ("connecting to postgres://app:Pa55word@db.example.test:5432/orders", "Pa55word", SecretKind.URL_PASSWORD),
    (
        f"loaded -----BEGIN RSA PRIVATE KEY-----\n{PEM_BODY}\n-----END RSA PRIVATE KEY----- from store",
        f"\n{PEM_BODY}\n",
        SecretKind.PRIVATE_KEY,
    ),
    (f"-----BEGIN PRIVATE KEY-----{PEM_BODY.splitlines()[0]}", PEM_BODY.splitlines()[0], SecretKind.PRIVATE_KEY),
    (f"using api key {HIGH_ENTROPY}", HIGH_ENTROPY, SecretKind.HIGH_ENTROPY),
]

ORDINARY_LINES = [
    "2026-11-13 10:15:02,123 [12] INFO Processed batch 6f1c2e7a-0d3b-4c1e-9a55-000000000001 in 532 ms",
    "2026-11-13T10:15:02.123Z DEBUG cache hit sha256 9f86d081884c7d659a2feaf0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "Uploaded blob checksum md5=5d41402abc4b2a76b9719d911017c592 size=1024",
    "payload=" + base64.b64encode(json.dumps({"id": 1, "name": "test", "items": [1, 2, 3]}).encode()).decode() + " ok",
    "body " + base64.b64encode(bytes(range(48))).decode(),
    "Refreshing access token for client 42",
    "Token expired at 2026-11-13T10:00:00Z; requesting a new one",
    "Basic authentication failed for user bob",
    "Authorization failed: user lacks permission",
    "Password policy updated; minimum length 12",
    "Commit 3f9a1c2 deployed by build 2026.11.13.4",
    "GET /api/orders?page=2&pageSize=50 HTTP/1.1 200 0.042s",
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Session 6f1c2e7a-0d3b-4c1e-9a55-000000000001 started for tenant 77",
    "maxTokens=4096 temperature=0.2",
    "pwd: /home/build/workspace",
    "the task-runner reported sk-learn style metrics",
    "keyboard layout 00000409 loaded; time zone Asia/Tokyo",
    "Secret rotation scheduled for 2026-12-01 02:00",
    "password: ******** (hidden)",
    "token=${API_TOKEN} from environment",
    "Event 4624: An account was successfully logged on. Logon Type: 3",
]


CASE_IDS = [f"{i}-{kind.value}" for i, (_line, _value, kind) in enumerate(CASES)]


@pytest.mark.parametrize(("line", "value", "kind"), CASES, ids=CASE_IDS)
def test_detects_each_kind(line: str, value: str, kind: SecretKind) -> None:
    secrets = find_secrets(line)
    assert [(s.kind, line[s.start : s.end]) for s in secrets] == [(kind, value)]
    assert value not in secrets[0].preview and f"{len(value)} chars" in secrets[0].preview
    assert has_secrets(line)


@pytest.mark.parametrize(("line", "value"), [(line, value) for line, value, _kind in CASES], ids=CASE_IDS)
def test_mask_hides_value_and_is_idempotent(line: str, value: str) -> None:
    masked = mask(line)
    assert value.strip() not in masked and MASK in masked
    assert mask(masked) == masked and find_secrets(masked) == []


def test_mask_keeps_key_names() -> None:
    assert mask("GET /login?user=bob&password=Hunter2x&next=/home") == f"GET /login?user=bob&password={MASK}&next=/home"
    assert mask('{"user": "bob", "password": "a b c"}') == f'{{"user": "bob", "password": "{MASK}"}}'
    assert mask("Server=db;Pwd=x y z;") == f"Server=db;Pwd={MASK};"
    assert mask(f"Authorization: Bearer {OPAQUE}") == f"Authorization: Bearer {MASK}"
    assert mask("https://bob:Pa55word@host.example.test/") == f"https://bob:{MASK}@host.example.test/"
    assert mask("nothing to see") == "nothing to see"


def test_several_secrets_in_one_line_are_ordered() -> None:
    line = f"user=bob password=Hunter2x token={JWT} key {AWS_KEY}"
    kinds = [s.kind for s in find_secrets(line)]
    assert kinds == [SecretKind.PASSWORD, SecretKind.JWT, SecretKind.API_KEY]


@pytest.mark.parametrize("line", ORDINARY_LINES)
def test_no_false_positives_on_ordinary_lines(line: str) -> None:
    assert find_secrets(line) == []
    assert not has_secrets(line)
    assert mask(line) == line


def test_not_a_jwt_without_alg_header() -> None:
    header = b64url(json.dumps({"typ": "JWT"}).encode())
    assert find_secrets(f"value {header}.{b64url(b'{}x')}.{fake(URLSAFE, 20, 30)}") == []


def test_ai_redaction_covers_everything_detected() -> None:
    for line, value, _kind in CASES:
        result = Redactor([Redact.SECRETS]).redact(line)
        assert value.strip() not in result.text, line
        assert result.total >= 1
    out = Redactor([Redact.SECRETS]).redact(f"keys {AWS_KEY} and {AWS_KEY}").text
    assert out == "keys <API_KEY_1> and <API_KEY_1>"  # consistent placeholders, as for the other categories
    assert Redactor([Redact.EMAILS]).redact(f"keys {AWS_KEY}").text == f"keys {AWS_KEY}"  # category still respected
