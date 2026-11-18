"""Regression tests for the security / privacy review fixes.

Zip extraction (drives, streams, devices, links), the local model provider (loopback only, no proxy, no redirects),
private keys logged line by line, session cookies / auth codes, always-on secret redaction, personal data in AI
redaction, redacted reports and Markdown fences, web-search queries, and elevation of a user-writable executable.

Synthetic data only: every token, key and name below is generated or made up here; none is a real credential.
"""

from __future__ import annotations

import base64
import logging
import os
import random
import string
import sys
import threading
import urllib.request
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from typing import ClassVar

import pytest

from loglens.core import elevation
from loglens.core.ai import local
from loglens.core.ai.claude import AIError
from loglens.core.ai.config import LOCAL_API_OLLAMA, AIConfig, Provider, Redact, is_loopback_url
from loglens.core.ai.explain import Cause, Explanation, build_request
from loglens.core.ai.local import LocalProvider, list_models
from loglens.core.ai.redaction import Redactor
from loglens.core.bundles import BundleError, extract_zip, safe_member_path
from loglens.core.report import EvidenceLine, IncidentReport, redact_report, to_html, to_markdown
from loglens.core.secrets import MASK, SecretKind, SecretMasker, find_secrets, has_secrets, mask
from loglens.core.websearch import build_query

ALNUM = string.ascii_letters + string.digits
URLSAFE = ALNUM + "_-"
BASE64 = ALNUM + "+/"
HEX = "0123456789ABCDEF"


def fake(alphabet: str, length: int, seed: int) -> str:
    """A random-looking token that always mixes letters and digits (like real generated secrets)."""
    rng = random.Random(seed)
    body = "".join(rng.choices(alphabet, k=length - 2))
    return rng.choice(string.ascii_letters) + rng.choice(string.digits) + body


def pem_body(lines: int, seed: int) -> list[str]:
    return [fake(BASE64, 64, seed + i) for i in range(lines)]


# ---- 1. zip extraction ----------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "name",
    [
        "a/D:/x.log",  # a drive anywhere in the path switches the drive on Windows
        "logs/C:/Users/Public/x.json",
        "x.log:stream",  # NTFS alternate data stream
        "logs/app.log:hidden.log",
        "con.log",  # device names, with any extension
        "logs/NUL.txt",
        "COM1.log",
        "lpt9.out",
        "aux .log",
        "a/../../x.log",
        "../x.log",
        "/etc/x.log",
        "\\\\server\\share\\x.log",  # UNC
        "C:\\x.log",
        "a//b.log",
        "a/./b.log",
        "dir./x.log",  # Windows trims trailing dots and spaces
        "dir /x.log",
        "a/b?.log",
    ],
)
def test_unsafe_member_names_are_rejected(name: str) -> None:
    assert safe_member_path(name) is None


def test_ordinary_member_names_are_kept() -> None:
    assert safe_member_path("logs\\2026\\app.log.1") == PurePosixPath("logs/2026/app.log.1")
    for name in ("console.log", "com10.log", "aux_data.log", "nul-report.txt", ".hidden.log", "a b/c d.log"):
        assert safe_member_path(name) == PurePosixPath(name), name


def test_member_with_a_drive_inside_the_path_is_refused(tmp_path: Path) -> None:
    archive = tmp_path / "evil.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr(f"logs/{tmp_path.drive or 'C:'}/escaped.log", "x")
    with pytest.raises(BundleError, match="Unsafe path"):
        extract_zip(archive, tmp_path / "out")


def test_nothing_is_extracted_when_any_member_is_unsafe(tmp_path: Path) -> None:
    archive = tmp_path / "mixed.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("logs/first.log", "fine")
        z.writestr("../../escape.log", "x")
    out = tmp_path / "out"
    with pytest.raises(BundleError, match="Unsafe path"):
        extract_zip(archive, out)
    assert not out.exists() or not any(out.rglob("*"))


def _link_folder(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        try:
            import _winapi  # CPython's own helper for directory junctions (no privilege needed)

            _winapi.CreateJunction(str(target), str(link))
        except (ImportError, AttributeError, OSError):
            pytest.skip("can't create a directory link here")


def test_member_written_through_a_link_inside_the_target_is_refused(tmp_path: Path) -> None:
    outside, out = tmp_path / "outside", tmp_path / "out"
    outside.mkdir()
    out.mkdir()
    _link_folder(out / "link", outside)
    archive = tmp_path / "linked.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("link/x.log", "x")
    with pytest.raises(BundleError, match="Unsafe path"):
        extract_zip(archive, out)
    assert not (outside / "x.log").exists()


# ---- 2. local model provider ----------------------------------------------------------------------------------------
class _Handler(BaseHTTPRequestHandler):
    """Records GET paths; answers with ``status``/``body`` (and ``location`` for redirects)."""

    seen: ClassVar[list[str]] = []
    status: ClassVar[int] = 200
    body: ClassVar[bytes] = b'{"models": [{"name": "tiny:latest"}]}'
    location: ClassVar[str] = ""

    def log_message(self, *_args: object) -> None:  # keep test output quiet
        pass

    def do_GET(self) -> None:
        type(self).seen.append(self.path)
        self.send_response(self.status)
        if self.location:
            self.send_header("Location", self.location)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)


@contextmanager
def _serve(**attributes: object) -> Iterator[tuple[str, list[str]]]:
    """A throwaway HTTP server on 127.0.0.1; yields its URL and the list of paths it was asked for."""
    seen: list[str] = []
    handler = type("Handler", (_Handler,), {"seen": seen, **attributes})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}", seen
    finally:
        httpd.shutdown()
        httpd.server_close()


def _local(url: str, *, allow_remote: bool = False) -> AIConfig:
    return AIConfig(
        enabled=True,
        provider=Provider.LOCAL,
        local_api=LOCAL_API_OLLAMA,
        local_url=url,
        local_model="tiny:latest",
        local_allow_remote=allow_remote,
    )


@pytest.mark.parametrize(
    ("url", "loopback"),
    [
        ("http://localhost:11434", True),
        ("http://LOCALHOST:1234/", True),
        ("http://127.0.0.1:11434", True),
        ("https://127.5.6.7", True),
        ("http://[::1]:8080", True),
        ("http://192.168.1.20:11434", False),
        ("http://gpu-box.example.test:11434", False),
        ("http://127.0.0.1.nip.example:80", False),
        ("http://127.0.0.1@models.example.test/", False),  # user info, the host is models.example.test
        ("http://localhost:99999", False),  # malformed port
        ("ftp://localhost/", False),
        ("localhost:11434", False),
        ("", False),
    ],
)
def test_is_loopback_url(url: str, loopback: bool) -> None:
    assert is_loopback_url(url) is loopback


def test_remote_local_server_is_refused_unless_explicitly_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    class NoNetwork:
        def open(self, *_args: object, **_kwargs: object) -> None:
            raise AssertionError("a request was made")

    monkeypatch.setattr(local, "_OPENER", NoNetwork())
    remote = "http://192.0.2.10:11434"
    with pytest.raises(AIError, match="not on this computer"):
        LocalProvider(_local(remote))
    with pytest.raises(AIError, match="not on this computer"):
        list_models(_local(remote))
    with pytest.raises(AIError, match="http:// or https://"):
        list_models(_local("file:///C:/Windows/win.ini", allow_remote=True))
    allowed = _local(remote, allow_remote=True)
    assert LocalProvider(allowed).config is allowed  # the user opted in
    assert "on this computer" not in allowed.model_label and remote in allowed.model_label
    assert "on this computer" in _local("http://localhost:11434").model_label


def test_local_requests_never_use_a_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    with _serve(status=502, body=b"{}") as (proxy_url, proxy_seen), _serve() as (model_url, model_seen):
        for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"):
            monkeypatch.setenv(name, proxy_url)
        for name in ("NO_PROXY", "no_proxy"):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setattr(urllib.request, "_opener", None)  # urlopen() would now build one that reads HTTP_PROXY
        assert list_models(_local(model_url)) == ["tiny:latest"]
    assert proxy_seen == [] and model_seen == ["/api/tags"]


def test_local_requests_do_not_follow_redirects() -> None:
    with (
        _serve() as (elsewhere_url, elsewhere_seen),
        _serve(status=302, body=b"", location=f"{elsewhere_url}/api/tags") as (model_url, _seen),
        pytest.raises(AIError, match="302"),
    ):
        list_models(_local(model_url))
    assert elsewhere_seen == []


# ---- 3. private keys logged line by line ----------------------------------------------------------------------------
def test_ai_redaction_masks_key_body_lines_when_the_end_line_is_outside_the_excerpt() -> None:
    body = pem_body(3, 100)
    lines = [(10, "2026-11-13 10:00:00 DEBUG loaded -----BEGIN RSA PRIVATE KEY-----"), *enumerate(body, start=11)]
    config = AIConfig(redactions=[])  # even with every category switched off
    request = build_request("app.log", lines, [10], Redactor(config.redaction_set()))
    for line in body:
        assert line not in request.user_text
    assert "L12| <KEY_" in request.user_text and "L14| <KEY_" in request.user_text  # numbering stays intact
    focused = build_request("app.log", lines, [11, 12], Redactor([Redact.SECRETS]))
    assert all(line not in focused.user_text for line in body) and "L12|>> <KEY_" in focused.user_text


def test_complete_and_cut_off_keys_in_one_text() -> None:
    body = pem_body(2, 200)
    text = "\n".join(["-----BEGIN PRIVATE KEY-----", *body, "2026-11-13 10:00:01 INFO next entry"])
    masked = mask(text)
    assert all(line not in masked for line in body) and masked.endswith("INFO next entry")


def test_secret_masker_carries_the_key_block_across_lines() -> None:
    body = pem_body(3, 300)
    masker = SecretMasker()
    first = masker.mask_lines(["2026-11-13 DEBUG key: -----BEGIN EC PRIVATE KEY-----", body[0]])
    assert first[1] == MASK and masker.in_private_key
    rest = masker.mask_lines([f"  {body[1]}  ", "Proc-Type: 4,ENCRYPTED", body[2], "-----END EC PRIVATE KEY-----"])
    assert rest == [f"  {MASK}  ", "Proc-Type: 4,ENCRYPTED", MASK, "-----END EC PRIVATE KEY-----"]
    assert not masker.in_private_key
    after = fake(BASE64, 40, 399)
    assert masker.mask_line(after) == after  # base64 after the END line is ordinary text again
    password = "pass" + fake(ALNUM, 10, 398)
    assert masker.mask_line(f"login password={password}") == f"login password={MASK}"  # still masks everything else
    masker.mask_line("-----BEGIN PRIVATE KEY-----")
    masker.reset()
    assert masker.mask_line(body[0]) == body[0]


# ---- 4. session cookies, auth tickets, OAuth codes, SAML ------------------------------------------------------------
ASP_SESSION = fake(string.ascii_lowercase + "012345", 24, 401)
ASPX_AUTH = fake(HEX, 96, 402)
JAVA_SESSION = fake(HEX, 32, 403)
CORE_SESSION = "CfDJ8" + fake(URLSAFE, 60, 404)
GENERIC_SESSION = fake(ALNUM, 32, 405)
CUSTOM_COOKIE = fake(URLSAFE, 40, 406)
OAUTH_CODE = "4/0A" + fake(URLSAFE, 60, 407)
SAML = base64.b64encode(b"<samlp:Response ID='_" + fake(ALNUM, 20, 408).encode() + b"'/>").decode("ascii")

SESSION_CASES: list[tuple[str, list[tuple[SecretKind, str]]]] = [
    (
        f"2026-11-13 10:00:00 W3SVC1 GET /app - 443 - 10.0.0.1 Mozilla/5.0 "
        f"ASP.NET_SessionId={ASP_SESSION};+.ASPXAUTH={ASPX_AUTH} 200 0 0 31",
        [(SecretKind.SESSION, ASP_SESSION), (SecretKind.SESSION, ASPX_AUTH)],
    ),
    (
        f"Cookie: JSESSIONID={JAVA_SESSION}; .AspNetCore.Session={CORE_SESSION}; theme=dark",
        [(SecretKind.SESSION, JAVA_SESSION), (SecretKind.SESSION, CORE_SESSION)],
    ),
    (f"Set-Cookie: session_id={GENERIC_SESSION}; Path=/; HttpOnly", [(SecretKind.SESSION, GENERIC_SESSION)]),
    (f"Cookie: tenant=contoso; xq_state={CUSTOM_COOKIE}", [(SecretKind.COOKIE, CUSTOM_COOKIE)]),
    (f"GET /oauth/callback?code={OAUTH_CODE}&state=xyz 302", [(SecretKind.AUTH_CODE, OAUTH_CODE)]),
    (f"POST /saml/acs SAMLResponse={SAML}&RelayState=home 302", [(SecretKind.AUTH_CODE, SAML)]),
]
NOT_SESSION_SECRETS = [
    "session_timeout=30 sessionCount=5 SessionState=Active sessions=12",
    "user_sid=S-1-5-18 sid=S-1-5-21-1004336348-1177238915-682003330-512",
    "Cookie consent banner shown to the visitor",
    "Set-Cookie header missing SameSite attribute",
    "GET /status?code=404 200",
    "assessment_id=done possession=ok",
    "Session 6f1c2e7a-0d3b-4c1e-9a55-000000000001 started for tenant 77",
]


@pytest.mark.parametrize(("line", "expected"), SESSION_CASES)
def test_session_cookies_and_auth_codes_are_secrets(line: str, expected: list[tuple[SecretKind, str]]) -> None:
    assert [(s.kind, line[s.start : s.end]) for s in find_secrets(line)] == expected
    assert has_secrets(line)
    masked = mask(line)
    assert all(value not in masked for _kind, value in expected)
    redacted = Redactor([Redact.SECRETS]).redact(line).text
    assert all(value not in redacted for _kind, value in expected)


@pytest.mark.parametrize("line", NOT_SESSION_SECRETS)
def test_session_rules_leave_ordinary_lines_alone(line: str) -> None:
    assert find_secrets(line) == [] and mask(line) == line


# ---- 5. secrets redaction can't be switched off ---------------------------------------------------------------------
def test_secrets_are_always_redacted_whatever_the_settings_say() -> None:
    assert Redact.SECRETS in AIConfig(redactions=[]).redaction_set()
    config = AIConfig.from_dict({"redactions": ["emails", "no-such-category"]})
    assert config.redaction_set() == {Redact.EMAILS, Redact.SECRETS}
    assert AIConfig.from_dict({"redactions": "garbage"}).redaction_set() >= {Redact.SECRETS, Redact.USER_PATHS}
    password = fake(ALNUM, 12, 501)
    out = Redactor(AIConfig(redactions=[]).redaction_set()).redact(f"login password={password}").text
    assert password not in out


def test_remote_opt_in_must_be_an_explicit_true() -> None:
    assert AIConfig().local_allow_remote is False
    assert AIConfig.from_dict({"local_allow_remote": "yes"}).local_allow_remote is False
    assert AIConfig.from_dict({"local_allow_remote": True}).local_allow_remote is True


# ---- 6. personal data in AI redaction -------------------------------------------------------------------------------
PERSONAL = [
    (r'{"path": "C:\\Users\\jdoe\\AppData\\Local\\app.log"}', "jdoe"),
    (r"copy to \\fs01\c$\Users\kfischer\Desktop failed", "kfischer"),
    (r'"share": "\\\\fs01\\c$\\Users\\mlopez\\x"', "mlopez"),
    ("listening on fe80::1ff:fe23:4567:890a%eth0", "fe80::1ff:fe23:4567:890a"),
    ("client 2001:db8::8a2e:370:7334 connected", "2001:db8::8a2e:370:7334"),
    ("[2001:db8::7]:443 refused", "2001:db8::7"),
    (r"Access denied for CONTOSO\jdoe.", "jdoe"),
    (r'"account": "CONTOSO\\asmith"', "asmith"),
    ("Login failed for user 'pbrown'. Reason: wrong password.", "pbrown"),
    ('{"username": "tgreen", "result": "ok"}', "tgreen"),
    ("Account Name:\t\trwhite", "rwhite"),
]


@pytest.mark.parametrize(("text", "personal"), PERSONAL)
def test_default_redaction_removes_personal_data(text: str, personal: str) -> None:
    result = Redactor(AIConfig().redaction_set()).redact(text)
    assert personal not in result.text and result.total >= 1


def test_personal_data_rules_keep_ordinary_text() -> None:
    text = r"at 10:15:02.123 std::vector<int> :: NT AUTHORITY\SYSTEM read HKLM\SOFTWARE\Vendor; user 'SYSTEM'"
    assert Redactor(AIConfig().redaction_set()).redact(text).text == text


# ---- 7. reports -----------------------------------------------------------------------------------------------------
def _explanation(text: str) -> Explanation:
    return Explanation(
        summary=f"Sign-in failures for {text}",
        severity="error",
        is_likely_noise=False,
        what_happened=f"{text} failed to sign in.",
        probable_causes=(Cause(f"Password of {text} expired", "high", (5,)),),
        next_steps=(f"Reset the password of {text}",),
        missing_information=f"Whether {text} changed it",
        confidence="medium",
        model="test-model",
        notes=(f"Mentioned {text}",),
    )


def _report(line: str, explanation: Explanation, title: str = "Incident") -> IncidentReport:
    return IncidentReport(
        title=title,
        source=r"C:\Users\jdoe\logs\app.log",
        created=datetime(2026, 11, 13, 12, 0).astimezone(),
        evidence=[EvidenceLine(5, line, "bookmark")],
        explanations=[explanation],
    )


def test_redacted_report_covers_the_title_and_the_ai_answer() -> None:
    who = r"CONTOSO\jdoe (jdoe@example.com) from 10.1.2.3"
    report = _report(f"login failed for {who}", _explanation(who), title=f"Failures of {who}")
    redacted = redact_report(report, Redactor((Redact.SECRETS, Redact.EMAILS, Redact.IP_ADDRESSES, Redact.USER_PATHS)))
    for document in (to_markdown(redacted), to_html(redacted)):
        assert "jdoe" not in document and "10.1.2.3" not in document, document


def test_markdown_code_blocks_cannot_be_closed_by_the_log_line() -> None:
    line = "x ``` ![t](http://198.51.100.7/p.png) ```` y"
    markdown = to_markdown(_report(line, _explanation("someone")))
    assert f"`````\n{line}\n`````" in markdown


def test_markdown_neutralises_images_and_html_from_the_ai() -> None:
    payload = "![t](http://198.51.100.7/p.png) <img src=http://198.51.100.7/q.png>"
    markdown = to_markdown(_report("ok", _explanation(payload)))
    assert "![t]" not in markdown and "<img" not in markdown and "!\\[t]" in markdown
    source = to_markdown(IncidentReport("T", "a`b.log", datetime(2026, 11, 13).astimezone()))
    assert "**Log:** ``a`b.log``" in source


def test_html_report_escapes_everything() -> None:
    payload = "<img src=x onerror=alert(1)><script>alert(2)</script>"
    page = to_html(_report(payload, _explanation(payload), title=payload))
    assert "<img" not in page and "<script" not in page and "&lt;img" in page


# ---- 8. web search ------------------------------------------------------------------------------------------------
def test_web_search_drops_user_names_domain_accounts_and_host_names() -> None:
    query = build_query(
        [
            "2026-11-13 10:00:00 ERROR System.Data.SqlClient.SqlException (0x80131904): "
            r"Login failed for user 'CONTOSO\jdoe' on db01.corp.example.com via FS01.CONTOSO.LOCAL"
        ]
    )
    assert query.startswith("System.Data.SqlClient.SqlException")
    for leaked in ("jdoe", "CONTOSO", "db01", "FS01", "example.com"):
        assert leaked not in query, query
    assert "Login failed for user" in query
    plain = build_query([r"2026-11-13 10:00:00 WARN access denied for contoso\asmith, user 'bking'"])
    assert "asmith" not in plain and "contoso" not in plain and "bking" not in plain
    kept = build_query(["System.IO.FileNotFoundException: Could not load file or assembly Newtonsoft.Json.Linq"])
    assert "Newtonsoft.Json.Linq" in kept


# ---- 9. elevation ---------------------------------------------------------------------------------------------------
@pytest.fixture
def user_folders(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point every user-writable folder variable into ``tmp_path/profile``."""
    profile = tmp_path / "profile"
    for variable, sub in (
        ("USERPROFILE", ""),
        ("APPDATA", "AppData/Roaming"),
        ("LOCALAPPDATA", "AppData/Local"),
        ("TEMP", "AppData/Local/Temp"),
        ("TMP", "AppData/Local/Temp"),
    ):
        folder = profile / sub
        folder.mkdir(parents=True, exist_ok=True)
        monkeypatch.setenv(variable, str(folder))
    return profile


def _frozen(monkeypatch: pytest.MonkeyPatch, executable: Path) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(executable))


def test_per_user_install_is_not_elevated(
    user_folders: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(elevation, "_shell_execute_runas", lambda exe, params: calls.append((exe, params)) or 42)
    for exe in (
        user_folders / "AppData/Local/Programs/LogLens/LogLens.exe",
        user_folders / "Downloads/LogLens/LogLens.exe",
        user_folders / "AppData/Local/Temp/x/LogLens.exe",
    ):
        _frozen(monkeypatch, exe)
        safe, reason = elevation.elevation_is_safe()
        assert not safe and "Program Files" in reason
        if sys.platform == "win32":
            with caplog.at_level(logging.WARNING, logger=elevation.__name__):
                assert elevation.relaunch_elevated(["a.log"]) is False
    assert calls == []
    if sys.platform == "win32":
        assert "not restarting as administrator" in caplog.text


def test_machine_wide_install_and_source_checkout_can_be_elevated(
    user_folders: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(elevation, "_shell_execute_runas", lambda exe, params: calls.append((exe, params)) or 42)
    program_files = Path(os.environ.get("PROGRAMFILES", "C:/Program Files")) / "LogLens/LogLens.exe"
    _frozen(monkeypatch, program_files)
    assert elevation.elevation_is_safe() == (True, "")
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    monkeypatch.setattr(sys, "executable", str(user_folders / "src/.venv/Scripts/python.exe"))
    safe, warning = elevation.elevation_is_safe()
    assert safe and "source" in warning
    if sys.platform == "win32":
        with caplog.at_level(logging.WARNING, logger=elevation.__name__):
            assert elevation.relaunch_elevated(["a.log"]) is True
        assert calls and calls[0][1] == "-m loglens --new-window a.log" and "from source" in caplog.text
