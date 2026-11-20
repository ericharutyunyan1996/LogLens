"""Digest of new problems, delivery (webhook / mail) and the command line."""

from __future__ import annotations

import json
import threading
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import ClassVar

import pytest

from loglens import cli
from loglens.core import digest as digest_module
from loglens.core import notify

TOKEN = "Zx9" + "Kq7Lm2Np4Rs6Tu8Vw0Yb1Cd3Ef5Gh"


def write(path: Path, lines: list[str], mode: str = "w") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open(mode, encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(lines) + "\n")
    return path


def stamp(i: int) -> str:
    return f"2026-11-13 10:{i // 60:02d}:{i % 60:02d},000"


def sample(n: int = 6, *, errors: int = 2) -> list[str]:
    lines = [f"{stamp(i)} [1] INFO  Shop - ok {i}" for i in range(n)]
    lines += [f"{stamp(n + i)} [1] ERROR Shop - payment {i} failed: timeout" for i in range(errors)]
    return lines


def test_digest_reports_only_new_lines_after_the_first_run(tmp_path: Path) -> None:
    log = write(tmp_path / "app.log", sample())
    state: dict[str, int] = {}
    first = digest_module.build([str(log)], state)
    assert first.errors == 2 and first.has_news and "app.log" in first.render()
    again = digest_module.build([str(log)], state)
    assert again.errors == 0 and not again.has_news and "Nothing new" in again.render()
    write(log, [f"{stamp(30)} [1] ERROR Shop - disk full"], mode="a")
    third = digest_module.build([str(log)], state)
    assert third.errors == 1 and third.files[0].new_lines == 1 and "disk full" in third.render()


def test_rotated_file_is_read_from_the_start(tmp_path: Path) -> None:
    log = write(tmp_path / "app.log", sample(20))
    state: dict[str, int] = {}
    digest_module.build([str(log)], state)
    write(log, [f"{stamp(1)} [1] ERROR Shop - after rotation"])
    assert digest_module.build([str(log)], state).errors == 1


def test_folders_and_globs(tmp_path: Path) -> None:
    write(tmp_path / "a.log", sample())
    write(tmp_path / "sub" / "b.log", sample())
    (tmp_path / "notes.bin").write_bytes(b"\x00\x01")
    found = digest_module.expand([str(tmp_path)])
    assert {p.name for p in found} == {"a.log", "b.log"}
    assert len(digest_module.expand([str(tmp_path / "*.log")])) == 1


def test_state_roundtrip_and_garbage(tmp_path: Path) -> None:
    path = tmp_path / "s" / "state.json"
    digest_module.save_state(path, {"x": 3})
    assert digest_module.load_state(path) == {"x": 3}
    path.write_text("not json", encoding="utf-8")
    assert digest_module.load_state(path) == {}


# ---- delivery -----------------------------------------------------------------------------------------------------
class Hook(BaseHTTPRequestHandler):
    received: ClassVar[list[dict]] = []
    status = 200

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers["Content-Length"]))
        Hook.received.append(json.loads(body))
        self.send_response(Hook.status)
        self.end_headers()

    def log_message(self, *_args: object) -> None:
        pass


@pytest.fixture
def hook():
    Hook.received, Hook.status = [], 200
    server = HTTPServer(("127.0.0.1", 0), Hook)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}/hook"
    server.shutdown()
    server.server_close()


def test_webhook_posts_text_and_refuses_plain_http_to_the_internet(hook: str) -> None:
    notify.post_webhook(hook, "hello", title="T")
    assert Hook.received == [{"text": "T\n\nhello"}]
    with pytest.raises(notify.DeliveryError, match="https"):
        notify.post_webhook("http://example.com/x", "no")
    Hook.status = 500
    with pytest.raises(notify.DeliveryError, match="500"):
        notify.post_webhook(hook, "again")
    with pytest.raises(notify.DeliveryError, match="could not be reached"):
        notify.post_webhook("http://127.0.0.1:9/hook", "x")


def test_mail_uses_smtp_and_explains_missing_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[object] = []

    class FakeSMTP:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            sent.append((host, port))

        def __enter__(self) -> FakeSMTP:
            return self

        def __exit__(self, *_a: object) -> None:
            return None

        def starttls(self, context: object) -> None:
            sent.append("tls")

        def login(self, user: str, password: str) -> None:
            sent.append(("login", user, password))

        def send_message(self, message) -> None:
            sent.append(("to", message["To"], message["Subject"]))

    monkeypatch.setattr(notify.smtplib, "SMTP", FakeSMTP)
    monkeypatch.setenv("LOGLENS_SMTP_PASSWORD", "pw")
    notify.send_mail(notify.MailSettings("smtp.x", 25, "a@x.org", ("b@x.org", "c@x.org"), "bot"), "Subj", "body")
    assert ("smtp.x", 25) in sent and "tls" in sent and ("login", "bot", "pw") in sent
    assert ("to", "b@x.org, c@x.org", "Subj") in sent
    with pytest.raises(notify.DeliveryError, match="needs a server"):
        notify.send_mail(notify.MailSettings(""), "s", "b")


# ---- command line ---------------------------------------------------------------------------------------------------
def test_parse_since() -> None:
    assert cli.parse_since("90m") == timedelta(minutes=90) and cli.parse_since("2d") == timedelta(days=2)
    for bad in ("", "0h", "abc", "5"):
        with pytest.raises(ValueError):
            cli.parse_since(bad)


def run(*args: str) -> int:
    return cli.run(["loglens", *args])


def test_summary_prints_and_can_fail_on_errors(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    log = write(tmp_path / "app.log", [*sample(), f"{stamp(40)} [1] INFO client_secret={TOKEN}"])
    assert run("summary", str(log)) == 0
    out = capsys.readouterr().out
    assert "# app.log" in out and "What to look at first" in out and TOKEN not in out
    assert run("summary", str(log), "--fail-on-errors") == 1
    assert run("summary", str(tmp_path / "missing.log")) == 2
    target = tmp_path / "s.md"
    run("summary", str(log), "-o", str(target))
    assert target.read_text(encoding="utf-8").startswith("# app.log")


def test_digest_to_a_webhook_remembers_what_it_sent(tmp_path: Path, hook: str) -> None:
    log = write(tmp_path / "app.log", sample())
    state = tmp_path / "state.json"
    assert run("digest", str(log), "--state", str(state), "--webhook", hook, "--title", "Nightly") == 0
    assert len(Hook.received) == 1 and "Nightly" in Hook.received[0]["text"] and "2 errors" in Hook.received[0]["text"]
    assert run("digest", str(log), "--state", str(state), "--webhook", hook, "--only-if-news") == 0
    assert len(Hook.received) == 1  # nothing new: nothing sent
    Hook.status = 500  # a failed delivery is an error and does not mark the lines as reported
    write(log, [f"{stamp(50)} [1] ERROR Shop - again"], mode="a")
    assert run("digest", str(log), "--state", str(state), "--webhook", hook) == 2
    Hook.status = 200
    assert run("digest", str(log), "--state", str(state), "--webhook", hook) == 0
    assert "1 errors" in Hook.received[-1]["text"]


def test_digest_without_a_target_prints(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    log = write(tmp_path / "app.log", sample())
    assert run("digest", str(log), "--state", str(tmp_path / "st.json")) == 0
    assert "2 errors" in capsys.readouterr().out


def test_schedule_prints_the_schtasks_command(capsys: pytest.CaptureFixture[str]) -> None:
    assert run("schedule", "--daily", "07:30", "--", "C:\\logs", "--webhook", "https://hooks.example/x") == 0
    out = capsys.readouterr().out
    assert "schtasks /Create" in out and "/ST 07:30" in out and "digest" in out and "--webhook" in out
    assert run("schedule", "--daily", "25:99", "--", "x") == 2
    assert run("schedule") == 2


def test_diagnose_validates_its_arguments(capsys: pytest.CaptureFixture[str]) -> None:
    assert run("diagnose", "--since", "soon") == 2
    assert run("diagnose", "--server", "no-such-server-xyz") == 2
    assert "no saved server" in capsys.readouterr().err


def test_is_cli_and_version(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.is_cli(["loglens", "summary", "x"])
    assert not cli.is_cli(["loglens", "C:\\a.log"]) and not cli.is_cli(["loglens"])
    assert run("--version") == 0 and "LogLens" in capsys.readouterr().out


def test_event_digest_counts_errors_and_remembers_the_time(tmp_path: Path) -> None:
    from datetime import UTC, datetime

    from loglens.core.winevent.models import EventRecord
    from loglens.core.winevent.reader import EventLogError, EventQuery

    asked: list[EventQuery] = []

    def reader(query: EventQuery):
        asked.append(query)
        if query.channel == "Security":
            raise EventLogError("Access is denied")
        when = datetime(2026, 11, 13, 10, 0, tzinfo=UTC)
        yield EventRecord("System", "Service Control Manager", 7031, 2, when, message="service crashed")
        yield EventRecord("System", "Service Control Manager", 7031, 2, when, message="service crashed again")
        yield EventRecord("System", "Disk", 51, 3, when, message="paging error")

    state: dict[str, int] = {}
    digest = digest_module.build_events(["System", "Security"], state, reader=reader)
    assert digest.errors == 2 and digest.warnings == 1 and "Service Control Manager (7031)" in digest.render()
    assert any("Access is denied" in p for p in digest.problems) and "event:this computer:System" in state
    assert "event:this computer:Security" not in state  # a channel that failed is retried next time
    digest_module.build_events(["System"], state, reader=reader)
    assert asked[-1].since is not None and asked[-1].since.timestamp() == pytest.approx(
        state["event:this computer:System"], abs=5
    )
