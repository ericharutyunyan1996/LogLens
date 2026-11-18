"""CSV / JSON Lines export and incident reports (Markdown / HTML, redaction)."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime

from loglens.core.ai.config import Redact
from loglens.core.ai.explain import Cause, Explanation
from loglens.core.ai.redaction import Redactor
from loglens.core.kb import Finding
from loglens.core.report import (
    EvidenceLine,
    IncidentReport,
    make_rows,
    redact_report,
    to_csv,
    to_html,
    to_json_lines,
    to_markdown,
)
from loglens.core.timeparse import parse_line_time

LINES = [
    (0, '2026-11-13 10:00:00,000 INFO  start, said "hi"'),
    (4, "2026-11-13 10:00:01,000 ERROR login failed for bob@example.com from 10.1.2.3"),
]


def test_csv_and_json_lines() -> None:
    rows = make_rows(LINES, time_of=parse_line_time, level_of=lambda t: "Error" if "ERROR" in t else "")
    parsed = list(csv.DictReader(io.StringIO(to_csv(rows))))
    assert parsed[0]["line"] == "1" and parsed[0]["text"] == LINES[0][1] and parsed[1]["level"] == "Error"
    assert parsed[1]["time"].startswith("2026-11-13T10:00:01")
    first = json.loads(to_json_lines(rows).splitlines()[0])
    assert first == {"line": 1, "time": first["time"], "level": "", "text": LINES[0][1]}


def _report() -> IncidentReport:
    finding = Finding("pattern", "login failed", "Failed sign-in", "Someone typed a wrong password.", source="KB")
    explanation = Explanation(
        summary="Repeated failed logins",
        severity="error",
        is_likely_noise=False,
        what_happened="A user failed to sign in.",
        probable_causes=(Cause("Wrong password", "high", (5,)),),
        next_steps=("Check the account",),
        missing_information="",
        confidence="medium",
        model="claude-opus-5-5",
    )
    return IncidentReport(
        title="Login <failures>",
        source=r"C:\Users\bob\logs\app.log",
        created=datetime(2026, 11, 13, 12, 0).astimezone(),
        summary="Users cannot sign in",
        counts=[("Error", 1)],
        evidence=[EvidenceLine(5, LINES[1][1], "bookmark", (finding,))],
        explanations=[explanation],
        windows_events=["2026-11-13 10:00:02 Security 4625 An account failed to log on."],
    )


def test_markdown_and_html() -> None:
    markdown = to_markdown(_report())
    assert "# Login <failures>" in markdown and "**Line 5** — bookmark" in markdown
    assert "Wrong password (high) — L5" in markdown and "Failed sign-in" in markdown and "4625" in markdown
    page = to_html(_report())
    assert "<h1>Login &lt;failures&gt;</h1>" in page and "<script" not in page


def test_redacted_report_hides_personal_data() -> None:
    redactor = Redactor((Redact.EMAILS, Redact.IP_ADDRESSES, Redact.USER_PATHS))
    markdown = to_markdown(redact_report(_report(), redactor))
    assert "bob@example.com" not in markdown and "10.1.2.3" not in markdown and r"Users\bob" not in markdown
