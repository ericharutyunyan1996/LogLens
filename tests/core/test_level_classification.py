"""Severity classification: the level in the record header wins over words in the message (no false errors).

Regression for logs where config / informational lines mention "Error" or "Failed" ("EventLogLevel: Error",
"Event log-level: Error.", "Processing types: New, Failed.") and were counted as errors.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from loglens.core.highlight import default_rules

LEVEL_RULES = [r for r in default_rules() if r.level_filter]


def level_of(line: str) -> str:
    """What the level chips / scrollbar marks make of a line (first matching level rule, as the UI does)."""
    for rule in LEVEL_RULES:
        pattern = rule.compiled()
        if pattern is not None and pattern.search(line):
            return rule.name.split(" / ")[0]
    return ""  # informational: no level chip counts it


TS = "2026-11-03 08:40:10,056"

# (log line, expected level) — configuration/info lines that mention error words, and real errors
REPORTED = [
    (f"{TS} [10] INFO  Worker - WorkerConfig.EventLogLevel: Error", ""),
    (f"{TS} [15] OFF   Worker - File log-level: Trace, Event log-level: Error.", ""),
    (f"{TS} [15] OFF   Worker - Processing types: New, Failed.", ""),
    (f"{TS} [15] ERROR Worker - Failed to connect to server", "Error"),
    (f"{TS} [15] ERROR Worker - System.Exception: Connection timeout", "Error"),
]


@pytest.mark.parametrize(("line", "expected"), REPORTED)
def test_config_and_info_lines_that_mention_error_words(line: str, expected: str) -> None:
    assert level_of(line) == expected


@pytest.mark.parametrize(
    "line",
    [
        f"{TS} [1] INFO  Svc - Retrying after the previous call Failed with an Exception",
        f"{TS} [1] INFO  Svc - level=error is the configured log level",
        f'{TS} [1] INFO  Svc - {{"level":"error"}} sent to the sink',
        f"{TS} [1] OFF   Svc - Exception handling is enabled; ERROR events are mirrored",
        f"{TS} [1] DEBUG Svc - Caught System.InvalidOperationException while probing, ignoring",
        f"{TS} [1] TRACE Svc - Operation=Execute, Exception=System.IO.IOException: gone",
        f"{TS} [1] DEBUG Svc - [ERROR] Failed to process the request. Exception = x",
        f"{TS} [1] NOTICE Svc - FAILED jobs: 0",
        f"{TS} [1] Info  Svc - Error count reset",
        f"{TS} [1] [INFO] Svc - Fatal errors: none",
        "INFO:root:error rate is fine",
    ],
)
def test_header_severity_beats_message_words(line: str) -> None:
    assert level_of(line) not in {"Error", "Fatal"}, line


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        (f"{TS} [1] ERROR Svc - boom", "Error"),
        (f"{TS} [1] Error Svc - boom", "Error"),
        (f"{TS} [1] [ERROR] Svc - boom", "Error"),
        (f"{TS} [1] FATAL Svc - out of memory", "Fatal"),
        (f"{TS} [1] WARN  Svc - Error budget low", "Warning"),
        (f"{TS} [1] DEBUG Svc - cache miss", "Debug"),
        (f"{TS} [1] TRACE Svc - entering", "Debug"),
        ("ERROR:root:Failed to connect", "Error"),
        ("WARNING:root:disk almost full", "Warning"),
        ("[ERROR] 2026-11-03 failed", "Error"),
        ("2018-07-21 11:17:26, Error                 DISM   DISM Package Manager: failed", "Error"),
        ("2026-11-03T08:40:10.1234|Warn|Svc|slow", "Warning"),
    ],
)
def test_real_severities_are_found(line: str, expected: str) -> None:
    assert level_of(line) == expected, line


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        # no header level: continuation lines / structured logs / free text keep the contextual fallback
        ("System.InvalidOperationException: Sequence contains no elements", "Error"),
        ("Exception: something broke", "Error"),
        ('{"@t":"2026-11-03","@l":"Error","@mt":"boom"}', "Error"),
        ('{"level":"warn","msg":"slow"}', "Warning"),
        ("level=fatal msg=died", "Fatal"),
        ("fail: Microsoft.AspNetCore.Server.Kestrel[13]", "Error"),
        ("this line is plain prose about an error", ""),
        ("Processing types: New, Failed.", ""),
    ],
)
def test_lines_without_a_header_level_use_context(line: str, expected: str) -> None:
    assert level_of(line) == expected, line


def test_level_rules_keep_a_literal_prefilter() -> None:
    """Marks over a 1 GB log depend on the regex prefilter: the header-first rules must still provide literals."""
    from loglens.core.regex_tools import literal_prefilter

    for rule in LEVEL_RULES:
        pattern = rule.compiled()
        assert pattern is not None
        if rule.name.startswith("HTTP"):
            continue
        assert literal_prefilter(pattern.pattern, pattern.flags), rule.name


# --- real-world logs: any folder of logs you point LOGLENS_REAL_LOGS at (never copied into the repo) ---------------
REAL_LOGS = os.environ.get("LOGLENS_REAL_LOGS", "")


@pytest.mark.skipif(not REAL_LOGS or not Path(REAL_LOGS).is_dir(), reason="set LOGLENS_REAL_LOGS to a folder of logs")
def test_real_logs_have_no_false_errors() -> None:
    """A line whose header says INFO / OFF / DEBUG / TRACE is never counted as an Error or Fatal."""
    wrong: list[str] = []
    for path in sorted(Path(REAL_LOGS).glob("*.log")):
        with path.open(encoding="utf-8-sig", errors="replace") as handle:
            for line in handle:
                head = line.split(None, 4)
                if (
                    len(head) > 3
                    and head[3] in {"INFO", "OFF", "DEBUG", "TRACE"}
                    and level_of(line) in {"Error", "Fatal"}
                ):
                    wrong.append(f"{path.name}: {line[:120].rstrip()}")
    assert not wrong, wrong[:3]
