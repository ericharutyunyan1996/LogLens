"""Generic timestamp detection at the start of log lines (formats from public log corpora and standards)."""

from __future__ import annotations

import pytest

from loglens.core.timestamps import PATTERNS, dominant_pattern, find_timestamp


@pytest.mark.parametrize(
    ("line", "name"),
    [
        ("2026-11-13 10:15:02,123 [14] ERROR Svc - failed", "iso8601"),  # log4net / NLog / Python logging
        ("2026-11-13T10:15:02.1234567Z INF started", "iso8601"),  # ISO / Serilog / .NET round-trip
        ("2018-07-06 09:02:17.148 +10:00 [INF] HTTP GET / responded 200", "iso8601"),  # Serilog default file
        ("2018-07-21 11:17:26, Error DISM DISM Package Manager: failed", "iso8601"),  # CBS / DISM
        ("- 1117838570 2005.06.03 R02-M1-N0 2005-06-03-15.42.50.675872 R02 RAS KERNEL INFO", "iso-dashed-time"),
        ("2019/07/19 14:58:27.5442492 4328 6336 Agent LogHistory called.", "slashed-ymd"),  # WindowsUpdate
        ('127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /a.gif HTTP/1.0" 200 2326', "clf"),  # Apache access
        ("[Sun Dec 04 04:47:44 2005] [notice] workerEnv.init() ok", "ctime"),  # Apache error
        ("11/13/2026 4:53:45 PM Service started", "dmy-or-mdy"),
        ("20171223-22:15:29:606|Step_LSC|30002312|onStandStepChanged 3579", "ymd-compact-time"),
        ("Jun 14 15:16:01 combo sshd(pam_unix)[19939]: authentication failure", "syslog"),  # Linux syslog
        ("03-17 16:13:38.811  1702  2395 D WindowManager: printFreezingDisplayLogs", "md-time"),  # Android
        ("081109 203615 148 INFO dfs.DataNode$PacketResponder: PacketResponder 1", "compact"),  # HDFS
        ("[10.30 16:49:06] chrome.exe - proxy.cse.cuhk.edu.hk:5070 open through proxy", None),  # Proxifier: no year
    ],
)
def test_find_timestamp(line: str, name: str | None) -> None:
    match = find_timestamp(line)
    assert (match.pattern.name if match else None) == name


def test_continuation_lines_have_no_timestamp() -> None:
    for line in [
        "   at System.Net.HttpWebRequest.EndGetRequestStream(IAsyncResult asyncResult)",
        "Content-Type : application/json",
        '{"user":"x","items":[1,2]}',
        "",
    ]:
        assert find_timestamp(line) is None, line


def test_timestamp_far_into_the_message_is_ignored() -> None:
    line = "x" * 100 + " 2026-11-13 10:15:02"
    assert find_timestamp(line) is None


def test_examples_match_their_own_pattern() -> None:
    for pattern in PATTERNS:
        assert pattern.regex.search(pattern.example), pattern.name


def test_dominant_pattern() -> None:
    lines = ["2026-11-13 10:00:00,000 INFO a", "  continuation", "2026-11-13 10:00:01,000 INFO b", "more"]
    pattern, share = dominant_pattern(lines)
    assert pattern is not None and pattern.name == "iso8601" and share == 0.5
