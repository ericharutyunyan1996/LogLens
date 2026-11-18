"""Web-search query building: keep what generalises (exception, message, codes, event id), drop local noise."""

from __future__ import annotations

from loglens.core.websearch import build_query, search_url


def test_exception_and_message() -> None:
    line = (
        "2026-11-11 13:47:26,153 [16] TRACE Http.Trace - Error Exception : System.Net.WebException: "
        "The remote server returned an error: (502) Bad Gateway."
    )
    assert build_query([line]) == 'System.Net.WebException "The remote server returned an error: (502) Bad Gateway."'


def test_multi_line_selection_uses_exception_line_and_redacts() -> None:
    lines = [
        "2026-11-13 10:15:02,123 [14] ERROR Shop.Orders - Could not save order 48213",
        "System.Data.SqlClient.SqlException (0x80131904): Transaction (Process ID 61) was deadlocked on lock "
        "resources with user alice@corp.com from 10.1.2.3",
    ]
    query = build_query(lines)
    assert query.startswith('System.Data.SqlClient.SqlException "Transaction (Process ID 61) was deadlocked')
    assert "alice" not in query and "10.1.2.3" not in query and "0x80131904" in query


def test_windows_event_line() -> None:
    line = (
        "2026-11-13 10:15:02.123 +04:00 Error [Application] Application Error (1000) — Faulting application name: "
        "w3wp.exe, Exception code: 0xc0000005 ‖ {}"
    )
    assert build_query([line]) == '"Application Error" event 1000 0xc0000005'


def test_plain_line_is_cleaned() -> None:
    line = (
        "2018-07-21 11:17:26, Error DISM DISM Package Manager: PID=15912 TID=16116 Failed processing package "
        "changes - CDISMPackageManager::RestoreHealth(hr:0x800f081f)"
    )
    query = build_query([line])
    assert "Failed processing package changes" in query and "0x800f081f" in query
    assert "15912" not in query and "2018-07-21" not in query


def test_python_error_and_url() -> None:
    assert build_query(["ValueError: invalid literal for int() with base 10: abc"]).startswith("ValueError")
    assert search_url("Bing", 'a "b" c') == "https://www.bing.com/search?q=a+%22b%22+c"
    assert search_url("unknown", "x").startswith("https://www.google.com/")
