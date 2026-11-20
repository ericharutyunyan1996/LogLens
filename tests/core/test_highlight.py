"""Highlight rules and default presets."""

from __future__ import annotations

from loglens.core.highlight import default_rules, style_line


def test_style_line_priority_and_spans() -> None:
    rules = default_rules()
    by_name = {r.name: r for r in rules}
    st = style_line(rules, "2026-11-13 10:00:00 ERROR Something failed for 0xc0000005 at 10.1.2.3")
    assert st.bg == by_name["Error"].bg
    assert any(fg == "#D2691E" for _, _, fg, _ in st.spans)  # hex code span
    assert style_line(rules, "2026-11-13 INFO all good").bg is None
    assert style_line(rules, "WARN disk 91% full").bg == by_name["Warning"].bg
    assert style_line(rules, "System.TimeoutException: The operation has timed out.").bg == by_name["Error"].bg
    assert style_line(rules, "   at Shop.Orders.Save() in C:\\x.cs:line 4").fg == by_name["Stack trace"].fg
    # common .NET logging frameworks' level tokens
    fatal, error, warn = by_name["Fatal / Critical"].bg, by_name["Error"].bg, by_name["Warning"].bg
    for line, bg in [
        ("2026-11-13 10:15:02.123 +04:00 [FTL] Application terminated", fatal),  # Serilog
        ("2026-11-13 10:15:02.123 +04:00 [ERR] Could not save", error),
        ("2026-11-13 10:15:02.123 +04:00 [WRN] Retrying", warn),
        ("2026-11-13 10:15:02,123 [14] FATAL Shop.Program - down", fatal),  # log4net
        ("2026-11-13 10:15:02.1234|ERROR|Shop.Orders|failed to save", error),  # NLog
        ('{"@t":"2026-11-13T10:15:02Z","@mt":"x","@l":"Fatal"}', fatal),  # Serilog CLEF
        ("fail: Microsoft.AspNetCore.Server.Kestrel[13]", error),  # Microsoft.Extensions.Logging
        ("crit: Microsoft.AspNetCore.Hosting.Diagnostics[6]", fatal),
        ("2018-07-21 11:17:26, Error                 DISM   DISM Package Manager: failed", error),  # CBS/DISM
        ("2023-03-30 18:38:29.3712|Warn|App.Cache|slow", warn),  # NLog without uppercase
        ('{"time":"2026-11-13T10:15:02Z","level":"error","msg":"boom"}', error),  # JSON lines
        ("ts=2026-11-13T10:15:02Z level=warning msg=retry", warn),  # logfmt
        ("2026-11-13T10:15:02.123Z Error Payment declined", error),  # ISO with Z
        ("2026-11-13 10:15:02,123 [14] Error Shop.Orders - Save failed", error),  # log4net, mixed-case level
        ("11/13/2026 4:53:45 PM Warning Disk almost full", warn),  # US date with AM/PM
    ]:
        assert style_line(rules, line).bg == bg, line


def test_prose_level_words_are_not_levels() -> None:
    """Words like 'critical' or 'error' inside a sentence must not make the line a fatal/error record."""
    rules = default_rules()
    issue_rules = [r for r in rules if r.scrollbar_mark]
    for line in [
        "!    idb:                     Assuming device class {99174451-71bd-11dc} is not critical.",
        "     sto: {Reflect Critical Driver Package: C:\\Windows\\System32\\DriverStore\\x.inf}",
        "     inf:                          Class Options  = Configurable BootCritical",
        "2026-11-13 10:00:00,000 [3] INFO  Worker - Processed 20 items, 0 errors, retry on failure disabled",
        "2026-11-13 10:00:00,000 [3] INFO  Worker - WorkerConfig.AlertOnErrors: False",
    ]:
        style = style_line(issue_rules, line)
        assert style.bg is None, line
    prose = style_line(rules, "INFO connection failed, retrying")
    assert prose.bg is None and any(fg == "#C0504D" for _, _, fg, _ in prose.spans)  # visible, not an issue
