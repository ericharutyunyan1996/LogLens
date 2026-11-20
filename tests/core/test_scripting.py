"""Scripting console: useful scripts run, escape routes are closed, runaway scripts are stopped."""

from __future__ import annotations

import threading
import time

import pytest

from loglens.core.scripting import EXAMPLES, LineView, check_script, run_script

LOG = [
    "2026-11-13 10:00:00,000 [1] INFO  Shop - request took 120 ms",
    "2026-11-13 10:00:01,000 [1] ERROR Shop - payment failed",
    "2026-11-13 11:00:02,000 [1] ERROR Shop - payment failed again",
    "2026-11-13 11:00:03,000 [1] INFO  Shop - request took 480 ms",
]


def run(code: str, lines: list[str] | None = None, **kw):
    return run_script(code, LOG if lines is None else lines, **kw)


def test_print_len_and_iteration() -> None:
    r = run("print(len(lines))\nfor l in lines[:2]:\n    print(l[:10])\n")
    assert r.ok and r.output.splitlines() == ["4", "2026-11-13", "2026-11-13"]


def test_helpers_counter_levels_and_table() -> None:
    r = run(
        "hours = Counter()\nfor l in lines:\n    t = parse_time(l)\n    if t and level_of(l) == 'Error':\n        hours[t.hour] += 1\ntable(sorted(hours.items()), ['Hour', 'Errors'])\n"
    )
    assert r.ok
    rows = r.output.splitlines()
    assert rows[0].split() == ["Hour", "Errors"] and rows[2].split() == ["10", "1"] and rows[3].split() == ["11", "1"]


def test_allowed_modules_can_be_imported_and_used() -> None:
    r = run(
        "import re, statistics\nimport json\nnums = [int(m.group(1)) for l in lines for m in [re.search(r'took (\\d+)', l)] if m]\nprint(statistics.median(nums), json.dumps({'a': 1}))"
    )
    assert r.ok and r.output.strip() == '300.0 {"a": 1}'


@pytest.mark.parametrize(
    "code",
    [
        "import os",
        "import subprocess",
        "from os import path",
        "open('C:/x.txt')",
        "__import__('os')",
        "exec('1')",
        "eval('1')",
        "getattr(lines, 'x')",
        "().__class__",
        "lines._fetch",
        "x = print.__globals__",
        "re.sys",
        "json.decoder",
        "'{0.__class__}'.format(1)",
        "def g():\n    yield 1\nx = g().gi_frame",
        "class A: pass",
        "type(1)",
        "globals()",
    ],
)
def test_escape_routes_are_refused_before_running(code: str) -> None:
    r = run(code)
    assert not r.ok and r.output == ""


def test_a_dotted_import_only_binds_the_safe_module() -> None:
    r = run("import re.os\nprint(re.sys)")
    assert not r.ok  # `re` is the proxy: nothing but its public names is reachable


def test_proxied_modules_hide_their_internals() -> None:
    assert "not available" in run("import sys").error
    r = run("import re\nprint(re.sys)")
    assert not r.ok
    assert run("import json\nprint(json.dumps([1]))").ok


def test_runtime_errors_report_the_line() -> None:
    r = run("x = 1\ny = 1 / 0\n")
    assert not r.ok and "ZeroDivisionError" in r.error and "line 2" in r.error


def test_syntax_errors_are_explained() -> None:
    r = run("for l in lines print(l)")
    assert not r.ok and r.error.startswith("Line 1")


def test_infinite_loops_are_stopped() -> None:
    started = time.monotonic()
    r = run("while True:\n    pass\n", timeout=0.5)
    assert not r.ok and "Stopped after" in r.error and time.monotonic() - started < 5


def test_cancel_stops_a_script() -> None:
    cancel = threading.Event()
    threading.Timer(0.2, cancel.set).start()
    r = run("while True:\n    pass\n", cancel=cancel, timeout=30)
    assert r.error == "Cancelled."


def test_output_is_capped() -> None:
    r = run("for i in range(200000):\n    print('x' * 50)\n", timeout=20)
    assert r.truncated and len(r.output) < 700_000


def test_the_line_view_is_read_only() -> None:
    view = LineView(4, lambda start, count: LOG[start : start + count])
    with pytest.raises(TypeError):
        view[0] = "x"  # type: ignore[index]


def test_line_view_slices_blocks_and_negative_indexes() -> None:
    view = LineView(12_000, lambda start, count: [f"l{i}" for i in range(start, start + count)])
    assert len(view) == 12_000 and view[0] == "l0" and view[-1] == "l11999" and view[5_001] == "l5001"
    assert view[3:6] == ["l3", "l4", "l5"] and sum(1 for _ in view) == 12_000
    with pytest.raises(IndexError):
        view[12_000]


def test_check_script_accepts_the_examples() -> None:
    for name, code in EXAMPLES:
        assert check_script(code) is None, name
        assert run(code).ok, name
