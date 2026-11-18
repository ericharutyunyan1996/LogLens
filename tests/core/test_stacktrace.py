"""Stack traces in multi-line records: .NET, Java, Python, JavaScript; prose is not a trace."""

from __future__ import annotations

from loglens.core.payloads import analyze
from loglens.core.payloads.stacktrace_payload import StackTraceFormatter

HEADER = "2026-11-13 10:00:01,000 [1] ERROR Svc - request failed"
DOTNET = "\n".join([
    HEADER,
    "System.InvalidOperationException: Sequence contains no elements",
    " ---> System.IO.IOException: The device is not ready. (0x80070015)",
    "   at Svc.Storage.Read(String path) in C:\\src\\Svc\\Storage.cs:line 42",
    "   at Svc.Worker.Run() in C:\\src\\Svc\\Worker.cs:line 17",
    "   --- End of inner exception stack trace ---",
    "   at Svc.Program.Main(String[] args)",
])  # fmt: skip
JAVA = "\n".join([
    "java.lang.IllegalStateException: bad state",
    "\tat com.example.Foo.bar(Foo.java:10)",
    "\tat com.example.Foo.main(Foo.java:5)",
    "Caused by: java.net.ConnectException: Connection refused",
    "\tat java.base/sun.nio.ch.Net.connect0(Native Method)",
    "\t... 3 more",
])  # fmt: skip
PYTHON = "\n".join([
    "Traceback (most recent call last):",
    '  File "app.py", line 12, in <module>',
    "    main()",
    '  File "app.py", line 8, in main',
    "    raise ValueError('nope')",
    "ValueError: nope",
])  # fmt: skip
NODE = "\n".join([
    "TypeError: Cannot read properties of undefined (reading 'id')",
    "    at handler (/srv/app/routes.js:14:21)",
    "    at async Router.dispatch (/srv/app/router.js:88:5)",
])  # fmt: skip


def traces(text: str) -> list[str]:
    return [s.kind for s in StackTraceFormatter().find(text)]


def test_dotnet_trace_with_inner_exception() -> None:
    sections = StackTraceFormatter().find(DOTNET)
    assert sections[0].kind == "Stack trace (3 frames)"
    assert sections[0].body.startswith("System.InvalidOperationException")
    assert "\n    at Svc.Storage.Read" in sections[0].body
    assert sections[1].kind == "Exception chain"
    assert sections[1].body == "System.InvalidOperationException\n  ↳ System.IO.IOException"
    assert DOTNET[sections[0].start : sections[0].end].endswith("Main(String[] args)")


def test_java_python_node() -> None:
    assert traces(JAVA) == ["Stack trace (4 frames)", "Exception chain"]
    assert traces(PYTHON) == ["Stack trace (2 frames)"]
    assert "        main()" in StackTraceFormatter().find(PYTHON)[0].body
    assert traces(NODE) == ["Stack trace (2 frames)"]


def test_not_a_trace() -> None:
    assert traces("Meeting at noon (room 4)\nat the office (main building)") == []
    assert traces("single line at Foo.Bar()") == []
    assert traces("ValueError: one header\n   at Only.One()") == []  # one frame is too weak


def test_trace_claimed_before_other_payloads() -> None:
    kinds = [s.kind for s in analyze(DOTNET).located]
    assert kinds == ["Stack trace (3 frames)"]  # paths inside frames are not separate payloads
