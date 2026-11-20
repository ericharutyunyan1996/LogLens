"""A small scripting console: Python over the lines of an open log, with no way to change anything.

The script only receives the log's lines (``lines``), a few helpers and a short list of harmless modules; there is no
file, network, process or import access, no dunder / private attribute access, and a time limit. It is a guard
against accidents in your own scripts, not a security boundary against hostile code: do not run scripts you do not
understand.
"""

from __future__ import annotations

import ast
import builtins
import collections
import datetime as datetime_module
import functools
import io
import itertools
import json
import math
import re
import statistics
import string
import sys
import textwrap
import threading
import time
from collections import Counter, defaultdict
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from itertools import groupby, islice
from typing import Any

from .timeparse import parse_line_time

MAX_OUTPUT_CHARS = 400_000
DEFAULT_TIMEOUT_S = 30.0


class SafeModule:
    """A module as scripts see it: only its public, documented names (``__all__``), so ``re.sys`` or
    ``json.decoder`` cannot lead to the interpreter's internals."""

    def __init__(self, module: Any) -> None:
        object.__setattr__(self, "_module", module)
        names = getattr(module, "__all__", None) or [n for n in dir(module) if not n.startswith("_")]
        object.__setattr__(self, "_names", frozenset(n for n in names if not n.startswith("_")))

    def __getattr__(self, name: str) -> Any:
        if name not in self._names:
            raise AttributeError(f"module has no attribute '{name}'")
        return getattr(self._module, name)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("modules are read-only in scripts")

    def __dir__(self) -> list[str]:
        return sorted(self._names)


ALLOWED_MODULES: dict[str, Any] = {
    name: SafeModule(module)
    for name, module in {
        "re": re,
        "json": json,
        "math": math,
        "statistics": statistics,
        "collections": collections,
        "itertools": itertools,
        "functools": functools,
        "datetime": datetime_module,
        "string": string,
        "textwrap": textwrap,
    }.items()
}
ALLOWED_LIST = ", ".join(sorted(ALLOWED_MODULES))
INTERNAL_MODULES = {"time", "_strptime", "locale", "calendar", "decimal", "_decimal", "fractions"}
DENIED_ATTRS = {
    "gi_frame",
    "gi_code",
    "gi_yieldfrom",
    "cr_frame",
    "cr_code",
    "ag_frame",
    "ag_code",
    "f_back",
    "f_globals",
    "f_locals",
    "f_builtins",
    "f_code",
    "tb_frame",
    "tb_next",
    "co_consts",
    "func_globals",
    "mro",
    "format",
    "format_map",
}  # fmt: skip - frame / code access and str.format attribute lookups: escape routes out of the allowed subset
FORBIDDEN_NAMES = {
    "exec", "eval", "compile", "open", "input", "breakpoint", "globals", "locals", "vars", "getattr", "setattr",
    "delattr", "memoryview", "help", "exit", "quit", "type", "super", "object", "classmethod", "staticmethod",
}  # fmt: skip
SAFE_BUILTINS = [
    "abs",
    "all",
    "any",
    "bin",
    "bool",
    "bytes",
    "chr",
    "dict",
    "divmod",
    "enumerate",
    "filter",
    "float",
    "format",
    "frozenset",
    "hasattr",
    "hash",
    "hex",
    "int",
    "isinstance",
    "issubclass",
    "iter",
    "len",
    "list",
    "map",
    "max",
    "min",
    "next",
    "oct",
    "ord",
    "pow",
    "range",
    "repr",
    "reversed",
    "round",
    "set",
    "slice",
    "sorted",
    "str",
    "sum",
    "tuple",
    "zip",
    "True",
    "False",
    "None",
    "Exception",
    "ValueError",
    "TypeError",
    "KeyError",
    "IndexError",
    "StopIteration",
    "ZeroDivisionError",
]


class ScriptError(Exception):
    """The script cannot be run (not allowed, or it does not parse): the message is shown to the user."""


class ScriptTimeoutError(Exception):
    pass


class ScriptCancelledError(Exception):
    pass


@dataclass(slots=True)
class ScriptResult:
    output: str = ""
    error: str = ""
    seconds: float = 0.0
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return not self.error


def check_script(code: str) -> str | None:  # noqa: PLR0911 - one message per refused construct
    """Why ``code`` may not run (None when it may): syntax errors and anything outside the allowed subset."""
    try:
        tree = ast.parse(code, "<script>", "exec")
    except SyntaxError as exc:
        return f"Line {exc.lineno}: {exc.msg}"
    for node in ast.walk(tree):
        line = getattr(node, "lineno", 0)
        if isinstance(node, ast.Attribute) and node.attr.startswith("_"):
            return f"Line {line}: attributes starting with an underscore are not available (.{node.attr})."
        if isinstance(node, ast.Attribute) and node.attr in DENIED_ATTRS:
            hint = " Use an f-string instead." if node.attr.startswith("format") else ""
            return f"Line {line}: '.{node.attr}' is not available in scripts.{hint}"
        if isinstance(node, ast.Name) and (node.id in FORBIDDEN_NAMES or node.id.startswith("__")):
            return f"Line {line}: '{node.id}' is not available in scripts."
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in ALLOWED_MODULES:
                    return f"Line {line}: module '{alias.name}' is not available (allowed: {ALLOWED_LIST})."
        if isinstance(node, ast.ImportFrom) and (
            node.level or (node.module or "").split(".")[0] not in ALLOWED_MODULES
        ):
            return f"Line {line}: module '{node.module}' is not available (allowed: {ALLOWED_LIST})."
        if isinstance(node, ast.ClassDef | ast.AsyncFunctionDef | ast.Await | ast.Global | ast.Nonlocal):
            return f"Line {line}: {type(node).__name__.replace('Def', '').lower()} is not supported in scripts."
    return None


class LineView(Sequence[str]):
    """The log's lines as a read-only sequence, fetched in blocks on demand (works for logs of any size)."""

    BLOCK = 5_000

    def __init__(self, count: int, fetch: Callable[[int, int], list[str]]) -> None:
        self._count, self._fetch = count, fetch
        self._block = -1
        self._cache: list[str] = []

    def __len__(self) -> int:
        return self._count

    def __getitem__(self, index: Any) -> Any:
        if isinstance(index, slice):
            return [self[i] for i in range(*index.indices(self._count))]
        if index < 0:
            index += self._count
        if not 0 <= index < self._count:
            raise IndexError(index)
        block = index // self.BLOCK
        if block != self._block:
            self._cache = self._fetch(block * self.BLOCK, min(self.BLOCK, self._count - block * self.BLOCK))
            self._block = block
        return self._cache[index - block * self.BLOCK]

    def __iter__(self) -> Iterator[str]:
        for start in range(0, self._count, self.BLOCK):
            yield from self._fetch(start, min(self.BLOCK, self._count - start))


def _table(rows: Sequence[Sequence[object]], headers: Sequence[str] | None = None) -> str:
    cells = [[str(c) for c in row] for row in rows]
    if headers:
        cells.insert(0, [str(h) for h in headers])
    if not cells:
        return "(no rows)"
    widths = [max(len(r[i]) if i < len(r) else 0 for r in cells) for i in range(max(len(r) for r in cells))]
    lines = ["  ".join(c.ljust(widths[i]) for i, c in enumerate(row)).rstrip() for row in cells]
    if headers:
        lines.insert(1, "  ".join("-" * w for w in widths))
    return "\n".join(lines)


@functools.cache
def _levels() -> Any:
    from .triage import _Levels  # noqa: PLC0415 - shared with the triage summary

    return _Levels()


def _level_of(line: str) -> str:
    return str(_levels().of(line))


class _Output(io.StringIO):
    def write(self, text: str) -> int:
        if self.tell() < MAX_OUTPUT_CHARS:
            return super().write(text)
        return len(text)


def run_script(
    code: str,
    lines: Sequence[str],
    *,
    title: str = "",
    timeout: float = DEFAULT_TIMEOUT_S,
    cancel: threading.Event | None = None,
) -> ScriptResult:
    """Run ``code`` with ``lines`` available; returns what it printed, or the error."""
    problem = check_script(code)
    if problem:
        return ScriptResult(error=problem)
    out = _Output()

    def printer(*args: object, sep: str = " ", end: str = "\n", **_ignored: object) -> None:
        out.write(sep.join(str(a) for a in args) + end)

    def restricted_import(name: str, *_a: Any, **_k: Any) -> Any:
        root = name.split(".", maxsplit=1)[0]
        if root in ALLOWED_MODULES:
            return ALLOWED_MODULES[root]
        if root in INTERNAL_MODULES:  # the standard library itself needs these (datetime.strftime imports time)
            return builtins.__import__(name, *_a, **_k)
        raise ImportError(f"module '{name}' is not available")

    safe = {name: getattr(builtins, name) for name in SAFE_BUILTINS if hasattr(builtins, name)}
    safe.update(print=printer, __import__=restricted_import)
    names: dict[str, Any] = {
        "__builtins__": safe,
        "lines": lines,
        "title": title,
        "parse_time": parse_line_time,
        "level_of": _level_of,
        "table": lambda rows, headers=None: printer(_table(rows, headers)),
        "Counter": Counter,
        "defaultdict": defaultdict,
        "groupby": groupby,
        "islice": islice,
        **ALLOWED_MODULES,
    }
    started = time.monotonic()
    deadline = started + timeout
    ticks = 0

    def guard(_frame: Any, event: str, _arg: Any) -> Any:
        nonlocal ticks
        if event == "line":
            ticks += 1
            if ticks % 500 == 0:
                if cancel is not None and cancel.is_set():
                    raise ScriptCancelledError
                if time.monotonic() > deadline:
                    raise ScriptTimeoutError
        return guard

    result = ScriptResult()
    previous = sys.gettrace()
    try:
        compiled = compile(code, "<script>", "exec")
        sys.settrace(guard)
        try:
            exec(compiled, names)
        finally:
            sys.settrace(previous)
    except ScriptTimeoutError:
        result.error = f"Stopped after {timeout:g} seconds (a script may run at most that long)."
    except ScriptCancelledError:
        result.error = "Cancelled."
    except Exception as exc:  # noqa: BLE001 - the user's script failed: show what and where
        tb = exc.__traceback__
        while tb is not None and tb.tb_next is not None and tb.tb_frame.f_code.co_filename != "<script>":
            tb = tb.tb_next
        where = f" (line {tb.tb_lineno})" if tb is not None and tb.tb_frame.f_code.co_filename == "<script>" else ""
        result.error = f"{type(exc).__name__}: {exc}{where}"
    result.output = out.getvalue()
    result.truncated = out.tell() >= MAX_OUTPUT_CHARS
    result.seconds = time.monotonic() - started
    return result


_EXAMPLE_ERRORS_PER_HOUR = """\
hours = Counter()
for line in lines:
    when = parse_time(line)
    if when and level_of(line) in ('Error', 'Fatal / Critical'):
        hours[when.strftime('%Y-%m-%d %H:00')] += 1
table(sorted(hours.items()), ['Hour', 'Errors'])
"""
_EXAMPLE_SLOWEST = """\
times = []
for n, line in enumerate(lines):
    m = re.search(r'took (\\d+(?:\\.\\d+)?) ?ms', line)
    if m:
        times.append((float(m.group(1)), n + 1))
times.sort(reverse=True)
table(times[:10], ['ms', 'line'])
if times:
    print('median', statistics.median(t for t, _ in times))
"""
_EXAMPLE_WORDS = """\
words = Counter()
for line in lines:
    parts = line.split()
    if len(parts) > 4:
        words[parts[4]] += 1
table(words.most_common(15), ['Word', 'Lines'])
"""
EXAMPLES: tuple[tuple[str, str], ...] = (
    ("Errors per hour", _EXAMPLE_ERRORS_PER_HOUR),
    ("Slowest numbers after 'took'", _EXAMPLE_SLOWEST),
    ("Most frequent word after the level", _EXAMPLE_WORDS),
)
