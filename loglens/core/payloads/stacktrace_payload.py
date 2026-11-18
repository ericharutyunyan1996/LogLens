"""Stack traces inside a multi-line record (.NET, Java/Kotlin, Python, JavaScript/Node).

A trace is a run of consecutive lines that are stack frames or exception headers ("System.IO.IOException: …",
"Caused by: …", "Traceback (most recent call last):", "--- End of inner exception stack trace ---"). It is shown as one
section with uniform indentation, and the exception chain (outermost first) as a derived summary.
"""

from __future__ import annotations

import re

from .base import Section

MIN_FRAMES = 2  # a single "at …" line is too weak a signal (prose can start with "at")

_FRAME = re.compile(
    r"^[ \t]*(?:"
    r"at [\w$.<>`\[\],:+|~/ -]+\([^\n]*\)(?: in [^\n]+?:line \d+)?"  # .NET / Java / Kotlin frame
    r"|at (?:async )?[^\s()]+ \([^\n()]+:\d+:\d+\)|at [^\s()]+:\d+:\d+"  # JavaScript / Node
    r'|File "[^"\n]+", line \d+(?:, in [^\n]+)?'  # Python frame
    r"|\.\.\. \d+ (?:more|common frames omitted)"  # Java elision
    r")[ \t]*$",
    re.M,
)
_PYTHON_CODE = re.compile(r"^[ \t]{4,}\S[^\n]*$", re.M)  # source line under a Python "File …" frame
_HEADER = re.compile(
    r"^[ \t]*(?:"
    r"Traceback \(most recent call last\):"
    r"|(?:Caused by|Suppressed|Unhandled exception\.|Exception in thread \"[^\"\n]*\")[: ][^\n]*"
    r"|-{2,3}> ?[^\n]+"  # .NET inner exception: " ---> System.IO.IOException: …"
    r"|-{2,3} ?[^\n]*(?:inner exception|End of stack trace)[^\n]*"
    r"|(?:[\w$]+\.)*[A-Z][\w$]*(?:Exception|Error|Fault)\b(?:\s*\([^)\n]*\))?(?::[^\n]*)?"
    r")[ \t]*$",
    re.M,
)
_EXCEPTION_TYPE = re.compile(r"\b((?:[\w$]+\.)*[A-Z][\w$]*(?:Exception|Error|Fault))\b")


def _classify(line: str) -> str:
    if _FRAME.fullmatch(line):
        return "frame"
    if _HEADER.fullmatch(line):
        return "header"
    return ""


class StackTraceFormatter:
    kind = "Stack trace"

    def find(self, text: str) -> list[Section]:
        if "\n" not in text:
            return []
        out: list[Section] = []
        positions = _line_spans(text)
        index = 0
        while index < len(positions):
            start, end = positions[index]
            if not _classify(text[start:end]):
                index += 1
                continue
            block_end, frames, last = self._extend(text, positions, index)
            if frames >= MIN_FRAMES:
                out.extend(self._sections(text, positions[index][0], positions[last][1], frames))
            index = block_end
        return out

    @staticmethod
    def _extend(text: str, positions: list[tuple[int, int]], first: int) -> tuple[int, int, int]:
        """Index after the block, number of frames, index of the block's last line."""
        frames, last, index = 0, first, first
        previous = ""
        while index < len(positions):
            start, end = positions[index]
            line = text[start:end]
            kind = _classify(line)
            if not kind and previous == "py-frame" and _PYTHON_CODE.fullmatch(line):
                kind = "code"
            if not kind:
                break
            if kind == "frame":
                frames += 1
                previous = "py-frame" if line.lstrip().startswith("File ") else "frame"
            else:
                previous = kind
            last = index
            index += 1
        return index, frames, last

    def _sections(self, text: str, start: int, end: int, frames: int) -> list[Section]:
        lines = text[start:end].splitlines()
        body = "\n".join(_normalise(line) for line in lines)
        sections = [Section(f"{self.kind} ({frames} frames)", body, start, end)]
        chain: list[str] = []
        for line in lines:
            if _HEADER.fullmatch(line) and (m := _EXCEPTION_TYPE.search(line)) and m.group(1) not in chain:
                chain.append(m.group(1))
        if len(chain) > 1:
            sections.append(Section("Exception chain", "\n  ↳ ".join(chain)))
        return sections


def _normalise(line: str) -> str:
    stripped = line.strip()
    if _FRAME.fullmatch(line):
        return "    " + stripped
    if _PYTHON_CODE.fullmatch(line):
        return "        " + stripped
    return stripped


def _line_spans(text: str) -> list[tuple[int, int]]:
    spans, start = [], 0
    for match in re.finditer(r"\r?\n", text):
        spans.append((start, match.start()))
        start = match.end()
    spans.append((start, len(text)))
    return spans
