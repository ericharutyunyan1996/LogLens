"""Exports (CSV / JSON Lines) and incident reports (Markdown / HTML).

Pure functions over plain data, so the UI, a future CLI and tests share them. Optional redaction uses the same
:class:`~loglens.core.ai.redaction.Redactor` as the AI preview, so a report can be shared outside the team.
"""

from __future__ import annotations

import csv
import html
import io
import json
import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime

from .ai.explain import Explanation
from .ai.redaction import Redactor
from .kb import Finding

EXPORT_FIELDS = ("line", "time", "level", "text")
MAX_REPORT_LINE_CHARS = 2_000  # long lines are clipped in reports (exports keep everything)
_BACKTICKS = re.compile(r"`+")


@dataclass(frozen=True, slots=True)
class ExportRow:
    line: int  # 1-based
    time: datetime | None
    level: str
    text: str

    def as_dict(self) -> dict[str, object]:
        return {
            "line": self.line,
            "time": self.time.isoformat() if self.time else None,
            "level": self.level,
            "text": self.text,
        }


def make_rows(
    numbered: Iterable[tuple[int, str]],
    *,
    time_of: Callable[[str], datetime | None],
    level_of: Callable[[str], str],
) -> list[ExportRow]:
    """``numbered`` = (0-based line, text) pairs → export rows with parsed time and level."""
    return [ExportRow(line + 1, time_of(text), level_of(text), text) for line, text in numbered]


def to_csv(rows: Iterable[ExportRow]) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(EXPORT_FIELDS)
    for row in rows:
        values = row.as_dict()
        writer.writerow(["" if values[k] is None else values[k] for k in EXPORT_FIELDS])
    return out.getvalue()


def to_json_lines(rows: Iterable[ExportRow]) -> str:
    return "".join(json.dumps(row.as_dict(), ensure_ascii=False) + "\n" for row in rows)


# ---- incident report ---------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class EvidenceLine:
    line: int  # 1-based
    text: str
    note: str = ""  # e.g. "bookmark", "match", "context"
    findings: tuple[Finding, ...] = ()


@dataclass(frozen=True)
class IncidentReport:
    title: str
    source: str  # file path or description
    created: datetime
    summary: str = ""  # free text written by the user
    time_span: str = ""
    filter_description: str = ""
    counts: Sequence[tuple[str, int]] = ()  # e.g. ("Error", 12)
    evidence: Sequence[EvidenceLine] = ()
    explanations: Sequence[Explanation] = ()
    windows_events: Sequence[str] = ()  # one rendered line per related Windows event
    extra_sections: Sequence[tuple[str, str]] = field(default=())  # (heading, plain text) e.g. patterns, diagnosis


def _clip(text: str) -> str:
    return text if len(text) <= MAX_REPORT_LINE_CHARS else text[:MAX_REPORT_LINE_CHARS] + " …"


def _redact_explanation(explanation: Explanation, r: Callable[[str], str]) -> Explanation:
    """The AI answer quotes the log (user names, hosts, paths): every text field is redacted too."""
    return replace(
        explanation,
        summary=r(explanation.summary),
        what_happened=r(explanation.what_happened),
        probable_causes=tuple(replace(cause, cause=r(cause.cause)) for cause in explanation.probable_causes),
        next_steps=tuple(r(step) for step in explanation.next_steps),
        missing_information=r(explanation.missing_information),
        notes=tuple(r(note) for note in explanation.notes),
    )


def redact_report(report: IncidentReport, redactor: Redactor) -> IncidentReport:
    """Copy of the report with the title, every log line, free text and AI answer passed through ``redactor``
    (consistent placeholders across the whole report)."""

    def r(text: str) -> str:
        return redactor.redact(text).text

    evidence = [EvidenceLine(e.line, r(e.text), r(e.note), e.findings) for e in report.evidence]
    return IncidentReport(
        r(report.title),
        r(report.source),
        report.created,
        r(report.summary),
        report.time_span,
        r(report.filter_description),
        report.counts,
        evidence,
        [_redact_explanation(explanation, r) for explanation in report.explanations],
        [r(e) for e in report.windows_events],
        [(r(heading), r(body)) for heading, body in report.extra_sections],
    )


def _longest_backtick_run(text: str) -> int:
    return max((len(run) for run in _BACKTICKS.findall(text)), default=0)


def _code_block(text: str) -> list[str]:
    """A fenced code block whose fence is longer than any backtick run in ``text``, so a log line containing ```
    can't close the block early and smuggle Markdown (e.g. a remote image) into the report."""
    fence = "`" * max(3, _longest_backtick_run(text) + 1)
    return [fence, text, fence]


def _inline_code(text: str) -> str:
    ticks = "`" * (_longest_backtick_run(text) + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{ticks}{pad}{text}{pad}{ticks}"


def _md_text(text: str) -> str:
    """AI-written text (which a crafted log line can steer) as inert Markdown: no raw HTML, no images that a viewer
    would load from a remote server."""
    return text.replace("<", "&lt;").replace("![", "!\\[")


def to_markdown(report: IncidentReport) -> str:
    out = [f"# {report.title}", ""]
    meta = [f"**Log:** {_inline_code(report.source)}", f"**Created:** {report.created:%Y-%m-%d %H:%M}"]
    if report.time_span:
        meta.append(f"**Time span:** {report.time_span}")
    if report.filter_description:
        meta.append(f"**Filter:** {report.filter_description}")
    out += ["  \n".join(meta), ""]
    if report.summary:
        out += ["## Summary", "", report.summary, ""]
    if report.counts:
        out += ["## Overview", "", "| Level | Lines |", "|---|---:|"]
        out += [f"| {name} | {count:,} |" for name, count in report.counts]
        out.append("")
    for explanation in report.explanations:
        out += _markdown_explanation(explanation)
    if report.evidence:
        out += ["## Evidence", ""]
        for item in report.evidence:
            note = f" — {item.note}" if item.note else ""
            out += [f"**Line {item.line:,}**{note}", "", *_code_block(_clip(item.text)), ""]
            for finding in item.findings:
                out.append(f"> **{finding.title}** — {finding.explanation}")
            if item.findings:
                out.append("")
    if report.windows_events:
        out += ["## Windows events around the incident", "", *_code_block("\n".join(report.windows_events)), ""]
    for heading, body in report.extra_sections:
        out += [f"## {heading}", "", *_code_block(body), ""]
    out.append("_Generated by LogLens._")
    return "\n".join(out) + "\n"


def _markdown_explanation(explanation: Explanation) -> list[str]:
    out = ["## AI analysis", "", f"**{explanation.severity.upper()}** — {_md_text(explanation.summary)}", ""]
    if explanation.what_happened:
        out += [_md_text(explanation.what_happened), ""]
    if explanation.probable_causes:
        out.append("**Probable causes**")
        for cause in explanation.probable_causes:
            lines = ", ".join(f"L{n}" for n in cause.evidence_lines)
            out.append(f"1. {_md_text(cause.cause)} ({cause.likelihood}){f' — {lines}' if lines else ''}")
        out.append("")
    if explanation.next_steps:
        out.append("**Next steps**")
        out += [f"1. {_md_text(step)}" for step in explanation.next_steps]
        out.append("")
    out += [f"_Model: {explanation.model}, confidence {explanation.confidence}. AI can be wrong._", ""]
    return out


def to_html(report: IncidentReport) -> str:
    """A self-contained HTML page (inline CSS, no scripts) of the Markdown content."""
    e = html.escape
    parts = [
        "<!doctype html><html><head><meta charset='utf-8'>",
        f"<title>{e(report.title)}</title>",
        "<style>body{font:14px/1.5 'Segoe UI',sans-serif;max-width:960px;margin:2em auto;color:#1f2328}"
        "pre{background:#f6f8fa;border:1px solid #d0d7de;padding:8px;white-space:pre-wrap;"
        "font:12px Consolas,'Cascadia Mono',monospace}table{border-collapse:collapse}"
        "td,th{border:1px solid #d0d7de;padding:4px 10px}.muted{color:#6b7280}"
        ".finding{border-left:3px solid #3b82f6;padding-left:8px;margin:4px 0}</style></head><body>",
        f"<h1>{e(report.title)}</h1>",
        f"<p class='muted'>Log: <code>{e(report.source)}</code> · created {report.created:%Y-%m-%d %H:%M}"
        + (f" · {e(report.time_span)}" if report.time_span else "")
        + (f"<br>Filter: {e(report.filter_description)}" if report.filter_description else "")
        + "</p>",
    ]
    if report.summary:
        parts += ["<h2>Summary</h2>", f"<p>{e(report.summary)}</p>"]
    if report.counts:
        rows = "".join(f"<tr><td>{e(name)}</td><td align='right'>{count:,}</td></tr>" for name, count in report.counts)
        parts += ["<h2>Overview</h2>", f"<table><tr><th>Level</th><th>Lines</th></tr>{rows}</table>"]
    for explanation in report.explanations:
        parts += _html_explanation(explanation)
    if report.evidence:
        parts.append("<h2>Evidence</h2>")
        for item in report.evidence:
            note = f" <span class='muted'>— {e(item.note)}</span>" if item.note else ""
            parts += [f"<p><b>Line {item.line:,}</b>{note}</p>", f"<pre>{e(_clip(item.text))}</pre>"]
            parts += [f"<div class='finding'><b>{e(f.title)}</b> — {e(f.explanation)}</div>" for f in item.findings]
    if report.windows_events:
        parts += ["<h2>Windows events around the incident</h2>", f"<pre>{e(chr(10).join(report.windows_events))}</pre>"]
    for heading, body in report.extra_sections:
        parts += [f"<h2>{e(heading)}</h2>", f"<pre>{e(body)}</pre>"]
    parts.append("<p class='muted'><i>Generated by LogLens.</i></p></body></html>")
    return "\n".join(parts)


def _html_explanation(explanation: Explanation) -> list[str]:
    e = html.escape
    parts = ["<h2>AI analysis</h2>", f"<p><b>{e(explanation.severity.upper())}</b> — {e(explanation.summary)}</p>"]
    if explanation.what_happened:
        parts.append(f"<p>{e(explanation.what_happened)}</p>")
    if explanation.probable_causes:
        items = "".join(
            f"<li>{e(c.cause)} <span class='muted'>({e(c.likelihood)})</span></li>" for c in explanation.probable_causes
        )
        parts.append(f"<p><b>Probable causes</b></p><ol>{items}</ol>")
    if explanation.next_steps:
        steps = "".join(f"<li>{e(step)}</li>" for step in explanation.next_steps)
        parts.append(f"<p><b>Next steps</b></p><ol>{steps}</ol>")
    parts.append(
        f"<p class='muted'>Model: {e(explanation.model)}, confidence {e(explanation.confidence)}. AI can be wrong.</p>"
    )
    return parts
