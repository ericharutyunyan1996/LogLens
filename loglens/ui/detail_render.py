"""HTML rendering for the Inspector panel (line details and AI explanations).

Pure functions (no widgets) producing Qt rich-text HTML. Links use custom schemes handled by the Inspector:
``copy:<index>`` copies a section, ``line:<number>`` (1-based) jumps to a log line.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass

from ..core.ai.explain import Explanation
from ..core.kb import Finding
from ..core.payloads import PayloadAnalysis, Section
from ..core.secrets import SecretMatch

MAX_SECTION_CHARS = 200_000  # render cap per section; "Copy" always copies everything
MONO_FONTS = "'Cascadia Mono', Consolas, monospace"
_MARKER = re.compile(r"⟨[^⟩]*⟩")


@dataclass(frozen=True, slots=True)
class Palette:
    text: str
    muted: str
    card: str
    border: str
    key: str
    string: str
    number: str
    literal: str
    tag: str
    accent: str


LIGHT = Palette("#1f2328", "#6b7280", "#f6f8fa", "#d0d7de", "#0550ae", "#0a3069", "#953800", "#8250df", "#116329",
                "#0969da")  # fmt: skip
DARK = Palette("#e6edf3", "#9aa1ad", "#161b22", "#30363d", "#79c0ff", "#a5d6ff", "#ffa657", "#d2a8ff", "#7ee787",
               "#58a6ff")  # fmt: skip
LEVEL_COLORS = {
    "critical": "#E0204A",
    "error": "#E5484D",
    "warning": "#F5A524",
    "info": "#30A46C",
    "unknown": "#8b949e",
}

_JSON_TOKEN = re.compile(
    r'(?P<key>"(?:[^"\\]|\\.)*")(?=\s*:)|(?P<str>"(?:[^"\\]|\\.)*")|(?P<num>-?\b\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b)'
    r"|(?P<lit>\b(?:true|false|null)\b)"
)
_XML_TOKEN = re.compile(r'(?P<tag></?[\w:.\-]+|/?>)|(?P<attr>[\w:.\-]+)(?==)|(?P<str>"[^"]*"|\'[^\']*\')')
_STACK_TOKEN = re.compile(
    r"(?P<exc>\b(?:[\w$]+\.)*[A-Z][\w$]*(?:Exception|Error|Fault)\b)"
    r"|(?P<loc>(?:\bin |\()?[^\s()\"]+?(?::line \d+|\.\w+:\d+(?::\d+)?|\", line \d+))"
    r"|(?P<at>^\s+at\b|^\s+File\b)",
    re.M,
)
_FIELD_LINE = re.compile(r"^(?P<key>\s*[^=:\n]{1,60}?\s[=:])(?P<rest>.*)$", re.M)
_SQL_KEYWORD = re.compile(
    r"\b(?:SELECT|FROM|WHERE|JOIN|INNER|LEFT|RIGHT|FULL|OUTER|CROSS|ON|AND|OR|GROUP BY|ORDER BY|HAVING|UNION|ALL|"
    r"INSERT|INTO|VALUES|UPDATE|SET|DELETE|MERGE|EXEC|EXECUTE|AS|IN|IS|NOT|NULL|LIMIT|OFFSET|TOP|DISTINCT)\b"
)


def _span(color: str, text: str, bold: bool = False) -> str:
    weight = "font-weight:600;" if bold else ""
    return f'<span style="color:{color};{weight}">{html.escape(text)}</span>'


def _tokenize(text: str, pattern: re.Pattern[str], colors: dict[str, str]) -> str:
    out, pos = [], 0
    for m in pattern.finditer(text):
        out.append(html.escape(text[pos : m.start()]))
        kind = m.lastgroup or ""
        out.append(
            _span(colors.get(kind, ""), m.group(0), bold=kind == "key") if kind in colors else html.escape(m.group(0))
        )
        pos = m.end()
    out.append(html.escape(text[pos:]))
    return "".join(out)


def highlight(kind: str, body: str, palette: Palette) -> str:
    """Syntax-coloured HTML for one section body."""
    family = kind.split(" ", maxsplit=1)[0].upper()
    if "JSON" in kind:  # "JSON", "body (embedded JSON)", "next (base64 → JSON)"
        colors = {"key": palette.key, "str": palette.string, "num": palette.number, "lit": palette.literal}
        return _tokenize(body, _JSON_TOKEN, colors)
    if family == "XML":
        return _tokenize(body, _XML_TOKEN, {"tag": palette.tag, "attr": palette.key, "str": palette.string})
    if family == "SQL":
        return _sql(body, palette)
    if family in {"FIELDS", "HEADERS", "URL", "QUERY", "JWT"}:
        return _fields(body, palette)
    if family in {"STACK", "EXCEPTION"}:
        return _tokenize(body, _STACK_TOKEN, {"exc": palette.key, "loc": palette.string, "at": palette.muted})
    return html.escape(body)


def _sql(body: str, palette: Palette) -> str:
    out, pos = [], 0
    for m in _SQL_KEYWORD.finditer(body):
        out.append(html.escape(body[pos : m.start()]))
        out.append(_span(palette.key, m.group(0), bold=True))
        pos = m.end()
    out.append(html.escape(body[pos:]))
    return "".join(out)


def _fields(body: str, palette: Palette) -> str:
    out, pos = [], 0
    for m in _FIELD_LINE.finditer(body):
        out.append(html.escape(body[pos : m.start()]))
        out.append(_span(palette.key, m["key"]) + html.escape(m["rest"]))
        pos = m.end()
    out.append(html.escape(body[pos:]))
    return "".join(out)


def _card(title: str, body_html: str, palette: Palette, copy_index: int | None) -> str:
    copy = (
        f' &nbsp;<a href="copy:{copy_index}" style="color:{palette.accent};text-decoration:none;">Copy</a>'
        if copy_index is not None
        else ""
    )
    return (
        f'<p style="margin:12px 0 4px 0;color:{palette.muted};font-weight:600;">{html.escape(title)}{copy}</p>'
        f'<table width="100%" cellspacing="0" cellpadding="8" bgcolor="{palette.card}" '
        f'style="border:1px solid {palette.border};"><tr><td>'
        f'<pre style="margin:0;white-space:pre-wrap;color:{palette.text};font-family:{MONO_FONTS};">'
        f"{body_html}</pre></td></tr></table>"
    )


@dataclass(frozen=True, slots=True)
class LineHeader:
    line_number: int  # 1-based
    timestamp: str = ""
    level: str = ""
    level_color: str = ""
    title: str = ""  # replaces "Line N" (e.g. for Windows events)


NOISE_BADGES = {
    "important": ("Important", "#E5484D"),
    "normal": ("Context", "#3b82f6"),
    "benign": ("Usually harmless", "#8b949e"),
}


def render_findings(findings: list[Finding], palette: Palette) -> str:
    """'What this means' cards from the offline knowledge base / Windows error tables."""
    if not findings:
        return ""
    parts = [
        f'<p style="margin:10px 0 4px 0;color:{palette.muted};font-weight:600;">What this means '
        f'<span style="font-weight:400;">(offline knowledge base)</span></p>'
    ]
    for finding in findings:
        label, color = NOISE_BADGES.get(finding.noise, NOISE_BADGES["normal"])
        badge = f'<span style="background:{color};color:white;font-weight:600;">&nbsp;{label}&nbsp;</span>'
        body = [
            f'<p style="margin:0 0 4px 0;">{badge}&nbsp; <b>{html.escape(finding.title)}</b></p>',
            f'<p style="margin:0 0 4px 0;color:{palette.text};">{html.escape(finding.explanation)}</p>',
        ]
        if finding.causes:
            items = "".join(f"<li>{html.escape(c)}</li>" for c in finding.causes)
            body.append(f'<p style="margin:4px 0 0 0;color:{palette.muted};">Likely causes</p><ul>{items}</ul>')
        if finding.steps:
            items = "".join(f"<li>{html.escape(step)}</li>" for step in finding.steps)
            body.append(f'<p style="margin:4px 0 0 0;color:{palette.muted};">What to do</p><ol>{items}</ol>')
        body.append(
            f'<p style="margin:2px 0 0 0;color:{palette.muted};font-size:8pt;">'
            f"matched “{html.escape(finding.matched)}” · {html.escape(finding.source)}</p>"
        )
        parts.append(
            f'<table width="100%" cellspacing="0" cellpadding="8" bgcolor="{palette.card}" '
            f'style="border:1px solid {palette.border};margin-bottom:6px;"><tr><td>{"".join(body)}</td></tr></table>'
        )
    return "".join(parts)


def render_secrets(secrets: list[SecretMatch], palette: Palette) -> str:
    """Warning card: the line holds credentials / tokens (always redacted for AI; mind screenshots and copies)."""
    if not secrets:
        return ""
    kinds = ", ".join(dict.fromkeys(str(s.kind) for s in secrets))
    return (
        f'<table width="100%" cellspacing="0" cellpadding="8" bgcolor="{palette.card}" '
        f'style="border:1px solid #F5A524;margin-bottom:6px;"><tr><td>'
        f'<span style="background:#F5A524;color:black;font-weight:600;">&nbsp;Secret in log&nbsp;</span>&nbsp; '
        f"<b>{len(secrets)} secret value{'s' if len(secrets) != 1 else ''}</b> ({html.escape(kinds)}). "
        f'<span style="color:{palette.muted};">They are always redacted before anything is sent to the AI. Use View → '
        "Mask secrets before screen sharing, and rotate credentials that should never have been logged.</span>"
        "</td></tr></table>"
    )


def render_facts(facts: list[tuple[str, str]], palette: Palette) -> str:
    """Key facts extracted from a Windows event (application, module, exception code, service, account, …)."""
    if not facts:
        return ""
    rows = "".join(
        f'<tr><td style="color:{palette.muted};padding-right:12px;">{html.escape(name)}</td>'
        f'<td style="color:{palette.text};">{html.escape(value)}</td></tr>'
        for name, value in facts
    )
    return (
        f'<p style="margin:10px 0 4px 0;color:{palette.muted};font-weight:600;">Event facts</p>'
        f'<table cellspacing="0" cellpadding="2">{rows}</table>'
    )


def render_details(
    header: LineHeader,
    analysis: PayloadAnalysis,
    palette: Palette,
    findings: list[Finding] | None = None,
    facts: list[tuple[str, str]] | None = None,
    *,
    collapse_chars: int | None = None,
) -> tuple[str, list[Section]]:
    """HTML for the Details tab and the list of sections addressable by ``copy:<index>``.

    A JSON / XML section longer than ``collapse_chars`` is NOT printed: its card is one collapsed line (the
    structured view next to it opens it on demand; "Copy" still copies all of it)."""
    parts = [_header(header, palette), render_findings(findings or [], palette), render_facts(facts or [], palette)]
    sections = analysis.located + analysis.derived
    message = _message_text(analysis)
    if _MARKER.sub("", message).strip(" \t:-=,;|"):  # skip when nothing but payload markers is left
        parts.append(_card("Message", html.escape(message), palette, None))
    for index, section in enumerate(sections):
        body = section.body
        if collapse_chars is not None and section.kind in ("JSON", "XML") and len(body) > collapse_chars:
            note = f"{len(body):,} characters, collapsed. Open it in the structure view below; Copy copies all of it."
            parts.append(_card(section.kind, _span(palette.muted, note), palette, index))
            continue
        truncated = len(body) > MAX_SECTION_CHARS
        rendered = highlight(section.kind, body[:MAX_SECTION_CHARS], palette)
        if truncated:
            rendered += _span(palette.muted, f"\n… {len(body) - MAX_SECTION_CHARS:,} more characters — use Copy")
        parts.append(_card(section.kind, rendered, palette, index))
    if not sections and not message:
        parts.append(_span(palette.muted, "(empty line)"))
    return "".join(parts), sections


def _message_text(analysis: PayloadAnalysis) -> str:
    """The line's own text with payload spans replaced by short markers."""
    if not analysis.located:
        return analysis.text
    out, cursor = [], 0
    for section in analysis.located:
        out.append(analysis.text[cursor : section.start])
        out.append(f"⟨{section.kind}⟩")
        cursor = section.end
    out.append(analysis.text[cursor:])
    return "".join(out).strip()


def _header(header: LineHeader, palette: Palette) -> str:
    bits = [_span(palette.text, header.title or f"Line {header.line_number:,}", bold=True)]
    if header.timestamp:
        bits.append(_span(palette.muted, header.timestamp))
    if header.level:
        bits.append(
            f'<span style="background:{header.level_color};color:white;font-weight:600;">'
            f"&nbsp;{html.escape(header.level)}&nbsp;</span>"
        )
    return '<p style="margin:2px 0 8px 0;">' + " &nbsp;·&nbsp; ".join(bits) + "</p>"


def _line_links(numbers: tuple[int, ...], palette: Palette) -> str:
    return ", ".join(
        f'<a href="line:{n}" style="color:{palette.accent};text-decoration:none;">L{n:,}</a>' for n in numbers
    )


def render_explanation(explanation: Explanation, palette: Palette) -> str:
    """HTML for an AI answer; evidence line numbers are links."""
    severity = explanation.severity.lower()
    chip = (
        f'<span style="background:{LEVEL_COLORS.get(severity, LEVEL_COLORS["unknown"])};color:white;'
        f'font-weight:600;">&nbsp;{html.escape(severity.upper())}&nbsp;</span>'
    )
    noise = _span(palette.muted, "  · likely harmless noise") if explanation.is_likely_noise else ""

    def h(title: str) -> str:
        return f'<p style="margin:12px 0 4px 0;color:{palette.muted};font-weight:600;">{html.escape(title)}</p>'

    parts = [
        f'<p style="margin:2px 0 6px 0;">{chip}{noise}</p>',
        f'<p style="color:{palette.text};font-size:11pt;">{html.escape(explanation.summary)}</p>',
    ]
    if explanation.what_happened:
        parts += [h("What happened"), f'<p style="color:{palette.text};">{html.escape(explanation.what_happened)}</p>']
    if explanation.probable_causes:
        items = []
        for cause in explanation.probable_causes:
            evidence = f" — {_line_links(cause.evidence_lines, palette)}" if cause.evidence_lines else ""
            items.append(
                f"<li>{html.escape(cause.cause)} {_span(palette.muted, f'({cause.likelihood})')}{evidence}</li>"
            )
        parts += [h("Probable causes"), f'<ol style="color:{palette.text};">{"".join(items)}</ol>']
    if explanation.next_steps:
        steps = "".join(f"<li>{html.escape(step)}</li>" for step in explanation.next_steps)
        parts += [h("Next steps"), f'<ol style="color:{palette.text};">{steps}</ol>']
    if explanation.missing_information:
        parts += [
            h("Would help to know"),
            f'<p style="color:{palette.text};">{html.escape(explanation.missing_information)}</p>',
        ]
    footer = [f"confidence: {explanation.confidence}", explanation.model]
    if explanation.input_tokens:
        footer.append(f"{explanation.input_tokens:,} in / {explanation.output_tokens:,} out tokens")
    footer += list(explanation.notes)
    parts.append(
        f'<p style="margin-top:14px;color:{palette.muted};">{html.escape(" · ".join(f for f in footer if f))}<br>'
        "AI can be wrong — check the cited lines before acting.</p>"
    )
    return "".join(parts)
