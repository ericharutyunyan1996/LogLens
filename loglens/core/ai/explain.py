"""'Explain this log line' — request building, answer schema and parsing (provider-independent)."""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from .redaction import Redactor

FOCUS_MARK = ">>"

SYSTEM_PROMPT = """\
You are the log-analysis assistant built into LogLens, a desktop log viewer used by developers, administrators and \
support engineers to investigate problems in any application's logs (Windows, .NET, Java, web servers, services, \
anything).

You receive an excerpt of one log file. Every line is prefixed with its line number, e.g. "L1234| ...". The line(s) \
the user asked about are marked with ">>" after the number. Some values were replaced by placeholders such as \
<IP_1>, <EMAIL_2>, <SECRET_1> or <USER_1> for privacy; treat equal placeholders as the same value.

Explain what the focus line means in plain language, using the surrounding lines as evidence. Identify the most \
probable causes and cite the line numbers that support each one — only cite numbers that appear in the excerpt. \
Suggest concrete next steps to confirm or fix the problem. Say so when the line is most likely harmless noise. \
If the excerpt is not enough to tell, say what additional logs or data would settle it instead of guessing. \
Be concise and specific; prefer facts visible in the lines over general advice."""

EXPLANATION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "summary": {"type": "string", "description": "One or two sentences: what this line means."},
        "severity": {"type": "string", "enum": ["info", "warning", "error", "critical", "unknown"]},
        "is_likely_noise": {"type": "boolean"},
        "what_happened": {"type": "string", "description": "Plain-language explanation of the sequence of events."},
        "probable_causes": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "cause": {"type": "string"},
                    "likelihood": {"type": "string", "enum": ["high", "medium", "low"]},
                    "evidence_lines": {"type": "array", "items": {"type": "integer"}},
                },
                "required": ["cause", "likelihood", "evidence_lines"],
                "additionalProperties": False,
            },
        },
        "next_steps": {"type": "array", "items": {"type": "string"}},
        "missing_information": {"type": "string", "description": "What else would help; empty if nothing."},
        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
    },
    "required": [
        "summary",
        "severity",
        "is_likely_noise",
        "what_happened",
        "probable_causes",
        "next_steps",
        "missing_information",
        "confidence",
    ],
    "additionalProperties": False,
}


@dataclass(frozen=True, slots=True)
class ExplainRequest:
    """What the user asked about, already redacted — exactly the text that will be sent."""

    file_name: str
    focus_lines: tuple[int, ...]  # 0-based file line numbers
    user_text: str
    redaction_counts: dict[str, int]
    first_line: int
    last_line: int


def build_request(
    file_name: str,
    numbered_lines: Sequence[tuple[int, str]],
    focus_lines: Sequence[int],
    redactor: Redactor,
    note: str = "",
) -> ExplainRequest:
    """Assemble the user message: file name, optional note, then the numbered (1-based for humans) excerpt."""
    focus = set(focus_lines)
    body = "\n".join(f"L{number + 1}|{FOCUS_MARK if number in focus else ''} {text}" for number, text in numbered_lines)
    redacted = redactor.redact(body)
    header = [f"Log file: {redactor.redact(file_name).text}"]
    if note:
        header.append(f"Note from the user: {redactor.redact(note).text}")
    lines_label = ", ".join(f"L{n + 1}" for n in sorted(focus))
    header.append(f"Explain {lines_label} (marked {FOCUS_MARK}).")
    user_text = "\n".join(header) + "\n\n" + redacted.text
    numbers = [n for n, _ in numbered_lines]
    return ExplainRequest(
        file_name=file_name,
        focus_lines=tuple(sorted(focus)),
        user_text=user_text,
        redaction_counts=dict(redacted.counts),
        first_line=min(numbers) if numbers else 0,
        last_line=max(numbers) if numbers else 0,
    )


@dataclass(frozen=True, slots=True)
class Cause:
    cause: str
    likelihood: str
    evidence_lines: tuple[int, ...]  # 1-based, as shown to the model and the user


@dataclass(frozen=True, slots=True)
class Explanation:
    summary: str
    severity: str
    is_likely_noise: bool
    what_happened: str
    probable_causes: tuple[Cause, ...]
    next_steps: tuple[str, ...]
    missing_information: str
    confidence: str
    model: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    notes: tuple[str, ...] = field(default_factory=tuple)  # e.g. "answered by fallback model"
    compatibility_used: bool = False  # the gateway needed the older request format

    @classmethod
    def from_json(cls, text: str, valid_lines: range | None = None) -> Explanation:
        """Parse the model's JSON answer; citations outside the excerpt are dropped (never trust, verify)."""
        data = json.loads(text)
        causes = []
        for item in data.get("probable_causes", []):
            lines = tuple(
                int(n) for n in item.get("evidence_lines", []) if valid_lines is None or int(n) in valid_lines
            )
            causes.append(Cause(str(item.get("cause", "")), str(item.get("likelihood", "low")), lines))
        return cls(
            summary=str(data.get("summary", "")),
            severity=str(data.get("severity", "unknown")),
            is_likely_noise=bool(data.get("is_likely_noise", False)),
            what_happened=str(data.get("what_happened", "")),
            probable_causes=tuple(causes),
            next_steps=tuple(str(s) for s in data.get("next_steps", [])),
            missing_information=str(data.get("missing_information", "")),
            confidence=str(data.get("confidence", "low")),
        )
