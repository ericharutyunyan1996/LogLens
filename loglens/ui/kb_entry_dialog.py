"""Create or edit one entry of the user's knowledge base, with a live 'does it match?' tester."""

from __future__ import annotations

import re
from dataclasses import replace

from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QVBoxLayout,
    QWidget,
)

from ..core.kb import KBEntry, compile_pattern, normalize_provider, validate_entry
from ..core.kb.knowledge import NOISE_LEVELS

NOISE_LABELS = {"important": "Important — act on it", "normal": "Context", "benign": "Usually harmless"}


def _lines(edit: QPlainTextEdit) -> tuple[str, ...]:
    return tuple(line.strip() for line in edit.toPlainText().splitlines() if line.strip())


class KBEntryDialog(QDialog):
    def __init__(self, entry: KBEntry, sample: str = "", *, title: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(title or "Knowledge base entry")
        self.resize(640, 620)
        self._entry = entry
        self.title = QLineEdit(entry.title, self)
        self.explanation = QPlainTextEdit(entry.explanation, self)
        self.explanation.setPlaceholderText("What this means, in plain words")
        self.causes = QPlainTextEdit("\n".join(entry.causes), self)
        self.causes.setPlaceholderText("One likely cause per line")
        self.steps = QPlainTextEdit("\n".join(entry.steps), self)
        self.steps.setPlaceholderText("One step per line: what to check or do")
        self.noise = QComboBox(self)
        for level in NOISE_LEVELS:
            self.noise.addItem(NOISE_LABELS.get(level, level), level)
        self.noise.setCurrentIndex(max(NOISE_LEVELS.index(entry.noise), 0) if entry.noise in NOISE_LEVELS else 1)
        self.providers = QLineEdit(", ".join(entry.providers), self)
        self.providers.setPlaceholderText("Windows event source(s), e.g. Service Control Manager")
        self.event_ids = QLineEdit(", ".join(str(i) for i in entry.event_ids), self)
        self.patterns = QPlainTextEdit("\n".join(p.pattern for p in entry.patterns), self)
        self.patterns.setPlaceholderText("Regular expressions, one per line (matched case-insensitively)")
        self.patterns.setMaximumHeight(70)
        self.sample = QLineEdit(sample, self)
        self.sample.setPlaceholderText("Paste a log line to test the match")
        self.match_result = QLabel(self)
        self.match_result.setWordWrap(True)
        for widget in (self.providers, self.event_ids, self.sample):
            widget.textChanged.connect(self._test)
        self.patterns.textChanged.connect(self._test)
        for edit in (self.explanation, self.causes, self.steps):
            edit.setMaximumHeight(90)

        form = QFormLayout()
        form.addRow("Title", self.title)
        form.addRow("Explanation", self.explanation)
        form.addRow("Likely causes", self.causes)
        form.addRow("What to do", self.steps)
        form.addRow("Importance", self.noise)
        form.addRow(QLabel("<b>Matches</b> — a Windows event, or a text pattern:", self))
        form.addRow("Event source", self.providers)
        form.addRow("Event IDs", self.event_ids)
        form.addRow("Patterns", self.patterns)
        form.addRow("Test line", self.sample)
        form.addRow("", self.match_result)
        self.error = QLabel(self)
        self.error.setStyleSheet("color: #E5484D;")
        self.error.setWordWrap(True)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel, self)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(self.error)
        layout.addWidget(buttons)
        self._test()

    def entry(self) -> KBEntry:
        """The edited entry; raises ValueError with a readable message when something is invalid."""
        edited = replace(
            self._matcher(),
            title=self.title.text().strip(),
            explanation=self.explanation.toPlainText().strip(),
            causes=_lines(self.causes),
            steps=_lines(self.steps),
            noise=str(self.noise.currentData()),
        )
        return validate_entry(edited)

    def _matcher(self) -> KBEntry:
        """The entry with only its matching fields updated (enough to test a line against)."""
        try:
            event_ids = tuple(int(part) for part in re.split(r"[,\s]+", self.event_ids.text().strip()) if part)
        except ValueError as exc:
            raise ValueError("Event IDs must be numbers separated by commas.") from exc
        providers = tuple(normalize_provider(p) for p in self.providers.text().split(",") if p.strip())
        patterns = tuple(compile_pattern(p) for p in _lines(self.patterns))
        if not providers and not patterns and not self._entry.codes:
            raise ValueError("Give an event source + ID, or at least one pattern, so LogLens knows when to show it.")
        if providers and not event_ids:
            raise ValueError("Add the event ID(s) for this event source.")
        return replace(self._entry, providers=providers, event_ids=event_ids, patterns=patterns)

    def _test(self) -> None:
        sample = self.sample.text()
        if not sample:
            self.match_result.setText("")
            return
        try:
            matched = self._matcher().matches(sample)
        except ValueError as exc:
            self.match_result.setText(f"<span style='color:#E5484D'>{exc}</span>")
            return
        self.match_result.setText("✔ matches this line" if matched else "✖ does not match this line")

    def _accept(self) -> None:
        try:
            self.entry()
        except ValueError as exc:
            self.error.setText(str(exc))
            return
        self.accept()
