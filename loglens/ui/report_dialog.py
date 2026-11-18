"""Incident report dialog: choose what goes in, optionally redact, save as Markdown or HTML."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from ..core.ai.config import Redact
from ..core.ai.redaction import Redactor
from ..core.report import EvidenceLine, IncidentReport, redact_report, to_html, to_markdown

if TYPE_CHECKING:
    from .log_tab import LogTab

MAX_EVIDENCE_LINES = 300  # matches / bookmarks included in one report
REPORT_REDACTIONS = (Redact.SECRETS, Redact.EMAILS, Redact.IP_ADDRESSES, Redact.USER_PATHS)
FORMATS = {"Markdown (.md)": ".md", "HTML page (.html)": ".html"}


class ReportDialog(QDialog):
    def __init__(self, tab: LogTab, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Incident report")
        self.resize(560, 520)
        self._tab = tab
        doc = tab.document
        self.title = QLineEdit(f"Incident: {doc.title}", self)
        self.summary = QPlainTextEdit(self)
        self.summary.setPlaceholderText("What happened, impact, what you already know (optional)")
        self.summary.setMaximumHeight(110)

        bookmarks, matches = len(doc.bookmarks), len(doc.hits)
        explanation, events = tab.inspector.last_explanation, tab.inspector.related_events
        self.use_bookmarks = self._check(f"Bookmarked lines ({bookmarks:,})", bookmarks > 0)
        self.use_selection = self._check("Selected line / record", tab.main_view.current_row() >= 0)
        self.use_matches = self._check(f"Filter matches ({matches:,}, first {MAX_EVIDENCE_LINES})", matches > 0)
        self.use_ai = self._check("AI answer shown in the Inspector", explanation is not None)
        self.use_events = self._check(f"Windows events found around the line ({len(events)})", bool(events))
        self.use_counts = self._check("Level overview (errors, warnings, …)", True)
        self.context = QSpinBox(self)
        self.context.setRange(0, 10)
        self.context.setSuffix(" lines")
        self.redact = QCheckBox("Redact secrets, e-mails, IP addresses and user paths", self)
        self.redact.setChecked(True)
        self.format = QComboBox(self)
        self.format.addItems(list(FORMATS))

        form = QFormLayout()
        form.addRow("Title", self.title)
        form.addRow("Summary", self.summary)
        include = QVBoxLayout()
        for box in (
            self.use_bookmarks, self.use_selection, self.use_matches, self.use_ai, self.use_events, self.use_counts,
        ):  # fmt: skip
            include.addWidget(box)
        form.addRow("Include", include)
        form.addRow("Context around each line", self.context)
        form.addRow("", self.redact)
        form.addRow("Format", self.format)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel, self)
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        note = QLabel("Redaction uses the same rules as the AI preview. Review the file before sharing it.", self)
        note.setObjectName("dialogNote")
        note.setWordWrap(True)
        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(note)
        layout.addWidget(buttons)

    def _check(self, text: str, available: bool) -> QCheckBox:
        box = QCheckBox(text, self)
        box.setChecked(available)
        box.setEnabled(available)
        return box

    # ---- building ------------------------------------------------------------------------------------------------
    def build(self) -> IncidentReport:
        tab, doc = self._tab, self._tab.document
        notes: dict[int, str] = {}
        if self.use_bookmarks.isChecked():
            notes.update(dict.fromkeys(sorted(doc.bookmarks)[:MAX_EVIDENCE_LINES], "bookmark"))
        if self.use_selection.isChecked():
            first, last = tab.selected_range()
            notes.update(dict.fromkeys(range(first, last + 1), "selected"))
        if self.use_matches.isChecked():
            for line in doc.hits[:MAX_EVIDENCE_LINES].tolist():
                notes.setdefault(int(line), "match")
        evidence = self._evidence(notes)
        counts = [(s.name, s.count) for s in doc.mark_summaries()] if self.use_counts.isChecked() else []
        explanation = tab.inspector.last_explanation
        begin, end = doc.time_bounds()
        span = f"{begin:%Y-%m-%d %H:%M:%S} → {end:%Y-%m-%d %H:%M:%S}" if begin and end else ""
        spec = doc.filter_spec
        filter_text = ", ".join([t.label for t in spec.terms] + list(spec.level_names)) if spec else ""
        if spec and spec.time_range:
            filter_text = ", ".join(filter(None, [filter_text, spec.time_range.label()]))
        report = IncidentReport(
            title=self.title.text().strip() or "Incident",
            source=doc.path,
            created=datetime.now().astimezone(),
            summary=self.summary.toPlainText().strip(),
            time_span=span,
            filter_description=filter_text,
            counts=counts,
            evidence=evidence,
            explanations=[explanation] if explanation is not None and self.use_ai.isChecked() else [],
            windows_events=[e.to_line() for e in tab.inspector.related_events] if self.use_events.isChecked() else [],
        )
        return redact_report(report, Redactor(REPORT_REDACTIONS)) if self.redact.isChecked() else report

    def _evidence(self, notes: dict[int, str]) -> list[EvidenceLine]:
        doc, context = self._tab.document, self.context.value()
        out: list[EvidenceLine] = []
        covered = -1
        for line in sorted(notes):
            if line <= covered:
                continue
            start = max(line - context, covered + 1, 0)
            end = min(line + context + 1, doc.source.line_count())
            text = "\n".join(doc.source.get_full_line(i) for i in range(start, end))
            out.append(
                EvidenceLine(
                    line + 1, text, notes[line], tuple(self._tab.knowledge.explain(doc.source.get_full_line(line)))
                )
            )
            covered = end - 1
        return out

    def _save(self) -> None:
        suffix = FORMATS[self.format.currentText()]
        default = str(Path(self._tab.document.path).with_name(Path(self._tab.document.path).stem + "-report" + suffix))
        target, _ = QFileDialog.getSaveFileName(self, "Save report", default, f"Report (*{suffix})")
        if not target:
            return
        failure: OSError | None = None
        # reading every evidence line and explaining it with the knowledge base takes a moment on big reports
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            report = self.build()
            text = to_html(report) if suffix == ".html" else to_markdown(report)
            Path(target).write_text(text, encoding="utf-8")
        except OSError as exc:
            failure = exc
        finally:
            QApplication.restoreOverrideCursor()
        if failure is not None:
            QMessageBox.warning(self, "Incident report", f"Could not write {target}:\n{failure}")
            return
        self.saved_path = target
        self.accept()
