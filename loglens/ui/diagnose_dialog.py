"""Diagnose this computer: findings from Windows event logs (crashes, restarts, failing services, logons, …),
coverage warnings, and recent crash reports — each with evidence and next steps."""

from __future__ import annotations

import html
from collections.abc import Callable, Sequence

from PySide6.QtCore import QEvent, Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QProgressBar,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTextBrowser,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..core.diagnose import DiagnosisFinding
from ..core.winevent.entities import extract
from ..core.winevent.remote import ServerProfile
from ..core.winevent.wer import WerReport
from ..services.diagnosis_jobs import DiagnosisResult, DiagnosisRunner
from ..services.knowledge_service import KnowledgeService
from .detail_render import LEVEL_COLORS
from .inspector import Inspector

PERIODS = {"Last hour": 1, "Last 24 hours": 24, "Last 3 days": 72, "Last 7 days": 168, "Last 30 days": 720}
INDEX_ROLE = Qt.ItemDataRole.UserRole
MAX_EVIDENCE_SHOWN = 30


class DiagnoseDialog(QDialog):
    def __init__(
        self,
        knowledge: KnowledgeService,
        open_lines: Callable[[list[str], str], None],
        open_path: Callable[[str], None],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Diagnose a computer")
        self.setWindowFlag(Qt.WindowType.WindowMaximizeButtonHint, True)
        self.resize(1080, 680)
        self._knowledge = knowledge
        self._open_lines = open_lines
        self._open_path = open_path
        self._result: DiagnosisResult | None = None
        self.runner = DiagnosisRunner(self)
        self.runner.finished.connect(self._show)
        self.runner.failed.connect(self._failed)

        intro = QLabel(
            "Reads the Application, System, Security and Setup event logs and looks for crash chains, unexpected "
            "restarts, failing services, installer failures, account lockouts and password guessing, IIS app-pool "
            "failures, storage problems and recent changes. Pick a saved server to diagnose it instead (read remotely, "
            "nothing installed on it). Nothing leaves your computer.",
            self,
        )
        intro.setObjectName("dialogNote")
        intro.setWordWrap(True)
        self.target = QComboBox(self)  # this computer, or one of the saved servers
        self.target.addItem("This computer", None)
        self.period = QComboBox(self)
        self.period.addItems(list(PERIODS))
        self.period.setCurrentText("Last 24 hours")
        self.run_button = QPushButton("Diagnose", self)
        self.run_button.setObjectName("primary")
        self.run_button.clicked.connect(self.run)
        self.progress = QProgressBar(self)
        self.progress.setRange(0, 0)
        self.progress.setMaximumWidth(140)
        self.progress.hide()
        self.status = QLabel(self)
        self.status.setObjectName("aiStatus")
        self.status.setWordWrap(True)
        top = QHBoxLayout()
        top.addWidget(self.target)
        top.addWidget(self.period)
        top.addWidget(self.run_button)
        top.addWidget(self.progress)
        top.addStretch(1)

        self.reports = QTreeWidget(self)
        self.reports.setHeaderLabels(["When", "Type", "Application", "Module", "Exception"])
        self.reports.setRootIsDecorated(False)
        self.reports.header().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.reports.itemDoubleClicked.connect(self._open_report)
        self.coverage = QTextBrowser(self)
        tabs = QTabWidget(self)
        tabs.addTab(self._build_findings(), "Findings")
        tabs.addTab(self.coverage, "What the logs can't show")
        tabs.addTab(self.reports, "Crash reports (WER)")
        self.tabs = tabs

        layout = QVBoxLayout(self)
        layout.addWidget(intro)
        layout.addLayout(top)
        layout.addWidget(self.status)
        layout.addWidget(tabs, 1)

    def _build_findings(self) -> QSplitter:
        self.findings = QTreeWidget(self)
        self.findings.setHeaderLabels(["Severity", "When", "Finding", "Confidence"])
        self.findings.setRootIsDecorated(False)
        self.findings.header().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.findings.header().setStretchLastSection(False)
        self.findings.header().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.findings.currentItemChanged.connect(self._show_finding)
        self.details = QTextBrowser(self)
        self.details.setOpenLinks(False)
        self.open_button = QPushButton("Open evidence as a log", self)
        self.open_button.setToolTip("Opens the evidence events in a tab: search, Inspector, AI, report")
        self.open_button.clicked.connect(self._open_evidence)
        self.open_button.setEnabled(False)
        right = QWidget(self)
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.addWidget(self.details, 1)
        right_layout.addWidget(self.open_button, 0, Qt.AlignmentFlag.AlignRight)
        split = QSplitter(Qt.Orientation.Horizontal, self)
        split.addWidget(self.findings)
        split.addWidget(right)
        split.setSizes([560, 520])
        return split

    def set_servers(self, servers: Sequence[ServerProfile]) -> None:
        """The computers to choose from (called when the dialog is shown: servers may have been added since)."""
        keep = self.target.currentData()
        self.target.clear()
        self.target.addItem("This computer", None)
        for server in servers:
            self.target.addItem(f"{server.name}  ({server.host})", server)
        index = max(0, self.target.findText(f"{keep.name}  ({keep.host})")) if keep is not None else 0
        self.target.setCurrentIndex(index)
        self.target.setVisible(bool(servers))

    # ---- running -------------------------------------------------------------------------------------------------
    def run(self) -> None:
        self.run_button.setEnabled(False)
        self.progress.show()
        self.status.setText("Reading event logs… (a few seconds; longer periods take longer)")
        self.runner.run(PERIODS[self.period.currentText()], self.target.currentData())

    def _failed(self, message: str) -> None:
        self.run_button.setEnabled(True)
        self.progress.hide()
        self.status.setText(f"⚠ {message}")

    def _show(self, result: DiagnosisResult) -> None:
        self._result = result
        self.run_button.setEnabled(True)
        self.progress.hide()
        read = ", ".join(f"{channel} {count:,}" for channel, count in result.events_read.items())
        problems = sum(1 for f in result.findings if f.severity in ("critical", "error"))
        warn = f" · ⚠ {len(result.warnings)} coverage notes" if result.warnings else ""
        self.status.setText(
            f"<b>{len(result.findings)} findings</b> ({problems} problems) from {read or 'no events'}{warn}"
        )
        self.findings.clear()
        for index, finding in enumerate(result.findings):
            item = QTreeWidgetItem([
                finding.severity.upper(), f"{finding.time.astimezone():%Y-%m-%d %H:%M}", finding.title,
                finding.confidence,
            ])  # fmt: skip
            item.setData(0, INDEX_ROLE, index)
            item.setForeground(0, Qt.GlobalColor.white)
            item.setBackground(0, _color(finding.severity))
            item.setToolTip(2, finding.summary)
            self.findings.addTopLevelItem(item)
        first = self.findings.topLevelItem(0)
        if first is not None:
            self.findings.setCurrentItem(first)
        else:
            self.details.setHtml("<p>No problems found in this period. 🎉</p>")
        notes = "".join(f"<li>{html.escape(w)}</li>" for w in result.warnings)
        self.coverage.setHtml(
            f"<ul>{notes}</ul>" if notes else "<p>No coverage problems: the logs cover the period.</p>"
        )
        self._fill_reports(result.crash_reports)

    def _fill_reports(self, reports: list[WerReport]) -> None:
        self.reports.clear()
        for report in reports:
            code = f"0x{report.exception_code:08X}" if report.exception_code is not None else report.exception_type
            item = QTreeWidgetItem([
                f"{report.event_time.astimezone():%Y-%m-%d %H:%M}" if report.event_time else "",
                report.event_type, report.app_name, report.faulting_module, code or "",
            ])  # fmt: skip
            item.setToolTip(0, report.summary())
            item.setData(0, INDEX_ROLE, str(report.path) if report.path else "")
            self.reports.addTopLevelItem(item)

    # ---- details -------------------------------------------------------------------------------------------------
    def _selected(self) -> DiagnosisFinding | None:
        item = self.findings.currentItem()
        if item is None or self._result is None:
            return None
        return self._result.findings[int(item.data(0, INDEX_ROLE))]

    def changeEvent(self, event: QEvent) -> None:
        """Light ↔ dark switch: the details HTML carries theme colours, so render the current finding again."""
        super().changeEvent(event)
        if event.type() == QEvent.Type.PaletteChange and getattr(self, "_result", None) is not None:
            self._show_finding(None, None)

    def _show_finding(self, _item: QTreeWidgetItem | None, _previous: QTreeWidgetItem | None) -> None:
        finding = self._selected()
        self.open_button.setEnabled(finding is not None and bool(finding.evidence))
        if finding is None:
            return
        palette = Inspector.palette_for_theme()
        steps = "".join(f"<li>{html.escape(step)}</li>" for step in finding.next_steps)
        evidence = []
        for event in finding.evidence[:MAX_EVIDENCE_SHOWN]:
            facts = extract(event)
            known = self._knowledge.lookup_event(event.provider, event.event_id)
            meaning = f" — <i>{html.escape(known[0].title)}</i>" if known else ""
            detail = ", ".join(f"{html.escape(k)}: {html.escape(v)}" for k, v in facts.items()[:6])
            evidence.append(
                f"<li><b>{event.time_created.astimezone():%Y-%m-%d %H:%M:%S}</b> {html.escape(event.provider)} "
                f"{event.event_id}{meaning}<br><span style='color:{palette.muted}'>{detail}</span></li>"
            )
        more = len(finding.evidence) - MAX_EVIDENCE_SHOWN
        self.details.setHtml(
            f"<h3 style='margin:0'>{html.escape(finding.title)}</h3>"
            f"<p>{html.escape(finding.summary)}</p>"
            + (f"<p><b>What to do</b></p><ol>{steps}</ol>" if steps else "")
            + f"<p><b>Evidence</b> ({len(finding.evidence)} events)</p><ul>{''.join(evidence)}</ul>"
            + (f"<p>… and {more} more — open the evidence as a log to see all.</p>" if more > 0 else "")
        )

    def _open_evidence(self) -> None:
        finding = self._selected()
        if finding is not None:
            lines = [event.to_line() for event in sorted(finding.evidence, key=lambda e: e.time_created)]
            self._open_lines(lines, finding.title)

    def _open_report(self, item: QTreeWidgetItem, _column: int) -> None:
        path = str(item.data(0, INDEX_ROLE) or "")
        if path:
            self._open_path(path)


def _color(severity: str) -> QColor:
    return QColor(LEVEL_COLORS.get(severity, LEVEL_COLORS["unknown"]))
