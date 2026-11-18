"""Diagnosis: service over synthetic events (fake reader) and the dialog rendering its result."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime, timedelta

from PySide6.QtWidgets import QApplication

from loglens.core.winevent.models import EventRecord
from loglens.core.winevent.reader import EventLogError, EventQuery
from loglens.services.diagnosis_jobs import diagnose
from loglens.services.knowledge_service import KnowledgeService
from loglens.ui.diagnose_dialog import DiagnoseDialog

NOW = datetime.now(UTC)


def _events(query: EventQuery) -> Iterable[EventRecord]:
    if query.channel == "Security":
        raise EventLogError("Access denied to 'Security' — this log needs LogLens to run as administrator.")
    if query.channel != "Application":
        return []
    crash = {"AppName": "shop.exe", "ModuleName": "ucrtbase.dll", "ExceptionCode": "0xc0000409"}
    return [
        EventRecord("Application", "Application Error", 1000, 2, NOW - timedelta(minutes=m), record_id=m, data=crash,
                    message="Faulting application name: shop.exe, faulting module name: ucrtbase.dll, "
                            "exception code: 0xc0000409")
        for m in (5, 30, 50)
    ]  # fmt: skip


def test_diagnose_and_show(qapp: QApplication) -> None:
    result = diagnose(NOW - timedelta(hours=2), NOW, reader=_events)
    assert any("shop.exe" in f.title for f in result.findings)
    assert any("Security" in w for w in result.warnings)
    opened: list[tuple[list[str], str]] = []
    dialog = DiagnoseDialog(KnowledgeService(), lambda lines, title: opened.append((lines, title)), lambda _p: None)
    dialog._show(result)
    assert dialog.findings.topLevelItemCount() >= 1 and "shop.exe" in dialog.details.toPlainText()
    dialog._open_evidence()
    assert opened and len(opened[0][0]) == 3
