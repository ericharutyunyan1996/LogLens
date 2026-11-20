"""The Ask-in-plain-words dialog shows how the sentence was understood and enables Apply only when it means something."""

from __future__ import annotations

from datetime import datetime

from PySide6.QtWidgets import QApplication

from loglens.ui.plain_search_dialog import PlainSearchDialog


def test_dialog_explains_the_sentence(qapp: QApplication) -> None:
    d = PlainSearchDialog(datetime(2026, 11, 13, 12, 0).astimezone())
    assert not d.apply_button.isEnabled()
    d.sentence.setText("errors in the last hour but not timeouts")
    assert d.apply_button.isEnabled()
    text = d.understood.text()
    assert "error lines" in text and "without" in text and "timeouts" in text
    assert d.query.levels == ["Error"] and d.query.time_range is not None
    d.sentence.setText("show me the logs")
    assert not d.apply_button.isEnabled() and "Nothing to filter" in d.understood.text()
