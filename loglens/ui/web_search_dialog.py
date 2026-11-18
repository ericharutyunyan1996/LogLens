"""Dialog: build a web-search query from the selected line(s) — toggle parts, edit freely, pick an engine."""

from __future__ import annotations

from collections.abc import Sequence

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from ..core.websearch import ENGINES, QueryPart, compose, search_url

GOOGLE_WORD_LIMIT = 32  # Google ignores words beyond this
NOTE = (
    "Timestamps, IDs, IP addresses, e-mail addresses, user and domain account names, internal host names, URLs and "
    "paths that LogLens recognises were removed — check the text before searching. Switch parts on/off above, or edit "
    "the text directly — whatever is in the box is what your browser searches for."
)


class WebSearchDialog(QDialog):
    def __init__(self, parts: Sequence[QueryPart], engine: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Search the web")
        self.resize(720, 360)
        self._parts = list(parts)
        self._engine = engine if engine in ENGINES else "Google"

        title = QLabel("<b>Search the web for this error</b>", self)
        self.toggles: list[QToolButton] = []
        parts_row = QHBoxLayout()
        parts_row.setSpacing(4)
        parts_label = QLabel("Include", self)
        parts_label.setObjectName("dialogNote")
        parts_row.addWidget(parts_label)
        for part in self._parts:
            toggle = QToolButton(self)
            toggle.setObjectName("levelChip")
            toggle.setText(part.label)
            toggle.setToolTip(part.text)
            toggle.setCheckable(True)
            toggle.setChecked(True)
            toggle.toggled.connect(self._rebuild)
            parts_row.addWidget(toggle)
            self.toggles.append(toggle)
        self.exact = QCheckBox("Message as exact phrase", self)
        self.exact.setChecked(True)
        self.exact.setVisible(any(p.kind == "message" for p in self._parts))
        self.exact.toggled.connect(self._rebuild)
        parts_row.addStretch(1)
        parts_row.addWidget(self.exact)

        self.query = QPlainTextEdit(self)
        self.query.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        self.query.setTabChangesFocus(True)
        self.query.textChanged.connect(self._update_counter)
        self.counter = QLabel(self)
        self.counter.setObjectName("dialogNote")
        note = QLabel(NOTE, self)
        note.setObjectName("dialogNote")
        note.setWordWrap(True)

        engines = QHBoxLayout()
        self.engine_buttons: dict[str, QPushButton] = {}
        for name in ENGINES:
            button = QPushButton(name, self)
            button.setObjectName("primary" if name == self._engine else "")
            button.setToolTip(f"Open the search in your browser with {name}")
            button.clicked.connect(lambda _checked=False, n=name: self._open(n))
            engines.addWidget(button)
            self.engine_buttons[name] = button
        engines.addStretch(1)
        cancel = QPushButton("Cancel", self)
        cancel.clicked.connect(self.reject)
        engines.addWidget(cancel)

        layout = QVBoxLayout(self)
        layout.addWidget(title)
        if self._parts:
            layout.addLayout(parts_row)
        layout.addWidget(self.query, 1)
        layout.addWidget(self.counter)
        layout.addWidget(note)
        layout.addLayout(engines)
        self._rebuild()
        self.engine_buttons[self._engine].setDefault(True)

    def selected_parts(self) -> list[QueryPart]:
        return [part for part, toggle in zip(self._parts, self.toggles, strict=True) if toggle.isChecked()]

    def query_text(self) -> str:
        return " ".join(self.query.toPlainText().split())

    def chosen_engine(self) -> str:
        return self._engine

    def _rebuild(self) -> None:
        self.query.setPlainText(compose(self.selected_parts(), exact_message=self.exact.isChecked()))

    def _update_counter(self) -> None:
        text = self.query_text()
        words = len(text.split())
        warning = f" — Google only uses the first {GOOGLE_WORD_LIMIT} words" if words > GOOGLE_WORD_LIMIT else ""
        self.counter.setText(f"{words} words · {len(text)} characters{warning}")
        for button in self.engine_buttons.values():
            button.setEnabled(bool(text))

    def _open(self, engine: str) -> None:
        self._engine = engine
        QDesktopServices.openUrl(QUrl(search_url(engine, self.query_text())))
        self.accept()
