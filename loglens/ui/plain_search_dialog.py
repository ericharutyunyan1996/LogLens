"""Ask in plain words: type a sentence, see how it was understood, and apply it as the log's filter."""

from __future__ import annotations

from datetime import datetime

from PySide6.QtWidgets import QDialog, QDialogButtonBox, QLabel, QLineEdit, QVBoxLayout, QWidget

from ..core.plainsearch import PlainQuery, parse


class PlainSearchDialog(QDialog):
    EXAMPLES = "errors in the last hour · critical or warnings today · 5xx responses · timeouts but not retry"

    def __init__(self, reference: datetime | None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Ask in plain words")
        self.resize(560, 300)
        self._reference = reference
        self.query: PlainQuery = PlainQuery()
        intro = QLabel(
            "Describe what you want to see. It becomes the log's filter, which you can change afterwards. "
            "Nothing leaves your computer.",
            self,
        )
        intro.setWordWrap(True)
        intro.setObjectName("dialogNote")
        self.sentence = QLineEdit(self)
        self.sentence.setPlaceholderText(self.EXAMPLES)
        self.sentence.textChanged.connect(self._update)
        self.understood = QLabel("", self)
        self.understood.setWordWrap(True)
        self.understood.setTextFormat(self.understood.textFormat().RichText)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel, self)
        self.apply_button = buttons.addButton("Show these lines", QDialogButtonBox.ButtonRole.AcceptRole)
        self.apply_button.setEnabled(False)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addWidget(intro)
        layout.addWidget(self.sentence)
        layout.addWidget(self.understood, 1)
        layout.addWidget(buttons)
        self.sentence.setFocus()

    def _update(self, text: str) -> None:
        self.query = parse(text, self._reference)
        self.apply_button.setEnabled(not self.query.is_empty)
        if not text.strip():
            self.understood.setText("")
        elif self.query.is_empty:
            self.understood.setText("Nothing to filter by yet. Try a level (errors, warnings), a word, or a time.")
        else:
            items = "".join(f"<li>{_escape(line)}</li>" for line in self.query.understood)
            self.understood.setText(f"<b>Understood:</b><ul>{items}</ul>")


def _escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
