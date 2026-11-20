"""Options for a share-safe copy of the current log."""

from __future__ import annotations

from PySide6.QtWidgets import QCheckBox, QDialog, QDialogButtonBox, QLabel, QVBoxLayout, QWidget

from ..core.pseudonyms import Pseudonymizer

CHOICES = (
    ("secrets", "Mask passwords, keys and tokens", True),
    ("email", "Replace e-mail addresses (person1@example.invalid)", True),
    ("ip", "Replace IP addresses (192.0.2.x)", True),
    ("host", "Replace server and domain names (host1.example.invalid)", True),
    ("user", "Replace user names (user1, user2, …)", True),
)


class ShareCopyDialog(QDialog):
    def __init__(self, title: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Save a share-safe copy")
        intro = QLabel(
            f"Writes a copy of “{title}” that is safer to send to someone else. The same person, address or "
            "server always gets the same replacement, so the story of the log stays readable. Check the copy "
            "before you share it: no tool finds everything.",
            self,
        )
        intro.setWordWrap(True)
        intro.setObjectName("dialogNote")
        layout = QVBoxLayout(self)
        layout.addWidget(intro)
        self.boxes: dict[str, QCheckBox] = {}
        for key, text, default in CHOICES:
            box = QCheckBox(text, self)
            box.setChecked(default)
            self.boxes[key] = box
            layout.addWidget(box)
        self.mapping = QCheckBox("Also save the list of replacements (keep it private: it undoes the copy)", self)
        layout.addWidget(self.mapping)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel, self)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def pseudonymizer(self) -> Pseudonymizer:
        kinds = frozenset(k for k in ("email", "ip", "host", "user") if self.boxes[k].isChecked())
        return Pseudonymizer(kinds=kinds, secrets=self.boxes["secrets"].isChecked())
