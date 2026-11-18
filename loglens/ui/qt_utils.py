"""Small Qt helpers shared by the windows and dialogs."""

from __future__ import annotations

from PySide6.QtWidgets import QApplication, QDialog, QLineEdit, QPlainTextEdit, QTextEdit


def exec_dialog(dialog: QDialog) -> bool:
    """Run a modal dialog and schedule its deletion (its values stay readable until control returns to Qt)."""
    try:
        return bool(dialog.exec())
    finally:
        dialog.deleteLater()


def copy_from_focused_text() -> bool:
    """Copy the selection of the focused text widget (Inspector details, raw text, inputs); False if none."""
    widget = QApplication.focusWidget()
    if isinstance(widget, QTextEdit | QPlainTextEdit) and widget.textCursor().hasSelection():
        widget.copy()
        return True
    if isinstance(widget, QLineEdit) and widget.hasSelectedText():
        widget.copy()
        return True
    return False
