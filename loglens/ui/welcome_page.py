"""Start page shown when no file is open: logo, open button, recent files, shortcut hints."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QLayout,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from .. import APP_NAME
from .icons import logo_pixmap, themed_icon
from .theme import is_dark

SHORTCUTS: tuple[tuple[str, str], ...] = (
    ("Ctrl+O", "open"),
    ("Ctrl+F", "search"),
    ("F3", "next match"),
    ("Ctrl+E", "next issue"),
    ("Ctrl+T", "follow"),
    ("Ctrl+B", "bookmark"),
    ("Alt+Z", "word wrap"),
    ("Ctrl+D", "line details"),
)
MAX_RECENT_SHOWN = 8
MISSING_FILE_COLOR = "#9aa1ad"


class WelcomePage(QWidget):
    openRequested = Signal()
    recentRequested = Signal(str)  # path

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("welcome")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        card = QFrame(self)
        card.setObjectName("welcomeCard")
        card.setMaximumWidth(760)

        self.recent_title = QLabel("<b>Recent files</b>", card)
        self.recent = QListWidget(card)
        self.recent.setObjectName("recentList")
        self.recent.setCursor(Qt.CursorShape.PointingHandCursor)
        self.recent.itemActivated.connect(self._emit_recent)
        self.recent.itemClicked.connect(self._emit_recent)

        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(32, 28, 32, 24)
        card_layout.setSpacing(14)
        card_layout.addLayout(self._title_row(card))
        card_layout.addLayout(self._action_row(card))
        card_layout.addSpacing(6)
        card_layout.addWidget(self.recent_title)
        card_layout.addWidget(self.recent)
        card_layout.addSpacing(4)
        card_layout.addWidget(self._shortcut_hint(card))

        centered = QHBoxLayout()
        centered.addStretch(1)
        centered.addWidget(card, 10)
        centered.addStretch(1)
        outer = QVBoxLayout(self)
        outer.addStretch(1)
        outer.addLayout(centered)
        outer.addStretch(2)

    # ---- construction --------------------------------------------------------------------------------------------
    @staticmethod
    def _title_row(card: QWidget) -> QLayout:
        logo = QLabel(card)
        logo.setPixmap(logo_pixmap(88))
        title = QLabel(APP_NAME, card)
        title.setObjectName("welcomeTitle")
        subtitle = QLabel("Fast log viewer & analyzer for Windows — huge files, live tail, smart search", card)
        subtitle.setObjectName("welcomeSubtitle")
        titles = QVBoxLayout()
        titles.addStretch(1)
        titles.addWidget(title)
        titles.addWidget(subtitle)
        titles.addStretch(1)
        row = QHBoxLayout()
        row.addWidget(logo)
        row.addSpacing(14)
        row.addLayout(titles, 1)
        return row

    def _action_row(self, card: QWidget) -> QLayout:
        open_button = QPushButton("Open log file…", card)
        open_button.setObjectName("primary")
        open_button.setCursor(Qt.CursorShape.PointingHandCursor)
        open_button.clicked.connect(self.openRequested)
        drop_hint = QLabel("or drop files anywhere in this window", card)
        drop_hint.setObjectName("welcomeHint")
        row = QHBoxLayout()
        row.addWidget(open_button)
        row.addSpacing(10)
        row.addWidget(drop_hint)
        row.addStretch(1)
        return row

    @staticmethod
    def _shortcut_hint(card: QWidget) -> QLabel:
        half = (len(SHORTCUTS) + 1) // 2
        html = "<br>".join(
            "   ·   ".join(f"<b>{key}</b>&nbsp;{label.replace(' ', '&nbsp;')}" for key, label in part)
            for part in (SHORTCUTS[:half], SHORTCUTS[half:])
        )
        hint = QLabel(html, card)
        hint.setObjectName("welcomeHint")
        hint.setWordWrap(True)
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        return hint

    # ---- behaviour -----------------------------------------------------------------------------------------------
    def _emit_recent(self, item: QListWidgetItem) -> None:
        self.recentRequested.emit(item.data(Qt.ItemDataRole.UserRole))

    def refresh(self, recent: list[str]) -> None:
        self.recent.clear()
        dark = is_dark()
        for path in recent[:MAX_RECENT_SHOWN]:
            file = Path(path)
            item = QListWidgetItem(themed_icon("file", dark), f"{file.name}     {file.parent}")
            item.setData(Qt.ItemDataRole.UserRole, path)
            item.setToolTip(path)
            if not file.exists():
                item.setForeground(QColor(MISSING_FILE_COLOR))
            self.recent.addItem(item)
        self.recent_title.setVisible(bool(recent))
        self.recent.setVisible(bool(recent))
        if recent:
            row_height = max(self.recent.sizeHintForRow(0), 24)
            shown = min(len(recent), MAX_RECENT_SHOWN)
            self.recent.setFixedHeight(shown * (row_height + 2) + 2 * self.recent.frameWidth() + 4)
