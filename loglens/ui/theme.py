"""Light/dark theme handling and the app-wide style sheet.

We keep Qt's native Windows 11 style (Fluent look, follows the OS accent) and only add a thin style sheet for the
LogLens-specific widgets (search field, chips, status pills, welcome page).
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication, QPalette
from PySide6.QtWidgets import QApplication

THEMES = {"system": "System", "light": "Light", "dark": "Dark"}

ERROR_COLOR = "#E5484D"
WARNING_COLOR = "#F5A524"
OK_COLOR = "#30A46C"


def apply_theme(app: QApplication, mode: str) -> None:
    hints = app.styleHints()
    scheme = {"light": Qt.ColorScheme.Light, "dark": Qt.ColorScheme.Dark}.get(mode, Qt.ColorScheme.Unknown)
    if hasattr(hints, "setColorScheme"):
        hints.setColorScheme(scheme)
    app.setStyleSheet(style_sheet(is_dark()))


def is_dark() -> bool:
    base = QGuiApplication.palette().color(QPalette.ColorRole.Window)
    return base.lightness() < 128


def style_sheet(dark: bool) -> str:
    muted = "#9aa1ad" if dark else "#6b7280"
    chip_bg = "#2b2f36" if dark else "#eef0f4"
    chip_fg = "#c9cdd6" if dark else "#3f4552"
    field_border = "#3a3f48" if dark else "#d5d9e0"
    header_bg = "#1b1d22" if dark else "#f7f8fa"
    card_bg = "#202329" if dark else "#ffffff"
    return f"""
    QWidget#fileHeader {{ background: {header_bg}; border-bottom: 1px solid {field_border}; }}
    QLabel#fileName {{ font-size: 10.5pt; font-weight: 600; }}
    QLabel#filePath {{ color: {muted}; }}
    QLabel#chip {{ background: {chip_bg}; color: {chip_fg}; border-radius: 9px; padding: 1px 9px; }}
    QLabel#liveChip {{ background: {OK_COLOR}; color: white; border-radius: 9px; padding: 1px 9px;
                       font-weight: 600; }}
    QLabel#warnChip {{ background: {WARNING_COLOR}; color: #1b1b1b; border-radius: 9px; padding: 1px 9px; }}

    QWidget#filterPanel {{ background: {header_bg}; border-top: 1px solid {field_border};
                           border-bottom: 1px solid {field_border}; }}
    QWidget#filterPanel QComboBox {{ min-height: 24px; }}
    QToolButton#panelButton {{ border: 1px solid transparent; border-radius: 5px; padding: 2px 8px; }}
    QToolButton#panelButton:hover {{ border-color: {field_border}; background: {chip_bg}; }}
    QToolButton#levelChip {{ border: 1px solid {field_border}; border-radius: 10px; padding: 1px 9px 1px 6px; }}
    QToolButton#levelChip:hover {{ background: {chip_bg}; }}
    QToolButton#levelChip:checked {{ background: palette(highlight); color: palette(highlighted-text);
                                     border-color: palette(highlight); }}
    QToolButton#filterChip {{ border-radius: 10px; padding: 1px 10px; font-weight: 600; color: white;
                              background: {OK_COLOR}; }}
    QToolButton#filterChip[mode="any"] {{ background: #3b82f6; }}
    QToolButton#filterChip[mode="none"] {{ background: {ERROR_COLOR}; }}
    QToolButton#filterChip::menu-indicator {{ image: none; width: 0; }}
    QLabel#emptyHint {{ color: {muted}; background: palette(base); padding: 24px; }}

    QWidget#inspector {{ background: palette(base); border-left: 1px solid {field_border}; }}
    QLabel#inspectorTitle {{ font-weight: 700; font-size: 10.5pt; }}
    QPushButton#smallButton {{ padding: 3px 10px; }}
    QLabel#aiStatus {{ color: {muted}; }}
    QLabel#dialogNote {{ color: {muted}; }}
    QLabel#warningNote {{ color: {WARNING_COLOR}; }}
    QToolButton#optionToggle {{ border: 1px solid transparent; border-radius: 5px; padding: 2px 6px;
                                font-family: "Cascadia Mono", Consolas, monospace; font-weight: 600; }}
    QToolButton#optionToggle:checked {{ background: palette(highlight); color: palette(highlighted-text); }}
    QToolButton#optionToggle:hover:!checked {{ border-color: {field_border}; }}
    QLabel#searchStatus {{ color: {muted}; }}

    QToolButton#statusPill {{ border: none; border-radius: 9px; padding: 1px 10px; }}
    QToolButton#statusPill:hover {{ background: {chip_bg}; }}
    QStatusBar QLabel {{ color: {muted}; }}

    QWidget#welcome {{ background: {header_bg}; }}
    QFrame#welcomeCard {{ background: {card_bg}; border: 1px solid {field_border}; border-radius: 14px; }}
    QLabel#welcomeTitle {{ font-size: 26pt; font-weight: 700; }}
    QLabel#welcomeSubtitle {{ color: {muted}; font-size: 11pt; }}
    QLabel#welcomeHint {{ color: {muted}; }}
    QPushButton#primary {{ background: palette(highlight); color: palette(highlighted-text); border: none;
                           border-radius: 6px; padding: 8px 18px; font-weight: 600; }}
    QPushButton#primary:hover {{ background: palette(dark); }}
    QListWidget#recentList {{ border: none; background: transparent; }}
    QListWidget#recentList::item {{ padding: 6px 8px; border-radius: 6px; }}
    QListWidget#recentList::item:hover {{ background: {chip_bg}; }}

    QSplitter::handle:vertical {{ height: 5px; }}
    QSplitter::handle:hover {{ background: palette(highlight); }}
    """
