"""Time dialogs: go to a time, filter a time range, and how a log's timestamps map to real time."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone

from PySide6.QtCore import QDateTime
from PySide6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QDateTimeEdit,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QRadioButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from ..core.filters import TimeRange
from ..core.timeparse import LineClock

DISPLAY_FORMAT = "yyyy-MM-dd HH:mm:ss"
ERROR_COLOR = "#E5484D"
PRESETS_MINUTES = (("Last 15 min", 15), ("Last hour", 60), ("Last 24 h", 24 * 60))
MAX_SHIFT_MINUTES = 7 * 24 * 60


def _to_qt(moment: datetime) -> QDateTime:
    return QDateTime.fromSecsSinceEpoch(int(moment.timestamp()))


def _from_qt(value: QDateTime) -> datetime:
    return datetime.fromtimestamp(value.toSecsSinceEpoch(), UTC).astimezone()


def _editor(parent: QWidget, moment: datetime) -> QDateTimeEdit:
    edit = QDateTimeEdit(_to_qt(moment), parent)
    edit.setDisplayFormat(DISPLAY_FORMAT)
    edit.setCalendarPopup(True)
    return edit


def _note(text: str, parent: QWidget) -> QLabel:
    label = QLabel(text, parent)
    label.setObjectName("dialogNote")
    label.setWordWrap(True)
    return label


class GoToTimeDialog(QDialog):
    """Pick a moment; the caller jumps to the first line at or after it."""

    def __init__(
        self, initial: datetime, bounds: tuple[datetime | None, datetime | None], parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Go to time")
        self.edit = _editor(self, initial)
        first, last = bounds
        span = f"This log runs from {first:%Y-%m-%d %H:%M:%S} to {last:%Y-%m-%d %H:%M:%S}." if first and last else ""
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel, self)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Jump to the first line at or after:", self))
        layout.addWidget(self.edit)
        if span:
            layout.addWidget(_note(span + " Times are shown in this computer's time zone.", self))
        layout.addWidget(buttons)

    def moment(self) -> datetime:
        return _from_qt(self.edit.dateTime())


class TimeRangeDialog(QDialog):
    """Pick [from, to]; either side can be left open. Presets count back from the end of the log."""

    def __init__(
        self,
        bounds: tuple[datetime | None, datetime | None],
        current: TimeRange | None = None,
        around: datetime | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Filter by time")
        self._cleared = False
        now = datetime.now().astimezone()
        first, last = bounds
        self._last = last or now
        start = current.start if current and current.start else first or now - timedelta(hours=1)
        end = current.end if current and current.end else self._last

        self.use_start = QCheckBox("From", self)
        self.use_start.setChecked(current is None or current.start is not None)
        self.start = _editor(self, start)
        self.use_end = QCheckBox("To", self)
        self.use_end.setChecked(current is None or current.end is not None)
        self.end = _editor(self, end)
        self.use_start.toggled.connect(self.start.setEnabled)
        self.use_end.toggled.connect(self.end.setEnabled)
        self.start.setEnabled(self.use_start.isChecked())
        self.end.setEnabled(self.use_end.isChecked())
        form = QFormLayout()
        form.addRow(self.use_start, self.start)
        form.addRow(self.use_end, self.end)

        presets = QHBoxLayout()
        for label, minutes in PRESETS_MINUTES:
            button = QPushButton(label, self)
            button.setObjectName("smallButton")
            button.setToolTip("Counted back from the last line of the log")
            button.clicked.connect(lambda _c=False, m=minutes: self._preset(self._last - timedelta(minutes=m), None))
            presets.addWidget(button)
        if around is not None:
            button = QPushButton("± 5 min around the selected line", self)
            button.setObjectName("smallButton")
            button.clicked.connect(lambda: self._preset(around - timedelta(minutes=5), around + timedelta(minutes=5)))
            presets.addWidget(button)
        presets.addStretch(1)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel, self)
        remove = buttons.addButton("Remove time filter", QDialogButtonBox.ButtonRole.ResetRole)
        remove.clicked.connect(self._clear)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        self.error = QLabel(self)
        self.error.setStyleSheet(f"color: {ERROR_COLOR};")
        self.error.setWordWrap(True)
        self.error.hide()
        for edit in (self.start, self.end):
            edit.dateTimeChanged.connect(lambda _value: self.error.hide())
        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addLayout(presets)
        if first and last:
            layout.addWidget(_note(f"This log runs from {first:%Y-%m-%d %H:%M:%S} to {last:%Y-%m-%d %H:%M:%S}.", self))
        layout.addWidget(self.error)
        layout.addWidget(buttons)

    def problem(self) -> str | None:
        """Why the chosen range can't be used (From after To), or None."""
        if self.use_start.isChecked() and self.use_end.isChecked() and self.start.dateTime() > self.end.dateTime():
            return "“From” is later than “To” — no line could match. Swap them or change one."
        return None

    def accept(self) -> None:
        problem = None if self._cleared else self.problem()
        if problem:
            self.error.setText(f"⚠ {problem}")
            self.error.show()
            return
        super().accept()

    def _preset(self, start: datetime, end: datetime | None) -> None:
        self.use_start.setChecked(True)
        self.start.setDateTime(_to_qt(start))
        self.use_end.setChecked(end is not None)
        if end is not None:
            self.end.setDateTime(_to_qt(end))

    def _clear(self) -> None:
        self._cleared = True
        self.accept()

    def time_range(self) -> TimeRange | None:
        """The chosen range (end inclusive to the second), or None when the filter was removed / left open."""
        if self._cleared:
            return None
        start = _from_qt(self.start.dateTime()) if self.use_start.isChecked() else None
        end = _from_qt(self.end.dateTime()) + timedelta(seconds=1) if self.use_end.isChecked() else None
        window = TimeRange(start, end)
        return None if window.is_open else window


class ClockDialog(QDialog):
    """How this log's timestamps map to real time: zone for times without an offset, plus a clock correction."""

    def __init__(self, clock: LineClock, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._base = clock
        self.setWindowTitle("Log time zone")
        self.local = QRadioButton("This computer's time zone (default)", self)
        self.utc = QRadioButton("UTC", self)
        self.fixed = QRadioButton("Fixed offset from UTC", self)
        group = QButtonGroup(self)
        for button in (self.local, self.utc, self.fixed):
            group.addButton(button)
        self.offset = QSpinBox(self)
        self.offset.setRange(-14 * 60, 14 * 60)
        self.offset.setSingleStep(30)
        self.offset.setSuffix(" min")
        self.shift = QSpinBox(self)
        self.shift.setRange(-MAX_SHIFT_MINUTES, MAX_SHIFT_MINUTES)
        self.shift.setSuffix(" min")
        self.shift.setValue(int(clock.shift.total_seconds() // 60))
        self._select(clock)
        self.offset.setEnabled(self.fixed.isChecked())
        self.fixed.toggled.connect(self.offset.setEnabled)

        fixed_row = QHBoxLayout()
        fixed_row.addWidget(self.fixed)
        fixed_row.addWidget(self.offset)
        fixed_row.addStretch(1)
        shift_row = QHBoxLayout()
        shift_row.addWidget(QLabel("Correct the writer's clock by", self))
        shift_row.addWidget(self.shift)
        shift_row.addStretch(1)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel, self)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("<b>Timestamps without a time zone in this log are:</b>", self))
        layout.addWidget(self.local)
        layout.addWidget(self.utc)
        layout.addLayout(fixed_row)
        layout.addSpacing(8)
        layout.addLayout(shift_row)
        layout.addWidget(
            _note(
                "Used for Go to time, time filters and finding Windows events around a line. Timestamps that carry "
                "their own offset (Z, +02:00) are always honoured.",
                self,
            )
        )
        layout.addWidget(buttons)

    def _select(self, clock: LineClock) -> None:
        if clock.zone is None:
            self.local.setChecked(True)
            return
        offset = clock.zone.utcoffset(None) or timedelta(0)
        if not offset:
            self.utc.setChecked(True)
        else:
            self.fixed.setChecked(True)
            self.offset.setValue(int(offset.total_seconds() // 60))

    def clock(self) -> LineClock:
        zone = None
        if self.utc.isChecked():
            zone = UTC
        elif self.fixed.isChecked():
            zone = timezone(timedelta(minutes=self.offset.value()))
        return replace(self._base, zone=zone, shift=timedelta(minutes=self.shift.value()))
