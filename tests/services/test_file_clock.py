"""LogDocument's clock follows the file (W3C = UTC, day/month order) until the user corrects it (headless)."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from PySide6.QtWidgets import QApplication

from loglens.core.filters import TimeRange
from loglens.core.highlight import default_rules
from loglens.core.search import shutdown_pool
from loglens.core.timeparse import LineClock, to_local
from loglens.services.log_document import LogDocument

W3C = [
    "#Software: Example HTTP Server 1.0",
    "#Version: 1.0",
    "#Fields: date time s-ip cs-method cs-uri-stem sc-status time-taken",
    *(f"2026-11-13 09:00:{second:02d} 10.0.0.1 GET /page/{second} 200 15" for second in range(30)),
]
DAY_FIRST = [f"{day:02d}.11.2026 10:00:00 INFO step {day}" for day in range(1, 29)]  # 13.11. … proves day first


def _open(path: Path, lines: list[str], wait_for: Callable[..., None]) -> LogDocument:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    doc = LogDocument(path, default_rules())
    doc.start()
    wait_for(lambda: doc.detection is not None)
    return doc


def test_w3c_log_defaults_to_utc(qapp: QApplication, wait_for: Callable[..., None], tmp_path: Path) -> None:
    doc = _open(tmp_path / "u_ex261113.log", W3C, wait_for)
    try:
        assert doc.log_format is not None and doc.log_format.times_utc
        assert doc.clock.zone == UTC and not doc.clock_chosen
        assert doc.line_time(W3C[3]) == datetime(2026, 11, 13, 9, 0, 0, tzinfo=UTC)
    finally:
        doc.close()
        shutdown_pool()


def test_user_clock_survives_detection(qapp: QApplication, wait_for: Callable[..., None], tmp_path: Path) -> None:
    doc = _open(tmp_path / "u_ex261113.log", W3C, wait_for)
    try:
        plus_two = timezone(timedelta(hours=2))
        doc.set_clock(LineClock(plus_two))
        doc.detect_again()  # a new detection must not undo the user's correction
        wait_for(lambda: not doc._running)
        assert doc.clock.zone == plus_two and doc.clock_chosen
        doc.set_format(None)
        assert doc.clock.zone == plus_two
    finally:
        doc.close()
        shutdown_pool()


def test_day_first_order_is_inferred_and_kept(
    qapp: QApplication, wait_for: Callable[..., None], tmp_path: Path
) -> None:
    doc = _open(tmp_path / "dotted.log", DAY_FIRST, wait_for)
    try:
        wait_for(lambda: doc.clock.day_first is True)
        local = datetime(2026, 11, 3, 10, 0, 0).astimezone()
        assert doc.line_time(DAY_FIRST[2]) == local  # 03.11.2026 is 3 November, not 11 March
        doc.set_clock(LineClock(UTC))  # the zone dialog's correction keeps the file's order
        assert doc.clock.day_first is True and doc.clock.zone == UTC
    finally:
        doc.close()
        shutdown_pool()


@pytest.mark.parametrize("moment", [datetime(1601, 1, 1, tzinfo=UTC), datetime(9999, 12, 31, tzinfo=UTC)])
def test_extreme_dates_display_without_error(moment: datetime) -> None:
    assert to_local(moment).year == moment.year
    assert TimeRange(moment, None).label().startswith(str(moment.year))
