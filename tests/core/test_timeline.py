"""Unified timeline: records of several logs merged by real time (time zones honoured, continuations kept)."""

from __future__ import annotations

from datetime import UTC
from pathlib import Path

from loglens.core.text_source import TextLogSource
from loglens.core.timeline import TimelineSource, merge_records, write_timeline
from loglens.core.timeparse import LineClock


def _source(tmp_path: Path, name: str, lines: list[str]) -> TextLogSource:
    path = tmp_path / name
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    source = TextLogSource(path)
    source.build_index()
    return source


def test_merge_in_time_order_with_zones_and_records(tmp_path: Path) -> None:
    app = _source(tmp_path, "app.log", [
        "2026-11-13 10:00:00,000 INFO  started",
        "2026-11-13 10:00:05,000 ERROR failed",
        "System.Exception: boom",
        "   at App.Run()",
    ])  # fmt: skip
    web = _source(tmp_path, "web.log", [  # written in UTC; the machine may be in any zone
        "2026-11-13T06:00:02Z GET /a 200",
        "2026-11-13T06:00:07Z GET /b 500",
    ])  # fmt: skip
    utc_app = TimelineSource("app.log", app, LineClock(UTC))  # read app.log as UTC too, so the order is fixed
    merged = list(merge_records([utc_app, TimelineSource("web.log", web)]))
    order = [(label, lines[0].split()[-1]) for _t, label, lines in merged]
    assert order == [("web.log", "200"), ("web.log", "500"), ("app.log", "started"), ("app.log", "failed")]
    assert merged[-1][2][1:] == ("System.Exception: boom", "   at App.Run()")

    target = tmp_path / "timeline.log"
    written, truncated = write_timeline([utc_app, TimelineSource("web.log", web)], target)
    text = target.read_text(encoding="utf-8").splitlines()
    assert written == 6 and not truncated
    assert "‹app.log› 2026-11-13 10:00:05,000 ERROR failed" in text[3] and text[4] == "    System.Exception: boom"
