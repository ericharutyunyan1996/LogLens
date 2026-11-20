"""Incident builder: pinned lines across logs in time order, saved, loaded and exported as a report."""

from __future__ import annotations

from pathlib import Path

import pytest

from loglens.core import incident as inc
from loglens.core.incident import Incident, load, render_markdown, save

TOKEN = "Zx9" + "Kq7Lm2Np4Rs6Tu8Vw0Yb1Cd3Ef5Gh"


def sample() -> Incident:
    i = Incident("Checkout outage", "Orders failed for 12 minutes.")
    i.pin(
        "pay.log",
        "C:/logs/pay.log",
        41,
        "2026-11-13 10:00:07,000 ERROR gateway timeout",
        label="Root cause",
        note="Gateway down",
    )
    i.pin("web.log", "C:/logs/web.log", 9, "2026-11-13 10:00:03,000 WARN slow response 3200 ms", label="Symptom")
    i.pin("web.log", "C:/logs/web.log", 80, "no time on this line")
    return i


def test_pinning_ignores_duplicates_and_respects_the_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    i = sample()
    assert i.pin("web.log", "C:/logs/web.log", 9, "again") is None and len(i.items) == 3
    monkeypatch.setattr(inc, "MAX_ITEMS", 3)
    assert i.pin("x", "", 1, "full") is None


def test_timeline_is_in_time_order_with_untimed_lines_last() -> None:
    order = [(item.source, item.line) for item in sample().timeline()]
    assert order == [("web.log", 9), ("pay.log", 41), ("web.log", 80)]


def test_save_and_load_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "outage.json"
    save(sample(), path)
    back = load(path)
    assert back.title == "Checkout outage" and len(back.items) == 3
    assert back.items[0].label == "Root cause" and back.items[0].note == "Gateway down"


def test_load_rejects_garbage_and_skips_bad_items(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("not json", encoding="utf-8")
    with pytest.raises(ValueError, match="Cannot read"):
        load(bad)
    partial = Incident.from_dict(
        {"items": [5, {"line": "x"}, {"source": "a", "line": 2, "text": "t", "label": "bogus"}]}
    )
    assert len(partial.items) == 1 and partial.items[0].label == ""
    with pytest.raises(ValueError):
        Incident.from_dict([])


def test_report_has_summary_key_moments_and_timeline() -> None:
    md = render_markdown(sample())
    assert md.startswith("# Checkout outage") and "Orders failed for 12 minutes." in md
    assert "## Key moments" in md and "**Root cause**" in md and "Gateway down" in md
    assert md.index("slow response") < md.index("gateway timeout")  # time order
    assert "no time on this line" in md and "time unknown" in md


def test_report_masks_secrets_and_applies_a_transform() -> None:
    i = Incident("x")
    i.pin("a.log", "", 1, f"2026-11-13 10:00:00,000 INFO client_secret={TOKEN} user=alice")
    assert TOKEN not in render_markdown(i)
    assert TOKEN in render_markdown(i, mask_secrets=False)
    assert "alice" not in render_markdown(i, transform=lambda t: t.replace("alice", "user1"))
