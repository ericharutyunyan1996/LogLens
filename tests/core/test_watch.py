"""Alert evaluation (threshold, window, cooldown) and newest-file selection."""

from __future__ import annotations

import os
import time
from pathlib import Path

from loglens.core.search import SearchQuery
from loglens.core.watch import AlertEvaluator, AlertRule, WatchProfile, default_alert_rules, newest_file

ERROR = SearchQuery("ERROR")


def test_single_match_rule_fires_then_cools_down() -> None:
    evaluator = AlertEvaluator([AlertRule("err", ERROR, cooldown_s=60)], "app.log")
    first = evaluator.feed(100.0, [[(5, "ERROR a")]])
    assert len(first) == 1 and first[0].first_line == 5 and first[0].sample == "ERROR a"
    assert evaluator.feed(130.0, [[(9, "ERROR b")]]) == []  # cooling down
    assert len(evaluator.feed(161.0, [[(12, "ERROR c")]])) == 1


def test_threshold_within_window() -> None:
    evaluator = AlertEvaluator([AlertRule("burst", ERROR, threshold=3, window_s=10)], "app.log")
    assert evaluator.feed(0.0, [[(1, "e"), (2, "e")]]) == []
    assert evaluator.feed(20.0, [[(3, "e")]]) == []  # the first two fell out of the window
    alerts = evaluator.feed(25.0, [[(4, "e"), (5, "e")]])
    assert len(alerts) == 1 and alerts[0].count == 3 and alerts[0].first_line == 3 and alerts[0].last_line == 5


def test_disabled_rules_and_round_trip() -> None:
    rules = default_alert_rules()
    assert all(not r.enabled for r in rules) and AlertEvaluator(rules, "x").rules == []
    assert AlertRule.from_dict(rules[1].to_dict()) == rules[1]
    profile = WatchProfile("svc", r"C:\logs", "*.log;*.txt", recursive=True)
    assert WatchProfile.from_dict(profile.to_dict()) == profile


def test_newest_file(tmp_path: Path) -> None:
    old, new, other = tmp_path / "app-1.log", tmp_path / "sub" / "app-2.log", tmp_path / "notes.md"
    new.parent.mkdir()
    for path in (old, new, other):
        path.write_text("x", encoding="utf-8")
    now = time.time()
    os.utime(old, (now - 100, now - 100))
    os.utime(new, (now, now))
    os.utime(other, (now + 50, now + 50))
    assert newest_file(tmp_path, "*.log") == old
    assert newest_file(tmp_path, "*.log", recursive=True) == new
    assert newest_file(tmp_path, "*.md;*.log", recursive=True) == other
    assert newest_file(tmp_path / "missing") is None
