"""Saved filters and shareable packs."""

from __future__ import annotations

import json

import pytest

from loglens.core.filters import FilterMode, FilterTerm
from loglens.core.highlight import default_rules
from loglens.core.packs import Pack, PackError, SavedFilter, merge_filters
from loglens.core.search import SearchQuery

TIMEOUTS = SavedFilter(
    "Timeouts",
    (FilterTerm(SearchQuery("timed? ?out", regex=True)), FilterTerm(SearchQuery("healthcheck"), FilterMode.NONE)),
    ("Error",),
    context=2,
    whole_records=True,
)


def test_pack_round_trip() -> None:
    pack = Pack("team", (TIMEOUTS,), tuple(default_rules()[:2]))
    again = Pack.from_json(pack.to_json())
    assert again == pack
    assert json.loads(pack.to_json())["format"] == "loglens-pack"


@pytest.mark.parametrize(
    "text",
    [
        "not json",
        json.dumps({"format": "something-else"}),
        json.dumps({"format": "loglens-pack", "version": 99}),
        json.dumps({"format": "loglens-pack", "filters": [{"name": "x", "terms": [{"pattern": "(", "regex": True}]}]}),
        json.dumps({"format": "loglens-pack", "filters": [{"name": " "}]}),
        json.dumps({"format": "loglens-pack", "highlights": [{"name": "bad", "pattern": "[", "regex": True}]}),
    ],
)
def test_invalid_packs_are_rejected(text: str) -> None:
    with pytest.raises(PackError):
        Pack.from_json(text)


def test_merge_keeps_both_on_name_clash() -> None:
    other = SavedFilter("Timeouts", (FilterTerm(SearchQuery("deadline")),))
    merged = merge_filters([TIMEOUTS], [TIMEOUTS, other])
    assert [f.name for f in merged] == ["Timeouts", "Timeouts (2)"]
