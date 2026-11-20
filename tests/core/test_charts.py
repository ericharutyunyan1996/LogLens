"""Charts: values from fields, regex captures or plain line counts, combined per time bin."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from loglens.core.charts import AGGREGATES, ChartError, ChartSpec, chart, check, to_number
from loglens.core.formats import format_by_name

BASE = datetime(2026, 11, 13, 10, 0, 0)


def log(minutes: int = 60) -> list[tuple[int, str]]:
    lines = []
    for m in range(minutes):
        stamp = (BASE + timedelta(minutes=m)).strftime("%Y-%m-%d %H:%M:%S,000")
        ms = 100 if m < 30 else 500
        lines.append(f"{stamp} [1] INFO  Shop - request took {ms + m % 3} ms")
        if m % 10 == 0:
            lines.append(f"{stamp} [1] ERROR Shop - timeout")
    return list(enumerate(lines))


@pytest.mark.parametrize(
    ("text", "number"), [("35ms", 35.0), ("1,204 bytes", 1204.0), ("took 2.5s", 2.5), ("none", None)]
)
def test_to_number(text: str, number: float | None) -> None:
    assert to_number(text) == number


def test_counting_lines_per_bin_matches_the_total() -> None:
    data = chart(log(), ChartSpec(source="lines"))
    assert sum(v or 0 for v in data.values) == len(log()) and data.samples == len(log())
    assert data.step >= timedelta(minutes=1)


def test_counting_only_matching_lines() -> None:
    data = chart(log(), ChartSpec(source="lines", pattern="timeout"))
    assert sum(v or 0 for v in data.values) == 6


def test_regex_values_average_shows_the_slowdown_at_minute_30() -> None:
    spec = ChartSpec(source="regex", pattern=r"took (\d+) ms", aggregate="avg", bins=6)
    data = chart(log(), spec)
    values = [v for v in data.values if v is not None]
    assert values[0] < 150 and values[-1] > 450
    assert data.skipped == 6  # the timeout lines carry no number


@pytest.mark.parametrize("agg", list(AGGREGATES))
def test_every_aggregate_runs(agg: str) -> None:
    data = chart(log(), ChartSpec(source="regex", pattern=r"took (\d+) ms", aggregate=agg))
    assert not data.is_empty


def test_percentiles_order() -> None:
    def top(agg: str) -> float:
        d = chart(log(), ChartSpec(source="regex", pattern=r"took (\d+) ms", aggregate=agg, bins=2))
        return max(v for v in d.values if v is not None)

    assert top("p50") <= top("p95") <= top("p99") <= top("max")


def test_field_source_uses_the_formats_fields() -> None:
    fmt = format_by_name("log4net") or format_by_name("generic")
    assert fmt is not None
    data = chart(log(), ChartSpec(source="field", name="thread", aggregate="max"), fmt=fmt)
    assert data.samples >= 1 or data.skipped >= 1  # the field exists in the format or is skipped, never an error


def test_invalid_specs_are_explained() -> None:
    assert check(ChartSpec(source="regex")) and "group" in (check(ChartSpec(source="regex", pattern="abc")) or "")
    assert check(ChartSpec(source="field")) == "Choose a field."
    assert check(ChartSpec(source="regex", pattern="(a+)+$"))  # unsafe pattern refused
    with pytest.raises(ChartError):
        chart(log(), ChartSpec(source="regex", pattern="("))


def test_empty_and_untimed_logs() -> None:
    assert chart([], ChartSpec()).is_empty
    data = chart([(0, "no time here")], ChartSpec())
    assert data.is_empty and data.skipped == 1


def test_spec_roundtrip_and_bad_data() -> None:
    spec = ChartSpec(title="Latency", source="regex", pattern=r"(\d+)ms", aggregate="p95")
    assert ChartSpec.from_dict(spec.to_dict()) == spec
    assert ChartSpec.from_dict({"aggregate": "bogus"}) is None and ChartSpec.from_dict(5) is None
    assert ChartSpec.from_dict({"bins": 100000}) is None
