"""Next/previous navigation over sorted line arrays."""

from __future__ import annotations

import numpy as np

from loglens.core.navigation import step, step_any
from loglens.core.units import human_size


def test_step_forward_backward_and_wrap() -> None:
    values = np.array([10, 20, 30])
    assert step(values, -1, True) == 10
    assert step(values, 10, True) == 20
    assert step(values, 30, True) == 10  # wraps
    assert step(values, 30, True, wrap=False) is None
    assert step(values, 20, False) == 10
    assert step(values, 10, False) == 30  # wraps
    assert step(np.empty(0, dtype=np.int64), 5, True) is None


def test_step_any_picks_nearest_across_arrays() -> None:
    errors, warnings = np.array([0, 250, 500]), np.array([97, 194, 291])
    assert step_any([errors, warnings], 0, True) == 97
    assert step_any([errors, warnings], 97, False) == 0
    assert step_any([errors, warnings], 500, True) == 0  # wrap to the very first
    assert step_any([np.empty(0, dtype=np.int64)], 3, True) is None


def test_human_size() -> None:
    assert human_size(0) == "0 B"
    assert human_size(1536) == "1.5 KB"
    assert human_size(1024**3 * 1.5) == "1.5 GB"
