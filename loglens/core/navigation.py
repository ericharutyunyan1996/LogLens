"""Next/previous navigation over sorted line-number arrays (search hits, marks, bookmarks)."""

from __future__ import annotations

from collections.abc import Sequence

import numpy as np


def step(values: np.ndarray, current: int, forward: bool, wrap: bool = True) -> int | None:
    """The value after (``forward``) or before ``current`` in sorted ``values``; wraps around by default."""
    return step_any([values], current, forward, wrap)


def step_any(arrays: Sequence[np.ndarray], current: int, forward: bool, wrap: bool = True) -> int | None:
    """Like :func:`step` across several sorted arrays: the nearest candidate in the requested direction."""
    arrays = [a for a in arrays if len(a)]
    if not arrays:
        return None
    candidates: list[int] = []
    for arr in arrays:
        if forward:
            i = int(np.searchsorted(arr, current, side="right"))
            if i < len(arr):
                candidates.append(int(arr[i]))
        else:
            i = int(np.searchsorted(arr, max(current, 0), side="left")) - 1
            if i >= 0:
                candidates.append(int(arr[i]))
    if candidates:
        return min(candidates) if forward else max(candidates)
    if not wrap:
        return None
    return min(int(a[0]) for a in arrays) if forward else max(int(a[-1]) for a in arrays)
