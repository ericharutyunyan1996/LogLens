"""Human-readable formatting of sizes and counts."""

from __future__ import annotations

_UNITS = ("B", "KB", "MB", "GB", "TB")


def human_size(num_bytes: float) -> str:
    """``1536`` → ``"1.5 KB"`` (binary multiples, one decimal; bytes without decimals)."""
    value = float(num_bytes)
    for unit in _UNITS:
        if value < 1024 or unit == _UNITS[-1]:
            return f"{value:,.0f} {unit}" if unit == "B" else f"{value:,.1f} {unit}"
        value /= 1024
    raise AssertionError("unreachable")
