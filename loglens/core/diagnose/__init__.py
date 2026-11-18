"""Guided diagnosis of Windows events: recipes that explain crashes, restarts, failing services, … and coverage checks.

Typical use: read ``channels_needed()`` for the period of interest, then ``run_all(events)`` for the findings and
``coverage_warnings(...)`` for what the findings cannot see (cleared logs, wrapped logs, inaccessible channels, gaps).
"""

from .coverage import coverage_warnings
from .recipes import RECIPES, DiagnosisFinding, Recipe, channels_needed, run_all

__all__ = ["RECIPES", "DiagnosisFinding", "Recipe", "channels_needed", "coverage_warnings", "run_all"]
