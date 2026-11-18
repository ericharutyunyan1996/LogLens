# LogLens coding standards

These rules keep LogLens fast, generic and maintainable. Tooling enforces most of them; the rest are reviewed.

## 1. Product rules
- **Generic only.** LogLens is for anyone's logs. Never special-case a particular application, vendor, connector or
  file seen in sample logs. Ask: *"would this work for any log of this shape?"* Sample logs inform generic features and
  tests — they never become code paths.
- **No user data in the repo.** Real logs are used read-only from where they live; tests use synthetic lines with the
  same *shape*. `samples/generated/` and `samples/internet/` are git-ignored.
- **Never get in the writer's way.** Open logs with `core.fileio.open_shared` (FILE_SHARE_DELETE); never memory-map.

## 2. Architecture & dependency direction
```
loglens/core/      pure Python: indexing, search, payloads, formats, navigation   (no Qt imports)
loglens/services/  QObject + signals, no widgets: LogDocument, jobs               (imports core)
loglens/ui/        widgets only: views, dialogs, main window                      (imports services, core)
loglens/app.py     bootstrap
```
- Dependencies point **downwards only** (`ui → services → core`). `core` must stay importable in worker processes and
  a future CLI.
- Widgets hold no business state: they forward user actions to a service and re-render on its signals.
- No cross-object access to private members (`obj._x`). If another class needs it, add a public method/property.
- New payload kinds = new `core/payloads/*_payload.py` implementing `PayloadFormatter`, registered in
  `DEFAULT_FORMATTERS`. New log formats (phase 2) follow the same plug-in pattern in `core/formats/`.

## 3. Threading & performance
- The UI thread never does O(file) work. Indexing runs on a worker thread; searches run in the process pools
  (`"search"` for interactive work, `"background"` at below-normal priority).
- Workers never mutate shared state: they emit queued signals tagged with a generation from `JobSlot`; handlers drop
  stale results with `is_current()`.
- No per-line Python loops over whole files: use numpy, `str.find`/`count`, block-wise regex, or the process pool.
- Every speed trick needs a **parity test** against the simple implementation (see `test_search.py`,
  `test_regex_tools.py`).

## 4. Python style
- Python ≥ 3.12, `from __future__ import annotations`, full type hints; `mypy` must pass (`disallow_untyped_defs`).
- Formatting and linting: `ruff format` + `ruff check` (config in `pyproject.toml`), line length 120.
- Naming: `snake_case` functions/variables, `PascalCase` classes, `UPPER_CASE` constants. Qt overrides
  (`paintEvent`) and Qt signals (`currentRowChanged`) keep Qt's camelCase.
- Prefer small functions with one job; ruff's complexity limits (branches ≤ 16, statements ≤ 60, positional args ≤ 5)
  are hard limits — split code or use a small dataclass instead of adding `noqa`.
- Options after the essential arguments are **keyword-only** (`def f(a, b, *, flag=False)`).
- Use `dataclass(frozen=True, slots=True)` for value objects; `pathlib.Path` for paths; `logging` (never `print`) in
  the package.
- Name magic thresholds as module constants with a comment explaining the choice.
- Catch specific exceptions. A broad `except Exception` is allowed only at a job boundary that logs the error.
- Every module starts with a docstring stating its purpose; public classes/functions get docstrings when the name alone
  doesn't say everything.
- `# noqa` / `# type: ignore` need a reason in the same comment, and are a last resort.

## 5. Tests
- `pytest` under `tests/`, mirroring the package: `tests/core`, `tests/services`, `tests/ui`.
- Core logic gets unit tests; services get headless tests (no widgets); the UI has an end-to-end smoke test on the
  offscreen platform. Shared fixtures live in `tests/conftest.py` (`qapp`, `wait_for`, isolated `%APPDATA%`).
- A bug fix comes with a test that fails without the fix.

## 6. Workflow
```
.venv\Scripts\ruff.exe format loglens tests tools
.venv\Scripts\ruff.exe check loglens tests tools
.venv\Scripts\mypy.exe
.venv\Scripts\python.exe -m pytest -q
```
`pre-commit install` runs all of the above before each commit. Work is done when all four pass and `PLAN.md`
checkboxes / decision log are updated.
