# LogLens plugins (interface version 1)

A plugin is one Python file in `%APPDATA%\LogLens\plugins`. It adds analyzers (reports over the open log), log formats
and sources (places to read lines from). Open **Analyze → Plugins → Manage plugins…** to approve it: plugins are
ordinary Python code that runs with your permissions, so nothing runs until you approve it, and editing the file
withdraws the approval.

Module-level names:

| Name | Shape |
|---|---|
| `PLUGIN` | `{"name": "…", "version": "1.0", "api": 1, "description": "…"}` (`api` must be 1) |
| `ANALYZERS` | `[{"title": "…", "run": fn(lines) -> str}]` – `lines` is an iterable of text lines |
| `SOURCES` | `[{"title": "…", "read": fn() -> iterable of str}]` – opened as a log tab |
| `FORMATS` | `[{"name": "…", "regex": "(?P<time>…) (?P<level>…) (?P<message>…)"}]` – same shape as File → Log formats |

Example (`example_orders.py` in this folder) counts lines that mention "order".
