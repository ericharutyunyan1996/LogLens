# LogLens — Project Guide

The complete map of the project: what LogLens does, how it is designed, where every piece lives, how to extend it,
and how to build and ship it. For the working plan and decision log see [PLAN.md](../PLAN.md); for the coding rules
see [CODING_STANDARDS.md](CODING_STANDARDS.md).

---

## 1. What LogLens is

A Windows desktop **log viewer and analyzer for any log**, with deep Windows support:

| Area | What it does |
|---|---|
| **Read** | Multi-GB files opened instantly (newline index, virtual view), live tail with rotation, any encoding, ANSI colours, multi-line records (stack traces stay together), payloads decoded in the Inspector (JSON, XML, JWT, URLs, SQL, headers, base64, stack traces) |
| **Find** | Filter chains (must / any / exclude + level chips + time range), context lines, whole records, saved filters & shareable packs, find in all open logs, go to line / time, timeline strip, bookmarks, issue navigation |
| **Understand** | Offline knowledge base (368 built-in entries + your own + packs + "not explained yet" queue), Windows event facts, *Diagnose this computer* (9 recipes, coverage warnings, WER crash reports), Windows events around any line, secrets detection/masking, cleaned web search |
| **Structure** | Format detection (25 formats + your own layouts/regexes), columns view, field value counts, SQL over parsed records |
| **Analyze** | Message patterns, compare logs / before-after, HTTP statistics, request/response pairs, merged timelines (logs + Windows events), folder / zip bundles |
| **Watch** | Follow the newest file of a folder, alerts (matches, bursts, new kinds of message), Windows service status, tray notifications, live dashboard, live Windows event channels |
| **AI (opt-in)** | Claude (API key, environment, Bedrock, Vertex, Foundry, corporate gateways) or a local model (Ollama / OpenAI-compatible); redacted, editable preview, live progress, cancel; explain lines/records/top patterns; save answers to the KB |
| **Share** | Export (text / CSV / JSON Lines), incident reports (Markdown / HTML, redacted) |
| **Ship** | Portable zip, MSI (WiX), Inno Setup script; single window per user session; "Open with LogLens" |

### Product principles (non-negotiable)
1. **Generic.** No code for one specific application or vendor; sample logs only inform generic features and tests.
2. **Never get in the writer's way.** Files are opened with `FILE_SHARE_DELETE`, never memory-mapped; rotation by the
   writing application always works.
3. **The UI thread never does O(file) work.** Indexing, search, analyses and tail processing run on workers / process
   pools; results come back as generation-tagged signals.
4. **Privacy.** Nothing leaves the machine unless the user clicks; AI requests are redacted (secrets always) and
   previewed (editable) by default; API keys live only in Windows Credential Manager.
5. **Quality gate.** ruff format + ruff check + mypy (strict-ish) + pytest (≈1,100 tests) must pass.

---

## 2. Quick start

```bat
:: from source
python -m venv .venv
.venv\Scripts\python.exe -m pip install -e .[dev,ai]
.venv\Scripts\python.exe -m loglens  [file.log | folder | bundle.zip | events.evtx ...]

:: quality gate
.venv\Scripts\ruff.exe format loglens tests tools
.venv\Scripts\ruff.exe check loglens tests tools
.venv\Scripts\mypy.exe
.venv\Scripts\python.exe -m pytest -q

:: distribution (portable folder + zip + MSI; Inno Setup installer if installed)
.venv\Scripts\python.exe -m pip install -e .[build]
.venv\Scripts\python.exe tools\build.py          :: --msi-only rebuilds just the MSI
```

> If the project folder is moved or renamed, recreate or repair the venv: script launchers (`mypy.exe`, `pytest.exe`)
> embed the old path. `python -m pip install --force-reinstall --no-deps mypy pytest pre-commit` regenerates them.

---

## 3. Using it — where things are

| Menu | Items |
|---|---|
| **File** | Open (Ctrl+O), Open Windows Event Logs (Ctrl+Shift+O), Open folder or zip (Ctrl+Shift+D), Open recent, Reload (F5), Merge into timeline, Export lines, Incident report (Ctrl+Shift+P), Close tab (Ctrl+W), Restart as administrator |
| **Edit** | Copy (Ctrl+C), Find (Ctrl+F), Find in all open logs (Ctrl+Shift+F), Find next/previous (F3/Shift+F3), Next/previous issue (Ctrl+E/Ctrl+Shift+E), Go to line (Ctrl+G), Go to time (Ctrl+Shift+G), Filter by time range (Ctrl+Shift+R), bookmarks (Ctrl+B, F2/Shift+F2) |
| **View** | Follow (Ctrl+T), Word wrap (Alt+Z), Inspector (Ctrl+D), Timeline (Ctrl+Shift+L), Columns view (Ctrl+Shift+T), Mask secrets (Ctrl+Shift+M), Highlighters (Ctrl+H), Theme, Encoding, Log time zone, Zoom |
| **Analyze** | Patterns (Ctrl+Shift+N), Compare, Fields, SQL over records (Ctrl+Shift+Q), HTTP requests (Ctrl+Shift+H), Request/response pairs, Knowledge base (Ctrl+Shift+K), Diagnose this computer |
| **Watch** | Watch a folder, Alerts, Live dashboard, saved folder profiles |
| **AI** | Explain selected line (Ctrl+Shift+A), AI settings |

No shortcut uses **Ctrl+Alt+letter**: on Windows AltGr is Ctrl+Alt, and AltGr+letter types characters on many
keyboard layouts (`@ € µ` German, `ą ć ó` Polish). Keep it that way (a test enforces it).

**In a log tab:** file header (encoding / size / lines chips, **format chip** — detected format, override, custom
formats), **timeline strip** (click = jump, drag = time filter, right-click = Windows events overlay), main view (or
columns view), **filter panel** (search box, + Include / − Exclude, Time…, Saved ▾, level chips, filter chips,
Whole records, Context, Copy / Export / Clear) with its results list, and the **Inspector** (Details — KB cards, event
facts, secrets warning, decoded payloads; Raw; Windows — events ±N minutes; AI).

---

## 4. Architecture

```
loglens/
  core/       pure Python — no Qt. Index, search, records, payloads, formats, KB, Windows events, diagnosis,
              patterns, HTTP, timeline, secrets, AI request building/providers, reports.  (importable by workers/CLI)
  services/   QObject + signals, no widgets — LogDocument (one open file), background jobs, AI service,
              knowledge service, watch/alerts, multi-log jobs, single instance.
  ui/         widgets only — main window, log tab, views, Inspector, dialogs, controllers that glue UI to services.
  app.py      bootstrap: logging, exception hooks, single instance, theme, main window.
  settings.py JSON settings (%APPDATA%\LogLens\settings.json).   paths.py: where LogLens keeps its files.
```

Dependencies point **downwards only** (`ui → services → core`). Widgets hold no business state; they forward user
actions to services and re-render on their signals.

### 4.1 Threading model
* **`JobSlot`** (`services/jobs.py`): one live job per kind; `begin()` cancels the previous one and returns
  `(generation, cancel_event)`; handlers drop results whose generation is no longer current.
* **`start_worker(name, fn)`**: daemon thread with exception logging.
* **Process pools** (`core/search.py`): `"search"` (interactive) and `"background"` (below-normal priority) for
  searching big ranges in parallel; a broken pool is replaced and the search retried.
* Workers never touch document state; they emit **queued signals**. Signals carry Python objects (`object`) for
  values that can exceed 32 bits (byte offsets, `id()` keys).

### 4.2 LogDocument lifecycle (`services/log_document.py`)
1. **Index** the file on a worker (`TextLogSource.build_index`, numpy newline index).
2. When indexing ends: start **scrollbar marks** (highlight rules with marks), **records + format detection** (dominant
   timestamp pattern → record starts; `formats.detect_format` on the first 2,000 lines), and the **pending filter**.
3. **Live growth — the "covered up to" contract.** Each result set (`filter`, `records`, `marks`) records the line
   count it is complete up to (`_covered`). A full job covers the lines that existed when it started (`_running`).
   `check_file` (every second) only stats the file; growth starts a **tail job** on a worker that indexes the new
   bytes and searches them for every result set not being recomputed, from where its coverage ends. When a full job
   finishes, `_catch_up` starts a tail job for the lines that arrived meanwhile. Hits therefore stay sorted, unique
   and complete; time-range filters extend incrementally; marks/records never have gaps.
4. **Alerts** get `linesAppendedRange(first, end)` = lines that *became complete* in a tick (a line written in two
   flushes is evaluated once).
5. **Truncation / rotation / reappearance** → a *fresh* `TextLogSource` (running workers keep a consistent old one),
   every job cancelled, everything recomputed (`_restart_after_reset`).
6. **Histogram** (timeline strip) recomputed on a debounce when marks/records/clock/search change.

### 4.3 Viewing pipeline
`TextLogSource` → `ui/models.py` (`SourceLines` / `FilteredLines` with context + whole records, secret masking) →
`ui/log_view.py` (virtual painting of visible rows only: highlight spans, ANSI colours, search hits, character
selection) or `ui/columns_view.py` (virtual table; fields parsed for visible rows only).

### 4.4 Inspector pipeline (`ui/log_tab.py` → `ui/inspector.py`)
current row → `LogDocument.record_range/record_text` (whole record) → `KnowledgeService.explain` (built-in + user KB)
→ `core/winevent/models.record_from_line` + `entities.extract` (event facts) → `core/secrets.find_secrets` (warning
card) → `core/payloads.analyze` (formatters in priority order) → `ui/detail_render.py` (HTML, theme palette).
The Inspector re-renders only when the shown record changes (tail growth keeps the user's selection/scroll).

### 4.5 AI pipeline
`ui/ai_controller.py` builds an `ExplainRequest` (`core/ai/explain.build_request`: numbered excerpt, focus marks,
`Redactor` placeholders) → editable preview (`ui/ai_dialogs.AIPreviewDialog`) → `services/ai_service.AIService`
(worker, progress phases, cancel) → `core/ai/providers.make_provider`:
* `core/ai/claude.ClaudeProvider` — official `anthropic` SDK; structured JSON answer (`output_config.format`),
  effort, cached system prompt, refusal fallbacks where supported, **compatibility mode** for corporate gateways
  (classic `anthropic-version`, auto-detected and remembered).
* `core/ai/local.LocalProvider` — Ollama native API or OpenAI-compatible server; streamed; stdlib HTTP without
  proxies; loopback-only unless explicitly allowed.
Answers render in the Inspector's AI tab (cited lines are links) and can be saved to the knowledge base.

### 4.6 Windows events
`core/winevent/reader.py` (EvtQuery/XPath, publisher message formatting) → `EventRecord` → one log line per event
(`to_line`, details JSON after `‖`) → opened as a normal tab (`services/eventlog_jobs.EventLogExporter`), optionally
**followed live** (`EventLogFollower`). `core/winevent/entities.py` extracts facts; `core/diagnose/` runs recipes and
coverage checks (`services/diagnosis_jobs.py`, `ui/diagnose_dialog.py`); `core/winevent/wer.py` parses WER reports.

### 4.7 Knowledge base
* Built-in: `core/kb/builtin.toml` (TOML `[[entry]]`: providers + event_ids, codes, or patterns; noise =
  important/normal/benign; sources cited in comments). Loaded by `core/kb/knowledge.KnowledgeBase`.
* User: `core/kb/user_store.UserKnowledgeStore` (SQLite + FTS5 at `%APPDATA%\LogLens\knowledge.db`; entries,
  packs as TOML, "not explained yet" queue keyed by `core/kb/signatures`). `services/knowledge_service.py` combines
  both (user entries win) and is what the UI uses.
* Windows' own message tables explain other codes (`core/kb/codes.py`).

### 4.8 Formats, columns, fields, SQL
`core/formats/`: `base.LogFormat` (fields, regex or parser factory, multiline, time/level/message roles, level map),
`builtin.py` catalog, `structured.py` (JSON/CLEF/logfmt/CSV/TSV/W3C), `windows.py` (setupapi, CMTrace),
`layout.py` (log4net/log4j/NLog/Serilog layout compiler), `custom.py` (user formats, saved in settings),
`detect.py` (scored detection), `extract.py` (records, facets). Used by the columns view, `core/field_stats.py`
(facets, SQLite table `log`) and the Analyze pages.

### 4.9 Analyses (`ui/analysis_window.py`, `ui/analysis_fields.py`, `ui/analysis_base.py`)
Each page = an `Analyzer` run by `services/analysis_jobs.AnalysisRunner` over the whole file or the current filter
(capped, cancellable). Pages: Patterns (`core/patterns.py`), Compare, Fields, SQL, HTTP (`core/http.py`),
Request/response. Results jump to lines or become filters (switching to the right tab).

### 4.10 Live watch
`core/watch.py` (alert rules with threshold/window/cooldown, new-pattern detector, folder profiles) →
`services/watch_service.AlertMonitor` (worker per batch, exact counts) and `FolderWatcher` →
`ui/watch_controller.py` (tray, notifications, run-in-tray, Windows services via `core/service_status.py`) and
`ui/dashboard.py`.

### 4.11 Persistence & files
| What | Where |
|---|---|
| Settings (filters, packs, highlighters, AI config without keys, alerts, watch profiles, custom formats, services) | `%APPDATA%\LogLens\settings.json` |
| User knowledge base | `%APPDATA%\LogLens\knowledge.db` |
| Saved SQL queries | `%APPDATA%\LogLens\sql_queries.json` |
| Application log | `%LOCALAPPDATA%\LogLens\logs\loglens.log` (rotating) |
| API keys | Windows Credential Manager (`core/ai/credentials.py`) |
| Event log exports, timelines, evidence | `%LOCALAPPDATA%\LogLens\eventlogs\` |
| Extracted zip bundles | `%LOCALAPPDATA%\LogLens\bundles\` |

### 4.12 Time
* **Parsing** (`core/timestamps.py` → `core/timeparse.py`): the *leftmost* timestamp of a line wins (ties → the more
  specific pattern; bare epoch numbers only when nothing else matches). Every parsed time is an aware datetime
  inside 1970-01-02 … 3000-12-30 UTC (`EARLIEST`/`LATEST`, what Windows can convert to local time); placeholders
  such as `0001-01-01` or `9999-12-31` give *no time*. Year-less dates (syslog, Android) get the latest year that
  is at most one day ahead of now (December lines read in January stay in last year).
* **`LineClock(zone, shift, day_first)`** = how one log's timestamps map to real time. The **file's own clock** is set
  automatically after format detection: `zone=UTC` for formats that always log UTC (`LogFormat.times_utc`, W3C /
  IIS), else local time; `day_first` from `infer_day_first` (majority of unambiguous `dd.mm.yyyy` / `mm/dd/yyyy`
  dates in the first lines; None = decide per line). The user's correction (View → Log time zone: zone + clock
  shift) is sticky (`LogDocument.clock_chosen`): detection never overrides it, and the file's day order is kept.
* **Navigation** (`core/records.py`): Go to time and time-range filters binary-search line times; a line without a
  timestamp takes the time of its own record (looked up to 2,000 lines back, then forward). Records longer than
  2,000 lines are clipped to a window around the hit.
* **Display**: `timeparse.to_local(moment)` — local time, or the moment's own zone when Windows can't convert it
  (never raises). Use it instead of `datetime.astimezone()` in display code.

---

## 5. Code map

### core (pure logic)
| Module | Responsibility |
|---|---|
| `fileio.py` | open logs with FILE_SHARE_DELETE (never block the writer) |
| `encoding.py` | encoding / BOM detection |
| `line_index.py` | incremental numpy newline index (partial last line aware) |
| `text_source.py` | numbered lines of a file, snapshots, change detection (grown / reset / missing) |
| `search.py`, `regex_tools.py` | multi-query block search, process pools, literal prefilters |
| `filters.py` | filter chains (all/any/none + levels + time range), context rows |
| `records.py` | multi-line records, record expansion, time navigation (binary search) |
| `timestamps.py`, `timeparse.py` | timestamp detection, parsing to aware datetimes, per-log `LineClock`, day/month order, `to_local` (see 4.12) |
| `histogram.py` | timeline bins via binary search, spikes |
| `highlight.py`, `navigation.py` | highlight rules, next/previous over sorted line arrays |
| `payloads/` | formatters: stack traces, JSON, XML, JWT, URL/query, SQL, key=value, base64, headers |
| `formats/` | format engine (see 4.8) |
| `field_stats.py` | facets, SQL loading, query library |
| `patterns.py` | Drain-style pattern mining, compare, template regex |
| `http.py` | HTTP parsing (W3C, CLF, JSON, text), endpoint stats, transactions |
| `timeline.py` | k-way merge of logs by real time |
| `bundles.py` | folder listing, safe zip extraction |
| `watch.py` | alert rules, evaluator, new-pattern detector, folder profiles |
| `secrets.py` | detect / mask secrets |
| `report.py` | CSV / JSON Lines rows, incident reports |
| `packs.py` | saved filters & shareable packs |
| `websearch.py` | cleaned web-search queries |
| `ansi.py` | ANSI SGR → colour spans |
| `elevation.py`, `service_status.py` | admin relaunch, read-only service states |
| `kb/` | knowledge base (builtin TOML, user store, signatures, codes) |
| `winevent/` | Windows Event Log reader, models, entities, WER |
| `diagnose/` | recipes, coverage warnings |
| `ai/` | config, credentials, redaction, explain (prompt/schema), Claude + local providers |

### services (Qt, no widgets)
`log_document.py` (per-file state & jobs) · `jobs.py` · `analysis_jobs.py` · `export_jobs.py` · `ai_service.py` ·
`knowledge_service.py` · `eventlog_jobs.py` · `diagnosis_jobs.py` · `multi_jobs.py` (timeline, find-all, bundles) ·
`watch_service.py` · `single_instance.py`

### ui (widgets)
`main_window.py` (menus, tabs, dialogs, controllers) · `log_tab.py` · `log_view.py` · `models.py` · `columns_view.py`
· `filter_panel.py` · `histogram_view.py` · `inspector.py` + `detail_render.py` · `analysis_*.py` · `ai_controller.py`
+ `ai_dialogs.py` · `kb_dialog.py` + `kb_entry_dialog.py` · `diagnose_dialog.py` · `eventlog_dialog.py` ·
`format_dialog.py` · `time_dialogs.py` · `report_dialog.py` · `watch_controller.py` + `watch_dialogs.py` +
`dashboard.py` · `multi_dialogs.py` · `bundle_dialog.py` · `packs_controller.py` · `highlighter_dialog.py` ·
`web_search_dialog.py` · `welcome_page.py` · `theme.py` · `icons.py` · `qt_utils.py`

### tests & tools
`tests/core`, `tests/services`, `tests/ui` mirror the package (fixtures in `tests/conftest.py`: `qapp`, `wait_for`,
isolated `%APPDATA%`). `tools/`: `fault_sim.py` (test logs, live append + rotation, real crashes of its own child
processes), `bench.py` / `ui_bench.py`, `screenshots.py`, `profile_logs.py`, `fetch_samples.py`, `build.py`.
`packaging/`: PyInstaller spec + launcher, WiX `loglens.wxs`, Inno Setup `installer.iss`.

---

## 6. How do I…

| Task | Where / how |
|---|---|
| **Add a payload kind** (Inspector decoding) | New `core/payloads/<kind>_payload.py` implementing `PayloadFormatter.find(text) -> list[Section]`; register in `DEFAULT_FORMATTERS` (order = priority); optional colouring in `ui/detail_render.highlight`; tests in `tests/core/test_payloads.py` |
| **Add a built-in log format** | `core/formats/builtin.py` (regex with named groups, compiled layout, or a parser factory in `structured.py`/`windows.py`); set time/level/message roles, `filename_hints`, `level_map`; sample-line tests in `tests/core/test_formats.py` |
| **Add knowledge** | Append an `[[entry]]` to `core/kb/builtin.toml` with a `# src:` comment; write in your own words; precise patterns; add an example line to `tests/core/test_kb_content.py` (and a harmless near-miss) |
| **Add a diagnosis recipe** | `core/diagnose/recipes.py`: a `Recipe(id, title, description, channels, event_filter, analyze)`; register in `RECIPES`; synthetic-event tests in `tests/core/test_diagnose.py` |
| **Add an event fact parser** | `core/winevent/entities.py` `PARSERS` keyed by (provider, event id) |
| **Add an analysis page** | Subclass `ui/analysis_base.AnalysisPage` (`title`, `intro`, `analyzer()`, `show_result()`), register in `PAGES` (`ui/analysis_window.py`), add a menu entry in `ANALYSIS_ACTIONS` (`ui/main_window.py`); keep the core logic in `core/` |
| **Add an AI provider** | Implement the `core/ai/providers.AIProvider` protocol (`explain(request, progress, cancel)`, `test_connection()`), add a `Provider` value + fields in `core/ai/config.py`, branch in `make_provider`, settings rows in `ui/ai_dialogs.py` |
| **Add a setting** | Field on `settings.Settings` (JSON-serialisable; tolerant loading); UI in the relevant dialog/menu |
| **Add a menu action / shortcut** | `MainWindow._build_*_actions` via `self._action(...)`; add to the menu in `_build_menus`/`_build_tool_menus`; enable/disable in `_update_ui`; **no Ctrl+Alt+letter** |
| **Add an alert kind** | `core/watch.py` (`AlertRule.kind`), evaluation in `services/watch_service.AlertMonitor._start_batch/_on_batch`, editor in `ui/watch_dialogs.py` |
| **Add a long-running job** | Core function (pure) + a service object with `JobSlot` / `start_worker` / generation-tagged signals; never block the UI thread; tests with `wait_for` and, for races, a gate around the worker (see `tests/services/test_tail_coordination.py`) |
| **Change what is redacted for AI** | `core/ai/redaction.py` (+ `core/secrets.py` for secrets); secrets are always on |
| **Test against real Windows events safely** | `tools/fault_sim.py crash-native|crash-dotnet|scenario` crash only their own child processes |

---

## 7. Quality, testing and conventions
* Rules: [CODING_STANDARDS.md](CODING_STANDARDS.md) — generic only, layering, typed, ruff line length 120, named
  constants, specific exceptions, a regression test with every bug fix, parity tests for speed tricks.
* Tests: ~1,100, run in ~30 s. UI tests run real widgets with an isolated `%APPDATA%`; services tests drive
  `LogDocument` headless; races are made deterministic with gates (hold a worker until the test releases it).
* Code review (Nov 2026): four independent reviews (core, services/threading, security/privacy, UI) — every
  confirmed finding fixed with a regression test (see PLAN.md decisions log).

---

## 8. Build, packaging, release
* **Version**: `loglens/__init__.py` `__version__` (used for the exe resource, zip, MSI ProductVersion).
* **`tools/build.py`**: renders the multi-size icon from the SVG logo, writes the version resource, runs PyInstaller
  (`packaging/loglens.spec`, one-folder build `dist\LogLens\`), zips it (`dist\LogLens-<ver>-portable.zip`),
  builds the **MSI** and, if Inno Setup 6 is installed, the setup exe.
* **MSI** (`packaging/loglens.wxs`, WiX Toolset **5** as a project-local dotnet tool in `dotnet-tools.json`;
  file list generated into `build\wix\files.wxs`): per-machine install to Program Files, Start-menu shortcut,
  "Open with LogLens" for any file and in the Open-with list of .log/.txt/.evtx, major upgrades by `UpgradeCode`.
  Passes ICE validation (`dotnet wix msi validate`). Install: `msiexec /i LogLens-<ver>.msi` (silent: `/qn`;
  uninstall: `msiexec /x …`). WiX 7 would require accepting the OSMF EULA — an organisational decision.
* **Signing**: none (internal distribution, by decision). Sign exe + MSI with `signtool` if distributed outside.
* **Optional dependencies**: `ai` extra (anthropic SDK with Vertex/Bedrock), `build` extra (PyInstaller), `dev`.

---

## 9. Privacy & security guarantees (and where they are enforced)
| Guarantee | Enforced in |
|---|---|
| AI requests only on explicit click; preview (editable) by default | `ui/ai_controller.py`, `ui/ai_dialogs.AIPreviewDialog` |
| Secrets always redacted before AI; e-mails, IPs, user paths/names by default | `core/ai/config.redaction_set`, `core/ai/redaction.py`, `core/secrets.py` |
| Local model really local (no proxies, loopback only unless allowed) | `core/ai/local.py` |
| API keys only in Credential Manager | `core/ai/credentials.py`, `services/ai_service.py` |
| Masking for screen sharing (views, Inspector, columns, copy/export, find-all, dashboard) | `ui/models.py`, `ui/log_tab.py`, `ui/columns_view.py`, … |
| Zip bundles can't write outside their folder (drive / ADS / device names / traversal) | `core/bundles.py` |
| Patterns can't freeze the UI (nested repeats with overlapping choices rejected by `highlight.backtracking_risk`; the highlighter editor says why) | `core/highlight.py`, `core/packs.py`, `core/kb/user_store.py` |
| Never block or modify the logs being read; never change the user's services | `core/fileio.py`, `core/service_status.py` (read-only) |
| Elevated restarts only of an installed (non user-writable) exe | `core/elevation.py` |

---

## 10. Troubleshooting
| Symptom | Cause / fix |
|---|---|
| AI: `400 anthropic-version: header is required` | corporate gateway — LogLens switches on *compatibility mode* automatically (AI settings) |
| AI: `missing dependency google-auth` | `pip install "anthropic[vertex]"` (or `.[ai]`) |
| Local model: "Can't reach a local model server" | start Ollama (`ollama serve`) / LM Studio server; check the address in AI settings |
| A second launch opens no window | it handed its files to the running window (single instance); `--new-window` forces a new one |
| Security event log: access denied | File → Restart as administrator |
| Something went wrong | `%LOCALAPPDATA%\LogLens\logs\loglens.log` has the traceback (unhandled errors are logged and shown) |
| `mypy.exe` / `pytest.exe` do nothing after moving the folder | regenerate launchers (see §2) |
| Times in an IIS / W3C log differ from local time | W3C logs are UTC by definition and read as such; View → Log time zone overrides it |
| A KB pattern / pack is refused as "too slow" | nested repetition such as `(a+)+` can take exponential time; rewrite it without the nested repeat |

---

## 11. Roadmap (open items — see PLAN.md for the full list)
Update check (needs a release host) · XMLLayout / MSI-verbose / Docker-Kubernetes JSON wrappers · multi-line CSV
fields · remote machines (event logs over RPC) · CLI (`loglens diagnose …`) · ETW sessions · code signing for
external distribution.
