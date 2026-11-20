# LogLens — Plan

> A fast **general-purpose log viewer & analyzer for Windows** (klogg/glogg-class speed, lnav-class understanding) that
> also **reads Windows Event Logs**, **correlates** them with any app/IIS log, and **explains** what went wrong —
> offline first, with an optional AI assistant.
> This file is the working plan: phases have checklists, tick them as we go.

**Status:** v0.3.0 is released (see the hand-off note below); v0.1.0 was the first release (signed MSI + portable build). Phases 0–8 are done apart from the open items marked
`[ ]` / `[~]` below (a few extra formats, an update check). The suite has 1,100+ tests; ruff, mypy and the full `pytest` run are clean.

> **Hand-off (resume point):** v0.3.0 is released (tag v0.3.0; the workflow builds the signed MSI). Everything through Phase 13, most of
> Phase 14 and Phase 9 (except below) is done. Still open: performance counters overlay, ForwardedEvents (WEF), SMB saved
> credentials + rotation-safe polling (9.4), Azure Monitor / CloudWatch (9.8), .zst + index cache (9.9), container digests.
> Gate: ruff check/format, `mypy loglens`, `pytest` via `.venv\Scripts\python.exe`.

**Contents**
1. [Vision](#1-vision) — who it is for and the problems it solves
2. [Feature pillars](#2-feature-pillars) — P1–P9, what each area covers
3. [Architecture](#3-architecture) — stack, layout, design rules, measured speed
4. [Phases & progress](#4-phases--progress) — checklists per phase
5. [Testing strategy](#5-testing-strategy)
6. [Research notes](#6-research-notes)
7. [Decisions log](#7-decisions-log) — decisions that still hold, grouped by topic

---

## 1. Vision

Today, investigating a problem on Windows means juggling a text viewer, Event Viewer (slow, one log at a time,
cryptic), IIS logs in UTC, PowerShell snippets from blogs, and web searches for codes like `0xc0000005`.
Users say it plainly: *"engineers don't want to search logs, they want to know what broke."*

**LogLens puts it in one place:**

1. Open **any** log instantly (multi-GB), search/filter it, follow it live — without locking the writer's rotation.
2. **Understand** it: auto-detected formats become columns, stack traces fold, JSON/XML is pretty-printed, errors are
   grouped into patterns, request/response pairs become timed transactions.
3. **Investigate**: one merged timeline across app logs, IIS logs and Windows Event Logs; "what happened ±5 min
   around this line"; "what's new compared to yesterday".
4. **Explain**: an offline knowledge base that decodes event IDs / error codes, flags known-benign noise, and
   **learns** (from you and from optional AI answers).
5. **Watch** live: profiles for "my app", tray alerts on new error patterns.

### Personas (from user research)

| Persona | Typical questions |
|---------|-------------------|
| **Developer** | Where's the exception + stack? What did request X do? Is my JSON log readable? Good run vs bad run? |
| **Windows sysadmin / ops** | Why did the app pool / service stop? Who rebooted the server? Is it still happening? |
| **Support engineer** (customer log bundles) | Open everything at once, find the *first* real error, decode codes, explain to the customer, redact. |
| **Endpoint / deployment admin** (MSI, SCCM, Intune) | Which MSI action returned 3? CMTrace-style red/yellow, error-code lookup. |
| **QA / CI** | Diff a passing vs failing run ignoring timestamps/IDs. |
| **Security / blue team** | 4625 bursts by IP/user, lockout source, new services, log cleared, logon sessions. |

### Main use cases

| # | Scenario | What LogLens does |
|---|----------|-------------------|
| U1 | "My service stopped at 03:12" | Last errors in the service log + SCM 7031/7034, Application Error 1000, WER 1001 → *"Crashed with access violation in `foo.dll` v1.2; SCM restarted it 3 times."* |
| U2 | "IIS site returns 503" | IIS W3C + HTTPERR + WAS 5002/5011/5117 → *"App pool `X` disabled by rapid-fail protection: worker crashed 5× in 5 min."* |
| U3 | "App is slow" | Request/response durations, p95 per endpoint, concurrency pile-up, + Resource-Exhaustion 2004 / disk 153 / app-pool recycle markers. |
| U4 | Customer log bundle | Open a folder/zip, merge by time with TZ correction, pattern summary, "first error", incident report. |
| U5 | Live watching | Profile "MyApp" → tail logs + event channels → tray notification on a *new* error pattern. |
| U6 | "What changed?" | Compare two time ranges or two files by pattern counts: new / vanished / over-represented patterns. |

---

## 2. Feature pillars

### P1. Viewer core (klogg parity) — *mostly done*
- Multi-GB files: background newline index (numpy), virtual view in *line* units, shared-delete file handles
  (log rotation never blocked), tail/follow with truncation/rotation detection.
- Encodings: UTF-8 (±BOM), UTF-16 LE/BE (±BOM), ANSI code pages; manual override.
- Search: plain/regex/case/exclude, filtered pane (click → jump), F3 navigation, parallel multi-core search,
  regex **literal prefilter** (regex only runs on candidate lines).
- Highlighters with presets + editor; scrollbar marks; bookmarks; **next/prev issue**; word wrap; line-details pane
  (JSON/XML pretty-print); light/dark theme.
- Still to do: char-level selection, search across all open files / a folder / a zip, AND/OR/NOT filter chains with an
  **active-filter list**, saved & shareable **filter/highlight packs**, context lines around matches, ANSI colours.

### P2. Structured logs (understand any format)
- **Format catalog with auto-detection** (BOM/NUL sniff → cheap signatures → score candidate regexes over the first
  ~1000 lines; specific formats before generic; detection can be overridden and *locked* per file —
  users dislike "magic" that changes its mind):
  IIS W3C (re-read `#Fields:` each time it appears), HTTPERR, Apache/Nginx access+error, Serilog text + CLEF JSON,
  NLog, log4net/log4j/Logback, MEL console (2-line records), ASP.NET Core hosting, Python logging, generic JSON lines
  (ECS / pino / bunyan / zap / structlog key aliases), logfmt, syslog 3164/5424, Docker json-file (unwrap → re-detect),
  Kubernetes CRI (`P`/`F` joins), **Windows**: CBS/DISM, WindowsUpdate, setupapi (block sections), MSI verbose
  (`Return value 3`), SQL Server ERRORLOG (UTF-16), **CMTrace** (`<![LOG[…]LOG]!>`, multi-line records).
- **Custom formats**: named-group regex editor with a live tester + **"paste your layout" compiler**
  (log4net `conversionPattern`, NLog layout, Serilog `outputTemplate` → regex).
- Columns view (timestamp, level, thread, logger, message + format fields), choose visible columns.
- **Multi-line records**: continuation lines belong to the previous record; fold/unfold stack traces
  (Java, .NET incl. localized `bei`/`à`/`場所`, Python tracebacks); filters match whole records.
- Level filter, time-range filter, jump-to-time, timestamps normalized with per-source **time zone / offset**.

### P3. Windows Event Log integration
- Browse channels (Application, System, Security*, Setup, Applications and Services Logs); query by level / provider /
  event ID / time / text; table + detail (message, data fields, XML). *Security needs admin.
- Open exported `.evtx` offline; handle "description cannot be found" (show raw data + KB explanation).
- Live subscription (`EvtSubscribe`); later remote machines (`EvtOpenSession`).
- Search across many channels at once (Event Viewer's biggest pain: one log at a time, 5–20 s to open).

### P4. Knowledge base + diagnosis (offline, self-learning)
- **Built-in seed KB** (TOML, read-only): Event IDs (1000, 1001, 1002, 1026, 1309, 41, 6008, 1074, SCM 7000/7009/7011/
  7023/7024/7031/7034/7045, WAS 5002/5009/5010/5011/5013/5074/5117/5186, disk 7/51/153, Ntfs 55/98, 2004, Schannel,
  DCOM 10016, MsiInstaller 1033/11707/11708, WindowsUpdate 19/20, security 4624/4625/4740/4771/4776/1102/4720/4732/
  4698/4719…), NTSTATUS (`0xc0000005`, `0xc0000409`, `0xc0000374`, `0xc00000fd`, `0xe0434352`…), HRESULT / Win32
  (`0x80070643` = 1603…), IIS status.substatus + win32-status, MSI error codes, app-log text patterns
  (OutOfMemory, deadlock, timeout, TLS handshake, login failed…).
- **"Is this normal?"** — each entry has a *noise* rating (e.g. DCOM 10016 "safe to ignore") so known-benign events are
  dimmed instead of chased.
- System lookups without KB: `FormatMessage` (Win32/HRESULT), NTSTATUS via `ntdll.dll`.
- **User KB** (SQLite in `%APPDATA%\LogLens`): unknown-signature queue (auto-collected), "Add to KB" from any line,
  AI answers saved after review, import/export packs to share with the team.
- **Diagnosis engine**: entity extraction (timestamps, codes, exception types, PIDs, processes, HTTP status, paths) →
  KB match → **correlation ±N min** across event channels and open logs → ranked findings with evidence & confidence.
- **Guided recipes** (deterministic, one click): app-pool / service crash chain, reboot cause (1074 vs 41+6008, bugcheck),
  service crash loop, installer failure (first `Return value 3`), account lockout source (4740 → 4771/4776 → 4625),
  RDP / brute-force (4625 grouped by IP/user/SubStatus), "what changed before" (updates, installs, new services, drivers).
- **Coverage / gap warnings**: "log starts at X", "Security log cleared (1102)", "rotation gap", "audit policy off",
  "clock changed" — *a gap means the conclusion is incomplete*.

#### P4 detail — how the knowledge base works

**1. Signatures: how LogLens knows two errors are "the same problem".** Every error-ish record gets one or more
signatures (kind + normalized key):

| Kind | Key | Example |
|------|-----|---------|
| `event` | provider + event ID (+ key data fields) | `Application Error/1000 · module=clr.dll · code=0xc0000005` |
| `code` | NTSTATUS / HRESULT / Win32 / SQL / HTTP code, normalized | `hresult:0x80070005`, `sql:1205`, `iis:500.19` |
| `exception` | .NET / Java / Python exception type (+ code if any) | `System.Data.SqlClient.SqlException#1205` |
| `template` | message with variables masked (numbers, GUIDs, IPs, paths, quoted strings) | `Payment failed for order <NUM>` |

**2. Lookup (using the KB).** When you select a line/event, open the Diagnose panel or run a recipe:
extract entities → build signatures → look up, most specific first:
**your KB** (team knowledge wins) → **built-in KB** → **system lookups** (FormatMessage, NTSTATUS) → *unknown*.
Result = a card: title, plain-language explanation, probable causes, next steps, noise rating ("usually harmless"),
origin (`builtin` / `user` / `ai`), confidence, how often seen, links. Match rules can be exact (signature), broader
(event ID only, exception type only) or regex on the message; broader matches show lower confidence.

**3. Saving — two different things are saved, under different rules:**
- *Observations* — saved **automatically** (they are facts, not claims): every signature seen gets counts,
  first/last seen, source files, up to N sample lines. Signatures with **no KB match go into the "Unknown" queue**,
  grouped (10,000 identical deadlock lines = one item, sorted by count and recency).
- *Knowledge* (explanations, causes, fixes) — saved **only through a decision**:
  - **You**: "Add to KB" on a line or an Unknown item → editor pre-filled with the signature, match rule and sample;
    you write/adjust title, explanation, causes, steps, noise rating.
  - **AI** (optional): "Ask AI" → answer → **"Save to KB"** → you review/edit → saved as `origin=ai`,
    status *unverified* until you confirm it. (Optional setting: keep AI answers as unverified drafts automatically.)
  - **Import** a KB pack from a colleague / shared folder.
- *Feedback* keeps it honest: 👍 / 👎 on a card, "this was the root cause", "mark as noise" → confidence and noise
  rating update; wrong entries can be edited or retired. Built-in entries are never modified — your entry with the same
  signature overrides them.

**4. Storage.** Built-in seed = TOML files shipped with the app (read-only, updated with new versions).
User KB = SQLite `%APPDATA%\LogLens\kb.sqlite` (tables: `entries`, `observations`, `feedback`; FTS5 full-text search).
Export/import = JSON packs; optional team folder (network share) merged read-only at startup.

**5. .NET specifics** (signature extraction + seed entries): exception chains (outer → ` ---> ` inner →
AggregateException; root cause = innermost), first *application* frame (skip `System.*`/`Microsoft.*`), HResult in
`(0x8013…)`, SqlException numbers (1205 deadlock, -2 timeout, 18456 login failed, 4060 db unavailable, 2627 duplicate
key), common types (TimeoutException, OutOfMemory, StackOverflow `0xc00000fd`, AccessViolation `0xc0000005`,
FileNotFound/FileLoad/BadImageFormat = assembly binding, TypeInitializationException → look inside,
TaskCanceledException = HTTP timeout, ObjectDisposed, NullReference), and the Windows side: .NET Runtime 1026,
Application Error 1000 with `0xe0434352` (= unhandled .NET exception), ASP.NET 1309, ANCM / IIS 500.30 / 500.19 / 502.5,
WAS 5011/5002.

### P5. Analysis & investigation
- **Unified timeline**: merge files + event channels by timestamp with source colours and TZ/offset correction.
- **Histogram** of events over time stacked by level; click/drag zooms the time filter; spike detection;
  **Windows events overlaid** as markers (app-pool recycle, crash, reboot) — "latency spike = app-pool recycle".
- **Pattern mining** (Drain-style, with masking of numbers/GUIDs/IPs/paths): pattern table with count, sparkline,
  first/last seen, include/exclude; "**new since baseline**".
- **Compare / what changed**: pattern-count diff between two time ranges or two files (chi-squared, ignores
  timestamps/IDs/PIDs) — new, vanished and over-represented patterns.
- **Request/response transactions**: correlation keys (W3C `traceparent`, TraceId/SpanId, RequestId/CorrelationId,
  ASP.NET Core `0H…` ids, custom regex), begin/end pairs (ASP.NET Core *Request starting/finished*, MSI actions,
  setupapi sections, user-defined), thread fallback (low confidence); durations; **per-endpoint stats** (count, error
  rate, p50/p95/p99, total time, status breakdown); **request lifecycle view** (all lines with the ID across files +
  event log entries, offsets, gaps, waterfall); IIS↔app join (exact via logged header, or fuzzy by URL/time).
- **HTTP access-log analytics** (IIS/Nginx/Apache): hits over time by status class, top/slowest URLs, 404s, status ×
  substatus × win32-status, top IPs / user agents, time-taken histogram, concurrency over time.
- **Field facets**: top values per field with counts, click to include/exclude.
- **SQL over parsed records** (SQLite) + query library in Log Parser Studio style ("top 25 slowest URLs", "hits/hour").
- Running counters / simple charts from extracted numbers.

### P6. Live watch
- **Profiles** ("MyApp", "IIS Default Web Site"): files/globs + newest-file follow in folders (IIS `W3SVC*\u_ex*.log`),
  event channels + filters, process / service names, alert rules.
- Live dashboard: per-source counters, error-rate sparkline, latest errors, service status.
- **Alert rules** (pattern / level / event ID / *new pattern* + threshold) → tray notification; run in tray.

### P7. AI assistant (optional, opt-in) — *determinism first, AI second*
- Runs on **deterministic aggregates** (patterns, correlated events, KB matches), not on 200K raw lines; every claim
  must **cite the exact lines/events** it used; suggestions, never actions.
- Pluggable `AIProvider`; first: **Claude** via the official `anthropic` SDK (default model `claude-opus-5-5`,
  structured JSON output, prompt caching). Connection: API key in Windows Credential Manager, env / `ant auth login`
  profile, or enterprise cloud (Bedrock / Vertex / Foundry). Also a **local model provider** (Ollama / OpenAI-compatible servers): no data leaves the PC.
- **Privacy**: redaction (users, hosts, IPs, emails, tokens, connection strings, profile paths) + preview of exactly what
  is sent; nothing sent without a click; per-profile disable.
- Reviewed answers can be saved into the user KB (→ offline next time).

### P8. Reports & export
- Export filtered lines / timeline slice / query results (CSV, JSON), and an **incident report** (Markdown/HTML) with the
  error, correlated events, diagnosis, KB references, AI notes — redacted on request.

### P9. Installed product (distribution)
- `LogLens.exe` via PyInstaller (no Python needed); **MSI** (WiX 5) per machine with an install-folder dialog, clean
  in-place upgrades and a remembered install folder, for Intune/SCCM/GPO and normal users alike; an Inno Setup installer
  (per user, no admin) and a portable zip are built too (users ask for no-install on servers).
- Standard layout: binaries in `Program Files\LogLens\bin`, settings and KB in `%APPDATA%\LogLens`, logs in
  `%LOCALAPPDATA%\LogLens` — nothing is written under Program Files.
- Start-menu shortcut, uninstall entry, file associations (`.log`, `.evtx`), Explorer "Open with LogLens".
- **Code signing**: a local self-signed certificate for testing, a real certificate via release-workflow secrets for
  public builds. Update check later. User data survives upgrades.
- **GitHub releases**: a tag builds, signs and publishes only the signed MSI; the demo video sits on its own release.

---

## 3. Architecture

**Stack:** Python 3.14 · PySide6 (Qt 6, native Windows 11 style) · numpy · pywin32 · SQLite · `anthropic` (optional) ·
pytest · PyInstaller.

```
LogLens/
├─ README.md · PLAN.md · LICENSE · pyproject.toml (ruff, mypy, pytest) · .pre-commit-config.yaml · .editorconfig
├─ docs/                          CODING_STANDARDS.md (rules), PROJECT_GUIDE.md (maintainer map), images/ (README shots)
├─ loglens/
│  ├─ app.py, __main__.py         bootstrap (python -m loglens), theme, logging
│  ├─ paths.py, settings.py       %APPDATA%\LogLens (settings, KB), %LOCALAPPDATA%\LogLens (logs, event exports)
│  ├─ core/                       ── pure Python, no Qt, unit-tested ──
│  │  ├─ files & search           encoding, fileio, line_index, text_source, search, regex_tools, filters, navigation
│  │  ├─ records & time           timestamps, timeparse, records, histogram, timeline, units
│  │  ├─ formats/                 detection engine + 25 built-in formats, custom layouts (log4net/NLog/Serilog)
│  │  ├─ payloads/                pluggable formatters: JSON, XML, JWT, URL/query, SQL, fields, base64, headers, stack traces
│  │  ├─ analysis                 patterns, field_stats, http (requests / transactions), secrets, highlight, ansi
│  │  ├─ winevent/                Event Log reader, entities, EventRecord models, WER reports
│  │  ├─ kb/                      built-in seed KB (TOML), codes, signatures, knowledge lookup, user store (SQLite)
│  │  ├─ diagnose/                recipes and coverage / gap warnings
│  │  ├─ ai/                      providers (Claude, local Ollama / OpenAI-compatible), config, credentials, redaction
│  │  └─ bundles, packs, report, watch, service_status, elevation, websearch
│  ├─ services/                   ── QObject + signals, no widgets ──
│  │                              jobs (JobSlot), log_document, analysis / diagnosis / eventlog / export / multi jobs,
│  │                              knowledge_service, ai_service, watch_service, single_instance
│  └─ ui/                         ── widgets only ──
│                                 main_window, log_tab, log_view, filter_panel, inspector, columns_view, analysis windows,
│                                 dialogs (AI, KB, diagnose, event logs, bundles, report, watch, time), dashboard, theme
├─ tests/                         mirrors the package: core/, services/, ui/ (1,100+ tests) + conftest (qapp, isolated APPDATA)
├─ tools/                         build (installer), signing.ps1, demo (live feature tour + video), fault_sim, bench,
│                                 ui_bench, screenshots, profile_logs, fetch_samples
├─ packaging/                     PyInstaller spec, WiX (MSI) source, Inno Setup script, launcher
└─ .github/                       release workflow (signed MSI), Dependabot for actions
```

**Design rules** (full list in `docs/CODING_STANDARDS.md`)
- **Generic only** — no code path for a specific application, vendor or connector; samples only inform generic features.
- Dependencies point down: `ui → services → core`. Widgets hold no business state; services own state and work.
- Heavy work never runs on the UI thread: indexing in a thread (numpy releases the GIL); searches in **process pools**
  ("search" pool for the user, "background" pool at below-normal priority for scrollbar marks).
- Workers report via generation-tagged queued signals (`JobSlot`); stale results are dropped.
- Common record shape (`LogRecord`: source, index, timestamp, level, text, fields) for files and events alike.
- Text view = custom `QAbstractScrollArea` painting only visible lines; event tables use `QTableView` models.
- Quality gate: `ruff format` · `ruff check` (broad rule set incl. complexity limits) · `mypy` (typed defs required)
  · `pytest` — all must pass; `pre-commit` runs them.

**Measured (1 GB / 10.2 M-line log, 16-core dev box)**
| Step | Time |
|------|------|
| First lines visible | 0.06 s |
| Full index | 1.3–1.7 s |
| Plain search (case-insensitive) | ~0.9 s |
| Regex search | ~3 s |
| Scrollbar marks (4 rules, background) | ~4.6 s (72 s originally → prefilter, priority pool, precise level rules) |
| Longest UI stall during all of the above | ≤ 30 ms |

---

## 4. Phases & progress

Legend: `[x]` done · `[~]` in progress · `[ ]` todo

### Phase 0 — Project setup ✅
- [x] Package skeleton `loglens/`, `pyproject.toml`, `requirements.txt`, `python -m loglens`
- [x] Deps in `.venv` (PySide6 6.12, numpy, pywin32, pytest)
- [x] App data folder + JSON settings + rotating log file of LogLens itself
- [x] Main window: tabs, menus, toolbar, status bar, drag & drop, recent files, welcome page
- [x] Project named LogLens (folder, package, IDE project)

### Phase 1 — Core text viewer ✅ (+ polish)
- [x] Encoding detection (BOM, UTF-16 heuristics, UTF-8, ANSI fallback) + manual override menu
- [x] Line index: numpy, background build with progress, incremental append, truncation/rotation detection
- [x] `LogView`: virtual painting, line numbers, line selection + copy, horizontal scroll, long-line clipping, word wrap
- [x] Search bar: plain/regex/case/exclude toggles, history, prev/next, progress, match highlighting
- [x] Filtered pane (click → jump, synced with main view)
- [x] Parallel search (process pool) + regex literal prefilter + case-insensitivity elision
- [x] Highlighter rules + presets + editor dialog (with live tester)
- [x] Bookmarks, go to line, follow/tail mode
- [x] Scrollbar marks (errors/warnings/IIS 5xx, search hits, bookmarks) + clickable status pills + next/prev issue
- [x] Line-details pane (JSON/XML pretty-print, raw multi-line exception fields; payload found after any prefix,
      several payloads per line, JSON embedded in JSON strings; reads the full line — tested on 1.1 MB lines)
- [x] UI polish: icons, logo, light/dark/system theme, file header chips, redesigned welcome page
- [x] **Payload formatters** (pluggable): JSON (after any prefix, several per line, embedded/base64 JSON), XML/SOAP,
      JWT (decoded, marked unverified), URL + query strings, SQL (clause layout), key=value / `Key: value` fields,
      base64 text, `Name : value` header blocks — verified on 9,439 real JSON response lines (up to 1.1 MB)
- [x] **Precise level detection**: CAPS tokens, level fields (`level=`, `"@l":`), header position after a timestamp,
      MEL prefixes; prose ("is not critical", "0 errors") no longer counts — verified against real CBS/DISM/setupapi
      level columns (exact match); prose problem words still shown, not counted
- [x] **Structure & quality**: core / services / ui layering, `LogDocument` service (headless-testable), welcome page
      module, typed actions (no string dispatch); ruff + mypy clean; pre-commit; coding standards; README
- [x] **Inspector panel** (right side, Ctrl+D): Details (header with line/timestamp/level, syntax-coloured payload
      cards with Copy), Raw, AI tabs — replaces the bottom details pane that crowded the results
- [x] **Filter panel** (replaces the search bar): pinned filter chips (must match / any of / exclude, click to change),
      one-click level chips with counts, context lines around matches (dimmed, group separators), results header
      with count/time, Copy, Export…, Clear, helpful empty state, search-as-you-type for files ≤ 50 MB
- [x] Default highlighters follow app updates unless the user customised them (`rules_customized`)
- [x] **Search the web** (Inspector button, right-click): query built from the selection — event source/id, exception
      type + message, error codes; timestamps/IDs/IPs/e-mails/user names/paths removed; editable; Google, Bing,
      DuckDuckGo, Stack Overflow, Microsoft Learn
- [x] Multi-line paste into the search box → one 'any of' filter per line
- [x] Tests: 105 (core per module, payloads, timestamps, filters, AI core, LogDocument headless, UI end-to-end)
- [x] `tools/fault_sim.py gen-log` / `append` (app text, IIS W3C, CLEF JSON; rotation), benchmarks, screenshots
- [x] **Find in all open logs** (Ctrl+Shift+F) with jump-to-line; context lines; **ANSI colours** rendered (16 / 256 /
      24-bit SGR), other escape sequences dropped
- [x] **Single window**: a second launch (Explorer "Open with", double-click) hands its files to the running window
- [x] **Character selection** within a line (drag; Ctrl+C copies just that part); line selection as before

### Phase 2 — Structured logs (formats, columns, records)
- [~] Generic timestamp detection (12 patterns incl. ISO, syslog, CLF, ctime, compact, epoch) → record vs
      continuation lines (`core/timestamps.py`, tested on public-corpus shapes)
- [x] `formats/` detection engine: 25 built-in formats scored on the first 2,000 lines (< 40 ms), filename hints,
      user formats win ties; **format chip** in the file header shows it and lets you override / go back
- [x] Format-specific structure: W3C `#Fields` (mid-file changes), setupapi sections (`!`/`!!!` levels), CMTrace
      records, CBS/DISM, Windows Update text, CLEF / JSON lines / logfmt / CSV / TSV, syslog 3164/5424 (PRI →
      level), Apache/nginx, log4net/log4j/NLog/Serilog/Logback/Python/MEL layouts; WER `Report.wer` (Diagnose)
- [x] Built-in format catalog with synthetic samples + tests for each (188 tests)
- [ ] XMLLayout / EventLog XML files, MSI verbose logs, Docker/Kubernetes JSON wrappers, multi-line CSV fields
- [x] **Multi-line records** detected in the background from the dominant timestamp layout (1 GB: 3 s, starts kept
      as int32); Inspector shows the whole record ("Lines 6–8 (one record)"); **Whole records** toggle in results;
      selection, web search and AI take whole records; **stack traces** (.NET / Java / Python / JS) formatted with
      the exception chain; `Key : Value` blocks as a table
- [x] **Go to time** (Ctrl+Shift+G, binary search), **time-range filter** (Ctrl+Shift+R, presets, chip, combines
      with terms and levels), **log time zone / clock shift** per log (View → Log time zone)
- [x] **Columns view** (View → Columns view, Ctrl+Shift+T): virtual table of parsed fields for any file size, level
      colours, synced with the Inspector and filters
- [x] **Custom format editor** (format chip → New custom format): paste a log4net / log4j / NLog / Serilog layout or
      a regex with named groups, live preview on the current file; saved in settings, used by detection
- [x] Filter chains (AND/OR/NOT + levels) with an active-filter chip list (done in phase 1 rework)
- [x] **Saved filters** (Saved ▾ in every tab) + shareable **packs** (JSON: saved filters + highlighters, import/export)

### Phase 3 — Windows Event Log
- [x] `winevent` reader: channel enumeration, `EvtQuery` + XPath (time, levels), render → `EventRecord`,
      publisher-metadata cache for messages, friendly access-denied / not-found errors
- [x] **File → Open Windows Event Logs…** (Ctrl+Shift+O): channels (common + all on the machine, filterable) or an
      `.evtx` file, time range, levels, limit → one time-ordered log tab, so search/filters/Inspector/AI all apply
- [x] **Inspector → Windows tab**: errors/warnings Windows logged ±N minutes around the selected line of *any* log
      (timestamp parsed generically, local/UTC/offsets honoured), each explained
- [x] `.evtx` files open directly (Open, drag & drop, double-click); **live follow** of exported channels (new events
      appended to the tab, deduplicated); admin detection + **Restart as administrator** (File menu, offered on
      access-denied channels and protected files; open files are reopened)
- [x] **WER crash reports** parsed (UTF-16/UTF-8 `Report.wer`: app, module, exception code, offset, CLR exception);
      listed in Diagnose → Crash reports
- [x] `fault_sim.py crash-native` / `crash-dotnet` (csc.exe) / `scenario` — verified: .NET Runtime 1026 recorded,
      explained by the KB, parsed into facts and reported by the crash recipe

### Phase 4 — Knowledge base + diagnosis
- [x] KB schema + built-in seed in `core/kb/builtin.toml` (93 entries: Windows events, NTSTATUS/HRESULT codes,
      logon sub-codes, .NET/SQL/HTTP/network/IO messages) with importance ratings (important / context / usually
      harmless); Windows' own FormatMessage / ntdll tables for other codes
- [x] Inspector **'What this means'** cards (offline) for the selected line; honest "not in the KB yet" for unknown
      events. Coverage of the dev machine's real last-7-days errors/warnings: 5 % → 97 %
- [x] **User KB** (SQLite + FTS5, WAL): "Add to KB" in the Inspector, **Save AI answer to KB**, entry editor with a
      live match tester, **Analyze → Knowledge base** (your entries, search, packs as TOML, built-in browser), and the
      **"not explained yet" queue** (errors/warnings you inspected that nothing explained); user entries win
- [x] Entity extraction for 1000/1001/1002/1026/1309, SCM, WAS, Kernel-Power, EventLog, User32, Security logons,
      MSI, Windows Update, time changes → **Event facts** in the Inspector and Diagnose
- [x] **Diagnose this computer** (Analyze menu): 9 recipes (crash chain, restarts, service failures/loops, installer
      failures, lockout, brute force, IIS app pools, storage, what changed) with evidence, confidence, next steps;
      "open evidence as a log"; real machine: 24 h diagnosed in 0.9 s
- [x] Coverage / gap warnings (cleared logs, clock jumps, wrapped logs, inaccessible channels, silences)
- [x] **Secrets in logs**: JWT, bearer/basic, API-key shapes, passwords in URLs / key=value / JSON / connection strings,
      private keys, high-entropy values → warning card in the Inspector, **View → Mask secrets** (Ctrl+Shift+M) for the
      views and Inspector, reports redacted, AI redaction always covers them
- [x] End-to-end `fault_sim.py scenario` (app error line + real crash at the same moment)
- [x] Online KB research: +274 entries (79 Windows events, 43 code groups, .NET / IIS / SQL Server / Java / Python /
      Node / PostgreSQL / MySQL / nginx / Apache / Linux / Kubernetes / TLS / network), each section with sources,
      written in our own words; 53 harmless near-miss lines must stay quiet (368 entries total)

### Phase 5 — Analysis & investigation
- [x] **Merge into timeline** (File menu): open logs + optional Windows errors of the same period, merged by real
      time (each log's clock honoured), records kept together, ‹source› on every record
- [x] **Folder / zip bundles** (File → Open folder or zip, drag & drop, command line): log files listed newest
      first, pick what to open, optionally merged into one timeline; zips extracted safely (no path escape, size /
      count / compression-ratio limits)
- [x] **Timeline strip** above the log (Ctrl+Shift+L): activity per bin with issue overlay, spikes (robust z-score),
      current position, click = jump, drag = time filter, **Windows errors/warnings overlay** (right-click); bins by
      binary search (1 GB: 0.5 s)
- [x] **Analyze → Patterns** (Drain-style mining, filter by pattern) and **Compare** (other log or before/after a
      line: new / gone / more-or-less frequent patterns)
- [x] **Analyze → Request / response pairs** (request ids, trace ids, GUIDs, threads; unanswered / errors / slowest)
- [x] **Analyze → HTTP requests** (W3C, CLF/combined, JSON, app lines): per-endpoint counts, errors, p50/p95/p99,
      status codes, busiest minutes, clients, slowest requests; double-click an endpoint to filter by it
- [x] **Analyze → Fields**: value counts per field (double-click filters); **Analyze → SQL**: parsed records in an
      SQLite table `log` (`_line, _time, _level, _message` + fields), example queries + your saved query library

### Phase 6 — Live watch
- [x] **Watch → Watch a folder**: newest matching file followed, switches to newer files (rolling logs); saved
      profiles; Windows event channels followed live
- [x] **Alerts** (Watch → Alerts): match rules with threshold / window / cooldown and a **new kind of message** rule,
      over every growing log; tray notifications (click → jump to the line); optional run in the tray
- [x] **Live dashboard** (Watch → Live dashboard): every open log's status, lines/min, errors, latest problem; chosen
      **Windows services** with their state (read-only) and a notification when one changes

### Phase 7 — AI assistant
- [x] Claude provider via the official `anthropic` SDK: structured JSON answer (`output_config.format`), effort,
      cached system prompt, server-side refusal fallbacks where supported (Claude API, not Haiku / Bedrock / Vertex /
      Foundry), refusal & truncation handling, typed error messages; citations outside the excerpt are dropped
- [x] **AI menu** + toolbar **Ask AI** (Ctrl+Shift+A) + **AI settings** dialog: provider (API key in Windows Credential
      Manager / environment or `ant` profile / Bedrock / Vertex / Foundry), model, effort, context lines, privacy,
      Test connection
- [x] Redaction (secrets, e-mails, IPs, user paths; optional hosts, GUIDs) with consistent placeholders +
      preview-before-send dialog (on by default); answer in the Inspector's AI tab with clickable cited lines
- [x] **Explain an aggregate**: Patterns → "Explain these patterns with AI" (top patterns with one example each)
- [x] Preview is **editable** — the user can remove or change anything; exactly the edited text is sent
- [x] Provider extras checked up front with an install hint (e.g. Vertex needs `anthropic[vertex]`)
- [x] Save reviewed answers to the KB (review dialog; match generalised from the line)
- [x] **Local model provider** (nothing leaves the computer): Ollama, or any OpenAI-compatible local server (LM Studio,
      llama.cpp, LocalAI, vLLM); installed models listed; structured answers with a readable fallback; streamed
- [x] **Visible progress** while asking the AI: phase + elapsed seconds in the AI tab and the status bar, busy bar,
      Cancel; the Inspector opens if it was hidden

### Phase 8 — Reports & distribution
- [x] **Export lines** as text / CSV / JSON Lines (what the results list shows: matches + context / records)
- [x] **Incident report** (Ctrl+Shift+P): bookmarks, selection, matches with context, KB findings, AI answer,
      Windows events, level overview → Markdown or self-contained HTML, redacted by default
- [x] `tools/build.py`: icon (multi-size .ico from the logo), version resource, PyInstaller one-folder build
      (`dist/LogLens`, 181 MB) + portable zip (83 MB)
- [x] `packaging/installer.iss` (Inno Setup): per-user or all users, Start menu / desktop, "Open with LogLens" for
      any file, optional default for .log / .evtx — built automatically when Inno Setup 6 is installed
- [x] **MSI** (`dist\release\LogLens-<ver>.msi`): WiX 5 as a project-local dotnet tool (MS-RL; no EULA step), per-machine
      install with an **install-folder dialog**, Start menu, "Open with LogLens", silent install `msiexec /i … /qn`;
      passes ICE validation
- [x] **Upgrades**: fixed `UpgradeCode`, `x.y.z` versions checked by the build, `MajorUpgrade` removes the old version
      first (no orphaned files), custom install folder remembered; tested install → upgrade → single entry
- [x] **Standard directory layout**: read-only binaries in `bin\`; settings/KB in `%APPDATA%`; logs and exports in
      `%LOCALAPPDATA%` (`paths.log_dir`)
- [x] **Local code signing**: `tools/signing.ps1` (self-signed cert in the user store, `signtool` with a PowerShell
      fallback, optional trust step), wired into `tools/build.py` (`--require-signature` / `--no-sign`)
- [x] **GitHub release workflow**: tag → build → sign → publish only the signed MSI; builds an unsigned test installer
      when no certificate is configured; current action versions + Dependabot
- [x] **Demo & README assets**: `tools/demo.py` drives the real app through every feature (65 steps, fails on any
      exception), records a narrated video (offline TTS) and saves the README screenshots; MIT license
- [ ] Update check (needs a release host)

### Phase 9 — More places to read logs from — *in progress*
Goal: install LogLens once, add your servers and containers, and read all their logs from one place, merged on one timeline.
Everything is agentless: it uses what is already on the machines (the Windows Event Log API, SMB, `docker`, `kubectl`, `ssh.exe`).
- [x] **9.1 Server list** (`File → Servers…`): name, host, sign-in (this Windows account / credentials saved per server);
      passwords only in Windows Credential Manager (`LogLens/server:<name>`), never in settings or logs; **Test** makes a real
      connection and reports name / port / sign-in / read access / channels found, with the fix for each failure (firewall
      rule "Remote Event Log Management", `Event Log Readers` group, wrong password, host not found, timeout).
- [x] **9.2 Remote Windows Event Logs**: a remote session for every query (channel list, events, message templates from the
      *server's* publishers), many servers in parallel, one merged timeline with the server on every line, progress and
      cancel, a failing server never hides the others.
- [x] **9.3 Remote live follow** of event channels and **Diagnose a server** (the recipes run on its events).
- [ ] **9.4 Server files over SMB**: open / merge / follow log files and folders on `\\server\share` (IIS, application
      logs) with the saved credentials, including rotation-safe live tail by polling.
- [x] **9.5 Docker and Kubernetes** (through the user's own `docker` and `kubectl`: contexts, kubeconfig and `minikube` /
      `kind` clusters just work): pick containers or pods (namespaces, containers, previous / crashed instance), live follow,
      time and tail limits, timestamps kept, one live tab per source (merging several tabs is the existing timeline merge).
      No credentials are stored by LogLens. Verified against Docker Desktop and a `kind` cluster.
- [x] 9.6 **WSL and Linux hosts** (File → WSL & Linux hosts): `wsl.exe` and `ssh.exe` (built into Windows) as live sources: tail files, `journalctl -f`.
- [x] 9.7 **Receivers** (File → Receive logs): syslog (UDP / TCP) and an HTTP endpoint, so servers and apps can push logs to LogLens.
- [~] 9.8 **Cloud and log platforms** (Loki and Elasticsearch done: File → Log platforms; Azure Monitor and CloudWatch not): Azure Monitor / Application Insights, AWS CloudWatch Logs, Grafana Loki, Elasticsearch,
      read through each service's own sign-in; queries limited by time and size.
- [~] 9.9 **Compressed logs** (`.gz` done: unpacked once into a cache; `.zst` and the index cache are not); **on-disk index cache** so a multi-GB file reopens at once.

### Phase 10 — Understand a log faster
- [x] **Triage summary** on open: the first real error, the noisiest patterns, busiest / quietest periods, slowest requests,
      "what to look at first" (one page, exportable).
- [x] **Ask in plain words** (Analyze → Ask in plain words, Ctrl+Shift+Y): a sentence becomes levels, include / exclude words and a
      time range, offline and rule based; every part is explained and editable in the filter panel. (An AI-assisted wording
      for sentences the rules do not understand is a later option.)
- [x] **Anomaly highlights**: rate spikes, new kinds of message, field-value shifts, with "started at 10:42" markers on the
      timeline.

### Phase 11 — See it visually
- [x] **Charts from any field**: counts, percentiles, averages over time; saved chart definitions; export as an image.
- [x] **Trace view**: one trace id across services and servers as a waterfall, built on the request / response pairs.
- [x] **Compare two runs side by side** (good run vs bad run): aligned diff of two logs or two time ranges.

### Phase 12 — Work as a team
- [x] **Incident builder**: pin lines to a timeline with notes and labels, export a report (extends bookmarks).
- [x] **Shared knowledge base** from a team folder or Git, with **runbooks** ("when you see X, check Y") linked to entries.
- [x] **Share-safe copy** of a whole log with consistent pseudonyms for users, IPs and hosts.

### Phase 13 — Automate and extend
- [x] **Scripting console / notebook**: SQL and Python over the open log (sandboxed, read-only on the file).
- [x] **Plugins** for formats, analyzers and sources (a documented, versioned interface).
- [x] **Scheduled digests**: watch folders, servers or containers and send a daily summary of new problems (email / Teams /
      Slack / webhook); alert delivery to the same channels. A command-line mode (`loglens diagnose --since 1h`, report
      generation) for scripts and CI.

### Phase 14 — Windows-specific depth
- [ ] **Performance counters** (CPU, memory, disk, network) overlaid on the log timeline, locally and from servers.
- [~] **More Windows sources** (Sysmon, PowerShell and Task Scheduler explanations are in; ForwardedEvents / WEF collectors not yet): Sysmon, PowerShell, Defender and Task Scheduler logs with their own explanations in the
      knowledge base; **Windows Event Forwarding** collectors (ForwardedEvents).
- [x] **Personal-data scan** (Analyze → Personal data scan; masked report, masking via the share-safe copy): find and report personal data in logs (names, e-mail addresses, card numbers, tokens) for
      compliance reviews, with a masked export.

### Later / ideas
Remote machines (event logs over RPC, UNC files) · CLI `loglens diagnose --profile MyApp --since 1h` · ETW sessions ·
WER crash-dump folder viewer · plugin formats.

---

## 5. Testing strategy
- **Tests own their servers:** anything that listens (the single-instance pipe) is closed by the test that made it,
  because a server garbage-collected with events still queued once crashed a *later*, unrelated Qt test.
- **Unit tests** for everything UI-free; parity tests for every speed trick (parallel vs single, prefilter vs full regex).
- **Headless UI smoke test** drives the real window (open → index → marks → search → navigate → wrap → details → tail).
- **Benchmarks**: `tools/bench.py` (core), `tools/ui_bench.py` (UI timings + longest UI stall) on a 1 GB generated log.
- **Screenshots**: `tools/screenshots.py` renders light/dark screens with the native style (off-screen) for review.
- **Profiler** `tools/profile_logs.py <files|folders|globs>`: encoding, record share, timestamp pattern, level
  counts, payload kinds, findings — used on generated, user, Windows and public logs to find generic gaps.
- **Public logs** `tools/fetch_samples.py`: Loghub (16 systems + ground-truth templates for pattern mining) and
  Elastic Apache/Nginx samples into `samples/internet/` (git-ignored).
- **Fault simulator** `tools/fault_sim.py`: `gen-log` (app / IIS / JSON), `append` (live + rotation); later
  `crash-native`, `crash-dotnet`, `scenario` for real Windows events.
- **Real data (read-only)**: local Application/System logs and IIS logs on the dev machine, and a private corpus of application
  logs (`tools/profile_logs.py <folder>` profiles any folder). Real logs are never copied into the repo; tests use
  synthetic lines with the same shapes. We do **not** stop or break the real IIS site or services.

## 6. Research notes (Nov 2026)
- *Most up-voted* requests in klogg / LogExpert / glogg issue trackers: **word wrap** and **dark theme** (both done),
  then scrollbar overview, next-error, search across files, JSON/columns.
- *Most painful* gaps are interpretive: cross-log correlation, plain-language explanation of events/codes, telling
  noise from real problems — nobody combines a fast text viewer with EVTX correlation and offline explanations.
- Other recurring pains: Event Viewer slowness & one-log-at-a-time, viewers that lock rotating logs, multi-line records
  split by filters, brittle format auto-detection, timezone mismatches when merging (IIS = UTC), UTF-16 files.
- AI attitude: useful as a "lead generator", but users fear hallucinations and data leaks → deterministic first,
  cite lines, redact, opt-in, local option.
- Key references: lnav formats/views (docs.lnav.org), klogg (github.com/variar/klogg), Drain3 (github.com/logpai/Drain3),
  Kibana log rate/pattern analysis, Datadog transactions/patterns, GoAccess panels, Log Parser examples
  (logparserplus.com), IIS W3C / time-taken docs (learn.microsoft.com), CMTrace format notes (cmtraceopen.com),
  W3C trace-context, EventLogExpert (Microsoft) for offline evtx rendering.

### Findings from a real-world corpus (a private set of application logs, 52 files, 282 MB, read-only)
LogLens is for *any* app; these logs are just a realistic test corpus (log4net layout, UTF-8 BOM, 985 K lines).
- **58 % of lines are continuation lines** (only 408 K of 985 K start a record): config dumps, summary reports,
  HTTP header blocks, `Key : Value` blocks, stack traces → **multi-line records are the #1 Phase 2 item**.
- **Request/response tracing**: `TraceLogger - [Request] [00000001] POST: 'url'` → `[ResponseHeader] [00000001]
  Status Code : …` (multi-line headers) → `[Response] [00000001] Content : {json}`. The response arrives on a
  **different thread** (11 → 16) 11 s later with a 502 → pairing must use the **sequence ID**, not the thread.
  Phase 5 needs a generic detector: "same ID token in a request-ish line and a response-ish line", plus user rules.
- **Single lines up to 1.1 MB** (JSON API responses) → details pane reads the full line, not the display clip (done);
  9,439 / 9,439 JSON response lines pretty-print correctly, payload found after any prefix.
- log4net `OFF` level is used for always-printed lines (treat as info, not as "off").
- Exceptions appear inside response blocks (`Error Exception : System.Net.WebException … (502) Bad Gateway`) and
  as `HttpResponseException` warnings → signature extraction must look inside multi-line records.

### Findings from real Windows logs on the dev machine (read-only)
CBS, DISM, setupapi (dev/setup), IIS W3C (2 sites, 126 files), HTTPERR, NetSetup, MRT, WER reports were profiled.
- Level precision matters: case-insensitive level words produced 86 / 230 / 1,934 false "errors/fatals" (prose such as
  `IIS-HttpErrors`, "is not critical", `{Reflect Critical Driver Package}`); precise rules now match the real level
  columns exactly (CBS 20 warnings, DISM 80 warnings, 0 errors).
- Block-structured logs (setupapi: 10–21 % of lines carry a timestamp) and W3C directive lines need format awareness.
- WER `Report.wer` = UTF-16 INI-style key=value with 23 K-char lines — a crash-report view is high value for diagnosis.
- Several logs are admin-only (Panther, MoSetup, some WER) → elevation path for files, not only the Security log.
- Payloads found in the wild: query strings (IIS), URLs, fields, JSON, **JWTs in query strings** (→ secrets feature).

## 7. Decisions log

Each entry is a decision that still holds; the *why* is in the sentence. Grouped by topic, newest ideas last in each group.

### Product & scope
- Name **LogLens**; Python + PySide6; an offline knowledge base that learns, plus an optional AI assistant (Claude first,
  pluggable; API key or other auth). Correlation, a unified timeline, insights and live watch belong together.
- Not only an Event Viewer companion: a **general log analyzer** first (formats, structure, request/response,
  patterns, compare), Windows specialisation second.
- **Generic only**: no app-, vendor- or connector-specific code. Samples inform generic features and tests.
- Testing uses our own fault simulator; real services and sites on the dev machine are never modified, and the
  fault simulator crashes only its own child processes (a Python null read, a csc-compiled .NET program).
- The project is open source under the **MIT** license, so anyone can use it.

### Files, search & performance
- Never memory-map log files, and always open them with `FILE_SHARE_DELETE`, so a writer's rotation is never broken.
- Search runs in process pools with a regex literal prefilter; background work runs at below-normal priority.
- Live growth is handled by a background *tail job* with a per-result-set "covered up to" contract: no synchronous
  tail on the UI thread, hits are always sorted and complete, and time-range filters extend incrementally. A reset
  gets a fresh `TextLogSource`.
- Analyses run as background jobs over the whole file or the current filter, with the caps stated in the UI.
- Formats: detection on the first 2,000 lines; the columns view parses only visible rows; facets and SQL stream
  records (the SQL table is capped at 1 M records).

### Parsing, records & time
- Level words count only as levels in level positions (CAPS token, level field, record header, MEL prefix); prose
  problem words are shown but not counted.
- A record is a timestamped line plus its continuations, with the layout taken from the file's dominant timestamp
  pattern. Time navigation and time filters use binary search (time is assumed to grow through the file).
- Details pane = pluggable payload formatters (JSON, XML, JWT, URL, SQL, fields, base64, headers).
- Time handling is hardened: parsed times are limited to 1970-01-02 … 3000-12-30 UTC (placeholder dates mean "no
  time"; Windows can't convert outside that range), the leftmost timestamp wins, a line without a timestamp takes its
  own record's time, and year-less dates never land in the future. Each log gets its **own clock** after detection
  (UTC for W3C/IIS via `LogFormat.times_utc`; day/month order inferred from the file) while the user's zone/shift
  correction stays sticky. Display code uses `timeparse.to_local`, which never raises.
- Patterns with nested repetition such as `(a+)+` are refused everywhere they can be entered (highlighters, packs, KB),
  with a readable reason.

### Knowledge, AI & privacy
- AI requests only on an explicit click, always redacted, preview on by default (and editable); API keys live only in
  the Windows Credential Manager; the default model is `claude-opus-5-5` with medium effort.
- Secrets redaction for AI can't be turned off. Secrets are detected once (`core/secrets.py`) and reused by the
  Inspector, masking, reports and AI.
- Local AI goes over plain HTTP (no extra packages): the Ollama native API or the OpenAI-compatible chat API. It
  bypasses proxies, is loopback-only by default, and answers are streamed so progress is visible and requests can be
  cancelled.
- Packs are plain JSON (filters + highlighters) and TOML (knowledge). The user KB is SQLite next to the settings;
  unknown errors queue themselves only when the user inspected them.

### UI & interaction
- Native Windows 11 Qt style with a thin style sheet; light, dark and system themes.
- Layering is `core → services → ui`; `LogDocument` owns per-file state.
- UI reworked after user testing: Inspector on the right (Details / Raw / AI), a filter panel with chips, levels and
  context lines; the AI assistant is reachable from the AI menu, the toolbar and the Inspector.
- No Ctrl+Alt+letter shortcuts (AltGr produces them). The Inspector re-renders only when its record changes; alerts
  evaluate each completed line once, on a worker.
- One window per user session (a local socket with acknowledgement; the pipe is per session and verifies the server's
  user). Elevated restarts use `--new-window` and reopen the same files.
- Zip extraction validates every path part.

### Real-world logs: classification, requests, payloads, AI providers
- **Severity comes from the record header**: when the header names a level (INFO, OFF, DEBUG, ERROR …) that is the
  record's level; words in the message ("EventLogLevel: Error", "Processing types: New, Failed") never change it.
  Keyword / level-field detection is only the fallback for lines without a header level (continuation lines, free
  text). Nothing in the rules knows any application name. DEBUG / TRACE lines that merely mention an exception are
  not errors; they keep the red problem-word highlight so they stay visible.
- **Request/response detection is by shape, not by vocabulary**: `METHOD /path` text, key=value traces
  (`Method=…, Url=…`, `Status=…`), `[START]`/`[END]` markers with an id, and verb + id + URL calls (`Requesting [id] …` /
  `Received … [id]`). A response is matched by shared id first (sure), then by the thread (medium) or the target (low):
  weak matches are flagged uncertain, a response that names an id nobody opened is never guessed onto another request, and
  unanswered requests and responses without a request stay in the list.
- **JSON / XML are first-class**: the exact raw text is always kept; the structured tree is built lazily (a page of
  children at a time), searchable, copyable, parsed off the UI thread, and says so when it is limited. Malformed payloads
  show a parse error next to their untouched raw text. XML with a DOCTYPE / ENTITY is never parsed (no external
  resources, no expansion).
- **AI providers report real statuses**: every provider is validated field by field before any request, "Test connection"
  makes a real tiny request (inference included for local models), errors name what is wrong (missing Vertex role,
  disabled API, missing model, timeout, quota …), secrets are scrubbed from every message, a status is dropped as soon as
  a setting changes, and a failing provider is never replaced silently by another one. Saved API keys can be deleted
  (one provider's, or all), and the deletion is verified by reading the entry back; cloud identities (gcloud, AWS) are
  not stored by LogLens.
- **Settings are saved only when valid**: with the assistant switched on, OK stays disabled (and Enter is refused, with
  the reason) while a required field is empty or malformed or a typed key was not saved; a switched-off assistant can be
  saved as is. Big JSON / XML open collapsed everywhere (Inspector structure view, request/response panes): the Details
  card prints only a one-line note, and the tree expands on demand.

### Quality & process
- Quality gate: ruff + mypy + pytest (plus pre-commit); standards live in `docs/CODING_STANDARDS.md`.
- `docs/PROJECT_GUIDE.md` is the developer/maintainer map (architecture, code map, how-tos, build).
- Four independent code reviews (core logic, services/threading, security/privacy, UI/UX; about 60 findings, most
  reproduced) led to every confirmed finding being fixed with a regression test.
- The README's screenshots, preview GIF and the demo video come from `tools/demo.py`, which drives the **real** app
  through every feature (and fails on any exception or dialog left open), so the documentation cannot drift from it.

### Packaging & release
- Distribution is an MSI (WiX **5**, MS-RL, as a project-local dotnet tool; WiX 7 needs the OSMF EULA, which is the
  organisation's decision), a portable zip, and an optional Inno Setup installer.
- The MSI is per-machine with an **install-folder dialog** (no license page). The `UpgradeCode` is fixed forever; the
  version is `x.y.z` from `loglens.__version__` (the build refuses anything else); `MajorUpgrade` removes the old version
  first so no files are orphaned; a custom install folder is remembered across upgrades.
- Install layout: read-only binaries under `Program Files\LogLens\bin`; settings and the knowledge base in
  `%APPDATA%\LogLens`; logs and event exports in `%LOCALAPPDATA%\LogLens` (nothing is written under Program Files).
  User data is kept on uninstall and upgrade on purpose.
- **Signing**: local testing uses a self-signed certificate that stays in the user's certificate store
  (`tools/signing.ps1`; the key never touches the repo). Public releases need a real code-signing certificate, supplied
  to the release workflow as secrets.
- **Releases** publish only the signed MSI (the README rides along). Intermediate build outputs stay in the workflow
  run, and the demo video lives on its own `demo` release so the installer release stays clean. Without a certificate
  the workflow builds an unsigned test installer and publishes nothing.
