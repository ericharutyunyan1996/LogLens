# LogLens

Fast log viewer & analyzer for Windows — for any log, with Windows Event Log correlation, an offline knowledge base
that explains errors and learns, and an optional AI assistant. Working plan and progress: [PLAN.md](PLAN.md).
**Developer / maintainer guide** (architecture, code map, how-tos, build, privacy): [docs/PROJECT_GUIDE.md](docs/PROJECT_GUIDE.md).

## What it does
- **Read any log fast**: multi-GB files, live tail with rotation, auto encoding, ANSI colours, multi-line records
  (stack traces kept together), payloads decoded in the Inspector (JSON, XML, JWT, URLs, SQL, headers, base64, stack
  traces), character or line selection.
- **Find things**: filter chains (must / any / exclude + levels + time range), context lines, whole records, saved
  filters and shareable packs, find in all open logs, go to line / time, timeline strip (click to jump, drag to
  filter), bookmarks, issue navigation.
- **Understand**: offline knowledge base for Windows events, error codes and common messages (built-in + your own
  entries, packs, "not explained yet" queue), event facts, **Diagnose this computer** (crashes, restarts, failing
  services, installers, lockouts, brute force, app pools, storage, what changed, coverage gaps, WER reports), Windows
  events around any line, secrets detection and masking, web search with a cleaned query.
- **Analyze**: automatic format detection (25 formats + your own layouts / regexes), columns view, field value
  counts, SQL over parsed records, message patterns, compare logs or before/after, HTTP request statistics,
  request/response pairs, merged timelines of several logs + Windows events, folder / zip bundles.
- **Watch**: follow the newest file of a folder, alerts (matches, bursts, new kinds of message), Windows services,
  tray notifications, live dashboard, Windows event channels followed live.
- **AI (optional, opt-in)**: Claude via API key, environment, Bedrock, Vertex or Foundry — or a **local model**
  (Ollama, LM Studio, llama.cpp) where nothing leaves the computer; redacted, editable preview before anything is
  sent; live progress and Cancel; explain lines, records or the top patterns; save answers to your knowledge base.
- **Share**: export lines as text / CSV / JSON Lines, incident reports (Markdown / HTML, redacted).

## Run (from source)
```
python -m venv .venv
.venv\Scripts\python.exe -m pip install -e .[dev,ai]
.venv\Scripts\python.exe -m loglens [file.log | folder | bundle.zip | events.evtx ...]
```

## Build the Windows app
```
.venv\Scripts\python.exe -m pip install -e .[build]
.venv\Scripts\python.exe tools\build.py
```
Intermediate outputs go to `dist\` (portable folder + zip, unsigned MSI); what you publish is `dist\release\`:
the **signed** `LogLens-<version>.msi` plus the README. The MSI (WiX 5 via a local dotnet tool; needs the .NET SDK)
shows an install-folder dialog, installs per machine, upgrades older versions in place (fixed UpgradeCode, version from
`loglens.__version__`, must be `x.y.z`) and remembers a custom folder. `tools\build.py --msi-only` rebuilds just the MSI.

### Local signing (testing only)
```
powershell -ExecutionPolicy Bypass -File tools\signing.ps1 -Setup            :: create self-signed cert
powershell -ExecutionPolicy Bypass -File tools\signing.ps1 -Setup -Trust     :: elevated: trust it on this PC
```
`build.py` then signs automatically (`--require-signature` / `--no-sign`). Public releases use a real certificate via the
GitHub secrets described in `.github\workflows\release.yml`; pushing a `vX.Y.Z` tag publishes only the signed MSI + docs.

### Installed layout
```
C:\Program Files\LogLens\    bin\ (LogLens.exe + _internal\ runtime)     read-only, admin-owned
%APPDATA%\LogLens\           settings.json, knowledge.db, SQL library            per user
%LOCALAPPDATA%\LogLens\      logs\loglens.log, eventlogs\                       per user, machine-local
```

## Layout
```
loglens/core       pure logic: index, search, records, payloads, formats, patterns, http, kb, diagnose, winevent
loglens/services   Qt services without widgets (LogDocument, jobs, knowledge, watch, diagnosis)
loglens/ui         widgets and dialogs
packaging/         PyInstaller spec, launcher, WiX (MSI) source, Inno Setup script
tests/             mirrors the package
tools/             developer tools (not shipped)
```

## License
MIT - free for everyone to use, change and share. See [LICENSE](LICENSE).
