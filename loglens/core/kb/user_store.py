"""The user's own knowledge base: entries they wrote, AI answers they saved and imported packs — plus a queue of
log-line signatures nothing explained yet.

Everything lives in one SQLite file (the app uses ``%APPDATA%/LogLens/knowledge.db``). Knowledge *packs* are TOML in
the same ``[[entry]]`` schema as the built-in ``builtin.toml``, so they can be shared, reviewed and diffed as text.
Combine with the built-in knowledge via ``KnowledgeBase.combined(builtin, store.all())`` (user entries win).
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
import threading
import tomllib
import unicodedata
from collections.abc import Collection, Iterable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..highlight import backtracking_risk, compile_safely
from ..secrets import mask as mask_secrets
from .knowledge import (
    NOISE_LEVELS,
    ORIGIN_AI,
    ORIGIN_IMPORTED,
    ORIGIN_USER,
    USER_ORIGINS,
    KBEntry,
    KnowledgeBase,
    normalize_provider,
)
from .signatures import KIND_EVENT, Signature, pattern_for, signature_of

logger = logging.getLogger(__name__)

BUSY_TIMEOUT_S = 5.0  # another LogLens window may hold the write lock for a moment
MAX_UNKNOWN_SIGNATURES = 2000  # the queue is for review by a person; beyond this the least recently seen are dropped
MAX_SAMPLE_CHARS = 2000  # enough of a sample line to recognise it; payload dumps can be megabytes
MAX_ID_SLUG_CHARS = 48  # ids stay readable in packs and file diffs
_TRIVIAL_TEXTS = ("", " ", "x", "0")  # a pattern matching one of these would match (almost) every line
_HEX_CODE = re.compile(r"(?i)(?:0x)?[0-9a-f]{1,8}")
_SEARCH_WORD = re.compile(r"[^\W_]+")  # same word split as FTS5's unicode61 tokenizer (so no LIKE escaping needed)

# ---- schema ---------------------------------------------------------------------------------------------------------
# One script per schema version, applied in order; PRAGMA user_version records the version reached.
_MIGRATIONS: tuple[str, ...] = (
    """
    CREATE TABLE entries (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        explanation TEXT NOT NULL,
        causes TEXT NOT NULL DEFAULT '[]',
        steps TEXT NOT NULL DEFAULT '[]',
        noise TEXT NOT NULL DEFAULT 'normal',
        providers TEXT NOT NULL DEFAULT '[]',
        event_ids TEXT NOT NULL DEFAULT '[]',
        codes TEXT NOT NULL DEFAULT '[]',
        patterns TEXT NOT NULL DEFAULT '[]',
        origin TEXT NOT NULL DEFAULT 'user' CHECK (origin IN ('user', 'ai', 'imported')),
        created TEXT NOT NULL,
        updated TEXT NOT NULL
    );
    CREATE TABLE unknown_signatures (
        signature TEXT PRIMARY KEY,
        sample TEXT NOT NULL,
        template TEXT NOT NULL DEFAULT '',
        provider TEXT,
        event_id INTEGER,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        count INTEGER NOT NULL DEFAULT 1,
        dismissed INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX unknown_signatures_last_seen ON unknown_signatures (last_seen);
    """,
)
SCHEMA_VERSION = len(_MIGRATIONS)

# Full-text index: derived data, rebuilt on open, so it is not part of the migrations.
_FTS_SCHEMA = (
    "CREATE VIRTUAL TABLE IF NOT EXISTS entries_fts USING fts5("
    "id UNINDEXED, title, explanation, causes, steps, matchers, tokenize = 'unicode61 remove_diacritics 2')"
)
_FTS_INSERT = "INSERT INTO entries_fts (id, title, explanation, causes, steps, matchers) VALUES (?, ?, ?, ?, ?, ?)"
_ENTRY_COLUMNS = (
    "id", "title", "explanation", "causes", "steps", "noise", "providers", "event_ids", "codes", "patterns", "origin"
)  # fmt: skip
_SELECT_ENTRIES = f"SELECT {', '.join(_ENTRY_COLUMNS)} FROM entries"
_INSERT_ENTRY = (
    f"INSERT INTO entries ({', '.join(_ENTRY_COLUMNS)}, created, updated) "
    f"VALUES ({', '.join('?' * (len(_ENTRY_COLUMNS) + 2))})"
)
_UPDATE_ENTRY = f"UPDATE entries SET {', '.join(f'{c} = ?' for c in _ENTRY_COLUMNS[1:])}, updated = ? WHERE id = ?"
_LIKE_COLUMNS = ("id", "title", "explanation", "causes", "steps", "providers", "event_ids", "codes")
_LIKE_CLAUSE = "(" + " OR ".join(f"{c} LIKE ?" for c in _LIKE_COLUMNS) + ")"
_UPSERT_UNKNOWN = (
    "INSERT INTO unknown_signatures (signature, sample, template, provider, event_id, first_seen, last_seen) "
    "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (signature) DO UPDATE SET count = count + 1, "
    "first_seen = min(first_seen, excluded.first_seen), last_seen = max(last_seen, excluded.last_seen)"
)


# ---- errors and results ---------------------------------------------------------------------------------------------
class KnowledgeStoreError(Exception):
    """The user knowledge base cannot be opened or changed."""


class InvalidEntryError(KnowledgeStoreError, ValueError):
    """An entry or pattern is not valid; the message explains why and is meant for display."""


class DuplicateEntryError(KnowledgeStoreError):
    """An entry with this id already exists."""


class EntryNotFoundError(KnowledgeStoreError, LookupError):
    """No entry with this id."""


class KnowledgePackError(KnowledgeStoreError, ValueError):
    """The text is not a knowledge pack at all (not TOML, or no ``[[entry]]`` tables)."""


@dataclass(frozen=True, slots=True)
class ImportResult:
    """Outcome of importing a pack: entry ids per outcome, and one readable message per rejected entry."""

    added: tuple[str, ...] = ()
    updated: tuple[str, ...] = ()
    skipped: tuple[str, ...] = ()  # already present: identical, or different and not overwritten
    errors: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class UnknownSignature:
    """A group of log lines nothing in the knowledge base explained, waiting for review."""

    signature: str  # Signature.key
    sample: str  # one example line, secrets masked
    template: str
    provider: str | None
    event_id: int | None
    first_seen: datetime
    last_seen: datetime
    count: int
    dismissed: bool


# ---- validation -----------------------------------------------------------------------------------------------------
def compile_pattern(text: str) -> re.Pattern[str]:
    """A knowledge-base pattern compiled case-insensitively; ``InvalidEntryError`` says why when it can't be used
    (invalid, matches every line, or could take exponential time on some lines — see ``backtracking_risk``)."""
    pattern = compile_safely(text, re.IGNORECASE)
    if isinstance(pattern, str):
        raise InvalidEntryError(f"pattern {text!r} {pattern}")
    if any(pattern.search(sample) for sample in _TRIVIAL_TEXTS):
        raise InvalidEntryError(f"pattern {text!r} would match every line; make it more specific")
    return pattern


def validate_entry(entry: KBEntry) -> KBEntry:
    """``entry`` checked and normalised for the user knowledge base.

    Providers are normalised, patterns recompiled case-insensitively and an origin outside ``USER_ORIGINS`` (e.g. a
    copied built-in entry) becomes ``"user"``. Raises ``InvalidEntryError`` listing every problem.
    """
    problems: list[str] = []
    for name, value in (("id", entry.id), ("title", entry.title), ("explanation", entry.explanation)):
        if not value.strip():
            problems.append(f"{name} is empty")
    if entry.noise not in NOISE_LEVELS:
        problems.append(f"noise must be one of {', '.join(NOISE_LEVELS)}")
    if not (entry.event_ids or entry.codes or entry.patterns):
        problems.append("it needs something to match: event ids, error codes or patterns")
    if entry.event_ids and not entry.providers:
        problems.append("event ids need at least one provider ('*' for any)")
    patterns: list[re.Pattern[str]] = []
    for pattern in entry.patterns:
        try:
            patterns.append(compile_pattern(pattern.pattern))
        except InvalidEntryError as exc:
            problems.append(str(exc))
    if problems:
        raise InvalidEntryError(f"{entry.id.strip() or 'entry'}: " + "; ".join(problems))
    return replace(
        entry,
        id=entry.id.strip(),
        providers=tuple(normalize_provider(p) for p in entry.providers),
        patterns=tuple(patterns),
        origin=entry.origin if entry.origin in USER_ORIGINS else ORIGIN_USER,
    )


def _is_string_list(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(v, str) for v in value)


def _field_problems(data: dict[str, Any]) -> list[str]:
    problems = [
        f"'{key}' must be a non-empty string"
        for key in ("id", "title", "explanation")
        if not isinstance(data.get(key), str) or not data[key].strip()
    ]
    problems += [
        f"'{key}' must be a list of strings"
        for key in ("causes", "steps", "providers", "patterns")
        if not _is_string_list(data.get(key, []))
    ]
    event_ids = data.get("event_ids", [])
    if not isinstance(event_ids, list) or not all(type(i) is int and i >= 0 for i in event_ids):
        problems.append("'event_ids' must be a list of non-negative integers")
    codes = data.get("codes", [])
    if not isinstance(codes, list) or not all(isinstance(c, str) and _HEX_CODE.fullmatch(c) for c in codes):
        problems.append("'codes' must be a list of hex strings such as \"0x80070005\"")
    if data.get("noise", "normal") not in NOISE_LEVELS:
        problems.append(f"'noise' must be one of {', '.join(NOISE_LEVELS)}")
    if _is_string_list(data.get("patterns", [])):
        for text in data.get("patterns", []):
            try:
                compile_pattern(text)
            except InvalidEntryError as exc:
                problems.append(str(exc))
    return problems


def entry_from_dict(data: dict[str, Any], *, origin: str = ORIGIN_USER) -> KBEntry:
    """An entry from the ``builtin.toml`` schema (a pack item or an editor form), validated with readable errors."""
    problems = _field_problems(data)
    if problems:
        ident = data.get("id")
        label = ident.strip() if isinstance(ident, str) and ident.strip() else "entry"
        raise InvalidEntryError(f"{label}: " + "; ".join(problems))
    return validate_entry(KBEntry.from_dict(data, origin))


# ---- building entries -----------------------------------------------------------------------------------------------
def unique_entry_id(title: str, *, origin: str = ORIGIN_USER, taken: Collection[str] = ()) -> str:
    """A readable id such as ``ai-sql-timeout-saving-orders`` that is not in ``taken``."""
    ascii_title = unicodedata.normalize("NFKD", title).encode("ascii", "ignore").decode("ascii")
    slug = re.sub(r"[^a-z0-9]+", "-", ascii_title.lower()).strip("-")[:MAX_ID_SLUG_CHARS].rstrip("-") or "entry"
    base = f"{origin}-{slug}"
    candidate, number = base, 1
    while candidate in taken:
        number += 1
        candidate = f"{base}-{number}"
    return candidate


def _clean(items: Iterable[str]) -> tuple[str, ...]:
    return tuple(text for item in items if (text := item.strip()))


def entry_from_explanation(
    source: str | Signature,
    title: str,
    summary: str,
    causes: Sequence[str] = (),
    steps: Sequence[str] = (),
    *,
    origin: str = ORIGIN_AI,
    noise: str = "normal",
    taken_ids: Collection[str] = (),
) -> KBEntry:
    """An entry explaining lines like ``source`` (a log line, or its signature), e.g. from an AI answer.

    Windows event lines match by provider + event id; any other line by a regex generalised from it
    (``pattern_for``). The id is a slug of ``title`` that is not in ``taken_ids`` (pass ``store.ids()``).
    Raises ``ValueError`` if the line has too little fixed text to be recognised again.
    """
    signature = source if isinstance(source, Signature) else signature_of(source)
    providers: tuple[str, ...] = ()
    event_ids: tuple[int, ...] = ()
    patterns: tuple[re.Pattern[str], ...] = ()
    if signature.kind == KIND_EVENT and signature.provider and signature.event_id is not None:
        providers, event_ids = (normalize_provider(signature.provider),), (signature.event_id,)
    else:
        patterns = (compile_pattern(pattern_for(signature)),)
    entry = KBEntry(
        id=unique_entry_id(title, origin=origin, taken=taken_ids),
        title=title.strip(),
        explanation=summary.strip(),
        causes=_clean(causes),
        steps=_clean(steps),
        noise=noise,
        providers=providers,
        event_ids=event_ids,
        patterns=patterns,
        origin=origin,
    )
    return validate_entry(entry)


# ---- packs (TOML) ---------------------------------------------------------------------------------------------------
_TOML_ESCAPES = {
    **{code: f"\\u{code:04X}" for code in (*range(0x20), 0x7F)},
    ord("\\"): "\\\\",
    ord('"'): '\\"',
    ord("\b"): "\\b",
    ord("\t"): "\\t",
    ord("\n"): "\\n",
    ord("\f"): "\\f",
    ord("\r"): "\\r",
}
_NOT_LITERAL_SAFE = re.compile(r"['\x00-\x08\x0a-\x1f\x7f]")


def _toml_value(value: object) -> str:
    if isinstance(value, str):
        if not _NOT_LITERAL_SAFE.search(value):
            return f"'{value}'"  # literal string: regexes and Windows paths stay readable
        return '"' + value.translate(_TOML_ESCAPES) + '"'
    if isinstance(value, list):
        return "[" + ", ".join(_toml_value(item) for item in value) + "]"
    return str(value)


def pack_text(entries: Iterable[KBEntry]) -> str:
    """A shareable knowledge pack: TOML ``[[entry]]`` tables in the built-in knowledge base's schema."""
    items = [entry.to_dict() for entry in entries]
    stamp = datetime.now(UTC).strftime("%Y-%m-%d")
    lines = [
        f"# LogLens knowledge pack: {len(items)} entries, exported {stamp}.",
        "# Same [[entry]] format as LogLens's built-in knowledge base; import it in LogLens to use these explanations.",
    ]
    for item in items:
        lines.append("")
        lines.append("[[entry]]")
        lines.extend(f"{key} = {_toml_value(value)}" for key, value in item.items())
    return "\n".join(lines) + "\n"


def _parse_pack(text: str) -> list[dict[str, Any]]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise KnowledgePackError(f"Not a valid knowledge pack (TOML error: {exc})") from exc
    items = data.get("entry")
    if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
        raise KnowledgePackError("Not a knowledge pack: it has no [[entry]] tables")
    return items


# ---- rows -----------------------------------------------------------------------------------------------------------
def _now(moment: datetime | None = None) -> str:
    return (moment or datetime.now(UTC)).astimezone(UTC).isoformat(timespec="seconds")


def _json(values: Iterable[object]) -> str:
    return json.dumps(list(values), ensure_ascii=False)


def _entry_values(entry: KBEntry) -> tuple[object, ...]:
    return (
        entry.id,
        entry.title,
        entry.explanation,
        _json(entry.causes),
        _json(entry.steps),
        entry.noise,
        _json(entry.providers),
        _json(entry.event_ids),
        _json(f"0x{code:08X}" for code in entry.codes),
        _json(p.pattern for p in entry.patterns),
        entry.origin,
    )


def _fts_values(entry: KBEntry) -> tuple[str, ...]:
    codes = [f"0x{code:08X} {code:08X}" for code in entry.codes]
    matchers = " ".join([entry.id, *entry.providers, *map(str, entry.event_ids), *codes])
    return (entry.id, entry.title, entry.explanation, "\n".join(entry.causes), "\n".join(entry.steps), matchers)


def _entry_from_row(row: sqlite3.Row) -> KBEntry | None:
    try:
        return KBEntry(
            id=row["id"],
            title=row["title"],
            explanation=row["explanation"],
            causes=tuple(json.loads(row["causes"])),
            steps=tuple(json.loads(row["steps"])),
            noise=row["noise"],
            providers=tuple(json.loads(row["providers"])),
            event_ids=tuple(int(i) for i in json.loads(row["event_ids"])),
            codes=tuple(int(c, 16) for c in json.loads(row["codes"])),
            patterns=_stored_patterns(row["id"], json.loads(row["patterns"])),
            origin=row["origin"],
        )
    # edited outside LogLens, or a regex this Python rejects (re.error; OverflowError / RecursionError for a{4294967296}
    # or groups nested thousands deep)
    except (ValueError, TypeError, re.error, OverflowError, RecursionError) as exc:
        logger.warning("Skipping unreadable knowledge entry %r: %s", row["id"], exc)
        return None


def _stored_patterns(entry_id: str, texts: Iterable[str]) -> tuple[re.Pattern[str], ...]:
    """Compiled patterns of a stored entry. One that could take exponential time (stored before LogLens checked for
    that) is left out with a warning, so it can never freeze matching; an invalid one raises like ``re.compile``."""
    patterns: list[re.Pattern[str]] = []
    for text in texts:
        pattern = re.compile(text, re.IGNORECASE)
        risk = backtracking_risk(text, re.IGNORECASE)
        if risk is None:
            patterns.append(pattern)
        else:
            logger.warning("Ignoring pattern %r of knowledge entry %r: it %s", text, entry_id, risk)
    return tuple(patterns)


def _entries(rows: Iterable[sqlite3.Row]) -> list[KBEntry]:
    return [entry for entry in map(_entry_from_row, rows) if entry is not None]


def _unknown_from_row(row: sqlite3.Row) -> UnknownSignature:
    return UnknownSignature(
        signature=row["signature"],
        sample=row["sample"],
        template=row["template"],
        provider=row["provider"],
        event_id=row["event_id"],
        first_seen=datetime.fromisoformat(row["first_seen"]),
        last_seen=datetime.fromisoformat(row["last_seen"]),
        count=row["count"],
        dismissed=bool(row["dismissed"]),
    )


def _same_content(a: KBEntry, b: KBEntry) -> bool:
    return replace(a, origin=ORIGIN_IMPORTED) == replace(b, origin=ORIGIN_IMPORTED)


# ---- store ----------------------------------------------------------------------------------------------------------
class UserKnowledgeStore:
    """The user's knowledge base in one SQLite file (WAL mode).

    One connection guarded by a lock, so it may be used from the UI thread and worker threads alike. Search uses
    SQLite FTS5 when available, else ``LIKE`` substring matching (``full_text=False`` forces that).
    """

    def __init__(self, path: Path | str, *, full_text: bool = True) -> None:
        self.path = Path(path)
        self._lock = threading.RLock()
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(
                self.path, timeout=BUSY_TIMEOUT_S, isolation_level=None, check_same_thread=False
            )
        except (OSError, sqlite3.Error) as exc:
            raise KnowledgeStoreError(f"Cannot open the knowledge base {self.path}: {exc}") from exc
        self._conn.row_factory = sqlite3.Row
        try:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._migrate()
            self._full_text = full_text and self._setup_full_text()
        except sqlite3.Error as exc:  # not a database, corrupt, locked…
            self._conn.close()
            raise KnowledgeStoreError(f"Cannot open the knowledge base {self.path}: {exc}") from exc
        except KnowledgeStoreError:
            self._conn.close()
            raise

    # -- lifecycle
    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> UserKnowledgeStore:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    @property
    def full_text_search(self) -> bool:
        """Whether search uses the FTS5 index (False: LIKE fallback)."""
        return self._full_text

    def _migrate(self) -> None:
        version = int(self._conn.execute("PRAGMA user_version").fetchone()[0])
        if version > SCHEMA_VERSION:
            raise KnowledgeStoreError(
                f"{self.path} was created by a newer LogLens (schema {version}, this version knows {SCHEMA_VERSION})"
            )
        for number, script in enumerate(_MIGRATIONS[version:], start=version + 1):
            try:
                self._conn.executescript(f"BEGIN;\n{script}\nPRAGMA user_version = {number};\nCOMMIT;")
            except sqlite3.Error:
                if self._conn.in_transaction:
                    self._conn.execute("ROLLBACK")
                raise

    def _setup_full_text(self) -> bool:
        try:
            self._conn.execute(_FTS_SCHEMA)
        except sqlite3.OperationalError as exc:
            logger.info("SQLite FTS5 is unavailable (%s); knowledge search falls back to LIKE", exc)
            return False
        with self._transaction() as conn:  # rebuilt so it is right even after edits made without FTS5
            conn.execute("DELETE FROM entries_fts")
            conn.executemany(_FTS_INSERT, map(_fts_values, _entries(conn.execute(_SELECT_ENTRIES).fetchall())))
        return True

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            self._conn.execute("COMMIT")

    # -- entries (callers hold the lock / transaction)
    def _get(self, entry_id: str) -> KBEntry | None:
        row = self._conn.execute(f"{_SELECT_ENTRIES} WHERE id = ?", (entry_id,)).fetchone()
        return None if row is None else _entry_from_row(row)

    def _exists(self, entry_id: str) -> bool:
        return self._conn.execute("SELECT 1 FROM entries WHERE id = ?", (entry_id,)).fetchone() is not None

    def _insert(self, entry: KBEntry) -> None:
        stamp = _now()
        self._conn.execute(_INSERT_ENTRY, (*_entry_values(entry), stamp, stamp))
        if self._full_text:
            self._conn.execute(_FTS_INSERT, _fts_values(entry))

    def _replace(self, entry: KBEntry) -> None:
        values = _entry_values(entry)
        self._conn.execute(_UPDATE_ENTRY, (*values[1:], _now(), entry.id))
        if self._full_text:
            self._conn.execute("DELETE FROM entries_fts WHERE id = ?", (entry.id,))
            self._conn.execute(_FTS_INSERT, _fts_values(entry))

    # -- entries
    def add(self, entry: KBEntry) -> KBEntry:
        """Store a new entry; returns it as stored (validated, normalised). Raises ``DuplicateEntryError``."""
        stored = validate_entry(entry)
        with self._transaction():
            if self._exists(stored.id):
                raise DuplicateEntryError(f"An entry with id '{stored.id}' already exists")
            self._insert(stored)
        return stored

    def update(self, entry: KBEntry) -> KBEntry:
        """Replace the entry with ``entry.id``; returns it as stored. Raises ``EntryNotFoundError``."""
        stored = validate_entry(entry)
        with self._transaction():
            if not self._exists(stored.id):
                raise EntryNotFoundError(f"No entry with id '{stored.id}'")
            self._replace(stored)
        return stored

    def delete(self, entry_id: str) -> bool:
        """Remove an entry; False if there was none."""
        with self._transaction() as conn:
            deleted = conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,)).rowcount > 0
            if self._full_text:
                conn.execute("DELETE FROM entries_fts WHERE id = ?", (entry_id,))
        return deleted

    def get(self, entry_id: str) -> KBEntry | None:
        with self._lock:
            return self._get(entry_id)

    def all(self) -> list[KBEntry]:
        """Every entry, by title."""
        with self._lock:
            return _entries(self._conn.execute(f"{_SELECT_ENTRIES} ORDER BY title COLLATE NOCASE, id").fetchall())

    def ids(self) -> set[str]:
        with self._lock:
            return {row[0] for row in self._conn.execute("SELECT id FROM entries")}

    def search(self, text: str) -> list[KBEntry]:
        """Entries containing every word of ``text`` in their title, explanation, causes, steps, id, providers,
        event ids or codes — best matches first with FTS5 (word-prefix match), by title with the LIKE fallback
        (substring match). Empty ``text`` returns everything."""
        words = _SEARCH_WORD.findall(text)
        if not words:
            return self.all()
        with self._lock:
            if self._full_text:
                columns = ", ".join(f"e.{c}" for c in _ENTRY_COLUMNS)
                rows = self._conn.execute(
                    f"SELECT {columns} FROM entries_fts JOIN entries e ON e.id = entries_fts.id "
                    "WHERE entries_fts MATCH ? ORDER BY bm25(entries_fts), e.id",
                    (" ".join(f'"{word}"*' for word in words),),
                ).fetchall()
            else:
                where = " AND ".join([_LIKE_CLAUSE] * len(words))
                params = [f"%{word}%" for word in words for _ in _LIKE_COLUMNS]
                rows = self._conn.execute(
                    f"{_SELECT_ENTRIES} WHERE {where} ORDER BY title COLLATE NOCASE, id", params
                ).fetchall()
        return _entries(rows)

    def knowledge_base(self, builtin: KnowledgeBase) -> KnowledgeBase:
        """``builtin`` combined with this store's entries (which take precedence)."""
        return KnowledgeBase.combined(builtin, self.all())

    # -- packs
    def export_pack(self, path: Path | str | None = None, *, ids: Collection[str] | None = None) -> str:
        """The entries (all, or only ``ids``) as a TOML knowledge pack; also written to ``path`` when given."""
        text = pack_text(entry for entry in self.all() if ids is None or entry.id in ids)
        if path is not None:
            Path(path).write_text(text, encoding="utf-8")
        return text

    def import_pack(self, text: str, *, overwrite: bool = False) -> ImportResult:
        """Import a pack's entries (origin "imported"). Invalid entries are reported in ``errors`` and skipped;
        an existing id is replaced only with ``overwrite``. Raises ``KnowledgePackError`` if ``text`` isn't a pack.
        """
        items = _parse_pack(text)
        added: list[str] = []
        updated: list[str] = []
        skipped: list[str] = []
        errors: list[str] = []
        seen: set[str] = set()
        with self._transaction():
            for number, item in enumerate(items, start=1):
                try:
                    entry = entry_from_dict(item, origin=ORIGIN_IMPORTED)
                except InvalidEntryError as exc:
                    errors.append(f"Entry {number}: {exc}")
                    continue
                if entry.id in seen:
                    errors.append(f"Entry {number}: id '{entry.id}' appears more than once in the pack")
                    continue
                seen.add(entry.id)
                existing = self._get(entry.id)
                if existing is None:
                    self._insert(entry)
                    added.append(entry.id)
                elif overwrite and not _same_content(existing, entry):
                    self._replace(entry)
                    updated.append(entry.id)
                else:
                    skipped.append(entry.id)
        return ImportResult(tuple(added), tuple(updated), tuple(skipped), tuple(errors))

    # -- unknown-signature queue
    def record_unknown(self, line: str, *, now: datetime | None = None) -> None:
        """Count one occurrence of a line nothing explained, grouped by its signature (secrets masked in the sample)."""
        signature = signature_of(line)
        seen = _now(now)
        sample = mask_secrets(line.rstrip("\r\n"))[:MAX_SAMPLE_CHARS]
        with self._transaction() as conn:
            conn.execute(
                _UPSERT_UNKNOWN,
                (signature.key, sample, signature.template, signature.provider, signature.event_id, seen, seen),
            )
            total = int(conn.execute("SELECT count(*) FROM unknown_signatures").fetchone()[0])
            if total > MAX_UNKNOWN_SIGNATURES:
                conn.execute(
                    "DELETE FROM unknown_signatures WHERE signature IN "
                    "(SELECT signature FROM unknown_signatures ORDER BY last_seen, count LIMIT ?)",
                    (total - MAX_UNKNOWN_SIGNATURES,),
                )

    def unknowns(self, *, include_dismissed: bool = False) -> list[UnknownSignature]:
        """Queued signatures, most frequent first."""
        where = "" if include_dismissed else " WHERE dismissed = 0"
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM unknown_signatures{where} ORDER BY count DESC, last_seen DESC, signature"
            ).fetchall()
        return [_unknown_from_row(row) for row in rows]

    def dismiss(self, signature: str, *, dismissed: bool = True) -> bool:
        """Hide (or, with ``dismissed=False``, restore) a queued signature; False if it isn't queued."""
        with self._transaction() as conn:
            cursor = conn.execute(
                "UPDATE unknown_signatures SET dismissed = ? WHERE signature = ?", (int(dismissed), signature)
            )
        return cursor.rowcount > 0

    def resolve(self, signature: str, entry: KBEntry) -> tuple[str, ...]:
        """Add ``entry`` and drop ``signature`` from the queue, plus any other queued signature whose sample the
        entry now explains. Returns the removed signatures. Raises ``DuplicateEntryError`` for an existing id."""
        stored = validate_entry(entry)
        with self._transaction() as conn:
            if self._exists(stored.id):
                raise DuplicateEntryError(f"An entry with id '{stored.id}' already exists")
            self._insert(stored)
            rows = conn.execute("SELECT signature, sample FROM unknown_signatures").fetchall()
            removed = [row[0] for row in rows if row[0] == signature or stored.matches(row[1])]
            conn.executemany("DELETE FROM unknown_signatures WHERE signature = ?", [(key,) for key in removed])
        return tuple(removed)
