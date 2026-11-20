"""User knowledge base: SQLite store, packs, unknown-signature queue, signatures and the combined knowledge base.

Synthetic lines only (same shapes as real logs, no real data).
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from loglens.core.kb import (
    ORIGIN_AI,
    ORIGIN_BUILTIN,
    ORIGIN_IMPORTED,
    ORIGIN_LABELS,
    ORIGIN_USER,
    DuplicateEntryError,
    EntryNotFoundError,
    ImportResult,
    InvalidEntryError,
    KBEntry,
    KnowledgeBase,
    KnowledgePackError,
    KnowledgeStoreError,
    UserKnowledgeStore,
    compile_pattern,
    default_kb,
    entry_from_dict,
    entry_from_explanation,
    pack_text,
    pattern_for,
    signature_of,
    unique_entry_id,
)
from loglens.core.kb.signatures import KIND_EVENT, KIND_EXCEPTION, KIND_TEXT, MAX_TEMPLATE_CHARS
from loglens.core.kb.user_store import SCHEMA_VERSION
from loglens.core.secrets import MASK

EVENT_LINE = (
    "2026-11-13 10:15:02.123 +01:00 Error [Application] Sample Agent (4711) — Sync of batch 17 failed after 3 attempts"
    ' ‖ {"record": 99, "pid": 4242}'
)
CRASH_LINE = (
    "2026-11-13 10:15:02.123 +01:00 Error [Application] Application Error (1000) — Faulting application name: "
    "app.exe, Exception code: 0xc0000005"
)
TIMEOUT_LINE = "2026-11-13 10:00:01,000 [3] ERROR Consumer orders-7 timed out after 30000 ms (password=Hunter2x)"
IO_ERROR = "System.IO.IOException: The process cannot access the file '{}' because it is being used by another process."
IO_LINE = "2026-11-13 10:15:02,123 [12] ERROR Worker - Failed " + IO_ERROR.format(r"C:\in\a.csv")


def entry(entry_id: str = "user-queue-timeout", **fields: Any) -> KBEntry:
    data: dict[str, Any] = {
        "id": entry_id,
        "title": "Queue consumer timed out",
        "explanation": "The consumer did not acknowledge the message in time.",
        "causes": ["Slow message handler"],
        "steps": ["Raise the visibility timeout"],
        "patterns": [r"consumer \S+ timed out"],
    }
    data.update(fields)
    return entry_from_dict(data)


@pytest.fixture
def store(tmp_path: Path) -> Iterator[UserKnowledgeStore]:
    with UserKnowledgeStore(tmp_path / "LogLens" / "knowledge.db") as opened:
        yield opened


# ---- store ----------------------------------------------------------------------------------------------------------
def test_crud_and_normalisation(store: UserKnowledgeStore) -> None:
    added = store.add(entry(providers=["Microsoft-Windows-Sample-Agent"], event_ids=[4711]))
    assert added.providers == ("sample-agent",) and added.origin == ORIGIN_USER
    assert store.get(added.id) == added and store.all() == [added] and store.ids() == {added.id}
    with pytest.raises(DuplicateEntryError):
        store.add(added)

    store.update(replace(added, title="Queue consumer stalled", noise="important"))
    current = store.get(added.id)
    assert current is not None and (current.title, current.noise) == ("Queue consumer stalled", "important")
    with pytest.raises(EntryNotFoundError):
        store.update(replace(added, id="user-missing"))

    copied = store.add(replace(added, id="user-copy", origin=ORIGIN_BUILTIN))  # e.g. a customised built-in entry
    assert copied.origin == ORIGIN_USER
    assert store.delete(added.id) and not store.delete(added.id) and store.get(added.id) is None
    assert [e.id for e in store.all()] == ["user-copy"]


def test_persists_and_checks_schema_version(tmp_path: Path) -> None:
    path = tmp_path / "knowledge.db"
    with UserKnowledgeStore(path) as first:
        first.add(entry())
    with UserKnowledgeStore(path) as second:
        assert [e.id for e in second.all()] == ["user-queue-timeout"]
    with sqlite3.connect(path) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
    with pytest.raises(KnowledgeStoreError, match="newer LogLens"):
        UserKnowledgeStore(path)
    garbage = tmp_path / "garbage.db"
    garbage.write_bytes(b"this is not a database" * 100)
    with pytest.raises(KnowledgeStoreError, match="Cannot open"):
        UserKnowledgeStore(garbage)


def test_full_text_search_and_like_fallback_agree(tmp_path: Path) -> None:
    entries = [
        entry("user-deadlock", title="Database deadlock victim", explanation="Two transactions waited on each other."),
        entry(
            "user-disk",
            title="Disk almost full",
            explanation="Free space dropped below the threshold.",
            causes=["Log rotation disabled"],
            patterns=[r"disk \w+ full"],
        ),
        entry(
            "user-agent",
            title="Agent sync failed",
            explanation="The agent gave up.",
            providers=["Sample Agent"],
            event_ids=[4711],
            codes=["0x80070005"],
            patterns=[],
        ),
    ]
    queries = {
        "deadlock": {"user-deadlock"},
        "dead trans": {"user-deadlock"},
        "rotation": {"user-disk"},
        "4711": {"user-agent"},
        "80070005": {"user-agent"},
        "agent sync": {"user-agent"},
        "nothing here": set(),
    }
    with (
        UserKnowledgeStore(tmp_path / "fts.db") as fts,
        UserKnowledgeStore(tmp_path / "like.db", full_text=False) as like,
    ):
        assert not like.full_text_search
        for item in entries:
            fts.add(item)
            like.add(item)
        stores = [fts, like] if fts.full_text_search else [like]
        for current in stores:
            for query, expected in queries.items():
                assert {e.id for e in current.search(query)} == expected, (current.full_text_search, query)
            assert len(current.search("  ")) == 3
            disk = current.get("user-disk")
            assert disk is not None
            current.update(replace(disk, title="Volume nearly full"))
            assert {e.id for e in current.search("volume")} == {"user-disk"} and current.search("almost") == []
            current.delete("user-disk")
            assert current.search("volume") == []


def test_full_text_index_is_rebuilt_on_open(tmp_path: Path) -> None:
    path = tmp_path / "knowledge.db"
    with UserKnowledgeStore(path, full_text=False) as without_index:
        without_index.add(entry(title="Written without an index"))
    with UserKnowledgeStore(path) as reopened:
        if reopened.full_text_search:
            assert [e.id for e in reopened.search("without index")] == ["user-queue-timeout"]


# ---- packs ----------------------------------------------------------------------------------------------------------
def test_pack_round_trip(tmp_path: Path, store: UserKnowledgeStore) -> None:
    store.add(entry("user-a", title="Alpha", explanation='It\'s "quoted"\nand has\ttabs — and ünïcode.'))
    store.add(entry("user-b", title="Beta", patterns=[r"C:\\data\\[^\\]+\.csv not found", "it's (?:gone|missing)"]))
    store.add(entry("user-c", title="Gamma", codes=["0x80070005", "c0000005"], patterns=[]))
    pack_path = tmp_path / "shared.toml"
    text = store.export_pack(pack_path)
    assert pack_path.read_text(encoding="utf-8") == text

    builtin_loader = KnowledgeBase.from_toml(text)  # packs use the built-in schema
    assert [e.id for e in builtin_loader.entries] == ["user-a", "user-b", "user-c"]

    with UserKnowledgeStore(tmp_path / "other.db") as other:
        assert other.import_pack(text) == ImportResult(added=("user-a", "user-b", "user-c"))
        assert other.all() == [replace(e, origin=ORIGIN_IMPORTED) for e in store.all()]
    assert [e.id for e in KnowledgeBase.from_toml(store.export_pack(ids={"user-b"})).entries] == ["user-b"]


def test_invalid_patterns_and_entries_are_rejected(store: UserKnowledgeStore) -> None:
    with pytest.raises(InvalidEntryError, match="not a valid regular expression"):
        entry(patterns=["timeout (after"])
    with pytest.raises(InvalidEntryError, match="match every line"):
        entry(patterns=[".*"])
    with pytest.raises(InvalidEntryError, match="something to match"):
        entry(patterns=[])
    with pytest.raises(InvalidEntryError, match="provider"):
        entry(patterns=[], event_ids=[7])
    with pytest.raises(InvalidEntryError, match="'codes'"):
        entry(codes=["not-hex"])
    with pytest.raises(InvalidEntryError, match="'causes' must be a list"):
        entry(causes="just one string")
    with pytest.raises(InvalidEntryError):
        compile_pattern("[unclosed")
    broad = KBEntry("user-broad", "Broad", "Matches anything", patterns=(re.compile("x?"),))
    with pytest.raises(InvalidEntryError, match="match every line"):
        store.add(broad)
    assert store.all() == []


def test_import_conflicts_and_errors(store: UserKnowledgeStore) -> None:
    store.add(entry("shared-1", title="Mine"))
    bad = "\n[[entry]]\nid = 'bad-1'\ntitle = 'Bad'\nexplanation = 'x'\npatterns = ['(unclosed']\n"
    pack = pack_text([entry("shared-1", title="Theirs"), entry("new-1", title="New"), entry("new-1")]) + bad

    first = store.import_pack(pack)
    assert (first.added, first.updated, first.skipped) == (("new-1",), (), ("shared-1",))
    assert len(first.errors) == 2
    assert "more than once" in first.errors[0] and "not a valid regular expression" in first.errors[1]
    mine = store.get("shared-1")
    assert mine is not None and (mine.title, mine.origin) == ("Mine", ORIGIN_USER)

    second = store.import_pack(pack, overwrite=True)
    assert (second.added, second.updated, second.skipped) == ((), ("shared-1",), ("new-1",))  # identical: skipped
    theirs = store.get("shared-1")
    assert theirs is not None and (theirs.title, theirs.origin) == ("Theirs", ORIGIN_IMPORTED)

    with pytest.raises(KnowledgePackError, match="TOML"):
        store.import_pack("this is = not toml [")
    with pytest.raises(KnowledgePackError, match=r"\[\[entry\]\]"):
        store.import_pack("title = 'no entries here'")


# ---- unknown-signature queue ----------------------------------------------------------------------------------------
def test_unknown_queue_lifecycle(store: UserKnowledgeStore) -> None:
    t0 = datetime(2026, 11, 13, 10, 0, tzinfo=UTC)
    store.record_unknown(TIMEOUT_LINE, now=t0)
    store.record_unknown(
        "2026-11-13 10:05:09,500 [9] ERROR Consumer orders-12 timed out after 15000 ms (password=Other99x)",
        now=t0 + timedelta(minutes=5),
    )
    store.record_unknown(EVENT_LINE, now=t0)
    store.record_unknown(
        "2026-11-13 10:06:00,000 [4] ERROR Consumer orders-3 timed out after 5 ms (password=Zz9) retrying"
    )

    queue = store.unknowns()
    assert [u.count for u in queue] == [2, 1, 1]
    top = queue[0]
    assert (top.first_seen, top.last_seen) == (t0, t0 + timedelta(minutes=5))
    assert "Hunter2x" not in top.sample and MASK in top.sample and top.template.startswith("Consumer orders-<NUM>")
    event = next(u for u in queue if u.event_id is not None)
    assert (event.provider, event.event_id, event.template) == (
        "Sample Agent",
        4711,
        "Sync of batch <NUM> failed after <NUM> attempts",
    )

    assert store.dismiss(event.signature) and not store.dismiss("text:not-queued")
    assert event.signature not in [u.signature for u in store.unknowns()]
    assert len(store.unknowns(include_dismissed=True)) == 3

    resolution = entry_from_explanation(
        top.sample, "Queue consumer timed out", "The consumer gave up.", ["Slow handler"], [], taken_ids=store.ids()
    )
    removed = store.resolve(top.signature, resolution)
    assert removed[0] == top.signature and len(removed) == 2  # the "retrying" variant is explained by it as well
    assert [u.signature for u in store.unknowns(include_dismissed=True)] == [event.signature]
    saved = store.get(resolution.id)
    assert saved is not None and saved.origin == ORIGIN_AI and saved.steps == ()
    assert saved.matches("2026-11-14 08:00:00,000 [1] ERROR Consumer orders-99 timed out after 5 ms (password=T3x)")
    with pytest.raises(DuplicateEntryError):
        store.resolve(event.signature, resolution)


def test_unknown_queue_is_bounded(store: UserKnowledgeStore, monkeypatch: pytest.MonkeyPatch) -> None:
    from loglens.core.kb import user_store

    monkeypatch.setattr(user_store, "MAX_UNKNOWN_SIGNATURES", 3)
    t0 = datetime(2026, 11, 13, tzinfo=UTC)
    for minute, word in enumerate(["alpha", "bravo", "charlie", "delta", "echo"]):
        store.record_unknown(f"ERROR stage {word} could not start", now=t0 + timedelta(minutes=minute))
    assert sorted(u.sample.split()[2] for u in store.unknowns()) == ["charlie", "delta", "echo"]


# ---- building entries -----------------------------------------------------------------------------------------------
def test_entry_from_explanation_for_events_and_ids() -> None:
    made = entry_from_explanation(
        EVENT_LINE, "Agent sync failed", "The agent gave up.", taken_ids={"ai-agent-sync-failed"}
    )
    assert made.id == "ai-agent-sync-failed-2" and made.origin == ORIGIN_AI
    assert (made.providers, made.event_ids, made.patterns) == (("sample agent",), (4711,), ())
    assert unique_entry_id("Ünïcode — Title!", origin=ORIGIN_USER) == "user-unicode-title"
    assert unique_entry_id("???") == "user-entry"
    with pytest.raises(ValueError, match="too little fixed text"):
        entry_from_explanation("2026-11-13 10:00:00 ERROR 42", "Number", "Just a number")
    with pytest.raises(InvalidEntryError, match="title is empty"):
        entry_from_explanation(TIMEOUT_LINE, "  ", "summary")


# ---- combined knowledge base ----------------------------------------------------------------------------------------
def test_combined_kb_precedence_and_finding_origin() -> None:
    builtin = KnowledgeBase.builtin()
    override = entry_from_dict(
        {
            "id": "event-app-crash",
            "title": "Our crash runbook",
            "explanation": "Page the on-call engineer.",
            "providers": ["Application Error"],
            "event_ids": [1000],
        }
    )
    saved = entry_from_explanation(
        "2026-11-13 02:00:00,000 ERROR Nightly export: Transaction (Process ID 61) was deadlocked on lock resources",
        "Nightly export deadlock",
        "The export collides with index maintenance.",
    )
    code = entry_from_dict(
        {
            "id": "user-sharing",
            "title": "File locked by backup",
            "explanation": "Backup holds it.",
            "codes": ["0x80070020"],
        }
    )
    imported = replace(code, id="user-imported", codes=(0x80070005,), origin=ORIGIN_IMPORTED)
    kb = KnowledgeBase.combined(builtin, [override, saved, code, imported])

    crash = kb.explain(CRASH_LINE)
    assert (crash[0].title, crash[0].source, crash[0].origin) == ("Our crash runbook", "Your knowledge base", "user")
    assert "An application crashed" not in [f.title for f in crash]  # same id: the user's entry replaces it
    assert [e.id for e in kb.entries].count("event-app-crash") == 1

    deadlock = kb.explain(
        "2026-11-14 02:00:00,000 ERROR Nightly export: Transaction (Process ID 75) was deadlocked on lock resources"
    )
    assert deadlock[0].source == ORIGIN_LABELS[ORIGIN_AI] == "AI answer you saved"
    assert any(f.origin == ORIGIN_BUILTIN for f in deadlock[1:])  # built-in SQL deadlock entry still listed, after

    assert [(f.title, f.origin) for f in kb.explain("copy failed with 0x80070020")] == [
        ("File locked by backup", "user")
    ]
    assert kb.explain("open failed: 0x80070005")[0].source == "Imported knowledge pack"

    builtin_crash = default_kb().explain(CRASH_LINE)[0]  # the built-in knowledge base itself is unchanged
    assert (builtin_crash.title, builtin_crash.source) == ("An application crashed", "LogLens knowledge base")


def test_store_knowledge_base_helper(store: UserKnowledgeStore) -> None:
    store.add(entry())
    kb = store.knowledge_base(default_kb())
    assert kb.explain("WARN consumer orders-1 timed out")[0].source == "Your knowledge base"


# ---- signatures -----------------------------------------------------------------------------------------------------
def test_signature_of_plain_lines() -> None:
    a = signature_of(
        "2026-11-13 10:15:02,123 [12] ERROR Sync.Worker - Timeout after 30000 ms calling "
        "https://api.example.test/v1/items/42 for item 6f1c2e7a-0d3b-4c1e-9a55-000000000001 from 10.1.2.3"
    )
    b = signature_of(
        "2026-11-14 23:01:00,999 [7] ERROR Sync.Worker - Timeout after 15 ms calling "
        "https://api.example.test/v1/items/7 for item 0a1b2c3d-0d3b-4c1e-9a55-0000000000ff from 192.168.10.20"
    )
    assert a == b and a.kind == KIND_TEXT and a.provider is None and a.event_id is None
    assert a.template == "Sync.Worker - Timeout after <NUM> ms calling <URL> for item <GUID> from <IP>"
    assert signature_of("2026-11-13 10:15:02,123 [12] ERROR Sync.Worker - Connection refused").key != a.key

    assert signature_of("ERROR [12] Disk full on volume 3").template == "Disk full on volume <NUM>"
    message_date = signature_of("Order 12 shipped on 2026-11-13 10:00:00 to customer")  # not a header timestamp
    assert message_date.template == "Order <NUM> shipped on <NUM>-<NUM>-<NUM> <NUM> to customer"
    quoted = signature_of(r'WARN [main] cannot open "C:\in\x 1.csv" (0x80070005) for user bob, attempt 3 of 5')
    assert quoted.template == 'cannot open "<STR>" (<HEX>) for user bob, attempt <NUM> of <NUM>'
    assert signature_of('{"level":"error","msg":"disk full","free":0}').template == (
        '{"level":"<STR>","msg":"<STR>","free":<NUM>}'
    )
    secret = signature_of("login for bob with password=Hunter2x failed")
    assert "Hunter2x" not in secret.template and "password=<SECRET>" in secret.template
    assert len(signature_of("word " * 5000).template) <= MAX_TEMPLATE_CHARS


def test_signature_of_events_and_exceptions() -> None:
    event = signature_of(EVENT_LINE)
    assert (event.kind, event.key, event.provider, event.event_id) == (
        KIND_EVENT,
        "event:sample agent:4711",
        "Sample Agent",
        4711,
    )
    assert event.template == "Sync of batch <NUM> failed after <NUM> attempts"

    io = signature_of(IO_LINE)
    assert io.kind == KIND_EXCEPTION and io.key.startswith("exception:System.IO.IOException:")
    assert io.template == IO_ERROR.format("<STR>")
    assert signature_of(IO_ERROR.format(r"D:\x.txt")).key == io.key
    python = signature_of("Traceback: ValueError: invalid literal for int() with base 10: 'abc'")
    assert python.kind == KIND_EXCEPTION and python.key.startswith("exception:ValueError:")
    coded = signature_of("System.Net.Sockets.SocketException (10061): No connection could be made")
    assert coded.template == "System.Net.Sockets.SocketException (<NUM>): No connection could be made"
    assert signature_of("at Sample.Worker.ThrowTimeoutException() in Worker.cs:line 42").kind == KIND_TEXT


@pytest.mark.parametrize(
    ("line", "variant", "unrelated"),
    [
        (
            TIMEOUT_LINE,
            "2026-11-14 11:00:00,001 [9] ERROR Consumer orders-12 timed out after   5 ms (password=Zz9y)",
            "2026-11-13 10:00:01,000 [3] ERROR Consumer orders-7 finished after 30000 ms (password=Hunter2x)",
        ),
        (
            IO_LINE,
            IO_ERROR.format(r"D:\x y.txt"),
            "System.IO.IOException: There is not enough space on the disk.",
        ),
        (
            '{"level":"error","msg":"disk full","free":0}',
            '{"level":"warn","msg":"disk nearly full","free":12}',
            '{"lvl":"error","msg":"disk full"}',
        ),
        (
            EVENT_LINE,
            EVENT_LINE.replace("17", "205").replace("3 attempts", "10 attempts"),
            EVENT_LINE.replace("Sync of batch 17 failed", "Sync of batch 17 succeeded"),
        ),
    ],
    ids=["text", "exception", "json", "event"],
)
def test_pattern_for_matches_variants_only(line: str, variant: str, unrelated: str) -> None:
    pattern = re.compile(pattern_for(signature_of(line)), re.IGNORECASE)
    assert pattern.search(line) and pattern.search(variant)
    assert not pattern.search(unrelated)


def test_pattern_for_needs_fixed_text() -> None:
    with pytest.raises(ValueError, match="too little fixed text"):
        pattern_for(signature_of("12345 67"))
