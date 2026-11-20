"""The knowledge base the app uses: built-in entries plus the user's own (SQLite), and the 'not explained yet' queue.

Views ask :meth:`KnowledgeService.explain`; edits go through the service so every view refreshes on ``changed``.
"""

from __future__ import annotations

import logging
from dataclasses import replace
from pathlib import Path

from PySide6.QtCore import QObject, Signal

from ..core.kb import (
    Finding,
    ImportResult,
    KBEntry,
    KnowledgeBase,
    KnowledgeStoreError,
    UnknownSignature,
    UserKnowledgeStore,
    default_kb,
)
from ..core.kb.team import TeamKnowledge, git_pull, is_git_repo, load_folder, runbook_target
from ..core.winevent.models import EVENT_LINE
from ..paths import app_data_dir

log = logging.getLogger(__name__)
QUEUE_LEVELS = frozenset({"Critical", "Fatal", "Error", "Warning"})  # lines worth queueing when nothing explains them


def knowledge_db_path() -> Path:
    return app_data_dir() / "knowledge.db"


class KnowledgeService(QObject):
    changed = Signal()  # user entries added/edited/removed/imported
    queueChanged = Signal()
    teamChanged = Signal(str)  # the team knowledge folder was set / cleared (new path, "" for none)

    def __init__(self, path: Path | None = None, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._store: UserKnowledgeStore | None
        try:
            self._store = UserKnowledgeStore(path or knowledge_db_path())
        except KnowledgeStoreError as exc:  # unreadable / newer database: keep working with the built-in KB
            log.warning("user knowledge base unavailable: %s", exc)
            self._store = None
        self._knowledge: KnowledgeBase | None = None
        self.team: TeamKnowledge | None = None

    @property
    def available(self) -> bool:
        return self._store is not None

    @property
    def store(self) -> UserKnowledgeStore:
        if self._store is None:
            raise KnowledgeStoreError("Your knowledge base could not be opened (see the log file).")
        return self._store

    @property
    def knowledge(self) -> KnowledgeBase:
        if self._knowledge is None:
            builtin = default_kb()
            if self.team is not None and self.team.entries:  # shared knowledge sits between built-in and your own
                builtin = builtin.with_entries(self.team.entries)
            self._knowledge = self._store.knowledge_base(builtin) if self._store is not None else builtin
        return self._knowledge

    def close(self) -> None:
        if self._store is not None:
            self._store.close()

    # ---- explaining ----------------------------------------------------------------------------------------------
    def explain(self, text: str) -> list[Finding]:
        """Findings for a line or record; for Windows events nobody knows, an honest 'not in the KB yet' card."""
        findings = [self._with_runbook(f) for f in self.knowledge.explain(text)]
        event = EVENT_LINE.match(text)
        if event is not None and not any(f.kind == "event" for f in findings):
            findings.insert(0, Finding(
                "unknown",
                f"{event['provider']} {event['event_id']}",
                "Not in the knowledge base yet",
                "LogLens has no curated explanation for this event source/ID. The message is what the program wrote "
                "— use 'Search web' or 'Explain with AI', then 'Add to knowledge base' to keep what you learn.",
                source="LogLens",
            ))  # fmt: skip
        return findings

    # ---- team knowledge folder -----------------------------------------------------------------------------------
    @property
    def team_dir(self) -> str:
        return str(self.team.folder) if self.team is not None else ""

    def set_team_dir(self, path: str, *, announce: bool = True) -> TeamKnowledge | None:
        """Use ``path`` as the team knowledge folder ("" turns it off) and (re)read it."""
        self.team = load_folder(path) if path.strip() else None
        self._knowledge = None
        if announce:
            self.teamChanged.emit(path.strip())
        self.changed.emit()
        return self.team

    def reload_team(self) -> TeamKnowledge | None:
        return self.set_team_dir(self.team_dir, announce=False) if self.team is not None else None

    def pull_team(self) -> tuple[bool, str]:
        """``git pull`` in the team folder, then re-read it."""
        if self.team is None:
            return False, "No team knowledge folder is set."
        ok, message = git_pull(self.team.folder)
        self.reload_team()
        return ok, message

    @property
    def team_is_git(self) -> bool:
        return self.team is not None and is_git_repo(self.team.folder)

    def _with_runbook(self, finding: Finding) -> Finding:
        """A finding whose ``runbook`` is a safe link (web address, or a file inside the team folder) or empty."""
        if not finding.runbook:
            return finding
        target = runbook_target(finding.runbook, self.team.folder if self.team is not None else None)
        return replace(finding, runbook=target[1] if target else "")

    def lookup_event(self, provider: str, event_id: int) -> list[KBEntry]:
        return self.knowledge.lookup_event(provider, event_id)

    def note_unexplained(self, text: str, level: str, findings: list[Finding]) -> None:
        """Queue an error/warning the user looked at that nothing explained, for later review."""
        if self._store is None or level not in QUEUE_LEVELS or any(f.kind != "unknown" for f in findings):
            return
        try:
            self._store.record_unknown(text.split("\n", 1)[0])
        except (KnowledgeStoreError, ValueError) as exc:
            log.debug("could not queue unexplained line: %s", exc)
            return
        self.queueChanged.emit()

    # ---- editing -------------------------------------------------------------------------------------------------
    def add(self, entry: KBEntry, *, resolves: str | None = None) -> KBEntry:
        """Save a new entry (and take its line out of the queue when ``resolves`` names a queued signature)."""
        if resolves:
            self.store.resolve(resolves, entry)
            saved = self.store.get(entry.id) or entry
            self.queueChanged.emit()
        else:
            saved = self.store.add(entry)
        self._changed()
        return saved

    def update(self, entry: KBEntry) -> KBEntry:
        saved = self.store.update(entry)
        self._changed()
        return saved

    def delete(self, entry_id: str) -> None:
        if self.store.delete(entry_id):
            self._changed()

    def import_pack(self, text: str, *, overwrite: bool = False) -> ImportResult:
        result = self.store.import_pack(text, overwrite=overwrite)
        if result.added or result.updated:
            self._changed()
        return result

    def unknowns(self, *, include_dismissed: bool = False) -> list[UnknownSignature]:
        return self.store.unknowns(include_dismissed=include_dismissed) if self._store is not None else []

    def dismiss(self, signature: str, *, dismissed: bool = True) -> None:
        if self.store.dismiss(signature, dismissed=dismissed):
            self.queueChanged.emit()

    def _changed(self) -> None:
        self._knowledge = None
        self.changed.emit()
