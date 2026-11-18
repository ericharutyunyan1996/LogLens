"""Knowledge base manager: your entries (search, edit, packs), lines nothing explained yet, and the built-in entries."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..core.kb import (
    ORIGIN_USER,
    KBEntry,
    KnowledgeStoreError,
    compile_pattern,
    default_kb,
    normalize_provider,
    pattern_for,
    signature_of,
    unique_entry_id,
)
from ..services.knowledge_service import KnowledgeService
from .kb_entry_dialog import KBEntryDialog

ID_ROLE = Qt.ItemDataRole.UserRole
PACK_FILTER = "Knowledge packs (*.toml);;All files (*)"


def describe_match(entry: KBEntry) -> str:
    if entry.providers:
        return f"{', '.join(entry.providers)} · event {', '.join(str(i) for i in entry.event_ids)}"
    if entry.codes:
        return ", ".join(f"0x{code:08X}" for code in entry.codes)
    return " | ".join(p.pattern for p in entry.patterns)[:120]


def _tree(headers: list[str], parent: QWidget) -> QTreeWidget:
    tree = QTreeWidget(parent)
    tree.setHeaderLabels(headers)
    tree.setRootIsDecorated(False)
    tree.setUniformRowHeights(True)
    tree.header().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
    tree.header().setStretchLastSection(True)
    return tree


def new_entry_for(line: str, service: KnowledgeService) -> tuple[KBEntry, str]:
    """A draft entry matching ``line`` (event source + id, or a pattern generalised from it), plus the test line.

    The draft is not validated: the user still writes the explanation, and the editor validates on save.
    """
    signature = signature_of(line) if line else None
    title = signature.template[:80] if signature is not None else ""
    entry = KBEntry(
        id=unique_entry_id(title or "entry", origin=ORIGIN_USER, taken=service.store.ids()),
        title=title,
        explanation="",
        origin=ORIGIN_USER,
    )
    if signature is None:
        return entry, line
    if signature.provider and signature.event_id is not None:
        return replace(
            entry, providers=(normalize_provider(signature.provider),), event_ids=(signature.event_id,)
        ), line
    try:
        return replace(entry, patterns=(compile_pattern(pattern_for(signature)),)), line
    except ValueError:  # too little fixed text to generalise: the user writes the pattern
        return entry, line


class KnowledgeDialog(QDialog):
    def __init__(self, service: KnowledgeService, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Knowledge base")
        self.resize(980, 600)
        self.service = service
        tabs = QTabWidget(self)
        tabs.addTab(self._entries_page(), "Your entries")
        tabs.addTab(self._queue_page(), "Not explained yet")
        tabs.addTab(self._builtin_page(), f"Built-in ({len(default_kb().entries)})")
        layout = QVBoxLayout(self)
        layout.addWidget(tabs)
        self.refresh()

    # ---- pages ---------------------------------------------------------------------------------------------------
    def _entries_page(self) -> QWidget:
        page = QWidget(self)
        self.search = QLineEdit(page)
        self.search.setPlaceholderText("Search your entries…")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self.refresh_entries)
        self.entries = _tree(["Title", "Matches", "Importance", "Origin"], page)
        self.entries.itemDoubleClicked.connect(lambda _i, _c: self._edit())
        row = QHBoxLayout()
        for text, slot in (("New…", self._new), ("Edit…", self._edit), ("Delete", self._delete),
                           ("Import pack…", self._import), ("Export pack…", self._export)):  # fmt: skip
            button = QPushButton(text, page)
            button.clicked.connect(slot)
            row.addWidget(button)
        row.addStretch(1)
        note = QLabel(
            "Your entries are shown in the Inspector next to the built-in ones (yours first). Packs are TOML files "
            "you can share with your team.",
            page,
        )
        note.setObjectName("dialogNote")
        note.setWordWrap(True)
        layout = QVBoxLayout(page)
        layout.addWidget(self.search)
        layout.addWidget(self.entries, 1)
        layout.addLayout(row)
        layout.addWidget(note)
        return page

    def _queue_page(self) -> QWidget:
        page = QWidget(self)
        self.queue = _tree(["Seen", "Last seen", "Example line"], page)
        self.queue.itemDoubleClicked.connect(lambda _i, _c: self._explain_unknown())
        self.show_dismissed = QCheckBox("Show dismissed", page)
        self.show_dismissed.toggled.connect(self.refresh_queue)
        row = QHBoxLayout()
        add = QPushButton("Add entry…", page)
        add.clicked.connect(self._explain_unknown)
        row.addWidget(add)
        self.dismiss_button = QPushButton("Dismiss", page)  # "Restore" when the selected line is a dismissed one
        self.dismiss_button.clicked.connect(self._dismiss)
        row.addWidget(self.dismiss_button)
        self.queue.currentItemChanged.connect(lambda _current, _previous: self._update_dismiss_button())
        row.addStretch(1)
        row.addWidget(self.show_dismissed)
        note = QLabel(
            "Errors and warnings you inspected that nothing in the knowledge base explained. Explain them once "
            "(yourself or with the AI) and LogLens recognises them from then on.",
            page,
        )
        note.setObjectName("dialogNote")
        note.setWordWrap(True)
        layout = QVBoxLayout(page)
        layout.addWidget(note)
        layout.addWidget(self.queue, 1)
        layout.addLayout(row)
        return page

    def _builtin_page(self) -> QWidget:
        page = QWidget(self)
        search = QLineEdit(page)
        search.setPlaceholderText("Search the built-in knowledge…")
        search.setClearButtonEnabled(True)
        tree = _tree(["Title", "Matches", "Importance"], page)
        entries = sorted(default_kb().entries, key=lambda e: e.title.lower())

        def fill(text: str = "") -> None:
            needle = text.lower()
            tree.clear()
            for entry in entries:
                haystack = f"{entry.title} {entry.explanation} {describe_match(entry)}".lower()
                if needle in haystack:
                    item = QTreeWidgetItem([entry.title, describe_match(entry), entry.noise])
                    item.setToolTip(0, entry.explanation)
                    tree.addTopLevelItem(item)

        search.textChanged.connect(fill)
        fill()
        layout = QVBoxLayout(page)
        layout.addWidget(search)
        layout.addWidget(tree, 1)
        return page

    # ---- data ----------------------------------------------------------------------------------------------------
    def refresh(self) -> None:
        self.refresh_entries()
        self.refresh_queue()

    def refresh_entries(self) -> None:
        self.entries.clear()
        if not self.service.available:
            return
        text = self.search.text().strip()
        found = self.service.store.search(text) if text else self.service.store.all()
        for entry in found:
            item = QTreeWidgetItem([entry.title, describe_match(entry), entry.noise, entry.origin])
            item.setData(0, ID_ROLE, entry.id)
            item.setToolTip(0, entry.explanation)
            self.entries.addTopLevelItem(item)

    def refresh_queue(self) -> None:
        self.queue.clear()
        for unknown in self.service.unknowns(include_dismissed=self.show_dismissed.isChecked()):
            sample = unknown.sample.replace("\n", " ")
            item = QTreeWidgetItem([f"{unknown.count:,}×", f"{unknown.last_seen:%Y-%m-%d %H:%M}", sample[:300]])
            item.setData(0, ID_ROLE, unknown.signature)
            item.setData(1, ID_ROLE, unknown.sample)
            item.setData(2, ID_ROLE, unknown.dismissed)
            item.setToolTip(2, sample)
            if unknown.dismissed:
                item.setText(0, f"{item.text(0)} (dismissed)")
                font = item.font(2)
                font.setItalic(True)
                for column in range(item.columnCount()):
                    item.setFont(column, font)
            self.queue.addTopLevelItem(item)
        self._update_dismiss_button()

    # ---- actions -------------------------------------------------------------------------------------------------
    def _selected_entry(self) -> KBEntry | None:
        item = self.entries.currentItem()
        return self.service.store.get(str(item.data(0, ID_ROLE))) if item is not None else None

    def _new(self) -> None:
        self.edit_new("", resolves=None)

    def edit_new(self, line: str, *, resolves: str | None) -> bool:
        """Open the editor for a new entry matching ``line``; True when saved."""
        try:
            entry, sample = new_entry_for(line, self.service)
        except KnowledgeStoreError as exc:
            QMessageBox.warning(self, "Knowledge base", str(exc))
            return False
        dialog = KBEntryDialog(entry, sample, title="New knowledge base entry", parent=self)
        if not dialog.exec():
            return False
        try:
            self.service.add(dialog.entry(), resolves=resolves)
        except (KnowledgeStoreError, ValueError) as exc:
            QMessageBox.warning(self, "Knowledge base", str(exc))
            return False
        self.refresh()
        return True

    def _edit(self) -> None:
        entry = self._selected_entry()
        if entry is None:
            return
        dialog = KBEntryDialog(entry, title="Edit knowledge base entry", parent=self)
        if dialog.exec():
            try:
                self.service.update(dialog.entry())
            except (KnowledgeStoreError, ValueError) as exc:
                QMessageBox.warning(self, "Knowledge base", str(exc))
            self.refresh_entries()

    def _delete(self) -> None:
        entry = self._selected_entry()
        if entry is not None and QMessageBox.question(self, "Knowledge base", f"Delete “{entry.title}”?") == (
            QMessageBox.StandardButton.Yes
        ):
            self.service.delete(entry.id)
            self.refresh_entries()

    def _import(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Import knowledge pack", "", PACK_FILTER)
        if not path:
            return
        try:
            result = self.service.import_pack(Path(path).read_text(encoding="utf-8"))
        except (OSError, KnowledgeStoreError, ValueError) as exc:
            QMessageBox.warning(self, "Import knowledge pack", str(exc))
            return
        lines = [f"Added {len(result.added)}, updated {len(result.updated)}, skipped {len(result.skipped)}."]
        lines += list(result.errors[:10])
        QMessageBox.information(self, "Import knowledge pack", "\n".join(lines))
        self.refresh_entries()

    def _export(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export knowledge pack", "my-knowledge.toml", PACK_FILTER)
        if path:
            try:
                self.service.store.export_pack(path)
            except (OSError, KnowledgeStoreError) as exc:
                QMessageBox.warning(self, "Export knowledge pack", str(exc))

    def _explain_unknown(self) -> None:
        item = self.queue.currentItem()
        if item is not None:
            self.edit_new(str(item.data(1, ID_ROLE)), resolves=str(item.data(0, ID_ROLE)))

    @staticmethod
    def _is_dismissed(item: QTreeWidgetItem | None) -> bool:
        return item is not None and bool(item.data(2, ID_ROLE))

    def _update_dismiss_button(self) -> None:
        """The button says what it will do to the selected line: Dismiss it, or Restore a dismissed one."""
        item = self.queue.currentItem()
        self.dismiss_button.setEnabled(item is not None)
        if self._is_dismissed(item):
            self.dismiss_button.setText("Restore")
            self.dismiss_button.setToolTip("Put the selected dismissed line back on the list")
        else:
            self.dismiss_button.setText("Dismiss")
            self.dismiss_button.setToolTip("Hide the selected line from this list (tick “Show dismissed” to undo)")

    def _dismiss(self) -> None:
        """Dismiss the selected line, or restore it when it is a dismissed one."""
        item = self.queue.currentItem()
        if item is not None:
            self.service.dismiss(str(item.data(0, ID_ROLE)), dismissed=not self._is_dismissed(item))
            self.refresh_queue()
