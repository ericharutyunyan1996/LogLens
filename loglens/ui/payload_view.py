"""Viewers for JSON / XML payloads and for a request with its response.

``PayloadTreeView`` shows a parsed payload as an expandable tree that is filled lazily (a page of children at a time,
only for what the user opens), with search, copy of the raw text / the formatted text / one value, and a note whenever
the structured view is limited. ``PayloadPane`` pairs it with the exact raw text, so nothing is ever lost or replaced.
``RequestResponseView`` puts a request and its response side by side, each with its own payloads.

Heavy work (finding and parsing payloads, searching) runs on the thread pool; the UI thread only builds the few tree
items that are visible.
"""

from __future__ import annotations

import html
import json
from collections import deque
from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QObject, QRunnable, Qt, QThreadPool, QTimer, Signal
from PySide6.QtGui import QColor, QFont, QFontDatabase, QGuiApplication
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QPlainTextEdit,
    QSplitter,
    QStackedWidget,
    QTabWidget,
    QToolButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..core.http import Transaction
from ..core.payload_tree import (
    AUTO_EXPAND_NODES,
    COLLAPSE_CHARS,
    PAGE_SIZE,
    Node,
    ParsedPayload,
    PayloadSlice,
    find_malformed,
    find_payloads,
    parse,
)

NODE_ROLE = Qt.ItemDataRole.UserRole
MORE_ROLE = Qt.ItemDataRole.UserRole + 1
PLACEHOLDER = "…"
AUTO_EXPAND_DEPTH = 3
MAX_VIEW_LINES = 200_000  # lines of one record shown in a request/response pane (the rest is announced, not dropped)
LAZY_RAW_CHARS = 5_000_000  # a raw text this large is loaded into its tab when the tab is first opened
RELATED_LINES = 60  # related (header / trace) lines appended to a request


def _child(item: QTreeWidgetItem, index: int) -> QTreeWidgetItem:
    child = item.child(index)
    assert child is not None
    return child


def _top(tree: QTreeWidget, index: int) -> QTreeWidgetItem:
    item = tree.topLevelItem(index)
    assert item is not None
    return item


# ---- background helper -----------------------------------------------------------------------------------------------
class _Signals(QObject):
    done = Signal(object, object)  # token, result


class _Job(QRunnable):
    def __init__(self, fn: Callable[[], object], token: object, signals: _Signals) -> None:
        super().__init__()
        self._fn, self._token, self._signals = fn, token, signals

    def run(self) -> None:
        try:
            result: object = self._fn()
        except Exception as exc:  # noqa: BLE001 - a viewer job must never take the app down
            result = exc
        self._signals.done.emit(self._token, result)


class Background(QObject):
    """Run a function on the thread pool; only the newest request's result is delivered (stale ones are dropped)."""

    def __init__(self, parent: QObject, deliver: Callable[[object], None]) -> None:
        super().__init__(parent)
        self._deliver = deliver
        self._current: object = None
        self._signals = _Signals(self)
        self._signals.done.connect(self._on_done)

    def start(self, fn: Callable[[], object]) -> None:
        self._current = token = object()
        QThreadPool.globalInstance().start(_Job(fn, token, self._signals))

    def cancel(self) -> None:
        self._current = None

    def _on_done(self, token: object, result: object) -> None:
        if token is self._current:
            self._deliver(result)


# ---- colours ---------------------------------------------------------------------------------------------------------
def _is_dark(widget: QWidget) -> bool:
    return widget.palette().base().color().lightness() < 128


def kind_color(widget: QWidget, kind: str) -> QColor | None:
    dark = _is_dark(widget)
    table = {
        "string": "#7EC27E" if dark else "#2E7D32",
        "number": "#6FB1FC" if dark else "#1565C0",
        "boolean": "#C792EA" if dark else "#7B1FA2",
        "null": "#8A8A8A",
        "attribute": "#E5B567" if dark else "#9A6700",
        "text": "#7EC27E" if dark else "#2E7D32",
        "element": "#6FB1FC" if dark else "#1565C0",
    }
    return QColor(table[kind]) if kind in table else None


# ---- the tree --------------------------------------------------------------------------------------------------------
class PayloadTreeView(QWidget):
    """An expandable, searchable tree of one parsed JSON / XML payload."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._parsed: ParsedPayload | None = None
        self._hits: list[tuple[int, ...]] = []
        self._hit = -1
        self.info = QLabel(self)
        self.info.setObjectName("dialogNote")
        self.info.setWordWrap(True)
        self.search = QLineEdit(self)
        self.search.setPlaceholderText("Search keys and values…")
        self.search.setClearButtonEnabled(True)
        self.hit_label = QLabel(self)
        self.prev_hit = self._button("◀", "Previous match")
        self.next_hit = self._button("▶", "Next match")
        self.expand_button = self._button(
            "Expand", "Expand as much as is practical (large payloads: the first few thousand nodes)"
        )
        self.collapse_button = self._button("Collapse", "Collapse everything")
        self.copy_raw = self._button("Copy raw", "Copy the exact original text")
        self.copy_formatted = self._button("Copy formatted", "Copy the indented text")
        self.copy_value = self._button("Copy value", "Copy the selected key's value (or whole subtree)")
        bar = QHBoxLayout()
        for widget in (
            self.search,
            self.prev_hit,
            self.next_hit,
            self.hit_label,
            self.expand_button,
            self.collapse_button,
        ):
            bar.addWidget(widget)
        bar.addStretch(1)
        for widget in (self.copy_raw, self.copy_formatted, self.copy_value):
            bar.addWidget(widget)
        self.tree = QTreeWidget(self)
        self.tree.setHeaderLabels(["Key", "Value", "Type"])
        self.tree.setUniformRowHeights(True)
        self.tree.setAlternatingRowColors(True)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.tree.setColumnWidth(0, 260)
        self.tree.setColumnWidth(1, 520)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.info)
        layout.addLayout(bar)
        layout.addWidget(self.tree, 1)
        self._searcher = Background(self, self._on_search_done)
        self._debounce = QTimer(self)
        self._debounce.setSingleShot(True)
        self._debounce.setInterval(300)
        self._debounce.timeout.connect(self._run_search)
        self.search.textChanged.connect(lambda _t: self._debounce.start())
        self.search.returnPressed.connect(lambda: self._step(1))
        self.prev_hit.clicked.connect(lambda: self._step(-1))
        self.next_hit.clicked.connect(lambda: self._step(1))
        self.expand_button.clicked.connect(lambda _checked=False: self.expand_all())
        self.collapse_button.clicked.connect(lambda _checked=False: self.collapse_all())
        self.copy_raw.clicked.connect(lambda: self._copy(self._parsed.raw if self._parsed else ""))
        self.copy_formatted.clicked.connect(lambda: self._copy(self._parsed.formatted() if self._parsed else ""))
        self.copy_value.clicked.connect(self._copy_selected)
        self.tree.itemExpanded.connect(self._on_expanded)
        self.tree.itemDoubleClicked.connect(self._on_double_click)
        self.tree.customContextMenuRequested.connect(self._context_menu)

    def _button(self, text: str, tip: str) -> QToolButton:
        button = QToolButton(self)
        button.setText(text)
        button.setToolTip(tip)
        return button

    # -- content --------------------------------------------------------------------------------------------------
    @property
    def parsed(self) -> ParsedPayload | None:
        return self._parsed

    def set_parsed(self, parsed: ParsedPayload | None, *, nodes: int | None = None) -> None:
        self._searcher.cancel()
        self.tree.clear()
        self._hits, self._hit = [], -1
        self.hit_label.clear()
        self._parsed = parsed
        has_tree = parsed is not None and parsed.ok
        for widget in (
            self.search,
            self.prev_hit,
            self.next_hit,
            self.expand_button,
            self.collapse_button,
            self.copy_formatted,
            self.copy_value,
        ):
            widget.setEnabled(has_tree)
        self.copy_raw.setEnabled(parsed is not None)
        if parsed is None:
            self.info.setText("")
            return
        size = f"{parsed.size_chars:,} characters"
        if not parsed.ok or parsed.root is None:
            problem = f"<span style='color:#c0504d'>{html.escape(parsed.error)}</span>"
            self.info.setText(
                f"<b>{parsed.kind.upper()}</b> · {size} · {problem} The original text is unchanged (Raw tab)."
            )
            return
        counted = nodes if nodes is not None else parsed.count_nodes(AUTO_EXPAND_NODES + 1)
        big = counted > AUTO_EXPAND_NODES or parsed.size_chars > COLLAPSE_CHARS
        note = "large payload: opened collapsed, expand what you need" if big else f"{counted:,} nodes"
        self.info.setText(f"<b>{parsed.kind.upper()}</b> · {size} · {note}")
        root = self._make_item(parsed.root, ())
        self.tree.addTopLevelItem(root)
        root.setExpanded(True)
        if not big:
            self.expand_levels()

    def _make_item(self, node: Node, path: tuple[int, ...]) -> QTreeWidgetItem:
        item = QTreeWidgetItem([node.key, node.preview, node.kind])
        item.setData(0, NODE_ROLE, (node, path))
        color = kind_color(self, node.kind)
        if color is not None:
            item.setForeground(1, color)
        if node.kind in {"string", "text"}:
            item.setToolTip(1, str(node.value)[:2000])
        if node.expandable:
            item.addChild(QTreeWidgetItem([PLACEHOLDER]))
        return item

    def _load(self, item: QTreeWidgetItem, start: int = 0) -> None:
        """Fill ``item`` with one page of its children (starting at ``start``) and a "more" row if there are more."""
        assert self._parsed is not None
        node, path = item.data(0, NODE_ROLE)
        kids = self._parsed.children(node, start, PAGE_SIZE)
        for offset, kid in enumerate(kids):
            item.addChild(self._make_item(kid, (*path, start + offset)))
        remaining = node.size - (start + len(kids))
        if remaining > 0:
            more = QTreeWidgetItem([f"… {remaining:,} more", "double-click to load the next page", ""])
            more.setData(0, MORE_ROLE, (item, start + len(kids)))
            item.addChild(more)

    def _on_expanded(self, item: QTreeWidgetItem) -> None:
        if (
            item.childCount() == 1
            and _child(item, 0).text(0) == PLACEHOLDER
            and _child(item, 0).data(0, NODE_ROLE) is None
        ):
            item.takeChild(0)
            self._load(item)

    def _on_double_click(self, item: QTreeWidgetItem, _column: int) -> None:
        more = item.data(0, MORE_ROLE)
        if more is None:
            return
        parent, start = more
        parent.removeChild(item)
        self._load_more(parent, start)

    def _load_more(self, parent: QTreeWidgetItem, start: int) -> None:
        assert self._parsed is not None
        node, path = parent.data(0, NODE_ROLE)
        kids = self._parsed.children(node, start, PAGE_SIZE)
        for offset, kid in enumerate(kids):
            parent.addChild(self._make_item(kid, (*path, start + offset)))
        remaining = node.size - (start + len(kids))
        if remaining > 0:
            more = QTreeWidgetItem([f"… {remaining:,} more", "double-click to load the next page", ""])
            more.setData(0, MORE_ROLE, (parent, start + len(kids)))
            parent.addChild(more)

    def expand_levels(self, depth: int = AUTO_EXPAND_DEPTH) -> None:
        """Open the first ``depth`` levels (only pages already cheap to build: one page per container)."""
        budget = [AUTO_EXPAND_NODES]

        def walk(item: QTreeWidgetItem, level: int) -> None:
            if level >= depth or budget[0] <= 0:
                return
            item.setExpanded(True)  # lazy: loads the first page
            for i in range(item.childCount()):
                budget[0] -= 1
                child = _child(item, i)
                if child.data(0, NODE_ROLE) is not None:
                    walk(child, level + 1)

        for i in range(self.tree.topLevelItemCount()):
            walk(_top(self.tree, i), 0)

    def expand_all(self, budget: int = AUTO_EXPAND_NODES) -> None:
        """Expand level by level, shallow levels first, until ``budget`` rows are open. A payload that is bigger than
        that is not expanded blindly (it would freeze the UI): the rest opens on demand, and the label says so."""
        queue: deque[QTreeWidgetItem] = deque(_top(self.tree, i) for i in range(self.tree.topLevelItemCount()))
        opened = 0
        cut = False
        while queue:
            item = queue.popleft()
            if item.data(0, NODE_ROLE) is None or item.childCount() == 0:
                continue  # a "more" row, a placeholder or a leaf
            if opened >= budget:
                cut = True
                break
            item.setExpanded(True)  # lazy: loads the first page of children
            opened += item.childCount()
            queue.extend(_child(item, i) for i in range(item.childCount()))
        self.hit_label.setText(f"expanded {opened:,} rows; open the rest on demand" if cut else "")

    def collapse_all(self) -> None:
        self.tree.collapseAll()
        if self.tree.topLevelItemCount():
            _top(self.tree, 0).setExpanded(True)  # keep the root open: a fully closed tree looks empty
        self.hit_label.clear()

    # -- search ---------------------------------------------------------------------------------------------------
    def _run_search(self) -> None:
        query = self.search.text()
        self._hits, self._hit = [], -1
        if self._parsed is None or not self._parsed.ok or not query:
            self.hit_label.clear()
            self._searcher.cancel()
            return
        parsed = self._parsed
        self.hit_label.setText("Searching…")
        self._searcher.start(lambda: parsed.search(query))

    def _on_search_done(self, result: object) -> None:
        if isinstance(result, Exception):
            self.hit_label.setText("Search failed")
            return
        self._hits = list(result)  # type: ignore[call-overload]
        if not self._hits:
            self.hit_label.setText("no match")
            return
        self._hit = 0
        self._show_hit()

    def _step(self, direction: int) -> None:
        if not self._hits:
            self._run_search()
            return
        self._hit = (self._hit + direction) % len(self._hits)
        self._show_hit()

    def _show_hit(self) -> None:
        capped = "+" if len(self._hits) >= 2000 else ""
        self.hit_label.setText(f"{self._hit + 1} / {len(self._hits)}{capped}")
        item = self.reveal(self._hits[self._hit])
        if item is not None:
            self.tree.setCurrentItem(item)
            self.tree.scrollToItem(item, QTreeWidget.ScrollHint.PositionAtCenter)

    def reveal(self, path: tuple[int, ...]) -> QTreeWidgetItem | None:
        """The item at ``path`` (child indices from the root), expanding ancestors and loading pages as needed."""
        if self._parsed is None or self.tree.topLevelItemCount() == 0:
            return None
        item = _top(self.tree, 0)
        for index in path:
            item.setExpanded(True)
            while True:
                loaded = sum(1 for i in range(item.childCount()) if _child(item, i).data(0, NODE_ROLE) is not None)
                if index < loaded:
                    break
                more = next(
                    (_child(item, i) for i in range(item.childCount()) if _child(item, i).data(0, MORE_ROLE)), None
                )
                if more is None:
                    return None
                _parent, start = more.data(0, MORE_ROLE)
                item.removeChild(more)
                self._load_more(item, start)
            item = _child(item, index)
        return item

    # -- copy -----------------------------------------------------------------------------------------------------
    @staticmethod
    def _copy(text: str) -> None:
        QGuiApplication.clipboard().setText(text)

    def _selected_node(self) -> tuple[Node, tuple[int, ...]] | None:
        item = self.tree.currentItem()
        return item.data(0, NODE_ROLE) if item is not None else None

    def value_text(self, node: Node) -> str:
        """Text of one node: a scalar as is, a container as its formatted subtree."""
        if node.kind in ("object", "array"):
            return json.dumps(node.value, indent=2, ensure_ascii=False)
        if node.kind == "element":
            return str(node.value.toprettyxml(indent="  "))
        return str(node.value)

    def _copy_selected(self) -> None:
        selected = self._selected_node()
        if selected is not None:
            self._copy(self.value_text(selected[0]))

    def key_path(self, item: QTreeWidgetItem) -> str:
        parts: list[str] = []
        current: QTreeWidgetItem | None = item
        while current is not None:
            parts.append(current.text(0))
            current = current.parent()
        parts.reverse()
        text = ""
        for part in parts[1:]:
            text += part if part.startswith("[") else f".{part}"
        return "$" + text

    def _context_menu(self, pos: Any) -> None:
        item = self.tree.itemAt(pos)
        if item is None or item.data(0, NODE_ROLE) is None:
            return
        node, _path = item.data(0, NODE_ROLE)
        menu = QMenu(self)
        menu.addAction("Copy value", lambda: self._copy(self.value_text(node)))
        menu.addAction("Copy key", lambda: self._copy(item.text(0)))
        menu.addAction("Copy path", lambda: self._copy(self.key_path(item)))
        menu.exec(self.tree.viewport().mapToGlobal(pos))


# ---- one side: raw text + structured view ---------------------------------------------------------------------------
class PayloadPane(QWidget):
    """The text of a request or a response: a Formatted tab (tree) when it holds JSON / XML, and the exact Raw text."""

    def __init__(self, title: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._text = ""
        self._slices: list[PayloadSlice] = []
        self._raw_loaded = False
        self.title = QLabel(f"<b>{title}</b>", self)
        self.note = QLabel(self)
        self.note.setWordWrap(True)
        self.note.setTextFormat(Qt.TextFormat.PlainText)
        self.note.setObjectName("dialogNote")
        self.choice = QComboBox(self)
        self.choice.hide()
        self.tabs = QTabWidget(self)
        self.tree = PayloadTreeView(self)
        self.message = QLabel(self)
        self.message.setWordWrap(True)
        self.message.setTextFormat(Qt.TextFormat.PlainText)
        self.message.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        self.stack = QStackedWidget(self)
        self.stack.addWidget(self.tree)
        self.stack.addWidget(self.message)
        self.raw = QPlainTextEdit(self)
        self.raw.setReadOnly(True)
        self.raw.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.raw.setUndoRedoEnabled(False)
        font = QFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.raw.setFont(font)
        self.tabs.addTab(self.stack, "Formatted")
        self.tabs.addTab(self.raw, "Raw")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        head = QHBoxLayout()
        head.addWidget(self.title)
        head.addStretch(1)
        head.addWidget(self.choice)
        layout.addLayout(head)
        layout.addWidget(self.note)
        layout.addWidget(self.tabs, 1)
        self._finder = Background(self, self._on_found)
        self._parser = Background(self, self._on_parsed)
        self.choice.currentIndexChanged.connect(self._show_slice)
        self.tabs.currentChanged.connect(self._on_tab)

    @property
    def text(self) -> str:
        return self._text

    def clear(self, message: str) -> None:
        """No text for this side (e.g. a request that was never answered)."""
        self._finder.cancel()
        self._parser.cancel()
        self._text, self._slices, self._raw_loaded = "", [], False
        self.choice.hide()
        self.note.setText(message)
        self.raw.clear()
        self.tree.set_parsed(None)
        self.message.setText("")
        self.stack.setCurrentWidget(self.message)

    def set_text(self, text: str, note: str = "") -> None:
        self._parser.cancel()
        self._text, self._slices, self._raw_loaded = text, [], False
        self.note.setText(note)
        self.choice.hide()
        self.tree.set_parsed(None)
        self.message.setText("Looking for JSON / XML …")
        self.stack.setCurrentWidget(self.message)
        if len(text) <= LAZY_RAW_CHARS or self.tabs.currentIndex() == 1:
            self._load_raw()
        else:
            self.raw.setPlainText(f"({len(text):,} characters: loaded when this tab is opened)")
        self._finder.start(lambda: find_payloads(text) or find_malformed(text))

    def _load_raw(self) -> None:
        if not self._raw_loaded:
            self.raw.setPlainText(self._text)
            self._raw_loaded = True

    def _on_tab(self, index: int) -> None:
        if index == 1:
            self._load_raw()

    def _on_found(self, result: object) -> None:
        if isinstance(result, Exception):
            self.message.setText(f"Could not look for JSON / XML: {result}")
            return
        self._slices = list(result)  # type: ignore[call-overload]
        if not self._slices:
            self.message.setText("No JSON or XML found in this text. The Raw tab shows it exactly as logged.")
            self.stack.setCurrentWidget(self.message)
            return
        self.choice.blockSignals(True)
        self.choice.clear()
        for number, piece in enumerate(self._slices, 1):
            self.choice.addItem(f"{piece.kind.upper()} #{number} ({len(piece.raw):,} chars)")
        self.choice.blockSignals(False)
        self.choice.setVisible(len(self._slices) > 1)
        self.choice.setCurrentIndex(0)
        self._show_slice()

    def _show_slice(self) -> None:
        index = self.choice.currentIndex()
        if not 0 <= index < len(self._slices):
            return
        piece = self._slices[index]
        self.message.setText(f"Parsing {len(piece.raw):,} characters …")
        self.stack.setCurrentWidget(self.message)
        self._parser.start(lambda: (parse(piece.raw, piece.kind), None))

    def _on_parsed(self, result: object) -> None:
        if isinstance(result, Exception):
            self.message.setText(f"Could not parse the payload: {result}")
            return
        parsed: ParsedPayload = result[0]  # type: ignore[index]
        self.tree.set_parsed(parsed)
        self.stack.setCurrentWidget(self.tree)


class PayloadStructure(QWidget):
    """The structured view of the JSON / XML in a text (the Inspector shows it for payloads too big to print).

    It finds and parses on the thread pool and opens collapsed (``PayloadTreeView`` decides by size), so a payload of
    any size appears at once as its top-level keys; everything else is expanded on demand."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._slices: list[PayloadSlice] = []
        self.title = QLabel("<b>Structure</b>", self)
        self.choice = QComboBox(self)
        self.choice.hide()
        self.message = QLabel(self)
        self.message.setTextFormat(Qt.TextFormat.PlainText)
        self.message.setWordWrap(True)
        self.tree = PayloadTreeView(self)
        head = QHBoxLayout()
        head.addWidget(self.title)
        head.addStretch(1)
        head.addWidget(self.choice)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 4, 6, 4)
        layout.addLayout(head)
        layout.addWidget(self.message)
        layout.addWidget(self.tree, 1)
        self._finder = Background(self, self._on_found)
        self._parser = Background(self, self._on_parsed)
        self.choice.currentIndexChanged.connect(self._show_slice)
        self.setVisible(False)

    def clear(self) -> None:
        self._finder.cancel()
        self._parser.cancel()
        self._slices = []
        self.tree.set_parsed(None)
        self.setVisible(False)

    def show_for(self, text: str) -> None:
        """Show the structure of the payloads in ``text`` (looked up in the background)."""
        self._parser.cancel()
        self._slices = []
        self.choice.hide()
        self.tree.set_parsed(None)
        self.message.setText("Looking for JSON / XML …")
        self.message.show()
        self.setVisible(True)
        self._finder.start(lambda: find_payloads(text) or find_malformed(text))

    def _on_found(self, result: object) -> None:
        if isinstance(result, Exception) or not result:
            self.message.setText("No JSON or XML could be read from this text; the Raw tab shows it exactly as logged.")
            return
        self._slices = sorted(result, key=lambda s: len(s.raw), reverse=True)  # type: ignore[call-overload]
        self.choice.blockSignals(True)
        self.choice.clear()
        for number, piece in enumerate(self._slices, 1):
            self.choice.addItem(f"{piece.kind.upper()} #{number} ({len(piece.raw):,} chars)")
        self.choice.blockSignals(False)
        self.choice.setVisible(len(self._slices) > 1)
        self.choice.setCurrentIndex(0)
        self._show_slice()

    def _show_slice(self) -> None:
        index = self.choice.currentIndex()
        if not 0 <= index < len(self._slices):
            return
        piece = self._slices[index]
        self.message.setText(f"Reading {len(piece.raw):,} characters …")
        self.message.show()
        self._parser.start(lambda: parse(piece.raw, piece.kind))

    def _on_parsed(self, result: object) -> None:
        if isinstance(result, Exception):
            self.message.setText(f"Could not read the payload: {result}")
            return
        self.message.hide()
        self.tree.set_parsed(result)  # type: ignore[arg-type]


# ---- a request with its response ---------------------------------------------------------------------------
def describe(tx: Transaction) -> str:
    """One line saying what was found and how sure we are."""
    what = html.escape(f"{tx.method} {tx.path}".strip()) or ("operation" if tx.form == "operation" else "call")
    if tx.orphan:
        return f"<b>{what}</b> · a response whose request could not be identified in this log"
    if not tx.paired:
        return f"<b>{what}</b> · <span style='color:#c0504d'>no response found in this log</span>"
    status = f" → {tx.status}" if tx.status is not None else ""
    took = f" · {tx.duration_ms:,.1f} ms" if tx.duration_ms is not None else ""
    ident = f" {html.escape(tx.key)}" if tx.key else ""
    how = {
        "key": f"matched by the shared id{ident}",
        "thread": f"matched by thread {html.escape(tx.thread) or '?'} only",
        "target": "matched by method + path only",
        "inline": "request and response on one line",
    }.get(tx.match, tx.match)
    flag = (
        ""
        if tx.confidence == "high"
        else f" · <span style='color:#c08a00'>⚠ uncertain ({tx.confidence} confidence)</span>"
    )
    return f"<b>{what}</b>{status}{took} · {how}{flag}"


class RequestResponseView(QWidget):
    """Request and response side by side (each with its own raw text and JSON / XML tree)."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.summary = QLabel(self)
        self.summary.setWordWrap(True)
        self.request = PayloadPane("Request", self)
        self.response = PayloadPane("Response", self)
        splitter = QSplitter(Qt.Orientation.Horizontal, self)
        splitter.addWidget(self.request)
        splitter.addWidget(self.response)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.summary)
        layout.addWidget(splitter, 1)
        self.clear()

    def clear(self) -> None:
        self.summary.setText("Select a request above to see it with its response.")
        self.request.clear("")
        self.response.clear("")

    def show_transaction(self, document: Any, tx: Transaction) -> None:
        self.summary.setText(describe(tx))
        if tx.orphan:
            self.request.clear("No request was found for this response (it may be outside this log).")
        else:
            text, note = request_text(document, tx)
            self.request.set_text(text, note)
        if tx.response_line is None:
            self.response.clear("No response was found for this request in this log.")
        else:
            text, note = record_text(document, tx.response_line)
            self.response.set_text(text, note)


def record_text(document: Any, line: int) -> tuple[str, str]:
    """The whole record containing ``line`` (header line + continuation lines: bodies, stack traces), uncapped up to
    MAX_VIEW_LINES lines. Returns (text, note) — the note says so when even that limit cut it."""
    start, end = document.record_range(line)
    total = end - start
    last = min(end, start + MAX_VIEW_LINES)
    source = document.source
    text = "\n".join(source.get_full_line(i) for i in range(start, last))
    note = f"Showing the first {MAX_VIEW_LINES:,} of {total:,} lines of this record." if last < end else ""
    return text, note


def request_text(document: Any, tx: Transaction) -> tuple[str, str]:
    """The request record plus the lines logged for the same call before its answer (headers, trace steps)."""
    text, note = record_text(document, tx.request_line)
    seen = set(range(*document.record_range(tx.request_line)))
    if tx.response_line is not None:
        seen |= set(range(*document.record_range(tx.response_line)))
    extra: list[str] = []
    for line in tx.all_lines:
        if line in seen or len(extra) >= RELATED_LINES:
            continue
        body, _ = record_text(document, line)
        extra.append(body)
        seen |= set(range(*document.record_range(line)))
    if extra:
        text += "\n\n— related lines of this call —\n" + "\n".join(extra)
    return text, note
