"""A very big JSON / XML payload must not be printed in the Inspector: it opens collapsed, on demand."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest
from PySide6.QtWidgets import QApplication

from loglens.core.payload_tree import COLLAPSE_CHARS
from loglens.core.search import shutdown_pool
from loglens.settings import Settings
from loglens.ui.main_window import MainWindow

TS = "2026-11-03 08:40:16,181"
BIG = {
    "ok": True,
    "users": [
        {"id": f"U{i:05d}", "name": f"user-{i}", "profile": {"title": "t" * 40, "tz": "UTC"}} for i in range(700)
    ],
}
SMALL = {"ok": True, "users": [{"id": "U1", "name": "ada"}]}


@pytest.fixture
def inspector(qapp: QApplication, wait_for: Callable[..., None], tmp_path: Path):
    lines = [
        f"{TS} [22] TRACE Client - Received JSON: [0000000C] ",
        json.dumps(BIG),  # the body is a continuation line, as in a real log
        f"{TS} [22] TRACE Client - Received JSON: [0000000D] ",
        json.dumps(SMALL),
        f"{TS} [22] TRACE Client - Received XML: [0000000E] ",
        "<r>" + "".join(f'<i n="{i}">value {i}</i>' for i in range(1500)) + "</r>",
    ]
    log = tmp_path / "calls.log"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    win = MainWindow(Settings())
    win.resize(1400, 900)
    win.show()
    win.open_file(str(log))
    tab = win.current_tab()
    assert tab is not None
    wait_for(lambda: not tab.document.is_indexing and tab.document.records.multi_line)
    yield tab, wait_for
    win.close()
    shutdown_pool()


def open_rows(structure) -> list[str]:
    tree = structure.tree.tree
    found: list[str] = []

    def walk(item) -> None:
        if item.isExpanded() and item.childCount():
            found.append(item.text(0))
        for i in range(item.childCount()):
            walk(item.child(i))

    for i in range(tree.topLevelItemCount()):
        walk(tree.topLevelItem(i))
    return found


def test_a_big_json_is_not_printed_and_opens_collapsed(inspector) -> None:
    tab, wait_for = inspector
    assert len(json.dumps(BIG)) > COLLAPSE_CHARS
    tab.main_view.go_to_row(0)  # the record with the big body
    inspector_ = tab.inspector
    plain = inspector_.details.toPlainText()
    assert "collapsed" in plain and len(plain) < 3000  # a one-line card, not 40,000 characters of pretty JSON
    assert "user-699" not in plain  # none of the body is printed
    structure = inspector_.structure
    assert structure.isVisible()
    wait_for(lambda: structure.tree.parsed is not None and structure.tree.parsed.ok)
    assert structure.tree.parsed.size_chars > COLLAPSE_CHARS
    assert open_rows(structure) == ["root"]  # only the first level is visible: everything else is collapsed
    assert "large payload" in structure.tree.info.text()
    assert inspector_.raw.toPlainText().count("user-699") == 1  # the raw tab still has the whole text
    structure.tree.expand_button.click()  # ... and the user can open it up
    assert "users" in open_rows(structure)


def test_a_small_json_is_still_printed_as_before(inspector) -> None:
    tab, _wait_for = inspector
    tab.main_view.go_to_row(2)
    inspector_ = tab.inspector
    plain = inspector_.details.toPlainText()
    assert '"name": "ada"' in plain and "collapsed" not in plain
    assert not inspector_.structure.isVisible()


def test_a_big_xml_also_opens_collapsed(inspector) -> None:
    tab, wait_for = inspector
    tab.main_view.go_to_row(4)
    structure = tab.inspector.structure
    assert "collapsed" in tab.inspector.details.toPlainText()
    wait_for(lambda: structure.tree.parsed is not None and structure.tree.parsed.ok)
    assert structure.tree.parsed.kind == "xml" and open_rows(structure) == ["<r>"]


def test_selecting_another_line_hides_the_structure_again(inspector) -> None:
    tab, wait_for = inspector
    tab.main_view.go_to_row(0)
    wait_for(lambda: tab.inspector.structure.tree.parsed is not None)
    tab.main_view.go_to_row(2)
    assert not tab.inspector.structure.isVisible()
    assert tab.inspector.structure.tree.parsed is None
