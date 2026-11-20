"""The JSON / XML tree viewer driven the way a user drives it: by clicking its buttons."""

from __future__ import annotations

import json

from PySide6.QtWidgets import QApplication, QTreeWidgetItem

from loglens.core.payload_tree import parse
from loglens.ui.payload_view import PayloadTreeView


def open_items(view: PayloadTreeView) -> list[str]:
    """Keys of every expanded item that has real children."""
    found: list[str] = []

    def walk(item: QTreeWidgetItem) -> None:
        if item.isExpanded() and item.childCount():
            found.append(item.text(0))
        for i in range(item.childCount()):
            walk(item.child(i))

    for i in range(view.tree.topLevelItemCount()):
        walk(view.tree.topLevelItem(i))
    return found


NESTED = {"a": {"b": {"c": {"d": {"e": [1, {"f": "deep"}]}}}}, "x": {"y": {"z": 1}}}


def test_expand_button_opens_the_whole_small_payload_and_collapse_closes_it(qapp: QApplication) -> None:
    view = PayloadTreeView()
    view.set_parsed(parse(json.dumps(NESTED)), nodes=5_000)  # pretend it is big: it opens collapsed
    assert open_items(view) == ["root"]  # only the root is open

    view.expand_button.click()  # the real button, not the method
    assert {"root", "a", "b", "c", "d", "e", "x", "y"} <= set(open_items(view))  # every level, however deep

    view.collapse_button.click()
    assert open_items(view) == ["root"]  # closed again (the root stays open)
    view.expand_button.click()  # ... and Expand works again, as many times as needed
    assert "e" in open_items(view)


def test_expand_button_on_a_huge_payload_opens_a_bounded_part_and_says_so(qapp: QApplication) -> None:
    view = PayloadTreeView()
    big = {f"group{i}": {f"item{j}": {"v": j} for j in range(50)} for i in range(200)}  # ~20,000 nodes
    view.set_parsed(parse(json.dumps(big)))
    view.collapse_button.click()
    view.expand_button.click()
    opened = len(open_items(view))
    assert 1 < opened < 200 + 1  # shallow levels first, but not the whole 20,000-node tree
    assert "expanded" in view.hit_label.text() and "on demand" in view.hit_label.text()


def test_expand_works_for_xml_too(qapp: QApplication) -> None:
    view = PayloadTreeView()
    view.set_parsed(parse("<a><b><c><d>deep</d></c></b></a>"), nodes=5_000)
    view.expand_button.click()
    assert {"<a>", "<b>", "<c>"} <= set(open_items(view))
