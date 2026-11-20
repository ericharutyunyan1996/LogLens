"""The Request / response page: every request listed, request and response shown together with their JSON / XML."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from loglens.core.search import shutdown_pool
from loglens.settings import Settings
from loglens.ui.main_window import MainWindow
from loglens.ui.payload_view import PAGE_SIZE

TS = "2026-11-13 10:00:0"
BIG = json.dumps({"rows": [{"id": i, "name": f"row-{i}"} for i in range(1_500)]})
LINES = [
    # key=value call (thread-paired), JSON request body on a continuation line, steps in between, JSON response body
    f"{TS}0,000 [1] TRACE Api - Request, Method=POST, Url=https://h/api/orders",
    '{"item":"A1","qty":2,"tags":["x","y"]}',
    f"{TS}0,050 [1] TRACE Api - Operation=Handler.Send, Status=200 (OK)",
    f"{TS}0,090 [1] TRACE Api - Response, Status=201 (Created), Method=POST, Url=https://h/api/orders",
    '{"id":77,"state":"created"}',
    # command markers with an id
    f"{TS}1,000 [2] DEBUG Bus - [START] GetUser [aa11bb22] " + '{"UserId":"u-1"}',
    f"{TS}1,004 [3] DEBUG Bus - [END] GetUser [aa11bb22]; Execution time=4ms",
    # verb + id, XML response on continuation lines
    f"{TS}2,000 [4] DEBUG Client - Requesting [00000001] https://h/soap",
    f"{TS}2,010 [4] TRACE Client - Received XML: [00000001] ",
    '<Envelope xmlns="urn:x"><Body><Ping id="9">pong</Ping></Body></Envelope>',
    # a request nobody answered, and an answer nobody asked for
    f"{TS}3,000 [5] INFO  Api - GET /api/lost requestId=rid00009",
    f"{TS}3,100 [6] INFO  Api - done status=200 requestId=rid00042",
    # malformed JSON body and a large body
    f"{TS}4,000 [7] DEBUG Client - Requesting [00000002] https://h/broken",
    f"{TS}4,010 [7] TRACE Client - Received JSON: [00000002] ",
    '{"a": [1, 2,, }',
    f"{TS}5,000 [8] DEBUG Client - Requesting [00000003] https://h/big",
    f"{TS}5,010 [8] TRACE Client - Received JSON: [00000003] ",
    BIG,
]


@pytest.fixture
def page(qapp: QApplication, wait_for: Callable[..., None], tmp_path: Path):
    log = tmp_path / "calls.log"
    log.write_text("\n".join(LINES) + "\n", encoding="utf-8")
    win = MainWindow(Settings())
    win.resize(1400, 900)
    win.show()
    win.open_file(str(log))
    tab = win.current_tab()
    assert tab is not None
    wait_for(lambda: not tab.document.is_indexing and tab.document.records.multi_line)
    win.analyze("transactions")
    analysis = win._analysis[id(tab)]
    transactions = analysis.pages["transactions"]
    transactions.run()
    wait_for(lambda: transactions.tree.topLevelItemCount() > 0)
    yield transactions, tab, win
    win.close()
    shutdown_pool()


def select(page, text: str):
    """Select the row whose path column holds ``text`` and return its transaction."""
    for i in range(page.tree.topLevelItemCount()):
        item = page.tree.topLevelItem(i)
        if text in item.text(3):
            page.tree.setCurrentItem(item)
            return page._shown[int(item.data(0, page.INDEX_ROLE))]
    raise AssertionError(f"no row for {text}")


def test_every_request_is_listed_with_its_kind_and_match(page) -> None:
    transactions, _tab, _win = page
    rows = {
        transactions.tree.topLevelItem(i).text(3): transactions.tree.topLevelItem(i)
        for i in range(transactions.tree.topLevelItemCount())
    }
    assert {"/api/orders", "GetUser", "/soap", "/api/lost", "/broken", "/big"} <= set(rows)
    assert rows["GetUser"].text(1) == "operation" and rows["GetUser"].text(7) == "key"
    assert rows["/api/orders"].text(7).startswith("thread") and "⚠" in rows["/api/orders"].text(7)  # uncertain: no id
    assert rows["/api/lost"].text(7) == "no response"
    status = transactions.status.text()
    assert "without a response" in status and "responses without a request" in status


def test_request_and_response_are_shown_together_with_their_json(page, wait_for: Callable[..., None]) -> None:
    transactions, _tab, _win = page
    tx = select(page=transactions, text="/api/orders")
    assert tx.paired and tx.status == 201
    detail = transactions.detail
    assert "uncertain" in detail.summary.text() and "thread" in detail.summary.text()
    # the request side holds the request's body, the response side the response's: never mixed
    assert '"item":"A1"' in detail.request.text and '"state"' not in detail.request.text
    assert '"state":"created"' in detail.response.text and '"item"' not in detail.response.text
    assert "Operation=Handler.Send" in detail.request.text  # the call's trace steps are listed with the request
    wait_for(lambda: detail.request.tree.parsed is not None and detail.response.tree.parsed is not None)
    assert detail.request.tree.parsed.ok and detail.request.tree.parsed.root.size == 3
    assert [detail.response.tree.tree.topLevelItem(0).child(i).text(0) for i in range(2)] == ["id", "state"]
    assert detail.request.raw.toPlainText() == detail.request.text  # raw text is exactly what was logged


def test_xml_response_and_marker_request_json(page, wait_for: Callable[..., None]) -> None:
    transactions, _tab, _win = page
    select(page=transactions, text="/soap")
    detail = transactions.detail
    wait_for(lambda: detail.response.tree.parsed is not None)
    assert detail.response.tree.parsed.kind == "xml" and detail.response.tree.parsed.ok
    select(page=transactions, text="GetUser")
    wait_for(lambda: detail.request.tree.parsed is not None)
    assert detail.request.tree.parsed.kind == "json" and detail.request.tree.parsed.root.size == 1
    assert "Execution time=4ms" in detail.response.text


def test_unanswered_request_and_unmatched_response_stay_inspectable(page) -> None:
    transactions, _tab, _win = page
    lost = select(page=transactions, text="/api/lost")
    assert not lost.paired
    assert "no response" in transactions.detail.summary.text()
    assert "No response was found" in transactions.detail.response.note.text()
    assert "rid00009" in transactions.detail.request.text or "/api/lost" in transactions.detail.request.text
    transactions.view.setCurrentIndex(transactions.VIEWS.index("Responses without a request"))
    assert transactions.tree.topLevelItemCount() == 1
    orphan = transactions.tree.topLevelItem(0)
    transactions.tree.setCurrentItem(orphan)
    assert "could not be identified" in transactions.detail.summary.text()
    assert "status=200" in transactions.detail.response.text
    assert "No request was found" in transactions.detail.request.note.text()


def test_malformed_json_shows_an_error_and_keeps_the_raw_text(page, wait_for: Callable[..., None]) -> None:
    transactions, _tab, _win = page
    select(page=transactions, text="/broken")
    detail = transactions.detail
    wait_for(lambda: detail.response.tree.parsed is not None)
    assert not detail.response.tree.parsed.ok
    assert "Not valid JSON" in detail.response.tree.info.text() or detail.response.message.text() != ""
    assert '{"a": [1, 2,, }' in detail.response.raw.toPlainText()  # original untouched


def test_large_payload_opens_collapsed_and_pages_on_demand(
    page, wait_for: Callable[..., None], qapp: QApplication
) -> None:
    transactions, _tab, _win = page
    select(page=transactions, text="/big")
    view = transactions.detail.response.tree
    wait_for(lambda: view.parsed is not None and view.parsed.ok)
    root = view.tree.topLevelItem(0)
    rows = root.child(0)  # "rows": 1,500 items
    assert rows.text(0) == "rows" and rows.text(1) == "[1,500 items]"
    view.tree.expandItem(rows)
    assert rows.childCount() == PAGE_SIZE + 1  # one page + the "more" row: not 1,500 widgets
    more = rows.child(PAGE_SIZE)
    assert "1,000 more" in more.text(0)
    view._on_double_click(more, 0)
    assert rows.childCount() == 2 * PAGE_SIZE + 1  # second page loaded, a new "more" row for the rest
    view._on_double_click(rows.child(2 * PAGE_SIZE), 0)
    assert rows.childCount() == 1_500  # all loaded now, the "more" row is gone
    assert view.reveal((0, 1_499)) is not None  # navigation reaches the last item


def test_tree_search_and_copy(page, wait_for: Callable[..., None], qapp: QApplication) -> None:
    transactions, _tab, _win = page
    select(page=transactions, text="/api/orders")
    view = transactions.detail.request.tree
    wait_for(lambda: view.parsed is not None and view.parsed.ok)
    view.search.setText("qty")
    wait_for(lambda: view.hit_label.text() == "1 / 1")
    assert view.tree.currentItem().text(0) == "qty"
    view.copy_raw.click()
    assert qapp.clipboard().text() == '{"item":"A1","qty":2,"tags":["x","y"]}'
    view.copy_value.click()
    assert qapp.clipboard().text() == "2"
    assert view.key_path(view.tree.currentItem()) == "$.qty"
    assert view.tree.currentItem().foreground(1).color().isValid()
    assert view.tree.currentItem().data(0, Qt.ItemDataRole.UserRole) is not None


def test_log_text_is_never_rendered_as_html(page) -> None:
    """A request line containing markup must show as text (no injected formatting, images or links)."""
    from loglens.core.http import Transaction
    from loglens.ui.payload_view import describe

    hostile = Transaction(
        key="<b>id</b>", request_line=0, response_line=1, method="GET", path='/<img src="file:///c:/secret.png">',
        status=200, duration_ms=1.0, all_lines=(0, 1), thread="<script>x</script>", match="thread", confidence="medium",
    )  # fmt: skip
    text = describe(hostile)
    assert "<img" not in text and "<script" not in text and "<b>id" not in text
    assert "&lt;img" in text and "&lt;script&gt;" in text
    transactions, _tab, _win = page
    assert transactions.detail.request.note.textFormat() == Qt.TextFormat.PlainText
    assert transactions.detail.request.message.textFormat() == Qt.TextFormat.PlainText
