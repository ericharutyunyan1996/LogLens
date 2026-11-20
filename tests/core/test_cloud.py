"""Loki and Elasticsearch sources against local fake services."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import ClassVar

import pytest

from loglens.core.cloud import CloudError, elastic_lines, loki_lines


class Fake(BaseHTTPRequestHandler):
    seen: ClassVar[list[tuple[str, str, str]]] = []
    answer: ClassVar[tuple[int, object]] = (200, {})

    def _reply(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode() if length else ""
        Fake.seen.append((self.path, self.headers.get("Authorization", ""), body))
        code, payload = Fake.answer
        data = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = _reply  # noqa: N815
    do_POST = _reply  # noqa: N815

    def log_message(self, *_a: object) -> None:
        pass


@pytest.fixture
def service():
    Fake.seen, Fake.answer = [], (200, {})
    server = HTTPServer(("127.0.0.1", 0), Fake)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()


def test_loki_lines_are_merged_in_time_order_with_labels(service: str) -> None:
    Fake.answer = (
        200,
        {
            "status": "success",
            "data": {
                "result": [
                    {"stream": {"app": "shop", "pod": "a"}, "values": [["1763000002000000000", "second\nline"]]},
                    {"stream": {"app": "shop", "pod": "b"}, "values": [["1763000001000000000", "first"]]},
                ]
            },
        },
    )
    lines = loki_lines(service, '{app="shop"}', token="tok")
    assert lines[0].endswith("[app=shop,pod=b] first") and lines[1].endswith("[app=shop,pod=a] second line")
    path, auth, _ = Fake.seen[0]
    assert path.startswith("/loki/api/v1/query_range?query=") and auth == "Bearer tok" and "direction=forward" in path


def test_loki_errors_are_explained(service: str) -> None:
    Fake.answer = (401, {})
    with pytest.raises(CloudError, match=r"401.*token"):
        loki_lines(service, '{a="b"}')
    Fake.answer = (200, {"status": "error", "error": "parse error"})
    with pytest.raises(CloudError, match="parse error"):
        loki_lines(service, "{bad")
    with pytest.raises(CloudError, match="Enter a LogQL"):
        loki_lines(service, " ")
    with pytest.raises(CloudError, match="https"):
        loki_lines("http://example.com", '{a="b"}')
    with pytest.raises(CloudError, match="could not be reached"):
        loki_lines("http://127.0.0.1:9", '{a="b"}')


def test_elastic_documents_become_lines(service: str) -> None:
    Fake.answer = (
        200,
        {
            "hits": {
                "hits": [
                    {"_source": {"@timestamp": "2026-11-13T10:00:00Z", "message": "disk full", "level": "error"}},
                    {"_source": {"@timestamp": "2026-11-13T10:00:01Z", "code": 5}},
                ]
            }
        },
    )
    lines = elastic_lines(service, "logs-*", "level:error", limit=20)
    assert lines[0] == "2026-11-13T10:00:00Z disk full" and lines[1].startswith("2026-11-13T10:00:01Z {")
    path, _auth, body = Fake.seen[0]
    assert path == "/logs-*/_search" and json.loads(body)["size"] == 20
    for bad in ("", "a b", "../x", "_all/x"):
        with pytest.raises(CloudError):
            elastic_lines(service, bad)


def test_dialog_fetches_from_a_service(service: str, qapp) -> None:
    from loglens.ui.cloud_dialog import CloudDialog, secret_name

    Fake.answer = (
        200,
        {"status": "success", "data": {"result": [{"stream": {"a": "b"}, "values": [["1763000001000000000", "hi"]]}]}},
    )
    d = CloudDialog()
    d.url.setText(service)
    d.query.setText('{a="b"}')
    assert d.fetch()[0].endswith("[a=b] hi")
    d.url.setText("")
    d.accept()
    assert "address" in d.problem_label.text()
    assert secret_name("https://Loki.Example.com/x") == "cloud:loki.example.com"
