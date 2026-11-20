"""Local model provider against a fake Ollama / OpenAI-compatible server (no real model needed)."""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

import pytest

from loglens.core.ai.claude import AIError
from loglens.core.ai.config import LOCAL_API_OLLAMA, LOCAL_API_OPENAI, AIConfig, Provider
from loglens.core.ai.explain import ExplainRequest
from loglens.core.ai.local import LocalProvider, list_models, parse_answer
from loglens.core.ai.providers import make_provider

ANSWER = {
    "summary": "The database refused the login.",
    "severity": "error",
    "is_likely_noise": False,
    "what_happened": "Login failed for the service account.",
    "probable_causes": [{"cause": "Wrong password", "likelihood": "high", "evidence_lines": [3, 999]}],
    "next_steps": ["Check the connection string"],
    "missing_information": "",
    "confidence": "medium",
}
REQUEST = ExplainRequest("app.log", (2,), "L3|>> login failed", {}, 0, 4)


class FakeServer(BaseHTTPRequestHandler):
    reject_schema = False
    answer_text = json.dumps(ANSWER)
    seen: ClassVar[list[dict]] = []

    def log_message(self, *_args: object) -> None:  # keep test output quiet
        pass

    def _send(self, status: int, body: bytes, content_type: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/api/tags":
            self._send(200, json.dumps({"models": [{"name": "llama3.1:latest"}, {"name": "qwen2.5:7b"}]}).encode())
        elif self.path == "/v1/models":
            self._send(200, json.dumps({"data": [{"id": "local-model"}]}).encode())
        else:
            self._send(404, b"{}")

    def do_POST(self) -> None:
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        FakeServer.seen.append(body)
        text = FakeServer.answer_text
        pieces = [text[i : i + 20] for i in range(0, len(text), 20)]
        if self.path == "/api/chat":
            if body["model"] == "missing":
                self._send(404, b'{"error": "model not found"}')
                return
            if body.get("stream") is False:  # a non-streaming request (the connection test): one JSON answer
                self._send(200, json.dumps({"message": {"content": "OK"}, "done": True}).encode())
                return
            lines = [json.dumps({"message": {"content": p}, "done": False}) for p in pieces]
            lines.append(
                json.dumps({"message": {"content": ""}, "done": True, "prompt_eval_count": 50, "eval_count": 9})
            )
            self._send(200, ("\n".join(lines) + "\n").encode(), "application/x-ndjson")
        elif self.path == "/v1/chat/completions":
            if FakeServer.reject_schema and "response_format" in body:
                self._send(400, b'{"error": "response_format not supported"}')
                return
            if body.get("stream") is not True:
                self._send(200, json.dumps({"choices": [{"message": {"content": "OK"}}]}).encode())
                return
            events = [f"data: {json.dumps({'choices': [{'delta': {'content': p}}]})}\n\n" for p in pieces]
            self._send(200, ("".join(events) + "data: [DONE]\n\n").encode(), "text/event-stream")


@pytest.fixture
def server() -> Iterator[str]:
    FakeServer.seen, FakeServer.reject_schema, FakeServer.answer_text = [], False, json.dumps(ANSWER)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), FakeServer)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def _config(url: str, api: str = LOCAL_API_OLLAMA, model: str = "llama3.1:latest") -> AIConfig:
    return AIConfig(enabled=True, provider=Provider.LOCAL, local_api=api, local_url=url, local_model=model)


def test_ollama_streams_structured_answer(server: str) -> None:
    config = _config(server)
    assert list_models(config) == ["llama3.1:latest", "qwen2.5:7b"]
    provider = make_provider(config, None)
    assert isinstance(provider, LocalProvider)
    phases: list[str] = []
    explanation = provider.explain(REQUEST, phases.append)
    assert explanation.summary == ANSWER["summary"] and explanation.probable_causes[0].evidence_lines == (3,)
    assert explanation.model == "llama3.1:latest (local)" and explanation.output_tokens == 9
    assert any("Receiving" in p for p in phases)
    assert FakeServer.seen[0]["format"]["type"] == "object" and FakeServer.seen[0]["stream"] is True
    assert provider.test_connection() == "llama3.1:latest (local)"


def test_openai_compatible_falls_back_without_schema(server: str) -> None:
    FakeServer.reject_schema = True
    explanation = LocalProvider(_config(server, LOCAL_API_OPENAI, "local-model")).explain(REQUEST)
    assert explanation.severity == "error"
    assert "response_format" in FakeServer.seen[0] and "response_format" not in FakeServer.seen[1]


def test_unstructured_answer_and_errors(server: str) -> None:
    FakeServer.answer_text = "It looks like the password is wrong. Check the account."
    explanation = LocalProvider(_config(server)).explain(REQUEST)
    assert explanation.summary.startswith("It looks like") and explanation.confidence == "low"
    assert any("structured" in note for note in explanation.notes)
    with pytest.raises(AIError, match="ollama pull missing"):
        LocalProvider(_config(server, model="missing")).explain(REQUEST)
    with pytest.raises(AIError, match="not installed"):
        LocalProvider(_config(server, model="other")).test_connection()
    with pytest.raises(AIError, match="can't reach"):
        list_models(_config("http://127.0.0.1:9"))
    with pytest.raises(AIError, match="Choose a local model"):
        LocalProvider(_config(server, model=""))


def test_parse_answer_handles_code_fences() -> None:
    explanation, structured = parse_answer("```json\n" + json.dumps(ANSWER) + "\n```", range(1, 10))
    assert structured and explanation.next_steps == ("Check the connection string",)
