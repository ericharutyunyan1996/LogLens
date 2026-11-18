"""Local model provider: a model server on this computer (Ollama, or any OpenAI-compatible server such as
LM Studio, llama.cpp ``llama-server``, LocalAI, vLLM). Nothing leaves the machine.

That promise is enforced here: requests only go to a loopback address (``localhost``, 127.0.0.0/8, ``::1``) unless the
user explicitly allowed a remote server (:attr:`AIConfig.local_allow_remote`), they never go through a proxy (neither
``HTTP_PROXY`` nor the Windows proxy settings), and redirects are not followed.

Plain HTTP with the standard library (no extra packages). The answer is streamed so the UI can show progress and a
request can be cancelled between chunks. Structured output is requested with the same JSON schema as for Claude;
small models that ignore it still get a readable answer (their text is shown as the summary).
"""

from __future__ import annotations

import json
import re
import threading
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator
from dataclasses import replace
from email.message import Message
from typing import IO, Any

from .claude import AIError
from .config import LOCAL_API_OLLAMA, AIConfig, is_loopback_url
from .explain import EXPLANATION_SCHEMA, SYSTEM_PROMPT, ExplainRequest, Explanation

__all__ = ["LocalProvider", "check_local_url", "is_loopback_url", "list_models", "parse_answer"]

CONNECT_TIMEOUT_S = 5.0  # listing models / testing: a local server answers at once or isn't running
GENERATION_TIMEOUT_S = 600.0  # per read while streaming; CPU-only models can pause a long time before the first token
PROGRESS_EVERY_CHUNKS = 8
MAX_FALLBACK_SUMMARY = 400
JSON_INSTRUCTION = (
    "\n\nAnswer with a single JSON object only (no prose, no code fences) with these keys: summary, severity "
    "(info|warning|error|critical|unknown), is_likely_noise (true/false), what_happened, probable_causes (list of "
    "{cause, likelihood: high|medium|low, evidence_lines: [line numbers]}), next_steps (list of strings), "
    "missing_information, confidence (high|medium|low)."
)
Progress = Callable[[str], None]
_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.IGNORECASE)


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """The model server must answer itself: following a redirect could send the excerpt to another host."""

    def redirect_request(  # noqa: PLR0917 - signature of the urllib method this overrides
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: Message,
        newurl: str,
    ) -> None:
        return None  # urllib then raises HTTPError for the 3xx answer


# No proxies at all: an empty ProxyHandler replaces the default one, which reads HTTP_PROXY and the Windows registry
# and would route "local" requests through a corporate proxy.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirects())


def check_local_url(config: AIConfig) -> None:
    """Raise AIError unless the model server is on this computer (or the user explicitly allowed a remote one)."""
    if not config.local_url.strip().lower().startswith(("http://", "https://")):
        raise AIError(f"The model server address must start with http:// or https:// (got {config.local_url!r}).")
    if not config.local_allow_remote and not is_loopback_url(config.local_url):
        raise AIError(
            f"The model server {config.local_url} is not on this computer, so log lines would be sent over the "
            "network to it. Use a local address (http://localhost:… or http://127.0.0.1:…), or explicitly allow a "
            "model server on another computer in AI settings."
        )


def _url(config: AIConfig, path: str) -> str:
    return config.local_url.strip().rstrip("/") + path


def _request(
    config: AIConfig, path: str, body: dict[str, Any] | None = None, timeout: float = CONNECT_TIMEOUT_S
) -> Any:
    """Open ``path`` on the configured model server — only after :func:`check_local_url`, never through a proxy."""
    check_local_url(config)
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(
        _url(config, path), data=data, headers={"Content-Type": "application/json"}, method="POST" if data else "GET"
    )
    return _OPENER.open(request, timeout=timeout)


def _friendly(exc: Exception, config: AIConfig) -> AIError:
    if isinstance(exc, urllib.error.HTTPError):
        detail = exc.read().decode("utf-8", "replace")[:300]
        if exc.code == 404:
            return AIError(
                f"The server doesn't know the model '{config.local_model}'. "
                + (
                    f"Install it with: ollama pull {config.local_model}"
                    if config.local_api == LOCAL_API_OLLAMA
                    else "Load it in your model server first."
                )
            )
        return AIError(f"The local model server answered {exc.code}: {detail}")
    server = "Ollama (start it, or run: ollama serve)" if config.local_api == LOCAL_API_OLLAMA else "your model server"
    return AIError(f"Can't reach a local model server at {config.local_url} — is {server} running? ({exc})")


def list_models(config: AIConfig) -> list[str]:
    """Models installed on the local server (raises AIError when it can't be reached)."""
    try:
        if config.local_api == LOCAL_API_OLLAMA:
            with _request(config, "/api/tags") as response:
                return sorted(m["name"] for m in json.load(response).get("models", []))
        with _request(config, "/v1/models") as response:
            return sorted(m["id"] for m in json.load(response).get("data", []))
    except (urllib.error.URLError, OSError, ValueError, KeyError) as exc:
        raise _friendly(exc, config) from exc


def parse_answer(text: str, valid: range) -> tuple[Explanation, bool]:
    """The model's answer as an Explanation; False when it wasn't valid JSON (its text becomes the summary)."""
    cleaned = _FENCE.sub("", text.strip())
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start >= 0 and end > start:
        try:
            return Explanation.from_json(cleaned[start : end + 1], valid), True
        except (ValueError, TypeError, AttributeError):
            pass
    summary = " ".join(text.split())
    return Explanation(
        summary=summary[:MAX_FALLBACK_SUMMARY] + ("…" if len(summary) > MAX_FALLBACK_SUMMARY else ""),
        severity="unknown",
        is_likely_noise=False,
        what_happened=text.strip() if len(summary) > MAX_FALLBACK_SUMMARY else "",
        probable_causes=(),
        next_steps=(),
        missing_information="",
        confidence="low",
    ), False


class LocalProvider:
    """Explains log lines with a model served on this computer."""

    compatibility_used = False

    def __init__(self, config: AIConfig) -> None:
        if not config.local_model:
            raise AIError("Choose a local model in AI settings (click Refresh to list the installed ones).")
        check_local_url(config)
        self.config = config

    # ---- streaming -----------------------------------------------------------------------------------------------
    def _messages(self, user_text: str) -> list[dict[str, str]]:
        return [{"role": "system", "content": SYSTEM_PROMPT + JSON_INSTRUCTION}, {"role": "user", "content": user_text}]

    def _ollama_chunks(self, user_text: str, *, structured: bool) -> Iterator[tuple[str, dict[str, Any]]]:
        body: dict[str, Any] = {
            "model": self.config.local_model,
            "messages": self._messages(user_text),
            "stream": True,
            "options": {"temperature": 0.2},
        }
        if structured:
            body["format"] = EXPLANATION_SCHEMA
        with _request(self.config, "/api/chat", body, GENERATION_TIMEOUT_S) as response:
            for raw in response:
                if raw.strip():
                    chunk = json.loads(raw)
                    if chunk.get("error"):
                        raise AIError(f"The local model failed: {chunk['error']}")
                    yield str(chunk.get("message", {}).get("content", "")), chunk

    def _openai_chunks(self, user_text: str, *, structured: bool) -> Iterator[tuple[str, dict[str, Any]]]:
        body: dict[str, Any] = {
            "model": self.config.local_model,
            "messages": self._messages(user_text),
            "stream": True,
            "temperature": 0.2,
        }
        if structured:
            body["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": "explanation", "schema": EXPLANATION_SCHEMA, "strict": True},
            }
        with _request(self.config, "/v1/chat/completions", body, GENERATION_TIMEOUT_S) as response:
            for raw in response:
                line = raw.decode("utf-8", "replace").strip()
                if not line.startswith("data:"):
                    continue
                payload = line[5:].strip()
                if payload == "[DONE]":
                    return
                chunk = json.loads(payload)
                choices = chunk.get("choices") or [{}]
                yield str((choices[0].get("delta") or {}).get("content") or ""), chunk

    def _generate(
        self, user_text: str, progress: Progress | None, cancel: threading.Event | None
    ) -> tuple[str, dict[str, Any]]:
        stream = self._ollama_chunks if self.config.local_api == LOCAL_API_OLLAMA else self._openai_chunks
        try:
            try:
                return self._collect(stream(user_text, structured=True), progress, cancel)
            except urllib.error.HTTPError as exc:
                if exc.code != 400:
                    raise
                return self._collect(stream(user_text, structured=False), progress, cancel)
        except AIError:
            raise
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise _friendly(exc, self.config) from exc

    def _collect(
        self, chunks: Iterator[tuple[str, dict[str, Any]]], progress: Progress | None, cancel: threading.Event | None
    ) -> tuple[str, dict[str, Any]]:
        parts: list[str] = []
        last: dict[str, Any] = {}
        if progress is not None:
            progress(f"Waiting for {self.config.local_model} to start answering…")
        for index, (text, chunk) in enumerate(chunks):
            if cancel is not None and cancel.is_set():
                raise AIError("Cancelled.")
            parts.append(text)
            last = chunk
            if progress is not None and index % PROGRESS_EVERY_CHUNKS == 0:
                words = len("".join(parts).split())
                progress(f"Receiving the answer from {self.config.local_model}… {words} words")
        return "".join(parts), last

    # ---- provider API --------------------------------------------------------------------------------------------
    def explain(
        self, request: ExplainRequest, progress: Progress | None = None, cancel: threading.Event | None = None
    ) -> Explanation:
        text, last = self._generate(request.user_text, progress, cancel)
        if not text.strip():
            raise AIError("The local model returned an empty answer.")
        valid = range(request.first_line + 1, request.last_line + 2)
        explanation, structured = parse_answer(text, valid)
        notes: tuple[str, ...] = (
            ("Answered on this computer — nothing was sent over the network.",)
            if self.config.local_url_is_loopback
            else (f"Answered by the model server at {self.config.local_url} — the excerpt was sent over the network.",)
        )
        if not structured:
            notes += ("The model didn't return the structured format; its text is shown as is.",)
        return replace(
            explanation,
            model=f"{self.config.local_model} (local)",
            notes=notes,
            input_tokens=int(last.get("prompt_eval_count") or (last.get("usage") or {}).get("prompt_tokens") or 0),
            output_tokens=int(last.get("eval_count") or (last.get("usage") or {}).get("completion_tokens") or 0),
        )

    def test_connection(self) -> str:
        models = list_models(self.config)
        if self.config.local_model not in models and f"{self.config.local_model}:latest" not in models:
            installed = ", ".join(models[:8]) or "none"
            raise AIError(f"'{self.config.local_model}' is not installed on the server. Installed: {installed}.")
        return f"{self.config.local_model} (local)"
