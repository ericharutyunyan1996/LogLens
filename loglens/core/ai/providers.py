"""Which AI provider answers: Claude (cloud platforms) or a local model server."""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Protocol

from .claude import ClaudeProvider
from .config import AIConfig
from .explain import ExplainRequest, Explanation
from .local import LocalProvider


class AIProvider(Protocol):
    compatibility_used: bool

    def explain(
        self,
        request: ExplainRequest,
        progress: Callable[[str], None] | None = None,
        cancel: threading.Event | None = None,
    ) -> Explanation: ...

    def test_connection(self) -> str: ...


def make_provider(config: AIConfig, api_key: str | None) -> AIProvider:
    if config.is_local:
        return LocalProvider(config)
    return ClaudeProvider(config, api_key)
