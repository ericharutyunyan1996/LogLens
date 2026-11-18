"""AIService — runs AI requests off the UI thread and reports results through signals."""

from __future__ import annotations

import logging
from collections.abc import Callable

from PySide6.QtCore import QObject, Signal

from ..core.ai import credentials
from ..core.ai.claude import API_KEY_SECRET, FOUNDRY_KEY_SECRET, AIError
from ..core.ai.config import AIConfig, Provider
from ..core.ai.explain import ExplainRequest, Explanation
from ..core.ai.providers import AIProvider, make_provider
from .jobs import JobSlot, start_worker

log = logging.getLogger(__name__)
ProviderFactory = Callable[[AIConfig, str | None], AIProvider]


def secret_name(config: AIConfig) -> str:
    return FOUNDRY_KEY_SECRET if config.provider is Provider.FOUNDRY else API_KEY_SECRET


def _default_factory(config: AIConfig, api_key: str | None) -> AIProvider:
    return make_provider(config, api_key)


class _Signals(QObject):
    explained = Signal(int, object)  # generation, Explanation
    progress = Signal(int, str)  # generation, phase message
    failed = Signal(int, str)  # generation, message
    tested = Signal(bool, str, bool)  # ok, message, compatibility mode was needed


class AIService(QObject):
    started = Signal()
    progress = Signal(str)  # what is happening now ("Sending…", "Receiving the answer… 120 words")
    finished = Signal(object)  # Explanation
    failed = Signal(str)
    connectionTested = Signal(bool, str, bool)  # ok, message, compatibility mode was needed

    def __init__(self, factory: ProviderFactory = _default_factory, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._factory = factory
        self._job = JobSlot()
        self._busy = False
        self._signals = _Signals(self)
        self._signals.explained.connect(self._on_explained)
        self._signals.progress.connect(self._on_progress)
        self._signals.failed.connect(self._on_failed)
        self._signals.tested.connect(self.connectionTested)

    @property
    def busy(self) -> bool:
        return self._busy

    def explain(self, config: AIConfig, request: ExplainRequest) -> None:
        generation, cancel = self._job.begin()
        self._busy = True
        self.started.emit()
        signals, factory = self._signals, self._factory

        def work() -> None:
            def report(message: str) -> None:
                signals.progress.emit(generation, message)

            try:
                report(f"Connecting to {config.model_label}…")
                provider = factory(config, _load_key(config))
                report(f"Sending {len(request.user_text):,} characters (redacted) to {config.model_label}…")
                signals.explained.emit(generation, provider.explain(request, report, cancel))
            except AIError as exc:
                signals.failed.emit(generation, str(exc))
            except Exception as exc:
                log.exception("AI request failed")
                signals.failed.emit(generation, f"Unexpected error: {exc}")

        start_worker("ai-explain", work)

    def cancel(self) -> None:
        self._job.cancel()
        self._busy = False

    def test_connection(self, config: AIConfig, api_key: str | None = None) -> None:
        """Check credentials/model with a tiny request; ``api_key`` overrides the stored key (unsaved edits)."""
        signals, factory = self._signals, self._factory

        def work() -> None:
            try:
                provider = factory(config, api_key or _load_key(config))
                model = provider.test_connection()
                needed = provider.compatibility_used and not config.compatibility_mode
                note = " Your AI gateway needs compatibility mode — it has been switched on." if needed else ""
                signals.tested.emit(True, f"Connected — {model} answered.{note}", needed)
            except AIError as exc:
                signals.tested.emit(False, str(exc), False)
            except Exception as exc:
                log.exception("AI connection test failed")
                signals.tested.emit(False, f"Unexpected error: {exc}", False)

        start_worker("ai-test", work)

    def _on_progress(self, generation: int, message: str) -> None:
        if self._job.is_current(generation):
            self.progress.emit(message)

    def _on_explained(self, generation: int, explanation: Explanation) -> None:
        if self._job.is_current(generation):
            self._busy = False
            self.finished.emit(explanation)

    def _on_failed(self, generation: int, message: str) -> None:
        if self._job.is_current(generation):
            self._busy = False
            self.failed.emit(message)


def _load_key(config: AIConfig) -> str | None:
    if not config.needs_api_key:
        return None
    try:
        return credentials.load_secret(secret_name(config))
    except OSError as exc:
        raise AIError(f"Could not read the saved API key: {exc}") from exc
