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
from ..core.ai.status import ProviderStatus, TestResult, scrub
from ..core.ai.validation import key_warning
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
    result = Signal(object)  # TestResult


class AIService(QObject):
    started = Signal()
    progress = Signal(str)  # what is happening now ("Sending…", "Receiving the answer… 120 words")
    finished = Signal(object)  # Explanation
    failed = Signal(str)
    connectionTested = Signal(bool, str, bool)  # ok, message, compatibility mode was needed
    testResult = Signal(object)  # TestResult: the status of the provider as configured right now

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
        self._signals.result.connect(self.testResult)

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
        """Validate the settings and make one tiny REAL request to the configured provider (credentials, authorization
        and model are all exercised). ``api_key`` overrides the stored key (unsaved edits). The outcome arrives as a
        :class:`TestResult` on ``testResult`` (and the older ``connectionTested``)."""
        signals, factory = self._signals, self._factory

        def finish(result: TestResult) -> None:
            signals.result.emit(result)
            signals.tested.emit(result.ok, result.message, result.compatibility_needed)

        def work() -> None:
            key: str | None = None
            try:
                key = api_key or _load_key(config)
                provider = factory(config, key)
                model = provider.test_connection()
                needed = provider.compatibility_used and not config.compatibility_mode
                note = " Your AI gateway needs compatibility mode: it has been switched on." if needed else ""
                finish(TestResult(ProviderStatus.CONNECTED, f"{model} answered.{note}", model, needed))
            except AIError as exc:
                hint = key_warning(config, key) if exc.status is ProviderStatus.AUTH_FAILED else ""
                finish(TestResult(exc.status, str(exc) + hint))
            except Exception as exc:
                log.exception("AI connection test failed")
                finish(TestResult(ProviderStatus.ERROR, scrub(f"Unexpected error: {exc}")))

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
