"""AIController — glue between a log tab's Inspector, the AI settings, the preview dialog and the AIService."""

from __future__ import annotations

import time
from collections.abc import Sequence
from dataclasses import replace
from typing import TYPE_CHECKING

from PySide6.QtCore import QObject, QTimer, Signal
from PySide6.QtWidgets import QWidget

from ..core.ai import credentials
from ..core.ai.config import PROVIDER_LABELS, AIConfig
from ..core.ai.explain import ExplainRequest, Explanation, build_request
from ..core.ai.redaction import Redactor
from ..services.ai_service import AIService, secret_name
from ..settings import Settings
from .ai_dialogs import AIPreviewDialog, AISettingsDialog
from .qt_utils import exec_dialog

if TYPE_CHECKING:
    from .log_tab import LogTab

MAX_FOCUS_LINES = 50
MAX_PATTERNS = 40  # patterns sent when explaining an aggregate (most frequent first)
MAX_CONTEXT_CHARS = 4_000  # per context line; keeps requests small (the focus line may be longer)
MAX_FOCUS_CHARS = 20_000


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit] + f" …[{len(text) - limit:,} more characters not sent]"


class AIController(QObject):
    configChanged = Signal()
    busyChanged = Signal(bool, str)  # busy, status text (for the window's status bar)

    def __init__(self, settings: Settings, window: QWidget) -> None:
        super().__init__(window)
        self._settings = settings
        self._window = window
        self._tab: LogTab | None = None  # tab waiting for an answer
        self._subject = ""  # "line 12" / "lines 12–15" of the pending request
        self.service = AIService(parent=self)
        self.service.finished.connect(self._on_finished)
        self.service.failed.connect(self._on_failed)
        self.service.progress.connect(self._on_progress)
        self._phase = ""
        self._started = 0.0
        self._ticker = QTimer(self)
        self._ticker.setInterval(1000)
        self._ticker.timeout.connect(self._tick)

    # ---- state ---------------------------------------------------------------------------------------------------
    def config(self) -> AIConfig:
        return self._settings.ai_config()

    def readiness(self) -> tuple[bool, str]:
        """Whether 'Explain' can be used, and a one-line status for the Inspector's AI tab."""
        config = self.config()
        if not config.enabled:
            return False, "The AI assistant is off. Enable it in AI settings (AI → AI settings…)."
        if config.is_local:
            preview = ", after a preview" if config.preview_before_send else ""
            return True, (
                f"Sends the selected line with {config.context_before} lines before and {config.context_after} after"
                f"{preview} to {config.model_label}"
                + (" — nothing leaves this computer." if config.local_url_is_loopback else " (over the network).")
            )
        if config.needs_api_key:
            try:
                has_key = credentials.load_secret(secret_name(config)) is not None
            except OSError:
                has_key = False
            if not has_key:
                return False, "No API key saved yet — open AI settings to add one."
        preview = ", after a preview" if config.preview_before_send else ""
        return True, (
            f"Sends the selected line with {config.context_before} lines before and {config.context_after} after "
            f"(redacted{preview}) to {config.model}."
        )

    def destination(self) -> str:
        config = self.config()
        if config.is_local:
            where = "this computer" if config.local_url_is_loopback else "another computer — sent over the network"
            return f"{config.local_model} at {config.local_url} ({where})"
        return f"{config.model} — {PROVIDER_LABELS[config.provider].split(' (')[0]}"

    # ---- actions -------------------------------------------------------------------------------------------------
    def open_settings(self) -> None:
        dialog = AISettingsDialog(self.config(), self.service, self._window)
        if exec_dialog(dialog):
            self._settings.set_ai_config(dialog.config())
            self._settings.save()
        self.configChanged.emit()

    def explain(self, tab: LogTab) -> None:
        ready, message = self.readiness()
        if not ready:
            tab.inspector.show_ai_error(message)
            return
        request = self._build(tab)
        if request is None:
            tab.inspector.show_ai_error("Select a line first.")
            return
        first, last = request.focus_lines[0] + 1, request.focus_lines[-1] + 1
        self._send(tab, request, f"line {first:,}" if first == last else f"lines {first:,}–{last:,}")

    def explain_patterns(self, tab: LogTab, patterns: Sequence[tuple[int, int, str, str]], scope: str) -> None:
        """Explain an aggregate: (count, sample line number, template, sample text) of the most frequent patterns."""
        ready, message = self.readiness()
        if not ready:
            tab.inspector.show_ai_error(message)
            return
        chosen = sorted(patterns[:MAX_PATTERNS], key=lambda p: p[1])
        numbered = [(line, _clip(f"[{count:,}× pattern: {template}] {sample}", MAX_CONTEXT_CHARS))
                    for count, line, template, sample in chosen]  # fmt: skip
        note = (
            f"These are the {len(chosen)} most frequent message patterns in {scope} (count × template, then one "
            "example line). Explain what is going on overall: which patterns point to problems, how they relate, "
            "and what to check first."
        )
        redactor = Redactor(self.config().redaction_set())
        request = build_request(tab.document.title, numbered, [line for _c, line, _t, _s in chosen], redactor, note)
        self._send(tab, request, f"the top {len(chosen)} patterns of {scope}")

    def _send(self, tab: LogTab, request: ExplainRequest, subject: str) -> None:
        config = self.config()
        if config.preview_before_send:
            preview = AIPreviewDialog(request, self.destination(), self._window)
            if not exec_dialog(preview):
                return
            request = replace(request, user_text=preview.edited_text())  # the user may have removed things
            if preview.dont_ask.isChecked():
                config.preview_before_send = False
                self._settings.set_ai_config(config)
                self._settings.save()
                self.configChanged.emit()
        if self._tab is not None and self._tab is not tab and self.service.busy:
            # one request at a time: the new one replaces the old, so release the other tab's "Asking…" state
            self.service.cancel()
            self._tab.inspector.show_ai_error("Replaced by a newer request in another tab.")
        self._tab = tab
        self._subject = subject
        self._phase = f"Preparing the request for {config.model_label}…"
        self._started = time.monotonic()
        tab.inspector.show_ai_busy(self._phase)
        self._ticker.start()
        self.busyChanged.emit(True, f"AI: {self._phase}")
        self.service.explain(config, request)

    def cancel(self) -> None:
        """Stop waiting: the answer of the running request (if it still comes) is dropped."""
        if self._tab is not None and self.service.busy:
            self.service.cancel()
            self._done()
            self._tab.inspector.show_ai_error("Cancelled — no answer will be shown for this request.")

    def _elapsed(self) -> int:
        return int(time.monotonic() - self._started)

    def _on_progress(self, message: str) -> None:
        self._phase = message
        self._tick()

    def _tick(self) -> None:
        if self._tab is not None and self.service.busy:
            self._tab.inspector.set_ai_progress(self._phase, self._elapsed())
            self.busyChanged.emit(True, f"AI: {self._phase} ({self._elapsed()} s)")

    def _done(self) -> None:
        self._ticker.stop()
        self.busyChanged.emit(False, "")

    def _build(self, tab: LogTab) -> ExplainRequest | None:
        config = self.config()
        first_sel, last_sel = tab.selected_range(MAX_FOCUS_LINES)  # whole multi-line records
        if first_sel < 0:
            return None
        source = tab.document.source
        first = max(first_sel - config.context_before, 0)
        last = min(last_sel + config.context_after, source.line_count() - 1)
        texts = source.get_lines(first, last - first + 1)
        focus = range(first_sel, last_sel + 1)
        numbered = []
        for number, text in zip(range(first, last + 1), texts, strict=False):
            full = source.get_full_line(number) if number in focus else text
            numbered.append((number, _clip(full, MAX_FOCUS_CHARS if number in focus else MAX_CONTEXT_CHARS)))
        return build_request(tab.document.title, numbered, list(focus), Redactor(config.redaction_set()))

    def forget(self, tab: LogTab) -> None:
        """The tab is closing: drop any answer still on its way to it."""
        if self._tab is tab:
            self._tab = None
            if self.service.busy:
                self.service.cancel()
                self._done()

    def _on_finished(self, explanation: Explanation) -> None:
        elapsed = self._elapsed()
        self._done()
        self.busyChanged.emit(False, f"AI answer received in {elapsed} s")
        if explanation.compatibility_used and not self.config().compatibility_mode:
            self.remember_compatibility()
        if self._tab is not None:
            self._tab.inspector.show_ai_result(explanation, self._subject)

    def remember_compatibility(self) -> None:
        """The gateway needed the older request format: keep using it (saves a retry per request)."""
        config = self.config()
        config.compatibility_mode = True
        self._settings.set_ai_config(config)
        self._settings.save()
        self.configChanged.emit()

    def _on_failed(self, message: str) -> None:
        self._done()
        if self._tab is not None:
            self._tab.inspector.show_ai_error(message)
