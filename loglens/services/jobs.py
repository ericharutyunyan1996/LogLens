"""Background job helpers: one live job per slot, cooperative cancellation, stale-result rejection."""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable

log = logging.getLogger(__name__)


class JobSlot:
    """Holds at most one live background job of a kind.

    ``begin()`` cancels the previous job and returns a new ``(generation, cancel_event)``. Results are delivered to
    the UI thread via queued signals carrying the generation; :meth:`is_current` lets the receiver drop results of
    jobs that were superseded or cancelled in the meantime.
    """

    def __init__(self) -> None:
        self._generation = 0
        self._cancel = threading.Event()

    def begin(self) -> tuple[int, threading.Event]:
        self._cancel.set()
        self._cancel = threading.Event()
        self._generation += 1
        return self._generation, self._cancel

    def cancel(self) -> None:
        self._cancel.set()
        self._generation += 1

    def is_current(self, generation: int) -> bool:
        return generation == self._generation


def start_worker(name: str, target: Callable[[], None]) -> threading.Thread:
    """Run ``target`` on a daemon thread; unexpected exceptions are logged instead of vanishing."""

    def run() -> None:
        try:
            target()
        except Exception:
            log.exception("background job %s failed", name)

    thread = threading.Thread(target=run, name=f"loglens-{name}", daemon=True)
    thread.start()
    return thread
