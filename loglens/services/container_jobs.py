"""Capture a container's / pod's log stream into a file that LogLens follows like any other log."""

from __future__ import annotations

import logging
import re
import subprocess
import threading
from collections import deque
from pathlib import Path

from PySide6.QtCore import QObject, Signal

from ..core.containers import NO_WINDOW, ContainerError, LogSource, explain_failure, find_tool

log = logging.getLogger(__name__)
STOP_WAIT_S = 3.0
_UNSAFE = re.compile(r'[<>:"/\\|?*\x00-\x1f]+')


def capture_path(folder: Path, source: LogSource, stamp: str) -> Path:
    """A file name for ``source``'s capture (names from clusters may hold characters Windows forbids)."""
    name = _UNSAFE.sub("_", source.title).strip(" ._")[:80] or source.kind
    return folder / f"{name} {stamp}.log"


class ContainerStreamer(QObject):
    """Runs ``docker logs`` / ``kubectl logs`` and appends every line to ``target`` as it arrives.

    One streamer per source. ``started`` fires once the process runs; ``failed`` carries a plain explanation when it
    ends with an error (engine stopped, pod gone, access denied …); ``ended`` fires when a finite read completes.
    """

    started = Signal()
    failed = Signal(str)
    ended = Signal()

    def __init__(self, source: LogSource, target: Path, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.source = source
        self.target = target
        self._proc: subprocess.Popen[bytes] | None = None
        self._stopping = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        tool = self.source.argv[0]
        path = find_tool(tool)
        if path is None:
            self.failed.emit(str(ContainerError(f"{tool} is not installed (or not on PATH).")))
            return
        try:
            self._proc = subprocess.Popen(
                [path, *self.source.argv[1:]],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                creationflags=NO_WINDOW,
            )
        except OSError as exc:
            self.failed.emit(f"Could not run {tool}: {exc}")
            return
        self.target.parent.mkdir(parents=True, exist_ok=True)
        self.target.write_bytes(b"")
        self._thread = threading.Thread(target=self._pump, name=f"stream-{self.source.title}"[:40], daemon=True)
        self._thread.start()
        self.started.emit()

    def _pump(self) -> None:
        proc = self._proc
        assert proc is not None
        last: deque[str] = deque(maxlen=5)  # the tail of the output explains a failure
        count = 0
        try:
            with self.target.open("ab") as out:
                assert proc.stdout is not None
                for raw in proc.stdout:
                    out.write(raw if raw.endswith(b"\n") else raw + b"\n")
                    out.flush()
                    count += 1
                    last.append(raw.decode("utf-8", "replace").strip())
        except OSError as exc:
            log.warning("container capture write failed: %s", exc)
        code = proc.wait()
        if self._stopping.is_set():
            return
        if code != 0:
            self.failed.emit(explain_failure(self.source.argv[0], " ".join(last)))
        else:
            self.ended.emit()

    def stop(self) -> None:
        self._stopping.set()
        proc = self._proc
        if proc is None or proc.poll() is not None:
            return
        proc.terminate()
        try:
            proc.wait(STOP_WAIT_S)
        except subprocess.TimeoutExpired:
            proc.kill()
