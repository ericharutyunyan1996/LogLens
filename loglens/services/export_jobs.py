"""Export lines of a log (text / CSV / JSON Lines) in the background, with progress and cancel."""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

import numpy as np
from PySide6.QtCore import QObject, Signal

from ..core.report import make_rows, to_csv, to_json_lines
from ..core.secrets import SecretMasker
from ..core.text_source import TextLogSource
from .jobs import start_worker

log = logging.getLogger(__name__)
EXPORT_CHUNK = 20_000
EXPORT_KINDS = ("text", "csv", "json")


class LineExporter(QObject):
    progress = Signal(int, int)  # lines written, lines total
    finished = Signal(str, int)  # target, lines written
    failed = Signal(str)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._cancel = threading.Event()

    def cancel(self) -> None:
        self._cancel.set()

    def export(
        self,
        source: TextLogSource,
        lines: np.ndarray,
        target: Path,
        *,
        kind: str,
        time_of: Callable[[str], datetime | None],
        level_of: Callable[[str], str],
        mask_secrets: bool = False,
    ) -> None:
        self._cancel = cancel = threading.Event()
        masker = SecretMasker()  # one masker for the whole export: private keys logged line by line stay masked

        def work() -> None:
            written = 0
            try:
                with target.open("w", encoding="utf-8", newline="\n") as out:
                    for start in range(0, len(lines), EXPORT_CHUNK):
                        if cancel.is_set():
                            break
                        chunk = lines[start : start + EXPORT_CHUNK]
                        texts = source.get_lines_at(chunk)
                        if mask_secrets:
                            texts = masker.mask_lines(texts)
                        out.write(_render(kind, chunk, texts, time_of, level_of, header=start == 0))
                        written += len(texts)
                        self.progress.emit(written, len(lines))
            except OSError as exc:
                self.failed.emit(f"Could not write {target}: {exc}")
                return
            except Exception as exc:
                log.exception("export failed")
                self.failed.emit(f"Export failed: {exc}")
                return
            if cancel.is_set():
                self.failed.emit(f"Export cancelled — {target.name} holds the first {written:,} lines.")
            else:
                self.finished.emit(str(target), written)

        start_worker("export", work)


def _render(
    kind: str,
    numbers: np.ndarray,
    texts: list[str],
    time_of: Callable[[str], datetime | None],
    level_of: Callable[[str], str],
    *,
    header: bool,
) -> str:
    if kind == "text":
        return "\n".join(texts) + "\n"
    rows = make_rows(zip(numbers.tolist(), texts, strict=True), time_of=time_of, level_of=level_of)
    if kind == "json":
        return to_json_lines(rows)
    text = to_csv(rows)
    return text if header else text.split("\n", 1)[1]
