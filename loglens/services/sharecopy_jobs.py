"""Write a share-safe copy of a whole log (secrets masked, people and machines pseudonymised) in the background."""

from __future__ import annotations

import csv
import logging
import threading
from pathlib import Path

from PySide6.QtCore import QObject, Signal

from ..core.pseudonyms import Pseudonymizer
from ..core.text_source import TextLogSource
from .jobs import start_worker

log = logging.getLogger(__name__)
CHUNK = 20_000


class ShareCopyJob(QObject):
    progress = Signal(int, int)  # lines written, lines total
    finished = Signal(str, object)  # target, {kind: replaced values}
    failed = Signal(str)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._cancel = threading.Event()

    def cancel(self) -> None:
        self._cancel.set()

    def run(
        self, source: TextLogSource, target: Path, pseudonymizer: Pseudonymizer, mapping_file: Path | None = None
    ) -> None:
        self._cancel = cancel = threading.Event()

        def work() -> None:
            total = source.line_count()
            try:
                with target.open("w", encoding="utf-8", newline="\n") as out:
                    for start in range(0, total, CHUNK):
                        if cancel.is_set():
                            break
                        texts = source.get_lines(start, min(CHUNK, total - start))
                        out.write("\n".join(pseudonymizer.lines(texts)) + "\n")
                        self.progress.emit(min(start + CHUNK, total), total)
                if mapping_file is not None and not cancel.is_set():
                    with mapping_file.open("w", encoding="utf-8", newline="") as handle:
                        writer = csv.writer(handle)
                        writer.writerow(["kind", "original", "pseudonym"])
                        writer.writerows(pseudonymizer.table())
            except OSError as exc:
                self.failed.emit(f"Could not write the copy: {exc}")
                return
            except Exception as exc:  # job boundary
                log.exception("share-safe copy failed")
                self.failed.emit(f"The copy failed: {exc}")
                return
            if cancel.is_set():
                self.failed.emit(f"Cancelled: {target.name} holds only the first part of the log.")
            else:
                self.finished.emit(str(target), pseudonymizer.counts())

        start_worker("share-copy", work)
