"""The share-safe copy job writes a whole log with consistent pseudonyms and an optional private mapping file."""

from __future__ import annotations

import csv
import time
from pathlib import Path

from PySide6.QtWidgets import QApplication

from loglens.core.pseudonyms import Pseudonymizer
from loglens.core.text_source import TextLogSource
from loglens.services.sharecopy_jobs import ShareCopyJob
from loglens.ui.sharecopy_dialog import ShareCopyDialog

LOG = [
    "2026-11-13 10:00:00,000 INFO user=alice connected from 10.1.1.5 (alice@corp.com)",
    "2026-11-13 10:00:01,000 WARN user=bob failed login from 10.1.1.6",
    "2026-11-13 10:00:02,000 INFO user=alice reconnected from 10.1.1.5",
]


def wait(app: QApplication, done: list, seconds: float = 10.0) -> None:
    end = time.time() + seconds
    while time.time() < end and not done:
        app.processEvents()
        time.sleep(0.02)
    assert done


def test_copy_is_consistent_and_mapping_is_optional(qapp: QApplication, tmp_path: Path) -> None:
    src = tmp_path / "app.log"
    src.write_text("\n".join(LOG) + "\n", encoding="utf-8")
    source = TextLogSource(src)
    source.build_index()
    target, mapping = tmp_path / "copy.log", tmp_path / "copy.replacements.csv"
    job = ShareCopyJob()
    done: list[tuple] = []
    job.finished.connect(lambda path, counts: done.append((path, counts)))
    job.failed.connect(lambda message: done.append(("failed", message)))
    job.run(source, target, Pseudonymizer(), mapping)
    wait(qapp, done)
    assert done[0][0] == str(target), done
    copy = target.read_text(encoding="utf-8").splitlines()
    assert len(copy) == 3 and "alice" not in "".join(copy) and "10.1.1" not in "".join(copy)
    assert copy[0].split()[3] == copy[2].split()[3]  # alice is the same pseudonym on both lines
    assert "INFO" in copy[0] and copy[0].startswith("2026-11-13 10:00:00,000")
    rows = list(csv.reader(mapping.open(encoding="utf-8")))
    assert rows[0] == ["kind", "original", "pseudonym"] and ["user", "alice", "user1"] in rows
    assert done[0][1]["user"] == 2


def test_dialog_options_build_the_pseudonymizer(qapp: QApplication) -> None:
    dialog = ShareCopyDialog("app.log")
    dialog.boxes["ip"].setChecked(False)
    dialog.boxes["secrets"].setChecked(False)
    z = dialog.pseudonymizer()
    assert "ip" not in z.kinds and not z.secrets and "user" in z.kinds
    assert not dialog.mapping.isChecked()
