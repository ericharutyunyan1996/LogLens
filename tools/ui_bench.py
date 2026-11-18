"""Drive the real UI headlessly on a big file and time the user-visible steps.

python tools/ui_bench.py samples/generated/app_big.log
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("QT_QPA_FONTDIR", "C:/Windows/Fonts")


def main(path: str) -> None:
    os.environ["APPDATA"] = tempfile.mkdtemp()  # don't touch the real settings
    from PySide6.QtWidgets import QApplication

    from loglens.core.search import SearchQuery, shutdown_pool
    from loglens.settings import Settings
    from loglens.ui.main_window import MainWindow

    app = QApplication([])
    win = MainWindow(Settings())
    win.resize(1400, 900)
    win.show()

    def wait(cond, label: str, t0: float, timeout: float = 120) -> None:
        worst = 0.0
        while not cond():
            a = time.perf_counter()
            app.processEvents()
            worst = max(worst, time.perf_counter() - a)
            if time.perf_counter() - t0 > timeout:
                raise SystemExit(f"timeout: {label}")
            time.sleep(0.005)
        print(f"{label:<28} {time.perf_counter() - t0:6.2f}s   (longest UI stall {worst * 1000:5.0f} ms)")

    t0 = time.perf_counter()
    win.open_file(path)
    tab = win.current_tab()
    wait(lambda: tab.document.source.line_count() > 0, "first lines visible", t0)
    wait(lambda: not tab.document.is_indexing, f"indexed {tab.document.source.line_count():,} lines", t0)
    t1 = time.perf_counter()
    wait(lambda: any(s.count for s in tab.document.mark_summaries()), "scrollbar marks ready", t1)
    finished: list[int] = []
    tab.document.searchFinished.connect(lambda count, _seconds: finished.append(count))
    for q in [SearchQuery("deadlock"), SearchQuery(r"in \d{4,} ms", regex=True)]:
        t2 = time.perf_counter()
        finished.clear()
        tab.run_search(q)
        wait(lambda: bool(finished), f"search {q.pattern!r}", t2)
        print(f"    -> {finished[0]:,} matching lines")
    t3 = time.perf_counter()
    for row in range(0, tab.document.source.line_count(), tab.document.source.line_count() // 50):
        tab.main_view.go_to_row(row)
        tab.main_view.viewport().repaint()
    print(f"50 jumps+repaints across file  {(time.perf_counter() - t3) * 1000 / 50:6.1f} ms each")
    win.grab().save(str(Path(path).with_suffix(".png")))
    win.close()
    shutdown_pool()


if __name__ == "__main__":
    main(sys.argv[1])
