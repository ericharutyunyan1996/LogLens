"""Quick performance check: python tools/bench.py <big.log>"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from loglens.core.search import SearchQuery, get_pool, search_source, shutdown_pool
from loglens.core.text_source import TextLogSource


def main(path: str) -> None:
    t = time.perf_counter()
    src = TextLogSource(path)
    src.build_index()
    print(f"index: {src.line_count():,} lines in {time.perf_counter() - t:.2f}s ({src.encoding.display_name})")
    t = time.perf_counter()
    get_pool().submit(int, 0).result()  # warm-up: start worker processes
    print(f"pool start: {time.perf_counter() - t:.2f}s")
    queries = [
        SearchQuery("ERROR"),
        SearchQuery("ERROR", case_sensitive=True),
        SearchQuery("deadlock"),
        SearchQuery(r"in \d{4,} ms", regex=True),
        SearchQuery("INFO", invert=True),
    ]
    for parallel in (False, True):
        for q in queries:
            t = time.perf_counter()
            hits = search_source(src, q, parallel=parallel)
            print(
                f"{'parallel' if parallel else 'single  '} {q.pattern!r:18} cs={q.case_sensitive!s:5} "
                f"regex={q.regex!s:5} inv={q.invert!s:5}: {len(hits):>10,} hits {time.perf_counter() - t:6.2f}s"
            )
    shutdown_pool()


if __name__ == "__main__":
    main(sys.argv[1])
