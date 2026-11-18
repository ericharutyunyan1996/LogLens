"""Line search over a TextLogSource: plain/regex, case, invert. Produces sorted numpy arrays of line numbers.

Speed strategy (Python's `re` is single-threaded and holds the GIL):
* plain-text queries use ``str.find`` (case-insensitive: on a lower-cased copy of the block), much faster than `re`;
* big files are split into line-aligned byte ranges and searched in a **process pool** in parallel; this also keeps
  the UI thread responsive because the GUI process only waits for results;
* several queries can run in one pass (``search_multi``), e.g. all scrollbar-mark rules at once;
* two pools: "search" for interactive searches, "background" (small) for marks, so background work never delays
  what the user is waiting for. A pool whose worker process died is replaced by a fresh one.
"""

from __future__ import annotations

import contextlib
import logging
import os
import re
import sys
import threading
from collections import deque
from collections.abc import Callable, Sequence
from concurrent.futures import Future, ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from dataclasses import dataclass

import numpy as np

from .fileio import open_shared
from .line_index import IndexSnapshot
from .regex_tools import fold_lowered, has_cased_literals, literal_prefilter, matching_lines_prefiltered
from .text_source import TextLogSource

if sys.platform == "win32":
    import pywintypes
    import win32api
    import win32process

log = logging.getLogger(__name__)

# In-process: keep blocks small so the UI thread gets the GIL often.
SEARCH_BLOCK_BYTES = 1024 * 1024
# Parallel: bigger ranges amortise process overhead.
PARALLEL_RANGE_BYTES = 16 * 1024 * 1024
PARALLEL_MIN_BYTES = 48 * 1024 * 1024


@dataclass(frozen=True)
class SearchQuery:
    pattern: str
    regex: bool = False
    case_sensitive: bool = False
    invert: bool = False

    def compile(self) -> re.Pattern[str]:
        """The compiled pattern; raises ``re.error`` for every unusable pattern.

        ``re`` itself rejects some patterns with OverflowError ("a{4294967296}"), RecursionError (thousands of nested
        groups) or ValueError; those are re-raised as ``re.error`` so callers need a single except clause.
        """
        source = self.pattern if self.regex else re.escape(self.pattern)
        flags = re.MULTILINE
        try:
            # IGNORECASE disables sre's fast literal-prefix scan; skip it when no letter could be affected.
            if not self.case_sensitive and has_cased_literals(source, flags):
                flags |= re.IGNORECASE
            return re.compile(source, flags)
        except RecursionError as exc:
            raise re.error("the pattern is nested too deeply") from exc
        except (OverflowError, ValueError) as exc:
            raise re.error(str(exc)) from exc

    def validate(self) -> str | None:
        """Error message if the pattern is unusable, else None."""
        if not self.pattern:
            return "Empty pattern"
        try:
            self.compile()
        except re.error as exc:
            return f"Invalid regex: {exc}"
        return None

    def plan(self) -> tuple:
        """How to execute this query on a block of text:

        ("literal", needle, use_lower) · ("prefilter", pattern, literals, use_fold) · ("regex", pattern)
        """
        if not self.regex:
            if self.case_sensitive or self.pattern.lower() == self.pattern.upper():
                return ("literal", self.pattern, False)
            return ("literal", self.pattern.lower(), True)
        pat = self.compile()
        lits = literal_prefilter(pat.pattern, pat.flags)
        if lits:
            return ("prefilter", pat, lits, bool(pat.flags & re.IGNORECASE))
        return ("regex", pat)

    def matching(
        self,
        text: str,
        line0: int,
        lower: Callable[[], str] | None = None,
        *,
        folded: Callable[[], str] | None = None,
    ) -> list[int]:
        """Matching line numbers in ``text`` (ignores ``invert``).

        ``lower`` / ``folded`` may supply a cached ``text.lower()`` / ``case_fold(text)`` shared by several queries.
        """
        plan = self.plan()
        get_lower = lower or text.lower
        if plan[0] == "literal":
            return matching_lines_literal(get_lower() if plan[2] else text, plan[1], line0)
        if plan[0] == "prefilter":
            _kind, pattern, literals, use_fold = plan
            if not use_fold:
                return matching_lines_prefiltered(text, pattern, literals, line0)
            haystack = folded() if folded is not None else fold_lowered(get_lower())
            if len(haystack) != len(text):  # a character lower-cases to several ("İ"): offsets would not line up
                return matching_lines(text, pattern, line0)
            return matching_lines_prefiltered(text, pattern, literals, line0, haystack=haystack)
        return matching_lines(text, plan[1], line0)


def matching_lines(text: str, pattern: re.Pattern[str], line0: int) -> list[int]:
    """Line numbers (offset by line0) of lines in ``text`` that contain a match; one hit per line."""
    out: list[int] = []
    pos = 0  # always at the start of a line
    line = line0  # line number at pos
    while True:
        m = pattern.search(text, pos)
        if m is None:
            break
        s = m.start()
        line += text.count("\n", pos, s)
        out.append(line)
        nl = text.find("\n", s)
        if nl < 0:
            break
        pos = nl + 1
        line += 1
    return out


def matching_lines_literal(text: str, needle: str, line0: int) -> list[int]:
    """Same as matching_lines for a plain substring, using str.find (no regex engine)."""
    out: list[int] = []
    if "\n" in needle:
        return out
    pos = 0
    line = line0
    find, count = text.find, text.count
    while True:
        s = find(needle, pos)
        if s < 0:
            break
        line += count("\n", pos, s)
        out.append(line)
        nl = find("\n", s)
        if nl < 0:
            break
        pos = nl + 1
        line += 1
    return out


def _search_text(queries: Sequence[SearchQuery], text: str, line0: int, count: int) -> list[np.ndarray]:
    out = []
    lowered: list[str] = []
    folded: list[str] = []

    def lower() -> str:  # computed at most once per block, shared by all case-insensitive queries
        if not lowered:
            lowered.append(text.lower())
        return lowered[0]

    def fold() -> str:  # likewise for the case-folded text the regex prefilter looks in
        if not folded:
            folded.append(fold_lowered(lower()))
        return folded[0]

    for q in queries:
        hits = np.asarray(q.matching(text, line0, lower, folded=fold), dtype=np.int64)
        if q.invert:
            hits = np.setdiff1d(np.arange(line0, line0 + count, dtype=np.int64), hits, assume_unique=True)
        out.append(hits)
    return out


def _decode_block(data: bytes, codec: str) -> str:
    text = data.decode(codec, errors="replace").replace("\r\n", "\n")
    return text[:-1] if text.endswith("\r") else text


@dataclass(frozen=True, slots=True)
class RangeTask:
    """A line-aligned byte range of a file, searched by one worker process."""

    path: str
    codec: str
    start_byte: int
    end_byte: int
    first_line: int
    line_count: int


def _search_range(task: RangeTask, queries: tuple[SearchQuery, ...]) -> list[np.ndarray]:
    """Worker-process entry point: search one range."""
    with open_shared(task.path) as f:
        f.seek(task.start_byte)
        data = f.read(task.end_byte - task.start_byte)
    return _search_text(queries, _decode_block(data, task.codec), task.first_line, task.line_count)


# ---- process pools -------------------------------------------------------------------------------------------------
_pools: dict[str, ProcessPoolExecutor] = {}
_pool_lock = threading.Lock()
BACKGROUND_NICENESS = 5
# A dead worker breaks its pool for good; replace the pool and retry this often before giving up (a crash that
# happens again right away is likely caused by the search itself, e.g. out of memory).
BROKEN_POOL_RETRIES = 1


def _below_normal_priority() -> None:
    """Initializer for background workers: let the OS prefer interactive work (best effort)."""
    if sys.platform == "win32":
        with contextlib.suppress(pywintypes.error):
            win32process.SetPriorityClass(win32api.GetCurrentProcess(), win32process.BELOW_NORMAL_PRIORITY_CLASS)
    else:  # pragma: no cover - non-Windows
        os.nice(BACKGROUND_NICENESS)


def get_pool(name: str = "search") -> ProcessPoolExecutor:
    """Shared process pool: ``"search"`` for interactive searches, anything else = low-priority background pool."""
    with _pool_lock:
        pool = _pools.get(name)
        if pool is None:
            cpus = os.cpu_count() or 4
            if name == "search":
                pool = ProcessPoolExecutor(max_workers=max(2, min(8, cpus - 2)))
            else:
                pool = ProcessPoolExecutor(max_workers=max(2, min(6, cpus // 3)), initializer=_below_normal_priority)
            _pools[name] = pool
        return pool


def shutdown_pool() -> None:
    with _pool_lock:
        for pool in _pools.values():
            pool.shutdown(wait=False, cancel_futures=True)
        _pools.clear()


def _discard_pool(name: str, broken: ProcessPoolExecutor) -> None:
    """Forget ``broken`` (a worker process died) so the next :func:`get_pool` starts a fresh pool.

    Only drops the registry entry if it still is ``broken``: another thread may already have replaced it.
    """
    with _pool_lock:
        if _pools.get(name) is broken:
            del _pools[name]
    broken.shutdown(wait=False, cancel_futures=True)


# ---- public API ----------------------------------------------------------------------------------------------------
PartialCallback = Callable[[list[np.ndarray], int, int], None]


def search_multi(
    source: TextLogSource,
    queries: Sequence[SearchQuery],
    first: int = 0,
    last: int | None = None,
    *,
    cancel: threading.Event | None = None,
    on_partial: PartialCallback | None = None,
    parallel: bool | None = None,
    pool: str = "search",
) -> list[np.ndarray]:
    """Run several queries over lines [first, last) in one pass. Returns one sorted hit array per query.

    ``on_partial(hits_per_query, lines_done, lines_total)`` is called in file order per block.
    ``parallel=None`` decides automatically (process pool for big ranges).
    """
    queries = tuple(queries)
    snap = source.snapshot()
    last = snap.line_count if last is None else min(last, snap.line_count)
    total = max(last - first, 0)
    if total == 0 or not queries:
        return [np.empty(0, dtype=np.int64) for _ in queries]
    if parallel is None:
        parallel = snap.line_end(last - 1) - snap.line_start(first) >= PARALLEL_MIN_BYTES

    chunks: list[list[np.ndarray]] = [[] for _ in queries]

    def collect(hits: list[np.ndarray], line0: int, count: int) -> None:
        for acc, h in zip(chunks, hits, strict=True):
            acc.append(h)
        if on_partial:
            on_partial(hits, line0 + count - first, total)

    if parallel:
        _search_in_pool(_split_ranges(source, snap, first, last), queries, collect, cancel, pool)
    else:
        for line0, count, text in source.iter_blocks(first, last, SEARCH_BLOCK_BYTES, snap):
            collect(_search_text(queries, text, line0, count), line0, count)
            if cancel is not None and cancel.is_set():
                break
    return [np.concatenate(c) if c else np.empty(0, dtype=np.int64) for c in chunks]


def _split_ranges(source: TextLogSource, snap: IndexSnapshot, first: int, last: int) -> list[RangeTask]:
    tasks: list[RangeTask] = []
    line = first
    while line < last:
        start_byte = snap.line_start(line)
        boundary = int(np.searchsorted(snap.ends, start_byte + PARALLEL_RANGE_BYTES, side="left"))
        nxt = min(max(line + 1, boundary), last)
        tasks.append(
            RangeTask(str(source.path), source.encoding.codec, start_byte, snap.line_end(nxt - 1), line, nxt - line)
        )
        line = nxt
    return tasks


def _search_in_pool(
    tasks: list[RangeTask],
    queries: tuple[SearchQuery, ...],
    collect: Callable[[list[np.ndarray], int, int], None],
    cancel: threading.Event | None,
    pool: str,
) -> None:
    """Search ``tasks`` in the named pool, collecting their hits in file order.

    When a worker process dies (killed, crashed, out of memory) its pool is broken for good: it is replaced by a fresh
    one and the ranges not collected yet are searched again, once. A second failure propagates.
    """
    pending = deque(tasks)
    for attempt in range(BROKEN_POOL_RETRIES + 1):
        executor = get_pool(pool)
        try:
            _run_ranges(executor, pending, queries, collect, cancel)
        except BrokenProcessPool:
            _discard_pool(pool, executor)
            if attempt == BROKEN_POOL_RETRIES:
                raise
            log.warning("search pool %r broke (a worker process died); retrying in a fresh pool", pool)
        else:
            return


def _run_ranges(
    executor: ProcessPoolExecutor,
    pending: deque[RangeTask],
    queries: tuple[SearchQuery, ...],
    collect: Callable[[list[np.ndarray], int, int], None],
    cancel: threading.Event | None,
) -> None:
    """Search the ``pending`` ranges in ``executor``; a range leaves ``pending`` once its hits were collected."""
    futures: list[Future[list[np.ndarray]]] = []
    try:
        futures.extend(executor.submit(_search_range, task, queries) for task in pending)
        for future in futures:  # in file order, so partial results stay sorted
            hits = _result_unless_cancelled(future, cancel)
            if hits is None:
                return
            task = pending.popleft()
            collect(hits, task.first_line, task.line_count)
    finally:
        for future in futures:
            future.cancel()


def _result_unless_cancelled(
    future: Future[list[np.ndarray]], cancel: threading.Event | None
) -> list[np.ndarray] | None:
    """The future's result, or None as soon as ``cancel`` is set."""
    while cancel is None or not cancel.is_set():
        try:
            return future.result(timeout=0.1)
        except TimeoutError:
            continue
    return None


def search_source(
    source: TextLogSource,
    query: SearchQuery,
    first: int = 0,
    last: int | None = None,
    *,
    cancel: threading.Event | None = None,
    on_partial: Callable[[np.ndarray, int, int], None] | None = None,
    parallel: bool | None = None,
) -> np.ndarray:
    """Single-query convenience wrapper around :func:`search_multi`."""

    def forward(hits: list[np.ndarray], done: int, total: int) -> None:
        if on_partial is not None:
            on_partial(hits[0], done, total)

    return search_multi(
        source, [query], first, last, cancel=cancel, on_partial=forward if on_partial else None, parallel=parallel
    )[0]
