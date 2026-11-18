"""Profile log files generically: how LogLens sees them today, and where it falls short.

    python tools/profile_logs.py <file|folder|glob> [...] [--sample 4000]

Per file: encoding, size, lines, longest line, record-start share (lines that begin with a timestamp; the rest are
continuation lines such as stack traces or dumped bodies), dominant timestamp pattern, how many lines the default
highlight rules classify (fatal / error / warning / debug / stack), and which payload kinds appear in a sample of
lines (JSON, XML, URL, SQL, fields, …). Nothing here knows about any particular application.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from loglens.core.highlight import default_rules
from loglens.core.payloads import analyze
from loglens.core.search import SearchQuery, search_multi, shutdown_pool
from loglens.core.text_source import TextLogSource
from loglens.core.timestamps import dominant_pattern
from loglens.core.units import human_size

LOG_SUFFIXES = {".log", ".txt", ".out", ".err", ".json", ".jsonl", ".csv", ".trace", ""}
RULE_NAMES = ("Fatal / Critical", "Error", "Warning", "Debug / Trace", "Stack trace", "HTTP 5xx (W3C)")


@dataclass
class FileProfile:
    path: Path
    encoding: str = ""
    size: int = 0
    lines: int = 0
    longest: int = 0
    record_share: float = 0.0
    timestamp: str = "-"
    rule_counts: dict[str, int] = field(default_factory=dict)
    payloads: Counter[str] = field(default_factory=Counter)
    sampled: int = 0
    error: str = ""


def expand(paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            files += sorted(p for p in path.rglob("*") if p.is_file() and p.suffix.lower() in LOG_SUFFIXES)
        elif path.is_file():
            files.append(path)
        else:  # absolute or relative glob, e.g. C:/logs/**/*.wer
            root = Path(path.anchor) if path.is_absolute() else Path()
            pattern = str(path.relative_to(root)) if path.is_absolute() else raw
            files += sorted(p for p in root.glob(pattern) if p.is_file())
    return files


def profile(path: Path, sample: int) -> FileProfile:
    result = FileProfile(path)
    try:
        source = TextLogSource(path)
        source.build_index()
    except OSError as exc:
        result.error = str(exc)
        return result
    result.encoding = source.encoding.display_name
    result.size = source.index.scanned
    result.lines = source.line_count()
    result.longest = source.max_line_chars
    if not result.lines:
        return result

    rows = np.unique(np.linspace(0, result.lines - 1, min(result.lines, sample)).astype(np.int64))
    sampled = [source.get_full_line(int(i), max_bytes=2_000_000) for i in rows]
    result.sampled = len(sampled)
    pattern, share = dominant_pattern(sampled)
    result.timestamp = pattern.name if pattern else "-"
    result.record_share = share
    for line in sampled:
        result.payloads.update(analyze(line).kinds)

    rules = {r.name: r for r in default_rules()}
    queries = [
        SearchQuery(rules[n].pattern, regex=rules[n].regex, case_sensitive=rules[n].case_sensitive) for n in RULE_NAMES
    ]
    counts = search_multi(source, queries)
    result.rule_counts = {name: len(hits) for name, hits in zip(RULE_NAMES, counts, strict=True)}
    return result


def report(profiles: list[FileProfile]) -> None:
    header = (
        f"{'file':<46} {'enc':<10} {'size':>9} {'lines':>9} {'longest':>9} {'records':>8} {'timestamp':<16} "
        f"{'fatal':>6} {'error':>7} {'warn':>7} {'debug':>8} {'stack':>7}  payloads (in sample)"
    )
    print(header)
    print("-" * len(header))
    for p in profiles:
        name = p.path.name if len(p.path.name) <= 45 else p.path.name[:42] + "…"
        if p.error:
            print(f"{name:<46} ERROR {p.error}")
            continue
        c = p.rule_counts
        payloads = ", ".join(f"{k} {v}" for k, v in p.payloads.most_common(5)) or "-"
        print(
            f"{name:<46} {p.encoding[:10]:<10} {human_size(p.size):>9} {p.lines:>9,} {p.longest:>9,} "
            f"{p.record_share:>7.0%} {p.timestamp:<16} {c.get('Fatal / Critical', 0):>6,} {c.get('Error', 0):>7,} "
            f"{c.get('Warning', 0):>7,} {c.get('Debug / Trace', 0):>8,} {c.get('Stack trace', 0):>7,}  {payloads}"
        )
    findings(profiles)


def findings(profiles: list[FileProfile]) -> None:
    ok = [p for p in profiles if not p.error and p.lines]
    print("\nFindings:")
    no_ts = [p.path.name for p in ok if p.timestamp == "-"]
    no_levels = [p.path.name for p in ok if p.lines > 100 and not any(p.rule_counts.get(n) for n in RULE_NAMES[:4])]
    multiline = [p.path.name for p in ok if p.timestamp != "-" and p.record_share < 0.9]
    if no_ts:
        print(f"  - no known timestamp at line start ({len(no_ts)}): {', '.join(no_ts[:8])}")
    if no_levels:
        print(f"  - no level words recognised by default rules ({len(no_levels)}): {', '.join(no_levels[:8])}")
    if multiline:
        print(
            f"  - multi-line records (<90% of lines start with a timestamp) ({len(multiline)}): "
            f"{', '.join(multiline[:8])}"
        )
    totals: Counter[str] = Counter()
    for p in ok:
        totals.update(p.payloads)
    print(f"  - payload kinds across samples: {dict(totals.most_common())}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("paths", nargs="+")
    parser.add_argument("--sample", type=int, default=4000, help="lines sampled per file for timestamps/payloads")
    args = parser.parse_args()
    files = expand(args.paths)
    if not files:
        parser.error("no files found")
    try:
        report([profile(f, args.sample) for f in files])
    finally:
        shutdown_pool()


if __name__ == "__main__":
    main()
