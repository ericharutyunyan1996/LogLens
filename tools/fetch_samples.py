"""Download public sample logs for testing LogLens on formats we don't produce ourselves.

    python tools/fetch_samples.py [--only loghub|elastic] [--force]

Sources (research datasets / official examples, plain-text logs):
  * LogPai Loghub — 2k-line samples of 16 real systems + ground-truth templates (useful later for pattern mining):
    https://github.com/logpai/loghub
  * Elastic examples — Apache / Nginx access logs, Nginx JSON logs:
    https://github.com/elastic/examples/tree/master/Common%20Data%20Formats

Each dataset is saved into its own new folder under ``samples/internet/<dataset>`` (git-ignored). Files are only
written to disk; nothing downloaded is executed or imported. Analyse them with ``tools/profile_logs.py``.
"""

from __future__ import annotations

import argparse
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "samples" / "internet"
TIMEOUT_S = 60
MAX_BYTES = 50 * 1024 * 1024  # refuse anything unexpectedly large

LOGHUB = "https://raw.githubusercontent.com/logpai/loghub/master"
LOGHUB_SYSTEMS = (
    "Android", "Apache", "BGL", "HDFS", "HPC", "Hadoop", "HealthApp", "Linux",
    "Mac", "OpenSSH", "OpenStack", "Proxifier", "Spark", "Thunderbird", "Windows", "Zookeeper",
)  # fmt: skip
ELASTIC = "https://raw.githubusercontent.com/elastic/examples/master/Common%20Data%20Formats"


@dataclass(frozen=True, slots=True)
class Download:
    dataset: str  # folder under samples/internet
    url: str
    filename: str


def manifest() -> list[Download]:
    items: list[Download] = []
    for system in LOGHUB_SYSTEMS:
        for suffix in ("_2k.log", "_2k.log_templates.csv"):
            name = f"{system}{suffix}"
            items.append(Download(f"loghub-{system.lower()}", f"{LOGHUB}/{system}/{name}", name))
    items.extend(
        Download(f"elastic-{name.replace('_', '-')}", f"{ELASTIC}/{name}/{name}", f"{name}.log")
        for name in ("apache_logs", "nginx_logs", "nginx_json_logs")
    )
    return items


def fetch(item: Download, force: bool) -> str:
    folder = TARGET / item.dataset
    destination = folder / item.filename
    if destination.exists() and not force:
        return "exists"
    folder.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(item.url, headers={"User-Agent": "LogLens-sample-fetcher"})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_S) as response:
            data = response.read(MAX_BYTES + 1)
    except (urllib.error.URLError, TimeoutError) as exc:
        return f"failed: {exc}"
    if len(data) > MAX_BYTES:
        return "skipped: too large"
    destination.write_bytes(data)
    return f"{len(data) / 1024:,.0f} KB"


def write_sources(items: list[Download]) -> None:
    lines = ["# Downloaded sample logs (not part of the repo)", "", "| dataset | file | source |", "|---|---|---|"]
    lines += [f"| {i.dataset} | {i.filename} | {i.url} |" for i in items]
    (TARGET / "SOURCES.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--only", choices=["loghub", "elastic"])
    parser.add_argument("--force", action="store_true", help="download again even if the file exists")
    args = parser.parse_args()
    items = [i for i in manifest() if not args.only or i.dataset.startswith(args.only)]
    TARGET.mkdir(parents=True, exist_ok=True)
    for item in items:
        print(f"{item.dataset:<28} {item.filename:<34} {fetch(item, args.force)}")
    write_sources(items)
    print(f"\nSaved under {TARGET}. Next: python tools/profile_logs.py {TARGET}")


if __name__ == "__main__":
    sys.exit(main())
