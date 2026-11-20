"""Plugins: nothing runs until approved, a changed file loses its approval, bad plugins never break the app."""

from __future__ import annotations

from pathlib import Path

from loglens.core import plugins
from loglens.core.plugins import describe_file, file_hash, read_source, run_analyzer, scan

GOOD = """
PLUGIN = {"name": "Orders", "version": "1.2", "api": 1, "description": "Counts orders"}

def count_orders(lines):
    return f"{sum('order' in l for l in lines)} order lines"

ANALYZERS = [{"title": "Count orders", "run": count_orders}]
SOURCES = [{"title": "Demo source", "read": lambda: iter(["one", "two\\n"])}]
FORMATS = [{"name": "orders", "regex": r"^(?P<time>\\d{4}-\\d\\d-\\d\\d) (?P<level>\\w+) (?P<message>.*)$"}]
"""


def make(folder: Path, name: str, code: str) -> Path:
    folder.mkdir(exist_ok=True)
    path = folder / name
    path.write_text(code, encoding="utf-8")
    return path


def test_nothing_runs_until_the_plugin_is_approved(tmp_path: Path) -> None:
    marker = tmp_path / "ran.txt"
    make(tmp_path / "p", "evil.py", f"open(r'{marker}', 'w').write('x')\nPLUGIN = {{'api': 1}}\n")
    (info,) = scan(tmp_path / "p", {})
    assert not info.enabled and not marker.exists() and info.status == "Off"


def test_an_approved_plugin_provides_analyzers_sources_and_formats(tmp_path: Path) -> None:
    path = make(tmp_path / "p", "orders.py", GOOD)
    (info,) = scan(tmp_path / "p", {"orders.py": file_hash(path)})
    assert info.status == "Enabled" and info.name == "Orders" and info.version == "1.2" and not info.error
    (analyzer,) = info.analyzers
    assert run_analyzer(analyzer, ["order 1", "x", "order 2"]) == "2 order lines"
    assert read_source(info.sources[0]) == ["one", "two"]
    assert [f.name for f in info.formats] == ["custom:orders"]


def test_editing_the_file_withdraws_the_approval(tmp_path: Path) -> None:
    path = make(tmp_path / "p", "orders.py", GOOD)
    approval = {"orders.py": file_hash(path)}
    path.write_text(GOOD + "\n# changed\n", encoding="utf-8")
    (info,) = scan(tmp_path / "p", approval)
    assert not info.enabled and not info.analyzers


def test_broken_plugins_are_reported_not_fatal(tmp_path: Path) -> None:
    folder = tmp_path / "p"
    cases = {
        "syntax.py": "def (:\n",
        "raises.py": "raise RuntimeError('boom')\n",
        "nometa.py": "x = 1\n",
        "oldapi.py": "PLUGIN = {'api': 99}\n",
        "badanalyzer.py": "PLUGIN = {'api': 1}\nANALYZERS = [{'title': 't'}]\n",
        "badformat.py": "PLUGIN = {'api': 1}\nFORMATS = [{'name': 'x', 'regex': '(unclosed'}]\n",
    }
    approval = {name: file_hash(make(folder, name, code)) for name, code in cases.items()}
    infos = {i.file: i for i in scan(folder, approval)}
    assert set(infos) == set(cases) and all(i.status == "Problem" for i in infos.values())
    assert "boom" in infos["raises.py"].error and "PLUGIN" in infos["nometa.py"].error
    assert "interface" in infos["oldapi.py"].error and "FORMATS" in infos["badformat.py"].error


def test_failing_analyzer_and_source_become_messages(tmp_path: Path) -> None:
    code = "PLUGIN = {'api': 1}\ndef bad(lines):\n    raise ValueError('nope')\n"
    code += "def src():\n    raise OSError('no host')\nANALYZERS = [{'title': 'bad', 'run': bad}]\nSOURCES = [{'title': 's', 'read': src}]\n"
    path = make(tmp_path / "p", "f.py", code)
    (info,) = scan(tmp_path / "p", {"f.py": file_hash(path)})
    assert "ValueError: nope" in run_analyzer(info.analyzers[0], [])
    assert "OSError: no host" in read_source(info.sources[0])[0]


def test_output_limits(tmp_path: Path, monkeypatch) -> None:
    code = "PLUGIN = {'api': 1}\nANALYZERS = [{'title': 't', 'run': lambda lines: 'x' * 300000}]\nSOURCES = [{'title': 's', 'read': lambda: (str(i) for i in range(100))}]\n"
    path = make(tmp_path / "p", "big.py", code)
    (info,) = scan(tmp_path / "p", {"big.py": file_hash(path)})
    assert len(run_analyzer(info.analyzers[0], [])) < 300_000
    monkeypatch.setattr(plugins, "MAX_SOURCE_LINES", 10)
    assert len(read_source(info.sources[0])) == 10


def test_a_missing_folder_is_fine_and_unapproved_plugins_are_described_without_running(tmp_path: Path) -> None:
    assert scan(tmp_path / "nope", {}) == []
    path = make(tmp_path / "p", "orders.py", GOOD)
    assert describe_file(path) == ("Orders", "Counts orders")
    assert describe_file(tmp_path / "missing.py") == ("", "")
