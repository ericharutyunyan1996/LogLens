"""The capture service: a log stream written to a file as it arrives, failures explained, stop ends the process."""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest
from PySide6.QtWidgets import QApplication

from loglens.core.containers import LogSource
from loglens.services import container_jobs
from loglens.services.container_jobs import ContainerStreamer, capture_path

PY = "python"


@pytest.fixture(autouse=True)
def _tool(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(container_jobs, "find_tool", lambda _name: sys.executable)


def wait(app: QApplication, cond, seconds: float = 15.0) -> bool:
    end = time.time() + seconds
    while time.time() < end:
        app.processEvents()
        if cond():
            return True
        time.sleep(0.02)
    return False


def test_capture_path_is_a_safe_file_name(tmp_path: Path) -> None:
    p = capture_path(tmp_path, LogSource("kubernetes", 'k8s ns/pod:"x"', ()), "20260101-000000")
    assert p.parent == tmp_path and not set('<>:"/\\|?*') & set(p.name)


def test_lines_are_written_as_they_arrive_and_the_end_is_reported(qapp: QApplication, tmp_path: Path) -> None:
    code = "import sys; [print(f'2026-01-01T00:00:0{i}Z line {i}', flush=True) for i in range(3)]"
    target = tmp_path / "out.log"
    s = ContainerStreamer(LogSource("docker", "t", (PY, "-c", code), follow=False), target)
    ended: list[bool] = []
    s.ended.connect(lambda: ended.append(True))
    s.start()
    assert wait(qapp, lambda: bool(ended))
    assert target.read_text(encoding="utf-8").splitlines()[-1].endswith("line 2")


def test_a_failing_process_reports_a_plain_explanation(qapp: QApplication, tmp_path: Path) -> None:
    code = "import sys; print('Error: No such container: abc'); sys.exit(1)"
    s = ContainerStreamer(LogSource("docker", "t", ("docker", "-c", code)), tmp_path / "f.log")
    msgs: list[str] = []
    s.failed.connect(msgs.append)
    s.start()
    assert wait(qapp, lambda: bool(msgs))
    assert "no longer exists" in msgs[0]


def test_stop_terminates_a_followed_stream(qapp: QApplication, tmp_path: Path) -> None:
    code = "import time\nwhile True:\n    print('tick', flush=True); time.sleep(0.05)"
    target = tmp_path / "f.log"
    s = ContainerStreamer(LogSource("docker", "t", (PY, "-c", code)), target)
    s.start()
    assert wait(qapp, lambda: target.exists() and target.stat().st_size > 20)
    s.stop()
    assert s._proc is not None and s._proc.poll() is not None
    size = target.stat().st_size
    time.sleep(0.3)
    assert target.stat().st_size == size


def test_missing_tool_is_reported(qapp: QApplication, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(container_jobs, "find_tool", lambda _name: None)
    s = ContainerStreamer(LogSource("docker", "t", ("docker", "logs", "x")), tmp_path / "m.log")
    msgs: list[str] = []
    s.failed.connect(msgs.append)
    s.start()
    assert msgs and "not installed" in msgs[0]
