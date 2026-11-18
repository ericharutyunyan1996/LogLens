"""A second launch (another process) hands its files to the running instance."""

from __future__ import annotations

import os
import subprocess
import sys
import uuid
from collections.abc import Callable

import pytest
from PySide6.QtNetwork import QLocalSocket
from PySide6.QtWidgets import QApplication

from loglens.services import single_instance
from loglens.services.single_instance import SingleInstance, server_name

CLIENT = (
    "import sys; from PySide6.QtCore import QCoreApplication; app = QCoreApplication([]); "
    "from loglens.services.single_instance import SingleInstance; "
    "sys.exit(0 if SingleInstance(sys.argv[1]).forward(sys.argv[2:]) else 3)"
)


def test_forward_to_running_instance(qapp: QApplication, wait_for: Callable[..., None]) -> None:
    name = f"LogLens-test-{uuid.uuid4().hex}"
    assert not SingleInstance(name).forward(["a.log"])  # nobody listening yet
    running = SingleInstance(name)
    assert running.listen()
    received: list[list[str]] = []
    running.filesReceived.connect(received.append)
    client = subprocess.Popen([sys.executable, "-c", CLIENT, name, r"C:\logs\a.log", "b.log"])
    wait_for(lambda: client.poll() is not None)
    assert client.returncode == 0  # acknowledged
    assert received == [[r"C:\logs\a.log", "b.log"]]


def test_second_instance_does_not_listen_on_the_same_name(qapp: QApplication) -> None:
    """On Windows two servers can share a pipe name: two launches at once must not both become "the" instance."""
    name = f"LogLens-test-{uuid.uuid4().hex}"
    first = SingleInstance(name)
    assert first.listen()
    second = SingleInstance(name)
    assert second.running_elsewhere()
    assert not second.listen()
    assert SingleInstance(f"{name}-other").listen()  # an unrelated name is free


def test_server_of_another_user_is_not_trusted(qapp: QApplication, monkeypatch: pytest.MonkeyPatch) -> None:
    """Anybody can create a pipe with our name first: never send it paths, and don't mistake it for LogLens."""
    name = f"LogLens-test-{uuid.uuid4().hex}"
    impostor = SingleInstance(name)
    assert impostor.listen()

    def foreign(_socket: QLocalSocket) -> bool:
        return False

    monkeypatch.setattr(single_instance, "served_by_current_user", foreign)
    client = SingleInstance(name)
    assert not client.running_elsewhere()
    assert not client.forward(["secret.log"])


@pytest.mark.skipif(sys.platform != "win32", reason="Windows sessions")
def test_server_name_is_per_session() -> None:
    import win32ts

    assert server_name("App").endswith(f"-s{win32ts.ProcessIdToSessionId(os.getpid())}")
