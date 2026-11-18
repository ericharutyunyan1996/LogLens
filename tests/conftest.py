"""Shared fixtures. One QApplication for the whole session (offscreen), usable by service and widget tests."""

from __future__ import annotations

import os
import time
from collections.abc import Callable

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("QT_QPA_FONTDIR", "C:/Windows/Fonts")

from PySide6.QtWidgets import QApplication


@pytest.fixture(scope="session")
def qapp() -> QApplication:
    app = QApplication.instance()
    if not isinstance(app, QApplication):
        app = QApplication([])
    return app


@pytest.fixture
def wait_for(qapp: QApplication) -> Callable[..., None]:
    """Process Qt events until ``condition()`` is true (or fail after ``timeout`` seconds)."""

    def wait(condition: Callable[[], object], timeout: float = 20.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            qapp.processEvents()
            if condition():
                return
            time.sleep(0.01)
        raise AssertionError("timed out waiting for condition")

    return wait


@pytest.fixture(autouse=True)
def _isolated_app_data(tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> None:
    """Never read or write the developer's real %APPDATA%\\LogLens settings during tests."""
    monkeypatch.setenv("APPDATA", str(tmp_path_factory.mktemp("appdata")))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path_factory.mktemp("localappdata")))
