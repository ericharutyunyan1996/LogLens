"""Saved credentials can be deleted from Windows Credential Manager, and the deletion is verified.

Uses the REAL Credential Manager with throw-away names (``LogLens/LogLensTest-…``), removed again by the test.
"""

from __future__ import annotations

import sys
import uuid

import pytest

from loglens.core.ai import credentials

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows Credential Manager")


@pytest.fixture
def names():
    made = [f"LogLensTest-{uuid.uuid4().hex}" for _ in range(3)]
    yield made
    for name in made:
        credentials.delete_secret(name)  # never leave a test credential behind


def test_saved_secrets_are_listed_and_deleted_for_real(names: list[str]) -> None:
    credentials.save_secret(names[0], "first-secret-value")
    credentials.save_secret(names[1], "second-secret-value")
    assert credentials.load_secret(names[0]) == "first-secret-value"
    assert credentials.saved_secrets(names) == names[:2]  # names[2] was never stored
    assert credentials.delete_secrets(names) == names[:2]  # the ones that were really there
    assert [credentials.load_secret(n) for n in names] == [None, None, None]  # gone from the storage itself
    assert credentials.saved_secrets(names) == []
    assert credentials.delete_secrets(names) == []  # deleting again is harmless


def test_a_deletion_that_did_not_happen_is_reported_not_claimed(
    names: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    credentials.save_secret(names[0], "stubborn")
    monkeypatch.setattr(credentials, "delete_secret", lambda _name: None)  # Windows "forgets" to delete
    with pytest.raises(OSError, match="still stored"):
        credentials.delete_secrets(names)
    monkeypatch.undo()
    assert credentials.delete_secrets(names) == [names[0]]
