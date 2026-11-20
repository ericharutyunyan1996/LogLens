"""Team knowledge folder: packs from a shared folder, runbook links that cannot escape it, Git pull."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from loglens.core.kb import team
from loglens.core.kb.knowledge import ORIGIN_TEAM, KBEntry, KnowledgeBase
from loglens.core.kb.team import git_pull, is_git_repo, load_folder, runbook_target

PACK = """
[[entry]]
id = "db-timeout"
noise = "important"
title = "Database timeout"
explanation = "The app could not get a connection from the pool."
causes = ["Pool exhausted"]
steps = ["Check the pool size"]
patterns = ["connection (pool|timeout)"]
runbook = "runbooks/db-timeout.md"
"""


def folder(tmp_path: Path) -> Path:
    (tmp_path / "packs").mkdir()
    (tmp_path / "packs" / "db.toml").write_text(PACK, encoding="utf-8")
    (tmp_path / "runbooks").mkdir()
    (tmp_path / "runbooks" / "db-timeout.md").write_text("# When the pool is exhausted\n1. Restart…", encoding="utf-8")
    return tmp_path


def test_entries_are_loaded_with_team_origin_and_runbook(tmp_path: Path) -> None:
    loaded = load_folder(folder(tmp_path))
    assert loaded.packs == ["packs/db.toml"] and not loaded.problems
    (entry,) = loaded.entries
    assert entry.origin == ORIGIN_TEAM and entry.runbook == "runbooks/db-timeout.md" and entry.id == "db-timeout"
    assert KBEntry.from_dict(entry.to_dict(), ORIGIN_TEAM).runbook == entry.runbook


def test_team_entries_explain_lines_and_carry_the_runbook(tmp_path: Path) -> None:
    kb = KnowledgeBase.builtin().with_entries(load_folder(folder(tmp_path)).entries)
    findings = kb.explain("2026-11-13 10:00:00 ERROR connection pool exhausted")
    mine = [f for f in findings if f.origin == ORIGIN_TEAM]
    assert mine and mine[0].runbook == "runbooks/db-timeout.md" and mine[0].source == "Team knowledge folder"


def test_bad_files_and_entries_are_reported_not_fatal(tmp_path: Path) -> None:
    root = folder(tmp_path)
    (root / "packs" / "broken.toml").write_text("this is [ not toml", encoding="utf-8")
    (root / "packs" / "badre.toml").write_text(
        '[[entry]]\nid="x"\ntitle="t"\nexplanation="e"\npatterns=["(unclosed"]\n[[entry]]\nid="db-timeout"\ntitle="dup"\nexplanation="e"\n',
        encoding="utf-8",
    )
    loaded = load_folder(root)
    text = " ".join(loaded.problems)
    assert "broken.toml" in text and "badre.toml" in text and "used twice" in text
    assert [e.id for e in loaded.entries] == ["db-timeout"]


def test_missing_folder_is_reported(tmp_path: Path) -> None:
    assert "not found" in load_folder(tmp_path / "nope").problems[0]


@pytest.mark.parametrize(
    "link",
    [
        "../outside.md",
        "..\\outside.md",
        "/etc/passwd",
        "C:\\Windows\\win.ini",
        "file:///C:/x.md",
        "javascript:alert(1)",
        "runbooks/missing.md",
        "runbooks/x.exe",
        "",
    ],
)
def test_runbook_links_cannot_leave_the_folder_or_run_things(tmp_path: Path, link: str) -> None:
    root = folder(tmp_path)
    (root / "runbooks" / "x.exe").write_bytes(b"MZ")
    (tmp_path.parent / "outside.md").write_text("x", encoding="utf-8")
    assert runbook_target(link, root) is None


def test_runbook_links_that_are_fine(tmp_path: Path) -> None:
    root = folder(tmp_path)
    assert runbook_target("https://wiki.example.com/db", root) == ("url", "https://wiki.example.com/db")
    kind, target = runbook_target("runbooks/db-timeout.md", root) or ("", "")
    assert kind == "file" and target.endswith("db-timeout.md")


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
def test_git_pull_updates_a_clone(tmp_path: Path) -> None:
    def git(*args: str, cwd: Path) -> None:
        subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)

    origin, clone = tmp_path / "origin", tmp_path / "clone"
    origin.mkdir()
    git("init", "-q", "-b", "main", cwd=origin)
    git("config", "user.email", "t@example.com", cwd=origin)
    git("config", "user.name", "t", cwd=origin)
    (origin / "a.toml").write_text(PACK, encoding="utf-8")
    git("add", ".", cwd=origin)
    git("commit", "-q", "-m", "one", cwd=origin)
    git("clone", "-q", str(origin), str(clone), cwd=tmp_path)
    assert is_git_repo(clone) and load_folder(clone).entries
    (origin / "b.toml").write_text(PACK.replace("db-timeout", "second"), encoding="utf-8")
    git("add", ".", cwd=origin)
    git("commit", "-q", "-m", "two", cwd=origin)
    ok, message = git_pull(clone)
    assert ok, message
    assert {e.id for e in load_folder(clone).entries} == {"db-timeout", "second"}


def test_git_pull_explains_a_plain_folder(tmp_path: Path) -> None:
    ok, message = git_pull(tmp_path)
    assert not ok and ("not a Git repository" in message or "not installed" in message)
    assert not is_git_repo(tmp_path)
    assert team.GIT_TIMEOUT_S > 0


def test_a_folder_inside_a_git_repository_counts_as_git(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    sub = tmp_path / "docs" / "knowledge"
    sub.mkdir(parents=True)
    assert is_git_repo(sub) and is_git_repo(tmp_path)
