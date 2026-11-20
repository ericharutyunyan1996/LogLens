"""Team knowledge folder through the knowledge service and the Knowledge base dialog."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import QApplication

from loglens.core.kb.knowledge import ORIGIN_TEAM
from loglens.services.knowledge_service import KnowledgeService
from loglens.ui.detail_render import LIGHT, render_findings
from loglens.ui.kb_dialog import KnowledgeDialog

PACK = """
[[entry]]
id = "pool"
noise = "important"
title = "Pool exhausted"
explanation = "No free connection."
patterns = ["pool exhausted"]
runbook = "runbooks/pool.md"
"""


def make_folder(root: Path) -> Path:
    (root / "runbooks").mkdir(parents=True)
    (root / "runbooks" / "pool.md").write_text("# Pool", encoding="utf-8")
    (root / "team.toml").write_text(PACK, encoding="utf-8")
    return root


def test_service_explains_with_team_entries_and_safe_runbooks(qapp: QApplication, tmp_path: Path) -> None:
    service = KnowledgeService(tmp_path / "kb.db")
    saved: list[str] = []
    service.teamChanged.connect(saved.append)
    folder = make_folder(tmp_path / "team")
    service.set_team_dir(str(folder))
    assert saved == [str(folder)] and service.team is not None and len(service.team.entries) == 1
    findings = [f for f in service.explain("ERROR pool exhausted for tenant 4") if f.origin == ORIGIN_TEAM]
    assert findings and findings[0].runbook.endswith("pool.md")
    html = render_findings(findings, LIGHT)
    assert "Open the runbook" in html and "runbook:" in html
    # a runbook that points outside the folder is dropped, the explanation stays
    (folder / "team.toml").write_text(PACK.replace("runbooks/pool.md", "../evil.md"), encoding="utf-8")
    service.reload_team()
    again = [f for f in service.explain("ERROR pool exhausted") if f.origin == ORIGIN_TEAM]
    assert again and again[0].runbook == ""
    service.set_team_dir("")
    assert service.team is None and not [f for f in service.explain("pool exhausted") if f.origin == ORIGIN_TEAM]
    service.close()


def test_dialog_shows_the_team_folder(qapp: QApplication, tmp_path: Path) -> None:
    service = KnowledgeService(tmp_path / "kb.db")
    service.set_team_dir(str(make_folder(tmp_path / "team")))
    dialog = KnowledgeDialog(service)
    assert dialog.team_entries.topLevelItemCount() == 1 and "1 entries" in dialog.team_status.text()
    assert not dialog.team_pull_button.isEnabled()  # not a Git folder
    dialog._team_off()
    assert dialog.team_entries.topLevelItemCount() == 0 and dialog.team_path.text() == ""
    service.close()
