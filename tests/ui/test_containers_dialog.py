"""The Containers & Kubernetes dialog: lists what the tools report, turns the selection into log sources."""

from __future__ import annotations

import time

import pytest
from PySide6.QtWidgets import QApplication

from loglens.core import containers
from loglens.core.containers import Container, ContainerError, Pod
from loglens.ui.containers_dialog import ContainersDialog


def settle(app: QApplication, cond, seconds: float = 5.0) -> None:
    end = time.time() + seconds
    while time.time() < end and not cond():
        app.processEvents()
        time.sleep(0.01)
    assert cond()


@pytest.fixture
def fakes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        containers,
        "list_containers",
        lambda **_: [Container("a1", "web", "nginx", "running", "Up"), Container("b2", "db", "pg", "exited", "Exited")],
    )
    monkeypatch.setattr(containers, "list_contexts", lambda: (["kind-a", "minikube"], "minikube"))
    monkeypatch.setattr(containers, "list_namespaces", lambda _c: ["default", "shop"])
    monkeypatch.setattr(
        containers,
        "list_pods",
        lambda _c, _n=None: [Pod("shop", "api-1", ("app", "side"), phase="Running", ready="2/2")],
    )


def test_selected_containers_become_docker_sources(qapp: QApplication, fakes: None) -> None:
    d = ContainersDialog()
    settle(qapp, lambda: d.docker_tree.topLevelItemCount() == 2)
    assert d.problem() == "Select at least one container."
    d.docker_tree.topLevelItem(0).setSelected(True)
    assert d.problem() is None
    (src,) = d.sources()
    assert src.argv[:3] == ("docker", "logs", "--timestamps") and src.argv[-1] == "a1" and src.follow


def test_pods_of_the_current_context_become_one_source_per_container(qapp: QApplication, fakes: None) -> None:
    d = ContainersDialog()
    d.tabs.setCurrentIndex(1)
    settle(qapp, lambda: d.pod_tree.topLevelItemCount() == 1)
    assert d.context_box.currentText() == "minikube"
    d.pod_tree.topLevelItem(0).setSelected(True)
    sources = d.sources()
    assert [s.title for s in sources] == ["k8s api-1/app", "k8s api-1/side"]
    assert "minikube" in sources[0].argv
    d.follow.setChecked(False)
    assert not any("--follow" in s.argv for s in d.sources())


def test_an_engine_that_is_down_is_explained_in_the_dialog(qapp: QApplication, monkeypatch: pytest.MonkeyPatch) -> None:
    def down(**_: object) -> list[Container]:
        raise ContainerError("Docker is installed but not running.")

    monkeypatch.setattr(containers, "list_containers", down)
    d = ContainersDialog()
    settle(qapp, lambda: "not running" in d.docker_note.text())


def test_linux_hosts_dialog_builds_sources_and_rejects_bad_values(qapp: QApplication) -> None:
    from loglens.ui.linuxhosts_dialog import LinuxHostsDialog

    d = LinuxHostsDialog()
    d.where.setCurrentIndex(d.where.findData("ssh"))
    d.host.setText("web1.example.com")
    d.target.setText("/var/log/app.log")
    assert d.source().argv[-2:] == ("web1.example.com", "tail -n 1000 -F /var/log/app.log")
    d.host.setText("-oProxyCommand=x")
    d.accept()
    assert "not a valid" in d.problem_label.text() and d.result() == 0
