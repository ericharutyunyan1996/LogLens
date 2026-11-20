"""File → Containers & Kubernetes…: pick Docker containers or Kubernetes pods and open their logs as live tabs."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..core import containers
from ..core.containers import Container, ContainerError, LogSource, Pod
from .payload_view import Background

ALL_NAMESPACES = "(all namespaces)"
SINCE_CHOICES = (
    ("Everything kept", ""),
    ("Last 15 minutes", "15m"),
    ("Last hour", "1h"),
    ("Last 6 hours", "6h"),
    ("Last day", "1d"),
)


class ContainersDialog(QDialog):
    """Two tabs (Docker, Kubernetes) listing what is running; the chosen ones become ``sources()``."""

    def __init__(self, parent: QWidget | None = None) -> None:  # noqa: PLR0915 - builds the whole dialog
        super().__init__(parent)
        self.setWindowTitle("Containers && Kubernetes")
        self.resize(760, 560)
        self._containers: list[Container] = []
        self._pods: list[Pod] = []
        self._context = ""
        self._docker_loader = Background(self, self._on_containers)
        self._context_loader = Background(self, self._on_contexts)
        self._pod_loader = Background(self, self._on_pods)

        intro = QLabel(
            "Reads logs through your own <b>docker</b> and <b>kubectl</b> (their sign-in and settings apply; "
            "LogLens stores nothing). Each choice opens as a live tab.",
            self,
        )
        intro.setWordWrap(True)
        intro.setObjectName("dialogNote")

        self.tabs = QTabWidget(self)
        # Docker tab
        docker = QWidget(self)
        self.docker_tree = QTreeWidget(docker)
        self.docker_tree.setHeaderLabels(["Name", "Image", "State", "Status"])
        self.docker_tree.setRootIsDecorated(False)
        self.docker_tree.setSelectionMode(QTreeWidget.SelectionMode.ExtendedSelection)
        self.docker_stopped = QCheckBox("Include stopped containers", docker)
        self.docker_stopped.setChecked(True)
        self.docker_stopped.toggled.connect(self.refresh_docker)
        self.docker_refresh = QPushButton("Refresh", docker)
        self.docker_refresh.clicked.connect(self.refresh_docker)
        self.docker_note = QLabel("", docker)
        self.docker_note.setWordWrap(True)
        top = QHBoxLayout()
        top.addWidget(self.docker_stopped)
        top.addStretch(1)
        top.addWidget(self.docker_refresh)
        dl = QVBoxLayout(docker)
        dl.addLayout(top)
        dl.addWidget(self.docker_tree, 1)
        dl.addWidget(self.docker_note)
        self.tabs.addTab(docker, "Docker")

        # Kubernetes tab
        kube = QWidget(self)
        self.context_box = QComboBox(kube)
        self.context_box.currentIndexChanged.connect(self._context_changed)
        self.namespace_box = QComboBox(kube)
        self.namespace_box.currentIndexChanged.connect(self._namespace_changed)
        self.pod_tree = QTreeWidget(kube)
        self.pod_tree.setHeaderLabels(["Namespace", "Pod", "Containers", "Ready", "Status", "Restarts"])
        self.pod_tree.setRootIsDecorated(False)
        self.pod_tree.setSelectionMode(QTreeWidget.SelectionMode.ExtendedSelection)
        self.previous = QCheckBox("Logs of the previous run (a pod that restarted or crashed)", kube)
        self.kube_refresh = QPushButton("Refresh", kube)
        self.kube_refresh.clicked.connect(self.refresh_kubernetes)
        self.kube_note = QLabel("", kube)
        self.kube_note.setWordWrap(True)
        form = QFormLayout()
        row = QHBoxLayout()
        row.addWidget(self.context_box, 1)
        row.addWidget(self.kube_refresh)
        form.addRow("Cluster (context)", row)
        form.addRow("Namespace", self.namespace_box)
        kl = QVBoxLayout(kube)
        kl.addLayout(form)
        kl.addWidget(self.pod_tree, 1)
        kl.addWidget(self.previous)
        kl.addWidget(self.kube_note)
        self.tabs.addTab(kube, "Kubernetes")

        # shared options
        self.since = QComboBox(self)
        for label, value in SINCE_CHOICES:
            self.since.addItem(label, value)
        self.tail = QSpinBox(self)
        self.tail.setRange(0, 1_000_000)
        self.tail.setSingleStep(500)
        self.tail.setValue(1000)
        self.tail.setSpecialValueText("All")
        self.follow = QCheckBox("Keep following new lines", self)
        self.follow.setChecked(True)
        options = QFormLayout()
        options.addRow("Start with", self.since)
        options.addRow("Most recent lines", self.tail)
        options.addRow("", self.follow)

        self.problem_label = QLabel("", self)
        self.problem_label.setObjectName("dialogProblem")
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel, self)
        self.open_button = buttons.addButton("Open logs", QDialogButtonBox.ButtonRole.AcceptRole)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(intro)
        layout.addWidget(self.tabs, 1)
        layout.addLayout(options)
        layout.addWidget(self.problem_label)
        layout.addWidget(buttons)

        self.tabs.currentChanged.connect(self._tab_changed)
        self.refresh_docker()

    # ---- docker ----------------------------------------------------------------------------------
    def refresh_docker(self) -> None:
        self.docker_note.setText("Looking for containers…")
        include = self.docker_stopped.isChecked()
        self._docker_loader.start(lambda: containers.list_containers(include_stopped=include))

    def _on_containers(self, result: object) -> None:
        self.docker_tree.clear()
        if isinstance(result, ContainerError):
            self._containers = []
            self.docker_note.setText(str(result))
            return
        if isinstance(result, Exception):
            self.docker_note.setText(f"Could not list containers: {result}")
            return
        self._containers = list(result) if isinstance(result, list) else []
        for c in self._containers:
            item = QTreeWidgetItem([c.name, c.image, c.state, c.status])
            item.setData(0, Qt.ItemDataRole.UserRole, c.id)
            self.docker_tree.addTopLevelItem(item)
        for col in range(3):
            self.docker_tree.resizeColumnToContents(col)
        self.docker_note.setText("" if self._containers else "No containers found.")

    # ---- kubernetes ------------------------------------------------------------------------------
    def _tab_changed(self, index: int) -> None:
        if index == 1 and self.context_box.count() == 0:
            self.refresh_kubernetes()

    def refresh_kubernetes(self) -> None:
        self.kube_note.setText("Reading your kubeconfig…")
        self._context_loader.start(containers.list_contexts)

    def _on_contexts(self, result: object) -> None:
        self.context_box.blockSignals(True)
        self.context_box.clear()
        self.context_box.blockSignals(False)
        if isinstance(result, Exception):
            self.kube_note.setText(str(result))
            return
        names, current = result if isinstance(result, tuple) else ([], "")
        if not names:
            self.kube_note.setText("No Kubernetes clusters are configured (kubeconfig has no contexts).")
            return
        self.context_box.blockSignals(True)
        for name in names:
            self.context_box.addItem(name, name)
        self.context_box.setCurrentIndex(max(0, self.context_box.findData(current)))
        self.context_box.blockSignals(False)
        self._context_changed()

    def _context_changed(self) -> None:
        self._context = str(self.context_box.currentData() or "")
        self.namespace_box.blockSignals(True)
        self.namespace_box.clear()
        self.namespace_box.addItem(ALL_NAMESPACES, None)
        self.namespace_box.blockSignals(False)
        self.refresh_pods()

    def _namespace_changed(self) -> None:
        self.refresh_pods()

    def refresh_pods(self) -> None:
        if not self._context:
            return
        context, namespace = self._context, self.namespace_box.currentData()
        self.kube_note.setText(f"Looking for pods in '{context}'…")
        self._pod_loader.start(lambda: (containers.list_pods(context, namespace), _safe_namespaces(context, namespace)))

    def _on_pods(self, result: object) -> None:
        self.pod_tree.clear()
        if isinstance(result, Exception):
            self._pods = []
            self.kube_note.setText(str(result))
            return
        pods, namespaces = result if isinstance(result, tuple) else ([], [])
        self._pods = list(pods)
        if namespaces and self.namespace_box.count() == 1:
            self.namespace_box.blockSignals(True)
            for ns in namespaces:
                self.namespace_box.addItem(ns, ns)
            self.namespace_box.blockSignals(False)
        for index, pod in enumerate(self._pods):
            item = QTreeWidgetItem(
                [pod.namespace, pod.name, ", ".join(pod.containers), pod.ready, pod.phase, str(pod.restarts)]
            )
            item.setData(0, Qt.ItemDataRole.UserRole, index)
            self.pod_tree.addTopLevelItem(item)
        for col in range(1, 6):
            self.pod_tree.resizeColumnToContents(col)
        self.kube_note.setText("" if self._pods else "No pods here.")

    # ---- result ----------------------------------------------------------------------------------
    def selected_containers(self) -> list[Container]:
        ids = {str(i.data(0, Qt.ItemDataRole.UserRole)) for i in self.docker_tree.selectedItems()}
        return [c for c in self._containers if c.id in ids]

    def selected_pods(self) -> list[Pod]:
        picked = {int(i.data(0, Qt.ItemDataRole.UserRole)) for i in self.pod_tree.selectedItems()}
        return [self._pods[n] for n in sorted(picked) if n < len(self._pods)]

    def problem(self) -> str | None:
        if self.tabs.currentIndex() == 0:
            return None if self.selected_containers() else "Select at least one container."
        return None if self.selected_pods() else "Select at least one pod."

    def sources(self) -> list[LogSource]:
        tail = self.tail.value() or None
        since = str(self.since.currentData() or "") or None
        follow = self.follow.isChecked()
        if self.tabs.currentIndex() == 0:
            return [
                containers.docker_source(c, tail=tail, since=since, follow=follow) for c in self.selected_containers()
            ]
        out: list[LogSource] = []
        for pod in self.selected_pods():
            out += containers.kubernetes_sources(
                self._context, pod, tail=tail, since=since, follow=follow, previous=self.previous.isChecked()
            )
        return out

    def accept(self) -> None:
        message = self.problem()
        self.problem_label.setText(message or "")
        if message is None:
            super().accept()

    def done(self, result: int) -> None:
        for loader in (self._docker_loader, self._context_loader, self._pod_loader):
            loader.cancel()
        super().done(result)


def _safe_namespaces(context: str, namespace: str | None) -> list[str]:
    """Namespace names for the picker, only fetched with the first (all namespaces) listing; failure is not fatal."""
    if namespace is not None:
        return []
    try:
        return containers.list_namespaces(context)
    except ContainerError:
        return []
