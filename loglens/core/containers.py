"""Docker containers and Kubernetes pods as log sources, through the user's own ``docker`` and ``kubectl``.

Nothing is installed anywhere and LogLens stores no credentials: it runs the command-line tools that are already on the
machine, with their existing configuration (Docker contexts, kubeconfig, minikube / kind / cloud clusters). Commands are
built as argument lists (never through a shell), and every name that goes into one is validated first, so a hostile
container or pod name cannot add options or run anything.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

DOCKER, KUBECTL = "docker", "kubectl"
LIST_TIMEOUT_S = 30.0
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0

DOCKER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")  # container name or id
K8S_NAME = re.compile(r"^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$")  # DNS-1123: namespace, pod, container
CONTEXT_NAME = re.compile(r"^[A-Za-z0-9][\w@:/.+=-]{0,252}$")  # kubeconfig context (may hold @ : / from cloud tools)
SINCE = re.compile(r"^[1-9]\d{0,3}[smhd]$")  # 30s, 15m, 6h, 2d


class ContainerError(Exception):
    """A user-presentable failure: the tool is missing, the engine / cluster is not running, access is denied …"""


@dataclass(frozen=True, slots=True)
class Container:
    id: str
    name: str
    image: str
    state: str  # running | exited | paused | restarting | created …
    status: str  # "Up 2 hours", "Exited (1) 3 minutes ago"


@dataclass(frozen=True, slots=True)
class Pod:
    namespace: str
    name: str
    containers: tuple[str, ...]
    init_containers: tuple[str, ...] = ()
    phase: str = ""
    ready: str = ""  # "2/3"
    restarts: int = 0
    node: str = ""


@dataclass(frozen=True, slots=True)
class LogSource:
    """One stream of log lines: the command that writes it, and what to call the tab."""

    kind: str  # "docker" | "kubernetes"
    title: str
    argv: tuple[str, ...] = field(default_factory=tuple)
    follow: bool = True


Runner = Callable[..., Any]  # subprocess.run-like; injectable for tests


def find_tool(name: str) -> str | None:
    return shutil.which(name)


def _run(argv: Sequence[str], runner: Runner = subprocess.run, timeout: float = LIST_TIMEOUT_S) -> str:
    """Run a read-only listing command and return its output; failures become ContainerError with what to do."""
    tool = argv[0]
    path = find_tool(tool) if runner is subprocess.run else tool
    if path is None:
        raise ContainerError(_missing(tool))
    try:
        done = runner(
            [path, *argv[1:]],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            creationflags=NO_WINDOW,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ContainerError(
            f"{tool} did not answer within {timeout:.0f} seconds. Is the engine or cluster responding?"
        ) from exc
    except OSError as exc:
        raise ContainerError(f"Could not run {tool}: {exc}") from exc
    if done.returncode != 0:
        raise ContainerError(explain_failure(tool, done.stderr or done.stdout or ""))
    return str(done.stdout)


def _missing(tool: str) -> str:
    if tool == DOCKER:
        return "Docker is not installed (or not on PATH). Install Docker Desktop, then reopen this window."
    return "kubectl is not installed (or not on PATH). Install it (it also ships with Docker Desktop and minikube)."


def explain_failure(tool: str, stderr: str, context: str = "") -> str:  # noqa: PLR0911 - one message per known failure
    """A short, actionable message for the usual ways ``docker`` / ``kubectl`` fail (raw output is never lost)."""
    text = " ".join(stderr.split())
    low = text.lower()
    if tool == DOCKER:
        if "docker api" in low or "daemon" in low or ("pipe" in low and "docker" in low):
            return "Docker is installed but not running. Start Docker Desktop and wait until it says it is running."
        if "no such container" in low:
            return "That container no longer exists. Refresh the list."
        if "permission denied" in low:
            return "Docker refused access (permission denied). Run Docker Desktop, or join the docker-users group."
    else:
        where = f" '{context}'" if context else ""
        if (
            "refused" in low
            or "unable to connect" in low
            or "no such host" in low
            or "i/o timeout" in low
            or "timeout" in low
        ):
            return (
                f"The Kubernetes cluster{where} is not reachable. Is it running (minikube start, Docker Desktop's "
                "Kubernetes, kind) and is the context right?"
            )
        if "forbidden" in low:
            return f"Kubernetes denied access{where} (forbidden). Your account may not read pods or logs there."
        if "unauthorized" in low or "must be logged in" in low or ("token" in low and "expired" in low):
            return f"Kubernetes sign-in{where} was rejected or expired. Log in again with your cluster's tool."
        if "notfound" in low or "not found" in low:
            return f"Not found{where}: the pod, container or namespace no longer exists. Refresh the list."
        if "context" in low and ("does not exist" in low or "not found" in low):
            return f"The context{where} does not exist in your kubeconfig."
    return f"{tool} failed: {text[:300] or 'no details'}"


# ---- validation (names reach a command line: options and shell tricks must be impossible) ----------------------------
def _check(pattern: re.Pattern[str], value: str, what: str) -> str:
    if not pattern.match(value or ""):
        raise ContainerError(f"'{value}' is not a valid {what} name.")
    return value


# ---- Docker --------------------------------------------------------------------------------------
def list_containers(*, include_stopped: bool = True, runner: Runner = subprocess.run) -> list[Container]:
    argv = [DOCKER, "ps", "--no-trunc", "--format", "{{json .}}"]
    if include_stopped:
        argv.insert(2, "-a")
    found: list[Container] = []
    for line in _run(argv, runner).splitlines():
        if not line.strip():
            continue
        try:
            data = json.loads(line)
        except ValueError:
            continue
        found.append(
            Container(
                id=str(data.get("ID", ""))[:64],
                name=str(data.get("Names", "")).split(",")[0],
                image=str(data.get("Image", "")),
                state=str(data.get("State", "")),
                status=str(data.get("Status", "")),
            )
        )
    return sorted(found, key=lambda c: (c.state != "running", c.name.lower()))


def docker_source(
    container: Container, *, tail: int | None = 1000, since: str | None = None, follow: bool = True
) -> LogSource:
    ref = container.id if DOCKER_NAME.match(container.id) else container.name
    _check(DOCKER_NAME, ref, "container")
    argv = [DOCKER, "logs", "--timestamps"]
    if tail:
        argv += ["--tail", str(int(tail))]
    if since:
        argv += ["--since", _check(SINCE, since, "time (like 15m)")]
    if follow:
        argv.append("--follow")
    return LogSource("docker", f"docker {container.name}", (*argv, ref), follow)


# ---- Kubernetes ----------------------------------------------------------------------------------
def _kubectl(context: str, *args: str) -> list[str]:
    argv = [KUBECTL]
    if context:
        argv += ["--context", _check(CONTEXT_NAME, context, "context")]
    return [*argv, *args]


def list_contexts(*, runner: Runner = subprocess.run) -> tuple[list[str], str]:
    """(all kubeconfig contexts, the current one)."""
    names = [
        n.strip() for n in _run([KUBECTL, "config", "get-contexts", "-o", "name"], runner).splitlines() if n.strip()
    ]
    try:
        current = _run([KUBECTL, "config", "current-context"], runner).strip()
    except ContainerError:
        current = ""
    return names, current


def list_namespaces(context: str, *, runner: Runner = subprocess.run) -> list[str]:
    out = _run(_kubectl(context, "get", "namespaces", "-o", "json"), runner)
    try:
        items = json.loads(out).get("items", [])
    except ValueError as exc:
        raise ContainerError("kubectl returned something that is not JSON.") from exc
    return sorted(str(i.get("metadata", {}).get("name", "")) for i in items if i.get("metadata", {}).get("name"))


def list_pods(context: str, namespace: str | None = None, *, runner: Runner = subprocess.run) -> list[Pod]:
    """Pods of one namespace, or of all namespaces when ``namespace`` is None."""
    scope = ["-A"] if namespace is None else ["-n", _check(K8S_NAME, namespace, "namespace")]
    out = _run(_kubectl(context, "get", "pods", *scope, "-o", "json"), runner)
    try:
        items = json.loads(out).get("items", [])
    except ValueError as exc:
        raise ContainerError("kubectl returned something that is not JSON.") from exc
    pods: list[Pod] = []
    for item in items:
        meta, spec, status = item.get("metadata", {}), item.get("spec", {}), item.get("status", {})
        states = status.get("containerStatuses") or []
        ready = sum(1 for s in states if s.get("ready"))
        pods.append(
            Pod(
                namespace=str(meta.get("namespace", "")),
                name=str(meta.get("name", "")),
                containers=tuple(str(c.get("name", "")) for c in spec.get("containers", [])),
                init_containers=tuple(str(c.get("name", "")) for c in spec.get("initContainers", [])),
                phase=str(status.get("phase", "")),
                ready=f"{ready}/{len(spec.get('containers', []))}",
                restarts=sum(int(s.get("restartCount", 0) or 0) for s in states),
                node=str(spec.get("nodeName", "")),
            )
        )
    return sorted(pods, key=lambda p: (p.namespace, p.name))


def kubernetes_sources(
    context: str,
    pod: Pod,
    *,
    containers: Sequence[str] | None = None,
    tail: int | None = 1000,
    since: str | None = None,
    follow: bool = True,
    previous: bool = False,
) -> list[LogSource]:
    """One source per container of ``pod`` (all of them unless ``containers`` lists some)."""
    _check(K8S_NAME, pod.namespace, "namespace")
    _check(K8S_NAME, pod.name, "pod")
    chosen = list(containers) if containers else list(pod.containers)
    sources: list[LogSource] = []
    for name in chosen:
        _check(K8S_NAME, name, "container")
        args = ["logs", pod.name, "-n", pod.namespace, "-c", name, "--timestamps"]
        if tail:
            args += [f"--tail={int(tail)}"]
        if since:
            args += [f"--since={_check(SINCE, since, 'time (like 15m)')}"]
        if previous:
            args.append("--previous")
        elif follow:
            args.append("--follow")
        label = pod.name if len(pod.containers) == 1 else f"{pod.name}/{name}"
        title = f"k8s {label}" + (" (previous)" if previous else "")
        sources.append(LogSource("kubernetes", title, tuple(_kubectl(context, *args)), follow and not previous))
    return sources


def run_logs(source: LogSource, runner: Runner = subprocess.run, timeout: float = 120.0) -> str:
    """The finished (non-following) output of a log source: for digests and checks, not for live tabs."""
    return _run(source.argv, runner, timeout)
