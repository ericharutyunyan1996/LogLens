"""Docker / Kubernetes log sources: discovery parsing, safe command building, failure explanations, real tools."""

from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace

import pytest

from loglens.core import containers
from loglens.core.containers import Container, ContainerError, Pod


def fake(stdout: str = "", stderr: str = "", code: int = 0):
    calls: list[list[str]] = []

    def run(argv, **_kwargs):
        calls.append(list(argv))
        return SimpleNamespace(stdout=stdout, stderr=stderr, returncode=code)

    run.calls = calls  # type: ignore[attr-defined]
    return run


def test_list_containers_parses_and_puts_running_first() -> None:
    lines = "\n".join(
        json.dumps(d)
        for d in (
            {"ID": "b" * 64, "Names": "zeta", "Image": "nginx", "State": "exited", "Status": "Exited (0) 1h ago"},
            {"ID": "a" * 64, "Names": "alpha,other", "Image": "redis", "State": "running", "Status": "Up 2 hours"},
        )
    )
    runner = fake(lines + "\nnot json\n")
    found = containers.list_containers(runner=runner)
    assert [c.name for c in found] == ["alpha", "zeta"]
    assert "-a" in runner.calls[0]
    assert "-a" not in fake().calls


def test_list_containers_stopped_excluded_by_default_flag() -> None:
    runner = fake("")
    containers.list_containers(include_stopped=False, runner=runner)
    assert "-a" not in runner.calls[0]


def test_docker_source_builds_an_argument_list() -> None:
    c = Container("abc123", "web", "nginx", "running", "Up")
    src = containers.docker_source(c, tail=50, since="15m", follow=True)
    assert src.argv == ("docker", "logs", "--timestamps", "--tail", "50", "--since", "15m", "--follow", "abc123")
    assert containers.docker_source(c, tail=None, follow=False).argv[-1] == "abc123"


@pytest.mark.parametrize("bad", ["--all", "a b", "x;rm", "$(id)", "", "-v"])
def test_docker_names_that_look_like_options_or_shell_are_refused(bad: str) -> None:
    with pytest.raises(ContainerError):
        containers.docker_source(Container(bad, bad, "i", "running", ""))


def test_since_is_validated() -> None:
    c = Container("abc", "web", "i", "running", "")
    with pytest.raises(ContainerError):
        containers.docker_source(c, since="1h --privileged")


POD_JSON = json.dumps(
    {
        "items": [
            {
                "metadata": {"namespace": "shop", "name": "api-1"},
                "spec": {"containers": [{"name": "app"}, {"name": "sidecar"}], "nodeName": "n1"},
                "status": {
                    "phase": "Running",
                    "containerStatuses": [{"ready": True, "restartCount": 2}, {"ready": False, "restartCount": 1}],
                },
            },
            {
                "metadata": {"namespace": "default", "name": "db-0"},
                "spec": {"containers": [{"name": "pg"}]},
                "status": {},
            },
        ]
    }
)


def test_list_pods_parses_and_sorts() -> None:
    runner = fake(POD_JSON)
    pods = containers.list_pods("kind-learn", None, runner=runner)
    assert [(p.namespace, p.name) for p in pods] == [("default", "db-0"), ("shop", "api-1")]
    api = pods[1]
    assert api.containers == ("app", "sidecar") and api.ready == "1/2" and api.restarts == 3
    assert runner.calls[0][:3] == ["kubectl", "--context", "kind-learn"] and "-A" in runner.calls[0]


def test_list_pods_one_namespace_and_invalid_names() -> None:
    runner = fake(POD_JSON)
    containers.list_pods("ctx", "shop", runner=runner)
    assert runner.calls[0][-3:-1] == ["-n", "shop"] or "shop" in runner.calls[0]
    with pytest.raises(ContainerError):
        containers.list_pods("ctx", "Shop; rm", runner=fake(POD_JSON))
    with pytest.raises(ContainerError):
        containers.list_pods("--kubeconfig=x", None, runner=fake(POD_JSON))


def test_kubernetes_sources_one_per_container() -> None:
    pod = Pod("shop", "api-1", ("app", "sidecar"))
    sources = containers.kubernetes_sources("kind-learn", pod, tail=200, since="1h")
    assert [s.title for s in sources] == ["k8s api-1/app", "k8s api-1/sidecar"]
    argv = sources[0].argv
    assert argv[:3] == ("kubectl", "--context", "kind-learn")
    assert "logs" in argv and "--timestamps" in argv and "--tail=200" in argv and "--since=1h" in argv
    assert "--follow" in argv and sources[0].follow


def test_kubernetes_previous_run_is_not_followed() -> None:
    pod = Pod("shop", "api-1", ("app",))
    (src,) = containers.kubernetes_sources("c", pod, previous=True)
    assert "--previous" in src.argv and "--follow" not in src.argv and not src.follow
    assert src.title == "k8s api-1 (previous)"


def test_kubernetes_source_refuses_hostile_pod_names() -> None:
    with pytest.raises(ContainerError):
        containers.kubernetes_sources("c", Pod("ns", "--all-namespaces", ("a",)))
    with pytest.raises(ContainerError):
        containers.kubernetes_sources("c", Pod("ns", "p", ("a",)), containers=["-f"])


@pytest.mark.parametrize(
    ("tool", "text", "expect"),
    [
        ("docker", "failed to connect to the docker API at npipe:////./pipe/x", "not running"),
        ("docker", "Error: No such container: abc", "no longer exists"),
        ("kubectl", "dial tcp 127.0.0.1:1: connectex: actively refused it", "not reachable"),
        ("kubectl", 'pods is forbidden: User "x" cannot list', "forbidden"),
        ("kubectl", "error: You must be logged in to the server (Unauthorized)", "sign-in"),
        ("kubectl", 'Error from server (NotFound): pods "p" not found', "Not found"),
        ("kubectl", "something odd happened", "kubectl failed"),
    ],
)
def test_failures_are_explained(tool: str, text: str, expect: str) -> None:
    assert expect in containers.explain_failure(tool, text)


def test_a_failing_command_becomes_a_container_error() -> None:
    with pytest.raises(ContainerError, match="not running"):
        containers.list_containers(runner=fake(stderr="cannot connect to the docker API daemon", code=1))


def test_timeout_and_missing_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    def slow(argv, **_):
        raise subprocess.TimeoutExpired(argv, 1)

    with pytest.raises(ContainerError, match="did not answer"):
        containers.list_containers(runner=slow)
    monkeypatch.setattr(containers, "find_tool", lambda _name: None)
    with pytest.raises(ContainerError, match="not installed"):
        containers.list_containers()


# ---- the real tools (skipped when Docker / a cluster is not up on this machine) ----------------------------------------
def _docker_up() -> bool:
    try:
        containers.list_containers()
    except ContainerError:
        return False
    return True


def _cluster_up() -> str | None:
    try:
        names, current = containers.list_contexts()
        if not names:
            return None
        containers.list_pods(current or names[0], None)
    except ContainerError:
        return None
    return current or names[0]


@pytest.mark.skipif(not _docker_up(), reason="Docker engine is not running here")
def test_real_docker_lists_containers_and_reads_a_log() -> None:
    found = containers.list_containers()
    if not found:
        pytest.skip("no containers on this Docker engine")
    src = containers.docker_source(found[0], tail=5, follow=False)
    done = subprocess.run(
        [containers.find_tool("docker") or "docker", *src.argv[1:]],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert done.returncode == 0


@pytest.mark.skipif(_cluster_up() is None, reason="no reachable Kubernetes cluster here")
def test_real_kubernetes_lists_pods_and_reads_a_log() -> None:
    context = _cluster_up()
    assert context
    pods = [p for p in containers.list_pods(context, None) if p.phase == "Running" and p.containers]
    assert pods
    (src, *_) = containers.kubernetes_sources(context, pods[0], tail=5, follow=False)
    done = subprocess.run(
        [containers.find_tool("kubectl") or "kubectl", *src.argv[1:]],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert done.returncode == 0
