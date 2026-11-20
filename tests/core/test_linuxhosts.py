"""WSL / SSH log sources: safe command lines only."""

from __future__ import annotations

import pytest

from loglens.core.containers import ContainerError
from loglens.core.linuxhosts import explain_ssh_failure, ssh_source, wsl_source


def test_wsl_file_and_journal() -> None:
    src = wsl_source("Ubuntu-22.04", "file", "/var/log/syslog", lines=50)
    assert src.argv == ("wsl", "-d", "Ubuntu-22.04", "--", "tail", "-n", "50", "-F", "/var/log/syslog") and src.follow
    jr = wsl_source("Ubuntu", "journal", "nginx.service", follow=False)
    assert jr.argv[3:5] == ("--", "journalctl") and "-u" in jr.argv and "nginx.service" in jr.argv
    assert "-f" not in jr.argv and not jr.follow


def test_ssh_uses_batch_mode_and_one_validated_command() -> None:
    src = ssh_source("web1.example.com", "file", "/var/log/app/app.log", user="deploy", lines=200)
    assert src.argv[:5] == ("ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10")
    assert src.argv[5:7] == ("-l", "deploy") and src.argv[-2] == "web1.example.com"
    assert src.argv[-1] == "tail -n 200 -F /var/log/app/app.log"


@pytest.mark.parametrize("host", ["-oProxyCommand=calc", "a b", "x;rm -rf /", "", "$(id)"])
def test_hostile_hosts_are_refused(host: str) -> None:
    with pytest.raises(ContainerError):
        ssh_source(host, "journal")


@pytest.mark.parametrize(
    "path", ["relative.log", "/var/log/a b", "/var/log/$(id)", "/var/../etc/shadow", "/a;b", "/x`y`"]
)
def test_hostile_paths_and_units_are_refused(path: str) -> None:
    with pytest.raises(ContainerError):
        ssh_source("h", "file", path)
    with pytest.raises(ContainerError):
        wsl_source("Ubuntu", "file", path)
    with pytest.raises(ContainerError):
        ssh_source("h", "journal", "a;b")
    with pytest.raises(ContainerError):
        ssh_source("h", "file", "/ok", user="-x")


def test_ssh_failures_are_explained() -> None:
    assert "keys or ssh-agent" in explain_ssh_failure("Permission denied (publickey).")
    assert "not be found" in explain_ssh_failure("Could not resolve hostname x")
    assert "trusted" in explain_ssh_failure("Host key verification failed.")
