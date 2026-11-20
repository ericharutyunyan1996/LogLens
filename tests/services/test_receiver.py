"""Receivers: syslog (UDP / TCP) and HTTP lines end up, timestamped, in a log file."""

from __future__ import annotations

import socket
import time
import urllib.request
from pathlib import Path

import pytest

from loglens.services.receiver import Sink, start_receiver


def wait_lines(path: Path, count: int, seconds: float = 5.0) -> list[str]:
    end = time.time() + seconds
    while time.time() < end:
        lines = path.read_text(encoding="utf-8").splitlines()
        if len(lines) >= count:
            return lines
        time.sleep(0.02)
    return path.read_text(encoding="utf-8").splitlines()


def test_udp_syslog(tmp_path: Path) -> None:
    sink = Sink(tmp_path / "in.log")
    rx = start_receiver("syslog-udp", sink)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(b"<34>Nov 13 10:00:00 host app: disk full", ("127.0.0.1", rx.port))
        lines = wait_lines(sink.path, 1)
    finally:
        rx.stop()
    assert len(lines) == 1 and "[127.0.0.1] <34>Nov 13 10:00:00 host app: disk full" in lines[0]
    assert lines[0][:4].isdigit()  # arrival time first, so the log has a timeline


def test_tcp_syslog_keeps_every_line_and_flattens_multiline(tmp_path: Path) -> None:
    sink = Sink(tmp_path / "in.log")
    rx = start_receiver("syslog-tcp", sink)
    try:
        with socket.create_connection(("127.0.0.1", rx.port)) as s:
            s.sendall(b"first\nsecond\r\n\nthird\n")
        lines = wait_lines(sink.path, 3)
    finally:
        rx.stop()
    assert [line.split("] ", 1)[1] for line in lines] == ["first", "second", "third"]


def test_http_post_lines_and_limits(tmp_path: Path) -> None:
    sink = Sink(tmp_path / "in.log")
    rx = start_receiver("http", sink)
    try:
        request = urllib.request.Request(f"http://127.0.0.1:{rx.port}/logs", data=b"a\nb", method="POST")
        with urllib.request.urlopen(request, timeout=5) as response:
            assert response.status == 204
        lines = wait_lines(sink.path, 2)
        big = urllib.request.Request(f"http://127.0.0.1:{rx.port}/logs", data=b"x" * 2_000_000, method="POST")
        # an oversized body is refused: depending on timing the client sees the 413 or a reset connection
        with pytest.raises((urllib.error.HTTPError, urllib.error.URLError, ConnectionError)):
            urllib.request.urlopen(big, timeout=5)
    finally:
        rx.stop()
    assert [line.split("] ", 1)[1] for line in lines] == ["a", "b"] and sink.count == 2


def test_taken_port_and_unknown_kind(tmp_path: Path) -> None:
    sink = Sink(tmp_path / "in.log")
    first = start_receiver("syslog-tcp", sink)
    try:
        with pytest.raises(OSError):
            start_receiver("syslog-tcp", sink, port=first.port)
    finally:
        first.stop()
    with pytest.raises(ValueError):
        start_receiver("ftp", sink)
