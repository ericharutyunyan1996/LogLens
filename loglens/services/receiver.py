"""Receive logs pushed by other machines or apps: syslog over UDP / TCP and a tiny HTTP endpoint.

Everything received is appended, one line per message, to a file that LogLens follows like any other log. By default
only this computer can connect (127.0.0.1); listening on all interfaces is an explicit choice of the user.
"""

from __future__ import annotations

import logging
import socket
import socketserver
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

log = logging.getLogger(__name__)
MAX_LINE = 16_384
MAX_BODY = 1_048_576
KINDS = ("syslog-udp", "syslog-tcp", "http")


class Sink:
    """Thread-safe appender: one received message per line, timestamped with the arrival time."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self.count = 0
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"")

    def write(self, source: str, text: str) -> None:
        text = " ".join(text.replace("\x00", "").splitlines())[:MAX_LINE]
        if not text.strip():
            return
        stamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
        with self._lock, self.path.open("a", encoding="utf-8", newline="\n") as out:
            out.write(f"{stamp} [{source}] {text}\n")
            self.count += 1


class Receiver:
    """A running listener; ``stop()`` closes it. Create with :func:`start_receiver`."""

    def __init__(self, kind: str, sink: Sink, server: object, thread: threading.Thread, port: int) -> None:
        self.kind, self.sink, self._server, self._thread, self.port = kind, sink, server, thread, port

    def stop(self) -> None:
        server = self._server
        if isinstance(server, socket.socket):
            server.close()
        else:
            server.shutdown()  # type: ignore[attr-defined]
            server.server_close()  # type: ignore[attr-defined]
        self._thread.join(timeout=3)


def start_receiver(kind: str, sink: Sink, *, host: str = "127.0.0.1", port: int = 0) -> Receiver:
    """Start listening; ``port`` 0 picks a free one (see ``Receiver.port``). Raises OSError when the port is taken."""
    if kind == "syslog-udp":
        return _udp(sink, host, port)
    if kind == "syslog-tcp":
        return _tcp(sink, host, port)
    if kind == "http":
        return _http(sink, host, port)
    raise ValueError(f"unknown receiver kind {kind!r}")


def _udp(sink: Sink, host: str, port: int) -> Receiver:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))

    def serve() -> None:
        while True:
            try:
                data, addr = sock.recvfrom(MAX_LINE)
            except OSError:
                return  # socket closed by stop()
            sink.write(addr[0], data.decode("utf-8", "replace"))

    thread = threading.Thread(target=serve, name="syslog-udp", daemon=True)
    thread.start()
    return Receiver("syslog-udp", sink, sock, thread, sock.getsockname()[1])


class _TcpHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        sink: Sink = self.server.sink  # type: ignore[attr-defined]
        self.request.settimeout(60)
        try:
            for raw in self.rfile:
                sink.write(self.client_address[0], raw[:MAX_LINE].decode("utf-8", "replace"))
        except OSError:
            return


def _tcp(sink: Sink, host: str, port: int) -> Receiver:
    server = socketserver.ThreadingTCPServer((host, port), _TcpHandler)
    server.daemon_threads = True
    server.sink = sink  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, name="syslog-tcp", daemon=True)
    thread.start()
    return Receiver("syslog-tcp", sink, server, thread, server.server_address[1])


class _HttpHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        sink: Sink = self.server.sink  # type: ignore[attr-defined]
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if not 0 <= length <= MAX_BODY:
            self.send_response(413)
            self.end_headers()
            return
        body = self.rfile.read(length).decode("utf-8", "replace")
        for line in body.splitlines() or [""]:
            sink.write(self.client_address[0], line)
        self.send_response(204)
        self.end_headers()

    def log_message(self, *_args: object) -> None:
        pass


def _http(sink: Sink, host: str, port: int) -> Receiver:
    server = ThreadingHTTPServer((host, port), _HttpHandler)
    server.sink = sink  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, name="log-http", daemon=True)
    thread.start()
    return Receiver("http", sink, server, thread, server.server_address[1])
