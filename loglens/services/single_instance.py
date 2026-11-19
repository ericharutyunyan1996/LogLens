"""One LogLens window per user session: a second launch hands its files to the running instance and exits.

Uses a per-user, per-session local socket (named pipe on Windows). A message is one JSON list of paths ended by a
newline. Pipe names are machine-global, so anybody could create one with our name first: a client only talks to a
server whose process runs as the same user.

An instance running elevated (the "restart as administrator" relaunch, ``--new-window``) must not call
:meth:`SingleInstance.listen`: later normal launches would otherwise hand their files to an elevated window.
"""

from __future__ import annotations

import ctypes
import getpass
import json
import logging
import os
import re
import sys

from PySide6.QtCore import QObject, Signal
from PySide6.QtNetwork import QLocalServer, QLocalSocket

if sys.platform == "win32":
    import pywintypes
    import win32api
    import win32con
    import win32pipe
    import win32security

log = logging.getLogger(__name__)
CONNECT_TIMEOUT_MS = 500
ACK_TIMEOUT_MS = 3000  # a busy (e.g. indexing) window still answers within this; otherwise open a new window
MAX_MESSAGE_BYTES = 1_000_000
MESSAGE_END = b"\n"
ACK = b"ok\n"


def server_name(app: str = "LogLens") -> str:
    """Pipe name for this user in this Windows session (each RDP / fast-user-switching session gets its own)."""
    user = re.sub(r"[^\w.-]", "_", getpass.getuser())
    session = _session_id()
    return f"{app}-{user}" if session is None else f"{app}-{user}-s{session}"


def _session_id() -> int | None:
    """The Windows session this process runs in (None elsewhere, or if Windows won't say)."""
    if sys.platform != "win32":  # pragma: no cover - Windows product
        return None
    session = ctypes.c_ulong()
    if not ctypes.windll.kernel32.ProcessIdToSessionId(os.getpid(), ctypes.byref(session)):
        return None
    return session.value


def _process_user(process: object) -> object:
    """The user SID of ``process`` (a process handle)."""
    token = win32security.OpenProcessToken(process, win32con.TOKEN_QUERY)
    try:
        return win32security.GetTokenInformation(token, win32security.TokenUser)[0]
    finally:
        win32api.CloseHandle(token)


def served_by_current_user(socket: QLocalSocket) -> bool:
    """True if the process serving ``socket``'s pipe runs as the current user.

    Anybody (another user, a service) can create a pipe with our predictable name before we do; talking to it would
    leak the paths we open and let it pose as LogLens.
    """
    if sys.platform != "win32":  # pragma: no cover - the server socket lives in a per-user location elsewhere
        return True
    try:
        pid = win32pipe.GetNamedPipeServerProcessId(int(socket.socketDescriptor()))
        process = win32api.OpenProcess(win32con.PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        try:
            server_user = _process_user(process)
        finally:
            win32api.CloseHandle(process)
        return bool(server_user == _process_user(win32api.GetCurrentProcess()))
    except pywintypes.error as exc:
        log.warning("cannot tell who serves the single-instance pipe: %s", exc.strerror)
        return False


class SingleInstance(QObject):
    filesReceived = Signal(list)  # list[str] — may be empty: "just bring the window to the front"

    def __init__(self, name: str | None = None, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._name = name or server_name()
        self._server: QLocalServer | None = None

    def _connect(self) -> QLocalSocket | None:
        """A connection to the running instance of this user, or None."""
        socket = QLocalSocket(self)
        socket.connectToServer(self._name)
        if not socket.waitForConnected(CONNECT_TIMEOUT_MS):
            socket.deleteLater()
            return None
        if not served_by_current_user(socket):
            log.warning("ignoring %s: it is served by a process of another user", self._name)
            socket.abort()
            socket.deleteLater()
            return None
        return socket

    def forward(self, paths: list[str]) -> bool:
        """Send ``paths`` to a running instance; True once it confirmed receipt (False: none running / no answer).

        Waiting for the acknowledgement matters: the caller exits right after, and a pipe closed before the other
        side read it loses the message.
        """
        socket = self._connect()
        if socket is None:
            return False
        socket.write(json.dumps(paths).encode("utf-8") + MESSAGE_END)
        socket.flush()
        acknowledged = socket.waitForReadyRead(ACK_TIMEOUT_MS) and bytes(socket.readAll().data()) == ACK
        socket.disconnectFromServer()
        return acknowledged

    def running_elsewhere(self) -> bool:
        """Another instance of this user is listening right now (a connection test only: nothing is sent)."""
        socket = self._connect()
        if socket is None:
            return False
        socket.abort()
        socket.deleteLater()
        return True

    def listen(self) -> bool:
        """Become the instance that receives files from later launches.

        False if that failed, or if another instance already listens: on Windows two servers can share one pipe name,
        so two launches at the same moment would otherwise both become "the" instance. The caller may then retry
        :meth:`forward`.
        """
        if self.running_elsewhere():
            log.info("another LogLens instance already listens on %s", self._name)
            return False
        QLocalServer.removeServer(self._name)  # a crashed instance may have left a stale pipe/socket
        server = QLocalServer(self)
        server.setSocketOptions(QLocalServer.SocketOption.UserAccessOption)
        if not server.listen(self._name):
            log.warning("single-instance server failed: %s", server.errorString())
            return False
        server.newConnection.connect(self._on_connection)
        self._server = server
        return True

    def close(self) -> None:
        """Stop listening: the pipe name is free again and the server is deleted on the event loop's next turn.

        Call it when the window shuts down; tests call it so no server outlives its test and gets destroyed with
        events still queued for it.
        """
        server, self._server = self._server, None
        if server is not None:
            server.close()
            server.deleteLater()

    def _on_connection(self) -> None:
        assert self._server is not None
        socket = self._server.nextPendingConnection()
        if socket is None:
            return
        buffer = bytearray()

        def read() -> None:
            buffer.extend(bytes(socket.readAll().data()))
            if len(buffer) > MAX_MESSAGE_BYTES:
                socket.abort()
                return
            if not buffer.endswith(MESSAGE_END):
                return  # message continues in a later chunk
            try:
                paths = json.loads(bytes(buffer).decode("utf-8"))
            except ValueError:
                log.warning("ignored malformed message from another LogLens launch")
                paths = None
            buffer.clear()
            if isinstance(paths, list):
                socket.write(ACK)
                socket.flush()
                self.filesReceived.emit([str(p) for p in paths])

        socket.readyRead.connect(read)
        socket.disconnected.connect(socket.deleteLater)
        if socket.bytesAvailable():
            read()
