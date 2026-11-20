"""Other Windows servers: profiles, remote Event Log sessions, and a connection check that says what to fix.

LogLens reads a server's Event Viewer logs agentless, through the same Windows Event Log API Event Viewer uses
(``EvtOpenSession``, RPC). Nothing is installed on the server. Sign-in is either the current Windows account (domain
servers just work) or a user name and password saved per server in Windows Credential Manager: never in settings
files, never in logs. A failure is reported with the reason and the setting on the *server* that fixes it.
"""

from __future__ import annotations

import logging
import re
import socket
import sys
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any

from ..ai import credentials
from ..ai.status import scrub

if sys.platform == "win32":
    import win32evtlog

log = logging.getLogger(__name__)

RPC_PORT = 135  # RPC endpoint mapper: if nothing answers here the Event Log API cannot connect either
CONNECT_TIMEOUT_S = 4.0  # a dead address would otherwise wait ~21 s inside RPC
SECRET_PREFIX = "server:"
AUTH_METHODS = {"negotiate": "Automatic (Kerberos or NTLM)", "kerberos": "Kerberos", "ntlm": "NTLM"}
MAX_NAME = 60

NAME_RE = re.compile(r"^[\w][\w .-]{0,59}$")
HOST_RE = re.compile(
    r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?)(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*$"
)
IPV6_RE = re.compile(r"^[0-9A-Fa-f:]{2,45}$")

# Windows error codes the remote Event Log API reports
ERROR_ACCESS_DENIED = 5
ERROR_BAD_NETPATH = 53
ERROR_NETWORK_UNREACHABLE = 1231
ERROR_LOGON_FAILURE = 1326
ERROR_RPC_UNAVAILABLE = 1722
ERROR_RPC_CALL_FAILED = 1726
ERROR_RPC_FAILED = 1727
ERROR_RPC_NO_MORE_ENDPOINTS = 1753
ERROR_TIMEOUT = 1460
ERROR_NO_LOGON_SERVERS = 1311
ERROR_NOT_FOUND = 2
ERROR_CHANNEL_NOT_FOUND = 15007


class ServerStatus(StrEnum):
    CONNECTED = "connected"
    HOST_NOT_FOUND = "host_not_found"
    UNREACHABLE = "unreachable"
    RPC_UNAVAILABLE = "rpc_unavailable"
    ACCESS_DENIED = "access_denied"
    LOGON_FAILED = "logon_failed"
    TIMED_OUT = "timed_out"
    ERROR = "error"


STATUS_LABELS = {
    ServerStatus.CONNECTED: "Connected",
    ServerStatus.HOST_NOT_FOUND: "Host not found",
    ServerStatus.UNREACHABLE: "Unreachable",
    ServerStatus.RPC_UNAVAILABLE: "Event Log service not reachable",
    ServerStatus.ACCESS_DENIED: "Access denied",
    ServerStatus.LOGON_FAILED: "Sign-in failed",
    ServerStatus.TIMED_OUT: "Timed out",
    ServerStatus.ERROR: "Failed",
}


class ServerError(Exception):
    """A remote server could not be read; ``status`` says why and the message says what to fix."""

    def __init__(self, message: str, status: ServerStatus = ServerStatus.ERROR) -> None:
        super().__init__(scrub(message))
        self.status = status


@dataclass(frozen=True, slots=True)
class ServerProfile:
    """One server LogLens can read. The password is NOT part of the profile: it lives in Credential Manager."""

    name: str  # what the user calls it; unique; also the key of the saved password
    host: str  # DNS name or IP address
    use_credentials: bool = False  # False: sign in as the current Windows account
    user: str = ""  # DOMAIN\user, user@domain, or a local account on that server
    auth: str = "negotiate"  # negotiate | kerberos | ntlm

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ServerProfile | None:
        """A profile from stored settings (None when the entry is unusable): settings files may be hand-edited."""
        try:
            profile = cls(
                name=str(data["name"]).strip(),
                host=str(data["host"]).strip(),
                use_credentials=data.get("use_credentials") is True,
                user=str(data.get("user", "")).strip(),
                auth=str(data.get("auth", "negotiate")),
            )
        except (KeyError, TypeError):
            return None
        if profile.auth not in AUTH_METHODS:
            profile = ServerProfile(profile.name, profile.host, profile.use_credentials, profile.user)
        return profile if validate(profile) is None else None

    @property
    def sign_in(self) -> str:
        return f"saved credentials ({self.user})" if self.use_credentials else "this Windows account"


def validate(profile: ServerProfile) -> str | None:
    """Why ``profile`` cannot be used, or None."""
    if not NAME_RE.match(profile.name):
        return "Give the server a name (letters, digits, spaces, '.', '-', '_'; up to 60 characters)."
    host = profile.host
    if not host or not (HOST_RE.match(host) or IPV6_RE.match(host)):
        return f"'{host}' is not a valid host name or IP address."
    if profile.use_credentials and not profile.user.strip():
        return "Enter the user name for the saved credentials (DOMAIN\\user, user@domain, or a local account)."
    return None


def secret_name(profile: ServerProfile) -> str:
    return f"{SECRET_PREFIX}{profile.name}"


def server_password(profile: ServerProfile) -> str | None:
    """The saved password of ``profile`` (None when it signs in as the Windows account or none is saved)."""
    if not profile.use_credentials:
        return None
    try:
        return credentials.load_secret(secret_name(profile))
    except OSError as exc:
        raise ServerError(f"Could not read the saved password of '{profile.name}': {exc}") from exc


def forget_password(profile: ServerProfile) -> bool:
    """Delete the saved password of ``profile`` (verified); True when one was stored."""
    return bool(credentials.delete_secrets([secret_name(profile)]))


def split_user(user: str, host: str) -> tuple[str, str | None]:
    """(user, domain) for the login: ``DOMAIN\\user`` and ``user@domain`` are understood; a bare name is a *local*
    account of the server (its domain is the server itself)."""
    user = user.strip()
    if "\\" in user:
        domain, _, name = user.partition("\\")
        return name, (host.partition(".")[0] if domain in (".", "") else domain)
    if "@" in user:
        return user, None  # a UPN: Windows resolves the domain from it
    return user, host.partition(".")[0]


def explain(code: int | None, profile: ServerProfile, detail: str = "") -> ServerError:  # noqa: PLR0911 - one per code
    """The failure for Windows error ``code`` on ``profile``, with what to change on the server (or here)."""
    host = profile.host
    who = f"'{profile.user}'" if profile.use_credentials else "the Windows account LogLens runs as"
    if code == ERROR_RPC_UNAVAILABLE or code in (ERROR_RPC_NO_MORE_ENDPOINTS, ERROR_RPC_CALL_FAILED, ERROR_RPC_FAILED):
        return ServerError(
            f"{host} did not answer the Event Log service. Check that the server is on, that it is reachable (VPN?), "
            "and that the Windows Firewall rule group 'Remote Event Log Management' is enabled on it "
            "(RPC, TCP 135 and the dynamic RPC ports).",
            ServerStatus.RPC_UNAVAILABLE,
        )
    if code == ERROR_ACCESS_DENIED:
        extra = (
            " The password may also be wrong."
            if profile.use_credentials
            else " If you need another account, edit the server and choose saved credentials."
        )
        return ServerError(
            f"Access denied: {who} may not read the event logs of {host}. Add the account to the 'Event Log Readers' "
            "group on that server (the Security log needs Administrators). For a local (non-domain) administrator "
            "account, 'UAC remote restrictions' can block this: set LocalAccountTokenFilterPolicy=1 on the server."
            + extra,
            ServerStatus.ACCESS_DENIED,
        )
    if code in (ERROR_LOGON_FAILURE, ERROR_NO_LOGON_SERVERS):
        return ServerError(
            f"Sign-in to {host} failed: the user name or password is wrong (or the domain controller is unreachable).",
            ServerStatus.LOGON_FAILED,
        )
    if code in (ERROR_BAD_NETPATH, ERROR_NETWORK_UNREACHABLE):
        return ServerError(f"{host} could not be reached over the network.", ServerStatus.UNREACHABLE)
    if code == ERROR_TIMEOUT:
        return ServerError(f"{host} did not answer in time.", ServerStatus.TIMED_OUT)
    if code in (ERROR_NOT_FOUND, ERROR_CHANNEL_NOT_FOUND):
        return ServerError(f"That event log does not exist on {host}. {detail}".strip(), ServerStatus.ERROR)
    return ServerError(f"Reading {host} failed (Windows error {code}): {detail or 'unknown error'}", ServerStatus.ERROR)


def precheck(
    profile: ServerProfile,
    *,
    resolve: Callable[..., Any] = socket.getaddrinfo,
    connect: Callable[..., Any] = socket.create_connection,
) -> None:
    """Fail fast and clearly (a few seconds, not RPC's ~21) when the server's name or RPC port cannot be reached."""
    try:
        resolve(profile.host, RPC_PORT)
    except OSError as exc:
        raise ServerError(
            f"The name '{profile.host}' could not be resolved. Check the spelling, DNS, and the VPN connection.",
            ServerStatus.HOST_NOT_FOUND,
        ) from exc
    try:
        connect((profile.host, RPC_PORT), timeout=CONNECT_TIMEOUT_S).close()
    except TimeoutError as exc:
        raise ServerError(
            f"{profile.host} did not answer on port {RPC_PORT} within {CONNECT_TIMEOUT_S:.0f} seconds: the server is "
            "off, unreachable (VPN?), or a firewall drops the traffic (Remote Event Log Management must be allowed).",
            ServerStatus.UNREACHABLE,
        ) from exc
    except OSError as exc:
        raise ServerError(
            f"{profile.host} refused the connection on port {RPC_PORT}: the RPC service is not listening or a firewall "
            "rejects it (enable 'Remote Event Log Management' on the server).",
            ServerStatus.UNREACHABLE,
        ) from exc


def open_session(profile: ServerProfile, password: str | None = None, *, api: Any = None) -> Any:
    """A remote Event Log session for ``profile`` (RPC connects on first use). Raises ServerError for bad settings."""
    api = api or win32evtlog
    problem = validate(profile)
    if problem:
        raise ServerError(problem)
    if not profile.use_credentials:
        login: tuple[Any, ...] = (profile.host, None, None, None, api.EvtRpcLoginAuthDefault)
    else:
        if not password:
            raise ServerError(
                f"No saved password for '{profile.name}': edit the server and enter it.", ServerStatus.LOGON_FAILED
            )
        user, domain = split_user(profile.user, profile.host)
        flag = {
            "kerberos": api.EvtRpcLoginAuthKerberos,
            "ntlm": api.EvtRpcLoginAuthNTLM,
            "negotiate": api.EvtRpcLoginAuthNegotiate,
        }[profile.auth]
        login = (profile.host, user, domain, password, flag)
    try:
        return api.EvtOpenSession(login, api.EvtRpcLogin, 0, 0)
    except Exception as exc:  # pywintypes.error
        raise explain(getattr(exc, "winerror", None), profile, str(getattr(exc, "strerror", exc))) from exc


def connect(profile: ServerProfile, *, api: Any = None, precheck_fn: Callable[[ServerProfile], None] = precheck) -> Any:
    """Pre-check, then open the session with the saved password: the one entry point readers use."""
    precheck_fn(profile)
    return open_session(profile, server_password(profile), api=api)


@dataclass(frozen=True, slots=True)
class ServerCheck:
    """Result of "Test" for one server."""

    status: ServerStatus
    message: str
    channels: int = 0
    seconds: float = 0.0

    @property
    def ok(self) -> bool:
        return self.status is ServerStatus.CONNECTED

    @property
    def label(self) -> str:
        return STATUS_LABELS[self.status]


def check_server(
    profile: ServerProfile,
    password: str | None = None,
    *,
    api: Any = None,
    precheck_fn: Callable[[ServerProfile], None] = precheck,
) -> ServerCheck:
    """A real test: name and port, sign-in, read access to the System log, and how many channels the server has.

    ``password`` overrides the saved one (an unsaved edit in the dialog)."""
    api = api or win32evtlog
    started = time.monotonic()
    try:
        precheck_fn(profile)
        session = open_session(profile, password if password is not None else server_password(profile), api=api)
        result = api.EvtQuery("System", api.EvtQueryChannelPath | api.EvtQueryReverseDirection, "*", session)
        api.EvtNext(result, 1)  # the first RPC call: this is where the server authenticates and authorizes us
        enumerator = api.EvtOpenChannelEnum(session)
        channels = 0
        while api.EvtNextChannelPath(enumerator) is not None:
            channels += 1
    except ServerError as exc:
        return ServerCheck(exc.status, str(exc), seconds=time.monotonic() - started)
    except Exception as exc:  # noqa: BLE001 - pywintypes.error from the calls above
        failure = explain(getattr(exc, "winerror", None), profile, str(getattr(exc, "strerror", exc)))
        return ServerCheck(failure.status, str(failure), seconds=time.monotonic() - started)
    took = time.monotonic() - started
    return ServerCheck(
        ServerStatus.CONNECTED,
        f"Signed in to {profile.host} as {profile.sign_in}; the System log can be read; {channels:,} event channels "
        f"found ({took:.1f} s).",
        channels,
        took,
    )


def list_channels(profile: ServerProfile, *, api: Any = None) -> list[str]:
    """The event channels of ``profile``'s server (common ones first)."""
    api = api or win32evtlog
    session = connect(profile, api=api)
    try:
        enumerator = api.EvtOpenChannelEnum(session)
        names: list[str] = []
        while (name := api.EvtNextChannelPath(enumerator)) is not None:
            names.append(name)
    except Exception as exc:  # pywintypes.error
        raise explain(getattr(exc, "winerror", None), profile, str(getattr(exc, "strerror", exc))) from exc
    common = ("Application", "System", "Security", "Setup")
    return [c for c in common if c in names] + sorted((n for n in names if n not in common), key=str.lower)
