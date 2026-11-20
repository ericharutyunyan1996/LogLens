"""Reading other Windows servers' Event Logs: profiles, sign-in, failure explanations, parallel reads.

Most tests use a FAKE Event Log API (no server needed). ``test_real_*`` at the bottom talk to a real remote Event Log
session: to this computer's own name (a true RPC round trip) and to a host that does not exist.
"""

from __future__ import annotations

import socket
import sys
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, ClassVar

import pytest

from loglens.core.ai import credentials
from loglens.core.winevent import reader, remote
from loglens.core.winevent.models import EventRecord, record_from_line
from loglens.core.winevent.remote import (
    ServerCheck,
    ServerError,
    ServerProfile,
    ServerStatus,
    check_server,
    explain,
    open_session,
    precheck,
    split_user,
    validate,
)
from loglens.settings import Settings

CURRENT = ServerProfile("Web 01", "web01.corp.example")
SAVED = ServerProfile("DB", "db01", use_credentials=True, user="CORP\\svc-logs", auth="ntlm")


class WinError(Exception):
    def __init__(self, winerror: int, strerror: str = "boom") -> None:
        super().__init__(strerror)
        self.winerror, self.strerror = winerror, strerror


class FakeApi:
    """Just enough of win32evtlog for sessions, one query and channel enumeration."""

    EvtRpcLogin = 1
    EvtRpcLoginAuthDefault = 0
    EvtRpcLoginAuthNegotiate = 1
    EvtRpcLoginAuthKerberos = 2
    EvtRpcLoginAuthNTLM = 3
    EvtQueryChannelPath = 1
    EvtQueryReverseDirection = 2

    def __init__(self, fail_at: str = "", code: int = 5, channels: int = 3) -> None:
        self.fail_at, self.code, self.channels = fail_at, code, channels
        self.logins: list[tuple[Any, ...]] = []
        self._names = [f"Chan{i}" for i in range(channels)]
        self._enum: Any = iter(())

    def _maybe_fail(self, where: str) -> None:
        if self.fail_at == where:
            raise WinError(self.code, f"failed in {where}")

    def EvtOpenSession(self, login, _cls, _timeout, _flags):  # noqa: N802
        self.logins.append(login)
        self._maybe_fail("session")
        return "SESSION"

    def EvtQuery(self, _path, _flags, _query, session):  # noqa: N802
        assert session == "SESSION"
        self._maybe_fail("query")
        return "RESULT"

    def EvtNext(self, _result, _count):  # noqa: N802
        self._maybe_fail("next")
        return []

    def EvtOpenChannelEnum(self, _session):  # noqa: N802
        self._enum = iter(self._names)
        return "ENUM"

    def EvtNextChannelPath(self, _enum):  # noqa: N802
        return next(self._enum, None)


def no_precheck(_profile: ServerProfile) -> None:
    return None


# ---- profiles ---------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("profile", "problem"),
    [
        (CURRENT, None),
        (SAVED, None),
        (ServerProfile("srv", "10.1.2.3"), None),
        (ServerProfile("srv", "fe80::1"), None),
        (ServerProfile("", "host"), "name"),
        (ServerProfile("a/b", "host"), "name"),
        (ServerProfile("x" * 61, "host"), "name"),
        (ServerProfile("srv", ""), "host name"),
        (ServerProfile("srv", "bad host"), "host name"),
        (ServerProfile("srv", "host/share"), "host name"),
        (ServerProfile("srv", "-bad.example"), "host name"),
        (ServerProfile("srv", "host", use_credentials=True, user=" "), "user name"),
    ],
)
def test_profile_validation(profile: ServerProfile, problem: str | None) -> None:
    result = validate(profile)
    assert (result is None) if problem is None else (result is not None and problem in result)


def test_profiles_round_trip_and_hand_edited_garbage_is_skipped() -> None:
    assert ServerProfile.from_dict(SAVED.to_dict()) == SAVED
    assert ServerProfile.from_dict({"name": "x"}) is None  # host missing
    assert ServerProfile.from_dict({"name": "ok", "host": "bad host"}) is None
    assert ServerProfile.from_dict({"name": "ok", "host": "h", "auth": "telepathy"}).auth == "negotiate"  # type: ignore[union-attr]
    settings = Settings()
    settings.set_servers([CURRENT, SAVED])
    settings.server_list.append({"name": "../evil", "host": "h"})  # invalid entries never reach the UI
    settings.server_list.append("not a dict")  # type: ignore[arg-type]
    assert settings.servers() == [CURRENT, SAVED]
    assert "password" not in str(settings.server_list).lower()  # profiles carry no password at all


@pytest.mark.parametrize(
    ("user", "expected"),
    [
        ("CORP\\svc", ("svc", "CORP")),
        ("svc@corp.example", ("svc@corp.example", None)),
        ("svc", ("svc", "db01")),  # a bare name is a local account of that server
        (".\\admin", ("admin", "db01")),
    ],
)
def test_user_name_forms(user: str, expected: tuple[str, str | None]) -> None:
    assert split_user(user, "db01.corp.example") == expected


# ---- sign-in -------------------------------------------------------------------------------------------------------------
def test_current_account_logs_in_without_credentials() -> None:
    api = FakeApi()
    assert open_session(CURRENT, None, api=api) == "SESSION"
    assert api.logins == [("web01.corp.example", None, None, None, FakeApi.EvtRpcLoginAuthDefault)]


@pytest.mark.parametrize(
    ("auth", "flag"),
    [
        ("negotiate", FakeApi.EvtRpcLoginAuthNegotiate),
        ("kerberos", FakeApi.EvtRpcLoginAuthKerberos),
        ("ntlm", FakeApi.EvtRpcLoginAuthNTLM),
    ],
)
def test_saved_credentials_are_split_and_use_the_chosen_method(auth: str, flag: int) -> None:
    api = FakeApi()
    profile = ServerProfile("DB", "db01", use_credentials=True, user="CORP\\svc-logs", auth=auth)
    open_session(profile, "s3cret", api=api)
    assert api.logins == [("db01", "svc-logs", "CORP", "s3cret", flag)]


def test_missing_saved_password_is_reported_before_connecting() -> None:
    api = FakeApi()
    with pytest.raises(ServerError) as raised:
        open_session(SAVED, None, api=api)
    assert raised.value.status is ServerStatus.LOGON_FAILED and "DB" in str(raised.value) and api.logins == []


def test_the_saved_password_is_used_and_forgotten_for_real_storage_semantics(monkeypatch: pytest.MonkeyPatch) -> None:
    store: dict[str, str] = {remote.secret_name(SAVED): "pw-from-store"}
    monkeypatch.setattr(credentials, "load_secret", store.get)
    monkeypatch.setattr(credentials, "delete_secret", lambda name: store.pop(name, None))
    assert remote.server_password(SAVED) == "pw-from-store"
    assert remote.server_password(CURRENT) is None  # signing in as the Windows account: no password involved
    assert remote.forget_password(SAVED) is True and store == {}
    assert remote.forget_password(SAVED) is False


# ---- failures: status + what to change -------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("code", "profile", "status", "needles"),
    [
        (1722, CURRENT, ServerStatus.RPC_UNAVAILABLE, ["web01.corp.example", "Remote Event Log Management", "135"]),
        (1753, CURRENT, ServerStatus.RPC_UNAVAILABLE, ["Remote Event Log Management"]),
        (
            5,
            CURRENT,
            ServerStatus.ACCESS_DENIED,
            ["Event Log Readers", "Windows account LogLens runs as", "choose saved credentials"],
        ),
        (
            5,
            SAVED,
            ServerStatus.ACCESS_DENIED,
            ["CORP\\svc-logs", "password may also be wrong", "LocalAccountTokenFilterPolicy"],
        ),
        (1326, SAVED, ServerStatus.LOGON_FAILED, ["user name or password is wrong"]),
        (53, CURRENT, ServerStatus.UNREACHABLE, ["could not be reached"]),
        (1460, CURRENT, ServerStatus.TIMED_OUT, ["did not answer in time"]),
        (15007, CURRENT, ServerStatus.ERROR, ["does not exist"]),
        (31337, CURRENT, ServerStatus.ERROR, ["31337"]),
    ],
)
def test_every_failure_says_what_to_fix(
    code: int, profile: ServerProfile, status: ServerStatus, needles: list[str]
) -> None:
    failure = explain(code, profile, "detail")
    assert failure.status is status
    for needle in needles:
        assert needle in str(failure), (needle, str(failure))


class Resolver:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail

    def __call__(self, *_a: Any) -> list[int]:
        if self.fail:
            raise socket.gaierror("no such host")
        return [1]


def test_precheck_tells_name_problems_from_unreachable_servers() -> None:
    with pytest.raises(ServerError) as raised:
        precheck(CURRENT, resolve=Resolver(fail=True))
    assert raised.value.status is ServerStatus.HOST_NOT_FOUND and "could not be resolved" in str(raised.value)

    def timed_out(*_a: Any, **_k: Any) -> Any:
        raise TimeoutError

    def refused(*_a: Any, **_k: Any) -> Any:
        raise ConnectionRefusedError

    with pytest.raises(ServerError) as raised:
        precheck(CURRENT, resolve=Resolver(), connect=timed_out)
    assert raised.value.status is ServerStatus.UNREACHABLE and "did not answer on port 135" in str(raised.value)
    with pytest.raises(ServerError) as raised:
        precheck(CURRENT, resolve=Resolver(), connect=refused)
    assert raised.value.status is ServerStatus.UNREACHABLE and "refused" in str(raised.value)
    precheck(
        CURRENT, resolve=Resolver(), connect=lambda *_a, **_k: SimpleNamespace(close=lambda: None)
    )  # reachable: no error


def test_a_successful_check_reports_what_was_verified() -> None:
    result = check_server(CURRENT, api=FakeApi(channels=7), precheck_fn=no_precheck)
    assert result.ok and result.channels == 7 and result.status is ServerStatus.CONNECTED
    assert (
        "web01.corp.example" in result.message
        and "System log can be read" in result.message
        and "7 event channels" in result.message
    )
    assert "this Windows account" in result.message


@pytest.mark.parametrize(
    ("fail_at", "code", "status"),
    [
        ("session", 1722, ServerStatus.RPC_UNAVAILABLE),
        ("query", 5, ServerStatus.ACCESS_DENIED),
        ("next", 5, ServerStatus.ACCESS_DENIED),
        ("session", 1326, ServerStatus.LOGON_FAILED),
    ],
)
def test_a_failed_check_names_the_stage_and_never_shows_the_password(
    fail_at: str, code: int, status: ServerStatus
) -> None:
    result = check_server(SAVED, "Sup3r-Secret-pw", api=FakeApi(fail_at, code), precheck_fn=no_precheck)
    assert not result.ok and result.status is status
    assert "Sup3r-Secret-pw" not in result.message


def test_check_uses_the_password_typed_in_the_dialog_not_only_the_saved_one(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(credentials, "load_secret", lambda _n: "OLD")
    api = FakeApi()
    check_server(SAVED, "TYPED", api=api, precheck_fn=no_precheck)
    assert api.logins[0][3] == "TYPED"


# ---- events carry their server; lines stay compatible -----------------------------------------------------------------------
def event(server: str = "", channel: str = "System") -> EventRecord:
    return EventRecord(
        channel,
        "Service Control Manager",
        7031,
        2,
        datetime(2026, 11, 20, 10, 0, tzinfo=UTC),
        5,
        "SRV1.corp",
        message="svc crashed",
        server=server,
    )


def test_event_lines_show_the_server_and_parse_back_with_the_plain_channel() -> None:
    line = event("Web 01").to_line()
    assert "[System @ Web 01]" in line
    parsed = record_from_line(line)
    assert parsed is not None and (parsed.channel, parsed.server, parsed.event_id) == (
        "System",
        "Web 01",
        7031,
    )  # "System" still equals System


def test_local_event_lines_are_unchanged() -> None:
    line = event().to_line()
    assert "[System]" in line and " @ " not in line.split("—")[0]
    parsed = record_from_line(line)
    assert parsed is not None and parsed.server == "" and parsed.channel == "System"


# ---- reader: a remote read passes the session and labels events ---------------------------------------------------------------
@pytest.mark.skipif(sys.platform != "win32", reason="Windows Event Log API")
def test_read_events_queries_through_the_remote_session_and_labels_events(monkeypatch: pytest.MonkeyPatch) -> None:
    xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="P"/><EventID>7031</EventID>'
        '<Level>2</Level><TimeCreated SystemTime="2026-11-20T10:00:00.000Z"/><EventRecordID>9</EventRecordID>'
        "<Channel>System</Channel><Computer>SRV1.corp</Computer></System></Event>"
    )
    calls: dict[str, Any] = {}

    class Evt:
        EvtQueryFilePath, EvtQueryChannelPath, EvtQueryReverseDirection, EvtQueryForwardDirection = 1, 2, 4, 8
        EvtRenderEventXml, EvtFormatMessageEvent = 1, 1
        batches: ClassVar[list[list[str]]] = [["h1"], []]

        @staticmethod
        def EvtQuery(channel, flags, xpath, session):  # noqa: N802
            calls["query"] = (channel, session)
            return "R"

        @classmethod
        def EvtNext(cls, _r, _n):  # noqa: N802
            return cls.batches.pop(0)

        @staticmethod
        def EvtRender(_h, _f):  # noqa: N802
            return xml

        @staticmethod
        def EvtOpenPublisherMetadata(provider, session):  # noqa: N802
            calls["metadata"] = (provider, session)
            return "META"

        @staticmethod
        def EvtFormatMessage(_m, _h, _f):  # noqa: N802
            return "The service crashed."

    monkeypatch.setattr(reader, "win32evtlog", Evt)
    monkeypatch.setattr(remote, "connect", lambda profile, **_k: f"SESSION:{profile.name}")
    events = list(reader.read_events(reader.EventQuery("System", server=CURRENT)))
    assert calls["query"] == ("System", "SESSION:Web 01")  # the query ran in the remote session
    assert calls["metadata"] == ("P", "SESSION:Web 01")  # and so did the message template lookup
    assert [(e.server, e.message) for e in events] == [("Web 01", "The service crashed.")]


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Event Log API")
def test_an_unreachable_server_raises_server_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    def down(_profile: ServerProfile, **_k: Any) -> Any:
        raise ServerError("no answer on port 135", ServerStatus.UNREACHABLE)

    monkeypatch.setattr(remote, "connect", down)
    with pytest.raises(reader.ServerUnavailableError, match="Web 01: no answer"):
        list(reader.read_events(reader.EventQuery("System", server=CURRENT)))


# ---- REAL: remote sessions that need no other machine ----------------------------------------------------------------------------
HERE = ServerProfile("This PC over RPC", socket.gethostname())
real = pytest.mark.skipif(sys.platform != "win32", reason="Windows Event Log API")


@real
def test_real_check_against_this_pcs_own_name_is_a_genuine_remote_session() -> None:
    result: ServerCheck = check_server(HERE)
    if result.status in (ServerStatus.UNREACHABLE, ServerStatus.RPC_UNAVAILABLE):
        pytest.skip(f"this PC does not accept remote Event Log sessions: {result.message}")
    assert result.ok, result.message
    assert result.channels > 50 and "System log can be read" in result.message


@real
def test_real_remote_read_returns_events_labelled_with_the_server() -> None:
    if not check_server(HERE).ok:
        pytest.skip("this PC does not accept remote Event Log sessions")
    events = list(reader.read_events(reader.EventQuery("Application", max_events=5, server=HERE)))
    assert events and all(e.server == HERE.name for e in events)
    assert all(f"@ {HERE.name}]" in e.to_line() for e in events)
    assert reader.list_channels(HERE)[:2] == ["Application", "System"]


@real
def test_real_unknown_host_fails_fast_and_clearly() -> None:
    result = check_server(ServerProfile("Nowhere", "no-such-host-xyz.invalid"))
    assert (
        result.status is ServerStatus.HOST_NOT_FOUND
        and result.seconds < 10
        and "could not be resolved" in result.message
    )
