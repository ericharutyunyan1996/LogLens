"""Event fact extraction (winevent.entities), diagnosis recipes and coverage warnings — all on synthetic events."""

from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta

import pytest

from loglens.core.diagnose import RECIPES, DiagnosisFinding, channels_needed, coverage_warnings, run_all
from loglens.core.diagnose.recipes import BRUTE_FORCE_ATTEMPTS, format_duration, format_time
from loglens.core.winevent.entities import (
    EventFacts,
    extract,
    has_parser,
    normalize_provider,
    parse_iso_time,
    time_change_seconds,
    to_int,
)
from loglens.core.winevent.models import EventRecord

BASE = datetime(2026, 11, 13, 8, 0, tzinfo=UTC)
SECURITY = "Microsoft-Windows-Security-Auditing"
SCM = "Service Control Manager"
WAS = "Microsoft-Windows-WAS"
KERNEL_GENERAL = "Microsoft-Windows-Kernel-General"


def ev(
    provider: str,
    event_id: int,
    *,
    at: float = 0,
    level: int = 2,
    channel: str = "System",
    message: str = "",
    **data: str,
) -> EventRecord:
    """A synthetic event ``at`` minutes after BASE."""
    return EventRecord(
        channel=channel,
        provider=provider,
        event_id=event_id,
        level=level,
        time_created=BASE + timedelta(minutes=at),
        message=message,
        data=dict(data),
    )


def run(recipe_id: str, events: list[EventRecord]) -> list[DiagnosisFinding]:
    return RECIPES[recipe_id].run(events)


# ---- crashes: Application Error / Hang, WER 1001, .NET 1026, ASP.NET 1309 ------------------------------------------
APP_ERROR_MESSAGE = (
    "Faulting application name: contoso.exe, version: 1.2.3.4, time stamp: 0x5f3e1a2b\r\n"
    "Faulting module name: contoso.core.dll, version: 2.0.0.1, time stamp: 0x6a000000\r\n"
    "Exception code: 0xc0000005\r\n"
    "Fault offset: 0x000000000004f7a1\r\n"
    "Faulting process id: 0x1A2B\r\n"
    "Faulting application start time: 0x01DD000000000000\r\n"
    "Faulting application path: C:\\Program Files\\Contoso\\contoso.exe\r\n"
    "Faulting module path: C:\\Program Files\\Contoso\\contoso.core.dll\r\n"
    "Report Id: 11111111-2222-3333-4444-555555555555\r\n"
    "Faulting package full name: \r\n"
    "Faulting package-relative application ID: "
)
APP_ERROR_NAMED = {
    "AppName": "contoso.exe",
    "AppVersion": "1.2.3.4",
    "ModuleName": "contoso.core.dll",
    "ModuleVersion": "2.0.0.1",
    "ExceptionCode": "c0000005",
    "FaultingOffset": "000000000004f7a1",
    "ProcessId": "0x1a2b",
    "AppPath": "C:\\Program Files\\Contoso\\contoso.exe",
    "ModulePath": "C:\\Program Files\\Contoso\\contoso.core.dll",
    "IntegratorReportId": "11111111-2222-3333-4444-555555555555",
}
APP_ERROR_POSITIONAL = {
    f"param{i}": value
    for i, value in enumerate(
        [
            "contoso.exe",
            "1.2.3.4",
            "5f3e1a2b",
            "contoso.core.dll",
            "2.0.0.1",
            "6a000000",
            "c0000005",
            "000000000004f7a1",
            "0x1a2b",
            "0x01dd000000000000",
            "C:\\Program Files\\Contoso\\contoso.exe",
            "C:\\Program Files\\Contoso\\contoso.core.dll",
            "11111111-2222-3333-4444-555555555555",
        ],
        start=1,
    )
}


@pytest.mark.parametrize(
    ("message", "data"),
    [("", APP_ERROR_NAMED), (APP_ERROR_MESSAGE, {}), ("", APP_ERROR_POSITIONAL)],
    ids=["named-data", "message", "positional-data"],
)
def test_application_error(message: str, data: dict[str, str]) -> None:
    facts = extract(ev("Application Error", 1000, channel="Application", message=message, **data))
    assert facts.kind == "app-crash"
    assert (facts.app_name, facts.app_version) == ("contoso.exe", "1.2.3.4")
    assert (facts.faulting_module, facts.module_version) == ("contoso.core.dll", "2.0.0.1")
    assert facts.exception_code == 0xC0000005 and facts.fault_offset == "0x4f7a1"
    assert facts.process_id == 0x1A2B
    assert facts.app_path == "C:\\Program Files\\Contoso\\contoso.exe"
    assert facts.report_id == "11111111-2222-3333-4444-555555555555"
    assert facts.extra["module_path"].endswith("contoso.core.dll")
    assert facts.subject == "contoso.exe"
    assert "C:\\Program Files\\Contoso\\contoso.exe" in facts.paths


def test_application_hang() -> None:
    named = extract(
        ev(
            "Application Hang",
            1002,
            channel="Application",
            AppName="northwind.exe",
            AppVersion="5.0.0.0",
            ProcessId="0x8d64",
            ExeFileName="C:\\Apps\\northwind.exe",
            HangType="Quiesce",
        )
    )
    assert named.kind == "app-hang" and named.app_name == "northwind.exe" and named.process_id == 0x8D64
    assert named.app_path == "C:\\Apps\\northwind.exe" and named.extra["hang_type"] == "Quiesce"
    positional = extract(ev("Application Hang", 1002, param1="northwind.exe", param2="5.0.0.0", param3="3bd4"))
    assert positional.process_id == 0x3BD4  # hex even without 0x


WER_CLR_MESSAGE = (
    "Fault bucket 123, type 5\r\nEvent Name: CLR20r3\r\nResponse: Not available\r\nCab Id: 0\r\n\r\n"
    "Problem signature:\r\nP1: fabrikam.worker.exe\r\nP2: 3.1.0.0\r\nP3: 91d14fcc\r\nP4: Fabrikam.Data\r\n"
    "P5: 3.1.0.0\r\nP6: d5703fbd\r\nP7: 1b5\r\nP8: 2a\r\nP9: System.InvalidOperationException\r\nP10: \r\n\r\n"
    "Attached files:\r\n\r\nThese files may be available here:\r\n"
    "\\\\?\\C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportArchive\\AppCrash_fabrikam\r\n\r\n"
    "Analysis symbol: \r\nRechecking for solution: 0\r\nReport Id: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\r\n"
    "Report Status: 268435456\r\nHashed bucket: \r\nCab Guid: 0"
)


def wer(event_name: str, *signature: str, at: float = 0, report_id: str = "") -> EventRecord:
    data = {f"P{i}": value for i, value in enumerate(signature, start=1)}
    return ev(
        "Windows Error Reporting",
        1001,
        at=at,
        level=4,
        channel="Application",
        EventName=event_name,
        ReportId=report_id,
        **data,
    )


def test_wer_event_named_and_message() -> None:
    appcrash = extract(
        wer("APPCRASH", "contoso.exe", "1.2.3.4", "5f3e1a2b", "contoso.core.dll", "2.0.0.1", "0", "c0000005", "4f7a1")
    )
    assert appcrash.kind == "wer-crash" and appcrash.extra["wer_event"] == "APPCRASH"
    assert appcrash.app_name == "contoso.exe" and appcrash.faulting_module == "contoso.core.dll"
    assert appcrash.exception_code == 0xC0000005 and appcrash.fault_offset == "0x4f7a1"
    clr = extract(ev("Windows Error Reporting", 1001, channel="Application", message=WER_CLR_MESSAGE))
    assert clr.kind == "wer-crash" and clr.app_name == "fabrikam.worker.exe"
    assert clr.exception_type == "System.InvalidOperationException" and clr.faulting_module == "Fabrikam.Data"
    assert clr.report_id == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    assert clr.extra["report_path"] == "C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportArchive\\AppCrash_fabrikam"
    other = extract(wer("StoreAgentInstallFailure1", "Update;Scan", "80073d02"))
    assert other.kind == "wer-report" and other.exception_code is None


DOTNET_FRAMEWORK = (
    "Application: contoso.service.exe\r\nFramework Version: v4.0.30319\r\n"
    "Description: The process was terminated due to an unhandled exception.\r\n"
    "Exception Info: System.IO.FileNotFoundException\r\n   at Contoso.Loader.Load(System.String)\r\n"
    "   at Contoso.Program.Main(System.String[])\r\n\r\n"
    "Exception Info: System.Reflection.TargetInvocationException\r\n   at System.RuntimeMethodHandle.Invoke()\r\n"
)
DOTNET_CORE = (
    "Application: contoso.api.exe\r\nCoreCLR Version: 8.0.1024.46610\r\n.NET Version: 8.0.10\r\n"
    "Description: The process was terminated due to an unhandled exception.\r\n"
    "Exception Info: System.InvalidOperationException: Sequence contains no elements\r\n"
    "   at System.Linq.ThrowHelper.ThrowNoElementsException()\r\n   at Contoso.Api.Startup.Configure()\r\n"
)


def test_dotnet_runtime_1026() -> None:
    framework = extract(ev(".NET Runtime", 1026, channel="Application", message=DOTNET_FRAMEWORK))
    assert framework.kind == "dotnet-crash" and framework.app_name == "contoso.service.exe"
    assert framework.exception_type == "System.IO.FileNotFoundException" and not framework.exception_message
    assert framework.extra["runtime_version"] == "v4.0.30319"
    assert "TargetInvocationException" in framework.extra["exception_chain"]
    assert framework.stack[0] == "Contoso.Loader.Load(System.String)" and len(framework.stack) == 3
    assert framework.failure_reason.startswith("The process was terminated")
    core = extract(ev(".NET Runtime", 1026, channel="Application", param1=DOTNET_CORE))  # no message: data only
    assert core.app_name == "contoso.api.exe" and core.extra["runtime_version"] == "8.0.1024.46610"
    assert core.exception_type == "System.InvalidOperationException"
    assert core.exception_message == "Sequence contains no elements"
    internal = extract(
        ev(
            ".NET Runtime",
            1026,
            message="Application: x.exe\r\nFramework Version: v4.0.30319\r\nDescription: The process was terminated "
            "due to an internal error in the .NET Runtime at IP 00007FFA1B2C3D4E (00007FFA1B200000) with exit code "
            "80131506.\r\n",
        )
    )
    assert internal.error_code == 0x80131506 and not internal.exception_type


ASPNET_MESSAGE = (
    "Event code: 3005 \r\nEvent message: An unhandled exception has occurred. \r\n"
    "Event time: 11/13/2026 10:15:02 AM \r\n \r\nApplication information: \r\n"
    "    Application domain: /LM/W3SVC/1/ROOT-1-1 \r\n    Trust level: Full \r\n"
    "    Application Virtual Path: /shop \r\n    Application Path: C:\\inetpub\\shop\\ \r\n"
    "    Machine name: WEB01 \r\n \r\nProcess information: \r\n    Process ID: 4242 \r\n"
    "    Process name: w3wp.exe \r\n    Account name: IIS APPPOOL\\ShopPool \r\n \r\n"
    "Exception information: \r\n    Exception type: NullReferenceException \r\n"
    "    Exception message: Object reference not set to an instance of an object.\r\n"
    "   at Shop.Cart.Total() in C:\\src\\Cart.cs:line 42\r\n \r\nRequest information: \r\n"
    "    Request URL: https://shop.example/cart \r\n    Request path: /cart \r\n"
    "    User host address: 203.0.113.7 \r\n"
)


def test_aspnet_1309() -> None:
    facts = extract(ev("ASP.NET 4.0.30319.0", 1309, level=3, channel="Application", message=ASPNET_MESSAGE))
    assert facts.kind == "aspnet-error"
    assert facts.exception_type == "NullReferenceException"
    assert facts.exception_message == "Object reference not set to an instance of an object."
    assert facts.url == "https://shop.example/cart" and facts.source_ip == "203.0.113.7"
    assert facts.app_name == "w3wp.exe" and facts.process_id == 4242
    assert facts.app_pool == "ShopPool" and facts.app_path == "C:\\inetpub\\shop\\"
    assert facts.extra["event_code"] == "3005" and facts.extra["virtual_path"] == "/shop"
    assert facts.stack == ("Shop.Cart.Total() in C:\\src\\Cart.cs:line 42",)


# ---- services and application pools ----------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("event_id", "message", "data", "expected", "extra"),
    [
        (
            7000,
            "The Contoso Sync service failed to start due to the following error: \r\n"
            "The service did not respond to the start or control request in a timely fashion.",
            {"param1": "Contoso Sync", "param2": "%%1053"},
            {
                "service_state": "failed to start",
                "error_code": 1053,
                "error_text": "The service did not respond to the start or control request in a timely fashion.",
            },
            {},
        ),
        (
            7001,
            "",
            {"param1": "Contoso Web", "param2": "Contoso Sync", "param3": "%%1068"},
            {"service_name": "Contoso Web", "error_code": 1068},
            {"depends_on": "Contoso Sync"},
        ),
        (
            7009,
            "",
            {"param1": "30000", "param2": "Contoso Sync"},
            {"service_state": "start timed out"},
            {"timeout_ms": "30000"},
        ),
        (7011, "", {"param1": "30000", "param2": "Contoso Sync"}, {}, {"timeout_ms": "30000"}),
        (7022, "", {"param1": "Contoso Sync"}, {"service_state": "hung on starting"}, {}),
        (
            7023,
            "The Contoso Sync service terminated with the following error: \r\n%%4294967290",
            {"param1": "Contoso Sync", "param2": "%%4294967290"},
            {"service_state": "terminated with an error", "error_code": 0xFFFFFFFA},
            {},
        ),
        (7024, "", {"param1": "Contoso Sync", "param2": "%%1"}, {"error_code": 1}, {}),
        (
            7031,
            "The Contoso Sync service terminated unexpectedly.  It has done this 2 time(s).  The following corrective "
            "action will be taken in 60000 milliseconds: Restart the service.",
            {},
            {"service_state": "terminated unexpectedly"},
            {"times": "2", "recovery_action": "Restart the service"},
        ),
        (
            7034,
            "",
            {"param1": "Contoso Sync", "param2": "3"},
            {"service_state": "terminated unexpectedly"},
            {"times": "3"},
        ),
        (7036, "The Contoso Sync service entered the stopped state.", {}, {"service_state": "stopped"}, {}),
        (
            7040,
            "The start type of the Contoso Sync service was changed from demand start to auto start.",
            {},
            {"service_state": "start type changed"},
            {"start_type_from": "demand start", "start_type_to": "auto start"},
        ),
        (
            7045,
            "",
            {
                "ServiceName": "Contoso Sync",
                "ImagePath": "C:\\Program Files\\Contoso\\sync.exe",
                "ServiceType": "user mode service",
                "StartType": "auto start",
                "AccountName": "LocalSystem",
            },
            {"service_state": "installed", "app_path": "C:\\Program Files\\Contoso\\sync.exe", "user": "LocalSystem"},
            {"start_type": "auto start", "service_type": "user mode service"},
        ),
    ],
)
def test_service_control_manager(
    event_id: int, message: str, data: dict[str, str], expected: dict[str, object], extra: dict[str, str]
) -> None:
    facts = extract(ev(SCM, event_id, message=message, **data))
    assert facts.kind == "service"
    expected = {"service_name": "Contoso Sync", **expected}
    assert {name: getattr(facts, name) for name in expected} == expected
    assert {name: facts.extra.get(name) for name in extra} == extra
    if event_id == 7023:
        assert not facts.error_text.startswith("%%")  # unresolved insertion strings are not shown as text


def test_service_driver_not_loaded() -> None:
    message = "The following boot-start or system-start driver(s) did not load: \r\ncontosodrv"
    assert extract(ev(SCM, 7026, message=message)).service_name == "contosodrv"


@pytest.mark.skipif(sys.platform != "win32", reason="uses the Windows message tables")
def test_service_error_text_from_windows_when_message_missing() -> None:
    facts = extract(ev(SCM, 7000, param1="Contoso Sync", param2="%%2"))
    assert facts.error_code == 2 and "cannot find the file" in facts.error_text


@pytest.mark.parametrize(
    ("event_id", "message", "data", "expected"),
    [
        (5002, "", {"AppPoolID": "ShopPool"}, {"app_pool": "ShopPool"}),
        (
            5009,
            "A process serving application pool 'ShopPool' terminated unexpectedly. The process id was '4242'. "
            "The process exit code was '0xc0000005'.",
            {},
            {"app_pool": "ShopPool", "process_id": 4242, "error_code": 0xC0000005},
        ),
        (
            5009,
            "",
            {"AppPoolID": "ShopPool", "ProcessID": "4242", "ExitCode": "-1073741819"},
            {"error_code": 0xC0000005},
        ),
        (5010, "", {"AppPoolID": "ShopPool", "ProcessID": "4242"}, {"process_id": 4242}),
        (5011, "", {"AppPoolID": "ShopPool", "ProcessID": "4242"}, {"app_pool": "ShopPool"}),
        (5013, "", {"AppPoolID": "ShopPool", "ProcessID": "4242"}, {"app_pool": "ShopPool"}),
        (5186, "", {"ProcessID": "4242", "AppPoolID": "ShopPool", "Minutes": "20"}, {"process_id": 4242}),
    ],
)
def test_was_application_pools(event_id: int, message: str, data: dict[str, str], expected: dict[str, object]) -> None:
    facts = extract(ev(WAS, event_id, message=message, **data))
    assert facts.kind == "app-pool" and facts.service_state
    assert {name: getattr(facts, name) for name in expected} == expected
    if event_id == 5186:
        assert facts.extra["idle_minutes"] == "20"


# ---- power, boot, shutdown -------------------------------------------------------------------------------------------
def test_kernel_power_41() -> None:
    blue = extract(ev("Microsoft-Windows-Kernel-Power", 41, level=1, BugcheckCode="209", BugcheckParameter1="0x10"))
    assert blue.kind == "unexpected-shutdown" and blue.error_code == 0xD1
    assert blue.extra["bugcheck_code"] == "0x000000D1" and "blue screen" in blue.failure_reason
    held = extract(ev("Microsoft-Windows-Kernel-Power", 41, BugcheckCode="0", LongPowerButtonPressDetected="true"))
    assert held.failure_reason == "power button held down" and held.error_code is None
    pressed = extract(ev("Microsoft-Windows-Kernel-Power", 41, BugcheckCode="0", PowerButtonTimestamp="13429801093"))
    assert pressed.failure_reason == "power button pressed"
    nothing = extract(ev("Microsoft-Windows-Kernel-Power", 41, BugcheckCode="0", PowerButtonTimestamp="0"))
    assert nothing.failure_reason.startswith("no bug check recorded")


def test_eventlog_markers() -> None:
    assert extract(ev("EventLog", 6005, level=4)).service_state == "started"
    assert extract(ev("EventLog", 6006, level=4)).service_state == "stopped"
    unexpected = extract(ev("EventLog", 6008, param1="4:18:36 PM", param2="\u200e7/\u200e29/\u200e2026"))
    assert unexpected.kind == "unexpected-shutdown" and unexpected.extra["previous_shutdown"] == "7/29/2026 4:18:36 PM"
    from_message = extract(
        ev("EventLog", 6008, message="The previous system shutdown at 1:02:03 AM on 3/4/2026 was unexpected.")
    )
    assert from_message.extra["previous_shutdown"] == "3/4/2026 1:02:03 AM"
    assert extract(ev("EventLog", 6013, level=4, param5="123456")).extra["uptime_seconds"] == "123456"


USER32_MESSAGE = (
    "The process C:\\Windows\\system32\\shutdown.exe (WS01) has initiated the restart of computer WS01 on behalf of "
    "user CONTOSO\\alice for the following reason: Application: Maintenance (Planned)\r\n Reason Code: 0x84040001\r\n"
    " Shutdown Type: restart\r\n Comment: monthly patching"
)


@pytest.mark.parametrize(
    "event",
    [
        ev("User32", 1074, level=4, message=USER32_MESSAGE),
        ev(
            "User32",
            1074,
            level=4,
            param1="C:\\Windows\\system32\\shutdown.exe (WS01)",
            param2="WS01",
            param3="Application: Maintenance (Planned)",
            param4="0x84040001",
            param5="restart",
            param6="monthly patching",
            param7="CONTOSO\\alice",
        ),
    ],
    ids=["message", "positional"],
)
def test_user32_1074(event: EventRecord) -> None:
    facts = extract(event)
    assert facts.kind == "planned-shutdown"
    assert facts.shutdown_initiator == "C:\\Windows\\system32\\shutdown.exe"
    assert facts.user == "CONTOSO\\alice" and facts.shutdown_reason == "Application: Maintenance (Planned)"
    assert facts.extra == {"reason_code": "0x84040001", "shutdown_type": "restart", "comment": "monthly patching"}
    assert facts.error_code is None  # the reason code is not an error


def test_kernel_general() -> None:
    changed = extract(
        ev(
            KERNEL_GENERAL,
            1,
            level=4,
            message="The system time has changed to \u200e2026\u200e-11-13T08:10:00Z.\r\n\r\n"
            "Change Reason: An application or system component changed the time.\r\n",
            NewTime="2026-11-13T08:10:00.0000000Z",
            OldTime="2026-11-13T08:00:00.0000000Z",
            TimeDeltaInMs="600000",
            ProcessName="\\Device\\HarddiskVolume3\\Windows\\System32\\svchost.exe",
            ProcessID="1234",
        )
    )
    assert changed.kind == "time-change" and time_change_seconds(changed) == 600
    assert changed.process_id == 1234 and changed.extra["change_reason"].startswith("An application")
    wrapped = extract(ev(KERNEL_GENERAL, 1, level=4, TimeDeltaInMs="4294967295"))  # unsigned 32-bit for -1 ms
    assert time_change_seconds(wrapped) == -0.001
    assert extract(ev(KERNEL_GENERAL, 12, level=4, StartTime="2026-11-13T07:59:00.5Z")).kind == "boot"
    assert extract(ev(KERNEL_GENERAL, 13, level=4, StopTime="2026-11-13T07:00:00Z")).extra["stop_time"]


# ---- security --------------------------------------------------------------------------------------------------------
def logon(event_id: int, *, at: float = 0, **data: str) -> EventRecord:
    return ev(SECURITY, event_id, at=at, level=0, channel="Security", **data)


def failed_logon(user: str, address: str, *, at: float = 0, sub_status: str = "0xc000006a") -> EventRecord:
    return logon(
        4625,
        at=at,
        TargetUserName=user,
        TargetDomainName="CONTOSO",
        Status="0xc000006d",
        SubStatus=sub_status,
        LogonType="3",
        IpAddress=address,
        WorkstationName="-",
    )


def test_security_logons() -> None:
    success = extract(
        logon(
            4624,
            TargetUserName="alice",
            TargetDomainName="CONTOSO",
            LogonType="10",
            IpAddress="203.0.113.7",
            WorkstationName="WS01",
            AuthenticationPackageName="Negotiate",
        )
    )
    assert success.kind == "logon" and success.user == "CONTOSO\\alice" and success.logon_type == 10
    assert success.logon_type_name == "remote interactive (RDP)" and success.source_ip == "203.0.113.7"
    assert success.workstation == "WS01" and success.extra["auth_package"] == "Negotiate"
    failure = extract(failed_logon("bob", "198.51.100.9"))
    assert failure.kind == "logon-failure" and failure.user == "CONTOSO\\bob"
    assert (failure.status, failure.sub_status) == (0xC000006D, 0xC000006A)
    assert failure.failure_reason == "wrong password" and failure.workstation == ""  # "-" means empty
    unknown_user = extract(failed_logon("eve", "198.51.100.9", sub_status="0x0"))
    assert unknown_user.failure_reason == "bad user name or password"  # falls back to Status


def test_security_other_events() -> None:
    lockout = extract(logon(4740, TargetUserName="bob", TargetDomainName="WS07", SubjectUserName="DC01$"))
    assert lockout.kind == "lockout" and lockout.user == "bob" and lockout.workstation == "WS07"
    explicit = extract(
        logon(
            4648,
            SubjectUserName="alice",
            SubjectDomainName="CONTOSO",
            TargetUserName="admin",
            TargetDomainName="CONTOSO",
            TargetServerName="fileserver",
            IpAddress="-",
        )
    )
    assert explicit.kind == "explicit-logon" and explicit.extra["target_user"] == "CONTOSO\\admin"
    assert explicit.extra["target_server"] == "fileserver" and explicit.source_ip == ""
    special = extract(logon(4672, SubjectUserName="admin", PrivilegeList="SeBackupPrivilege\r\n\t\t\tSeDebugPrivilege"))
    assert special.kind == "special-logon" and special.extra["privileges"] == "SeBackupPrivilege SeDebugPrivilege"
    clock = extract(
        logon(
            4616,
            SubjectUserName="alice",
            SubjectDomainName="CONTOSO",
            PreviousTime="2026-11-13T08:00:00.000000000Z",
            NewTime="2026-11-13T09:00:00.500000000Z",
            ProcessName="C:\\Windows\\System32\\cmd.exe",
            ProcessId="0x1f4",
        )
    )
    assert clock.kind == "time-change" and time_change_seconds(clock) == 3600.5 and clock.process_id == 500


def test_log_cleared() -> None:
    security = extract(
        ev("Microsoft-Windows-Eventlog", 1102, channel="Security", SubjectUserName="alice", SubjectDomainName="CONTOSO")
    )
    assert security.kind == "log-cleared" and security.user == "CONTOSO\\alice"
    assert security.extra["channel"] == "Security"
    system = extract(ev("Microsoft-Windows-Eventlog", 104, level=4, SubjectUserName="bob", Channel="Application"))
    assert system.extra["channel"] == "Application" and system.user == "bob"


# ---- installs and updates --------------------------------------------------------------------------------------------
MSI_FAILED = (
    "Windows Installer installed the product. Product Name: Contoso Agent. Product Version: 4.2.0. Product Language: "
    "1033. Manufacturer: Contoso Ltd. Installation success or error status: 1603."
)


def test_msi_installer() -> None:
    failed = extract(ev("MsiInstaller", 1033, level=4, channel="Application", message=MSI_FAILED))
    assert failed.kind == "installer" and failed.product_name == "Contoso Agent" and failed.product_version == "4.2.0"
    assert failed.error_code == 1603 and failed.extra == {
        "manufacturer": "Contoso Ltd",
        "action": "install",
        "outcome": "failed",
    }
    ok = extract(ev("MsiInstaller", 1033, level=4, param1="Contoso Agent", param2="4.2.0", param4="0"))
    assert ok.extra["outcome"] == "success" and ok.error_code == 0
    reboot = extract(ev("MsiInstaller", 1034, level=4, param1="Contoso Agent", param4="3010"))
    assert reboot.extra == {"action": "removal", "outcome": "success"}
    done = extract(
        ev("MsiInstaller", 11707, level=4, param1="Product: Contoso Agent -- Installation completed successfully.")
    )
    assert done.product_name == "Contoso Agent" and done.extra == {"action": "install", "outcome": "success"}
    broken = extract(ev("MsiInstaller", 11708, message="Product: Contoso Agent -- Installation failed."))
    assert broken.extra["outcome"] == "failed"
    removed = extract(ev("MsiInstaller", 11724, message="Product: Contoso Agent -- Removal completed successfully."))
    assert removed.extra == {"action": "removal", "outcome": "success"}


def test_windows_update_and_servicing() -> None:
    wu = "Microsoft-Windows-WindowsUpdateClient"
    installed = extract(ev(wu, 19, level=4, updateTitle="Contoso Driver Update 1.0", updateGuid="{0}"))
    assert installed.kind == "update" and installed.update_title == "Contoso Driver Update 1.0"
    assert installed.extra["outcome"] == "success"
    failed = extract(ev(wu, 20, errorCode="0x80070070", updateTitle="Contoso Security Update (KB0000001)"))
    assert failed.error_code == 0x80070070 and failed.extra["outcome"] == "failed"
    from_message = extract(
        ev(
            wu,
            20,
            message="Installation Failure: Windows failed to install the following update with error 0x80073D02: "
            "9ABC-Contoso.App.",
        )
    )
    assert from_message.update_title == "9ABC-Contoso.App" and from_message.error_code == 0x80073D02
    started = extract(
        ev(wu, 43, level=4, message="Installation Started: Windows has started installing the following update: Pack 2")
    )
    assert started.update_title == "Pack 2" and started.extra["outcome"] == "pending"
    package = extract(
        ev(
            "Microsoft-Windows-Servicing",
            2,
            level=4,
            channel="Setup",
            PackageIdentifier="KB0000002",
            IntendedPackageStateTextized="Installed",
            ErrorCode="0x0",
        )
    )
    assert package.update_title == "KB0000002" and package.extra == {"state": "Installed", "outcome": "success"}


# ---- generic and helpers ---------------------------------------------------------------------------------------------
def test_unknown_events_get_generic_facts() -> None:
    facts = extract(
        ev(
            "Contoso-App",
            5,
            channel="Application",
            message="Could not open C:\\Data\\contoso\\config.json: 0x80070005. Also tried \\\\fs01\\share\\cfg.json "
            "and C:\\Program Files (x86)\\Contoso App\\bin\\tool.exe.",
        )
    )
    assert facts.kind == "generic" and facts.error_code == 0x80070005 and facts.codes == (0x80070005,)
    assert facts.paths == (
        "C:\\Data\\contoso\\config.json",  # no trailing ":" or "."
        "\\\\fs01\\share\\cfg.json",
        "C:\\Program Files (x86)\\Contoso App\\bin\\tool.exe",
    )
    prose = extract(
        ev("Contoso-App", 6, message="The process C:\\Tools\\a.exe ran on behalf of user NT AUTHORITY\\SYSTEM")
    )
    assert prose.paths == ("C:\\Tools\\a.exe",)
    assert extract(ev("Contoso-App", 7)).items() == []


def test_helpers() -> None:
    assert normalize_provider("Microsoft-Windows-Security-Auditing") == "security-auditing"
    assert normalize_provider("ASP.NET 2.0.50727.0") == "asp.net"
    assert has_parser("Service Control Manager", 7031) and not has_parser("Contoso", 1)
    assert to_int("%%1053") == 1053 and to_int("-1073741819") == 0xC0000005 and to_int("0x1F") == 31
    assert to_int("ff", hexadecimal=True) == 255 and to_int("-") is None and to_int("abc") is None
    assert parse_iso_time("\u200e2026\u200e-11-13T05:50:16.185759900Z") == datetime(
        2026, 11, 13, 5, 50, 16, 185759, UTC
    )
    assert parse_iso_time("nope") is None
    facts = EventFacts(kind="service", service_name="Contoso Sync", error_code=0x80070005, codes=(0x80070005,))
    assert facts.subject == "Contoso Sync"
    assert ("error_code", "0x80070005") in facts.items() and ("codes", "0x80070005") in facts.items()
    assert format_duration(timedelta(days=2, hours=3, minutes=5)) == "2 d 3 h"
    assert format_duration(timedelta(hours=3, seconds=20)) == "3 h"
    assert format_duration(timedelta(seconds=45)) == "45 s" and format_duration(timedelta()) == "0 s"


# ---- recipes ---------------------------------------------------------------------------------------------------------
def crash_chain(at: float, app: str = "contoso.exe") -> list[EventRecord]:
    message = DOTNET_CORE.replace("contoso.api.exe", app)
    return [
        ev(".NET Runtime", 1026, at=at, channel="Application", message=message),
        ev(
            "Application Error",
            1000,
            at=at + 0.05,
            channel="Application",
            **{**APP_ERROR_NAMED, "AppName": app, "ExceptionCode": "e0434352"},
        ),
        wer(
            "CLR20r3",
            app,
            "1.2.3.4",
            "0",
            "Contoso.Api",
            "1.0",
            "0",
            "1b5",
            "2a",
            "System.InvalidOperationException",
            at=at + 0.2,
            report_id="11111111-2222-3333-4444-555555555555",
        ),
    ]


def test_crash_recipe_groups_one_crash_and_counts_repeats() -> None:
    single = run("crashes", crash_chain(0))
    assert len(single) == 1
    finding = single[0]
    assert finding.title == "contoso.exe crashed" and finding.severity == "error" and finding.confidence == "high"
    assert len(finding.evidence) == 3 and finding.time == BASE + timedelta(minutes=0.2)
    assert "System.InvalidOperationException: Sequence contains no elements" in finding.summary
    assert any("Reliability Monitor" in step for step in finding.next_steps)
    repeated = run("crashes", crash_chain(0) + crash_chain(30) + crash_chain(60) + crash_chain(5, app="other.exe"))
    by_title = {f.title: f for f in repeated}
    assert by_title["contoso.exe crashed 3 times"].severity == "critical"
    assert "other.exe crashed" in by_title
    assert any("What changed" in step for step in by_title["contoso.exe crashed 3 times"].next_steps)


def test_crash_recipe_wer_only_package_names_and_hangs() -> None:
    only_wer = run("crashes", [wer("APPCRASH", "lonely.exe", "1.0", "0", "x.dll", "1.0", "0", "c0000409", "10")])
    assert only_wer[0].confidence == "medium" and "stack buffer overrun" in only_wer[0].summary
    package = "Contoso.LockScreen_1.0.0.0_neutral__abcdefghijklm"
    store = run(
        "crashes",
        [
            ev("Application Error", 1000, channel="Application", AppName="LockScreen.exe", ExceptionCode="c000027b"),
            wer("MoAppCrash", package, "praid:App", "1.0.0.0", "0", "ui.dll", "1.0", "0", "c000027b", "10", at=0.1),
        ],
    )
    assert [f.title for f in store] == ["LockScreen.exe crashed"] and len(store[0].evidence) == 2
    hangs = run(
        "crashes",
        [
            wer("MoAppHang", "Contoso.Notes_1.0.0.0_x64__abcdefghijklm", "praid:App", at=0),
            wer("MoAppHang", "Contoso.Notes_1.1.0.0_x64__abcdefghijklm", "praid:App", at=600),
            ev("Application Hang", 1002, at=900, channel="Application", AppName="paint.exe", AppVersion="1.0"),
        ],
    )
    titles = {f.title: f for f in hangs}
    assert set(titles) == {
        "Contoso.Notes_1.1.0.0_x64__abcdefghijklm stopped responding 2 times",
        "paint.exe stopped responding",
    }
    assert titles["paint.exe stopped responding"].severity == "warning"
    assert any("dump" in step for step in titles["paint.exe stopped responding"].next_steps)


def test_crash_recipe_ignores_other_events() -> None:
    noise = [wer("StoreAgentInstallFailure1", "Update", "80073d02"), ev("Contoso", 1, channel="Application")]
    assert run("crashes", noise) == []


def test_restart_recipe_blue_screen_with_hung_shutdown() -> None:
    events = [
        ev("User32", 1074, at=-10, level=4, message=USER32_MESSAGE),
        ev(KERNEL_GENERAL, 12, at=0, level=4),
        ev("Microsoft-Windows-Kernel-Power", 41, at=0.2, level=1, BugcheckCode="209"),
        ev("EventLog", 6008, at=0.3, param1="7:49:00 AM", param2="11/13/2026"),
        ev("EventLog", 6005, at=0.3, level=4),
    ]
    findings = run("restarts", events)
    unclean = [f for f in findings if f.severity == "critical"]
    assert len(unclean) == 1 and unclean[0].title == "Unexpected restart — blue screen 0x000000D1"
    assert "probably hung while shutting down" in unclean[0].summary
    assert "11/13/2026 7:49:00 AM was unexpected" in unclean[0].summary
    assert any("WinDbg" in step for step in unclean[0].next_steps)
    assert {f.severity for f in findings} == {"critical", "info"}  # plus the requested restart itself
    power = run("restarts", [ev("Microsoft-Windows-Kernel-Power", 41, level=1, BugcheckCode="0")])
    assert power[0].title == "Unexpected restart or power loss" and any("UPS" in s for s in power[0].next_steps)


def test_restart_recipe_inferred_and_clean() -> None:
    unflagged = [
        ev(KERNEL_GENERAL, 12, at=0, level=4),
        ev("EventLog", 6005, at=0.5, level=4),
        ev(KERNEL_GENERAL, 12, at=600, level=4),
        ev("EventLog", 6005, at=600.5, level=4),
    ]
    inferred = run("restarts", unflagged)
    assert [(f.title, f.severity, f.confidence) for f in inferred] == [
        ("Restart without a logged shutdown", "error", "medium")
    ]
    clean = [
        ev(KERNEL_GENERAL, 12, at=0, level=4),
        ev("EventLog", 6005, at=0.5, level=4),
        ev("User32", 1074, at=499, level=4, message=USER32_MESSAGE.replace("CONTOSO\\alice", "NT AUTHORITY\\SYSTEM")),
        ev("User32", 1074, at=499.5, level=4, message=USER32_MESSAGE.replace("CONTOSO\\alice", "NT AUTHORITY\\SYSTEM")),
        ev(KERNEL_GENERAL, 13, at=500, level=4),
        ev("EventLog", 6006, at=500.1, level=4),
        ev(KERNEL_GENERAL, 12, at=510, level=4),
        ev("EventLog", 6005, at=510.5, level=4),
    ]
    planned = run("restarts", clean)
    assert [(f.title, f.severity) for f in planned] == [("Restart requested by NT AUTHORITY\\SYSTEM", "info")]
    assert len(planned[0].evidence) == 2  # the duplicate 1074 is one restart


def scm(event_id: int, at: float, **data: str) -> EventRecord:
    return ev(SCM, event_id, at=at, **data)


def test_service_recipe() -> None:
    loop = [
        scm(7031, minute, param1="Contoso Sync", param2=str(i + 1), param5="Restart the service")
        for i, minute in enumerate((0, 10, 20))
    ]
    findings = run("services", [*loop, scm(7034, 30, param1="Fabrikam Agent", param2="1")])
    by_title = {f.title: f for f in findings}
    assert by_title["Service 'Contoso Sync' keeps crashing"].severity == "error"
    assert "3 times" in by_title["Service 'Contoso Sync' keeps crashing"].summary
    assert by_title["Service 'Fabrikam Agent' terminated unexpectedly"].severity == "warning"
    start = run(
        "services",
        [scm(7000, 0, param1="Contoso Sync", param2="%%1069"), scm(7009, 1, param1="30000", param2="Late Svc")],
    )
    by_title = {f.title: f for f in start}
    assert any("Log on as a service" in s for s in by_title["Service 'Contoso Sync' failed to start"].next_steps)
    assert any("30 s by default" in s for s in by_title["Service 'Late Svc' failed to start"].next_steps)
    exits = run("services", [scm(7023, 0, param1="Contoso Sync", param2="%%1")])
    assert [(f.title, f.severity) for f in exits] == [("Service 'Contoso Sync' stopped with an error", "warning")]
    assert run("services", [scm(7036, 0, param1="Contoso Sync", param2="running"), scm(7040, 1, param1="X")]) == []


def test_installer_recipe() -> None:
    failures = [
        ev(
            "MsiInstaller", 11708, at=0, channel="Application", message="Product: Contoso Agent -- Installation failed."
        ),
        ev("MsiInstaller", 1033, at=0.1, level=4, channel="Application", message=MSI_FAILED),
        ev("Microsoft-Windows-WindowsUpdateClient", 20, at=5, errorCode="0x80070070", updateTitle="Contoso Pack"),
        ev("Microsoft-Windows-WindowsUpdateClient", 20, at=65, errorCode="0x80070070", updateTitle="Contoso Pack"),
    ]
    findings = {f.title: f for f in run("installers", failures)}
    msi = findings["Installation of Contoso Agent 4.2.0 failed"]
    assert msi.severity == "error" and "Status 1603" in msi.summary and len(msi.evidence) == 2
    assert any("Return value 3" in step for step in msi.next_steps)
    update = findings["Update failed: Contoso Pack"]
    assert update.severity == "warning" and "2 times" in update.summary
    assert any("disk space" in step for step in update.next_steps)
    successes = [
        ev("MsiInstaller", 1033, level=4, param1="Contoso Agent", param4="0"),
        ev("MsiInstaller", 1033, level=4, param1="Contoso Agent", param4="3010"),
        ev("MsiInstaller", 11707, level=4, param1="Product: Contoso Agent -- Installation completed successfully."),
    ]
    assert run("installers", successes) == []


def test_account_lockout_recipe() -> None:
    events = [
        failed_logon("bob", "198.51.100.9", at=-60),  # too early to count
        *(failed_logon("bob", "198.51.100.9", at=minute) for minute in (0, 2, 4, 6)),
        failed_logon("carol", "198.51.100.9", at=5),
        logon(4740, at=7, TargetUserName="bob", TargetDomainName="WS07", SubjectUserName="DC01$"),
    ]
    findings = run("account-lockout", events)
    assert len(findings) == 1
    lockout = findings[0]
    assert lockout.title == "Account 'bob' locked out" and lockout.severity == "error" and lockout.confidence == "high"
    assert "4 failed logon(s)" in lockout.summary and "WS07" in lockout.summary
    assert "198.51.100.9" in lockout.summary and "wrong password" in lockout.summary
    assert len(lockout.evidence) == 5 and any("WS07" in step for step in lockout.next_steps)
    assert run("account-lockout", [failed_logon("bob", "198.51.100.9", at=m) for m in range(5)]) == []


def test_brute_force_recipe() -> None:
    attacker = "203.0.113.50"
    users = ["admin", "administrator", "backup", "sql", "test", "guest"]
    burst = [failed_logon(users[i % len(users)], attacker, at=i * 0.3) for i in range(12)]
    findings = run("brute-force", burst)
    assert len(findings) == 1 and findings[0].severity == "error"
    assert "12 failed logons from 203.0.113.50" in findings[0].summary and "password spraying" in findings[0].summary
    breached = run(
        "brute-force",
        [
            *burst,
            logon(4624, at=15, TargetUserName="backup", TargetDomainName="CONTOSO", IpAddress=attacker, LogonType="3"),
        ],
    )
    assert breached[0].severity == "critical" and breached[0].title.endswith("followed by a successful logon")
    assert breached[0].next_steps[0].startswith("Treat CONTOSO\\backup as compromised")
    below = [failed_logon("bob", attacker, at=i * 0.3) for i in range(BRUTE_FORCE_ATTEMPTS - 1)]
    spread = [failed_logon("bob", attacker, at=i) for i in range(12)]  # one per minute: at most 6 in 5 minutes
    local = [failed_logon("bob", "-", at=i * 0.1) for i in range(20)]
    assert run("brute-force", below) == run("brute-force", spread) == run("brute-force", local) == []


def test_app_pool_recipe() -> None:
    events = [
        ev(WAS, 5009, at=0, AppPoolID="ShopPool", ProcessID="11", ExitCode="0xc0000005"),
        ev(WAS, 5009, at=1, AppPoolID="ShopPool", ProcessID="12", ExitCode="0xc0000005"),
        ev(WAS, 5002, at=2, AppPoolID="ShopPool"),
        ev(WAS, 5010, at=3, level=3, AppPoolID="ReportPool", ProcessID="13"),
        ev(WAS, 5186, at=4, level=4, AppPoolID="IdlePool", ProcessID="14", Minutes="20"),
    ]
    findings = {f.title: f for f in run("app-pools", events)}
    assert set(findings) == {"IIS application pool 'ShopPool' failing", "IIS application pool 'ReportPool' failing"}
    shop = findings["IIS application pool 'ShopPool' failing"]
    assert shop.severity == "critical" and "worker process crashed 2 times" in shop.summary
    assert "0xC0000005 (access violation)" in shop.summary and any("Rapid-Fail" in s for s in shop.next_steps)
    report = findings["IIS application pool 'ReportPool' failing"]
    assert report.severity == "warning" and any("ProcDump" in s for s in report.next_steps)


def test_storage_recipe() -> None:
    bad_block = "The device, \\Device\\Harddisk1\\DR1, has a bad block."
    events = [
        ev("disk", 7, at=0, message=bad_block),
        ev("disk", 7, at=5, message=bad_block),
        ev(
            "disk", 153, at=6, level=3, message="The IO operation at logical block address 0x10 for Disk 2 was retried."
        ),
        ev("volsnap", 36, at=7, level=3, VolumeName="C:", DeviceName="\\Device\\HarddiskVolumeShadowCopy12"),
        ev("volsnap", 36, at=8, level=3, VolumeName="C:", DeviceName="\\Device\\HarddiskVolumeShadowCopy13"),
        ev("Microsoft-Windows-Ntfs", 98, at=9, level=2, DriveName="D:"),
        ev("Microsoft-Windows-Ntfs", 98, at=10, level=4, DriveName="C:"),  # "volume is healthy"
        ev("volsnap", 25, at=11, level=4),
    ]
    findings = {f.title: f for f in run("storage", events)}
    assert set(findings) == {
        "Bad block on \\Device\\Harddisk1\\DR1",
        "I/O operation retried on Disk 2",
        "Shadow copy problem on C:",
        "Volume needs repair (chkdsk) on D:",
    }
    assert findings["Bad block on \\Device\\Harddisk1\\DR1"].severity == "critical"
    assert "2 times" in findings["Shadow copy problem on C:"].summary
    assert any("chkdsk" in s for s in findings["Volume needs repair (chkdsk) on D:"].next_steps)
    assert run("storage", [ev("volsnap", 25, level=4), ev("Microsoft-Windows-Ntfs", 98, level=4)]) == []


def test_what_changed_recipe() -> None:
    wu = "Microsoft-Windows-WindowsUpdateClient"
    events = [
        ev(SCM, 7045, at=0, level=4, ServiceName="Contoso Sync", ImagePath="C:\\Contoso\\sync.exe"),
        *(
            ev(SCM, 7040, at=i, level=4, param1="Contoso Sync", param2="demand start", param3="auto start")
            for i in (1, 2, 3)
        ),
        ev(
            "MsiInstaller",
            11707,
            at=4,
            level=4,
            param1="Product: Contoso Agent -- Installation completed successfully.",
        ),
        ev("MsiInstaller", 1034, at=5, level=4, param1="Old Tool", param2="1.0", param4="0"),
        ev(wu, 19, at=6, level=4, updateTitle="Contoso Driver Update 1.0"),
        ev(
            "Microsoft-Windows-Servicing",
            2,
            at=7,
            level=4,
            PackageIdentifier="KB0000002",
            IntendedPackageStateTextized="Installed",
            ErrorCode="0x0",
        ),
        ev(
            "Microsoft-Windows-Servicing",
            2,
            at=7,
            level=4,
            PackageIdentifier="KB0000003",
            IntendedPackageStateTextized="Staged",
            ErrorCode="0x0",
        ),
        ev(KERNEL_GENERAL, 1, at=8, level=4, OldTime="2026-11-13T08:08:00Z", NewTime="2026-11-13T08:18:00Z"),
        logon(
            4616, at=8.1, PreviousTime="2026-11-13T08:08:00Z", NewTime="2026-11-13T08:18:00Z", SubjectUserName="alice"
        ),
        ev(KERNEL_GENERAL, 1, at=9, level=4, OldTime="2026-11-13T08:09:00.000Z", NewTime="2026-11-13T08:09:00.300Z"),
        ev("User32", 1074, at=10, level=4, message=USER32_MESSAGE),
        ev("User32", 1074, at=11, level=4, message=USER32_MESSAGE.replace("CONTOSO\\alice", "NT AUTHORITY\\SYSTEM")),
    ]
    findings = {f.title: f for f in run("changes", events)}
    assert set(findings) == {
        "New services installed (1)",
        "Service start types changed (1)",
        "Software installed (1)",
        "Software removed (1)",
        "Updates installed (2)",
        "System clock changed (1)",
        "Restarts or shutdowns by a user (1)",
    }
    assert "Contoso Sync: demand start → auto start (3×)" in findings["Service start types changed (1)"].summary
    assert "C:\\Contoso\\sync.exe" in findings["New services installed (1)"].summary
    assert "KB0000003" not in findings["Updates installed (2)"].summary
    clock = findings["System clock changed (1)"]
    assert clock.severity == "warning" and "+10 min" in clock.summary and len(clock.evidence) == 2
    assert "CONTOSO\\alice: restart" in findings["Restarts or shutdowns by a user (1)"].summary
    assert all(f.severity in ("info", "warning") for f in findings.values())
    routine = [events[-1], events[-3]]  # a system restart and a 0.3 s time-sync correction
    assert run("changes", routine) == []


def test_run_all_sorting_and_channels() -> None:
    events = [
        *crash_chain(30),  # error
        ev("Microsoft-Windows-Kernel-Power", 41, at=40, level=1, BugcheckCode="0"),  # critical
        scm(7034, 5, param1="Fabrikam Agent", param2="1"),  # warning
        ev("User32", 1074, at=1, level=4, message=USER32_MESSAGE),  # info (restart + change)
        ev("Microsoft-Windows-Kernel-Power", 41, at=2, level=1, BugcheckCode="0"),  # critical, earlier
    ]
    findings = run_all(events)
    assert [f.severity for f in findings] == ["critical", "critical", "error", "warning", "info", "info"]
    assert findings[0].time < findings[1].time
    assert run_all(events, recipes=[RECIPES["services"]])[0].recipe_id == "services"
    assert run_all([]) == []
    assert channels_needed() == ("Application", "System", "Security", "Setup")
    assert channels_needed([RECIPES["crashes"], RECIPES["brute-force"]]) == ("Application", "Security")
    assert all(recipe.title and recipe.description and recipe.channels for recipe in RECIPES.values())


# ---- coverage --------------------------------------------------------------------------------------------------------
START = BASE
END = BASE + timedelta(days=1)


def system(at: float, provider: str = "Contoso-Driver", event_id: int = 1, **data: str) -> EventRecord:
    return ev(provider, event_id, at=at, level=4, **data)


def steady(provider: str = "Contoso-Driver", *, hours: int = 24, channel: str = "System") -> list[EventRecord]:
    """An event every hour across the requested day."""
    return [ev(provider, 1, at=h * 60, level=4, channel=channel) for h in range(hours)]


def test_coverage_clean_period_has_no_warnings() -> None:
    by_channel = {"System": steady(), "Application": steady("Contoso-App", channel="Application"), "Setup": []}
    assert coverage_warnings(by_channel, START, END, {}) == []


def test_coverage_access_errors_and_cleared_logs() -> None:
    cleared = [
        *steady(),
        ev("Microsoft-Windows-Eventlog", 104, at=90, level=4, Channel="Application", SubjectUserName="bob"),
    ]
    security = [ev("Microsoft-Windows-Eventlog", 1102, at=30, level=4, channel="Security", SubjectUserName="alice")]
    warnings = coverage_warnings(
        {"System": cleared, "Security": security}, START, END, {"Setup": "Access denied — run as administrator."}
    )
    assert warnings[0] == "The Setup log could not be read: Access denied — run as administrator."
    assert f"The Application log was cleared at {format_time(BASE + timedelta(minutes=90))} by bob" in warnings[2]
    assert any(w.startswith("The Security log was cleared") and "by alice" in w for w in warnings)


def test_coverage_log_start_truncation_and_empty_channels() -> None:
    late = [ev("Contoso-Driver", 1, at=minute, level=4) for minute in range(600, 1440, 60)]
    warnings = coverage_warnings({"System": late, "Setup": late[-1:]}, START, END, {})
    assert any(w.startswith(f"The System log only goes back to {format_time(late[0].time_created)}") for w in warnings)
    assert not any("Setup" in w for w in warnings)  # a quiet channel is not a wrapped one
    booted = [ev(KERNEL_GENERAL, 12, at=599, level=4), *late]
    assert not any("only goes back" in w for w in coverage_warnings({"System": booted}, START, END, {}))
    truncated = coverage_warnings({"System": late}, START, END, {}, truncated_channels={"System"})
    assert any(w.startswith("Only the newest 14 System events were read") for w in truncated)
    empty = coverage_warnings({"Application": [], "System": steady(), "Setup": []}, START, END, {})
    assert empty == [
        "No Application events at all in the requested period — the log may have been cleared or the system was off."
    ]


def test_coverage_clock_changes() -> None:
    events = [
        *steady(),
        ev(KERNEL_GENERAL, 1, at=120.1, level=4, OldTime="2026-11-13T11:00:00Z", NewTime="2026-11-13T10:00:00Z"),
        logon(
            4616, at=120.2, PreviousTime="2026-11-13T11:00:00Z", NewTime="2026-11-13T10:00:00Z", SubjectUserName="eve"
        ),
        ev(KERNEL_GENERAL, 1, at=300, level=4, OldTime="2026-11-13T13:00:00Z", NewTime="2026-11-13T13:00:01Z"),
    ]
    warnings = coverage_warnings({"System": events}, START, END, {})
    assert len(warnings) == 1 and warnings[0].startswith("The system clock was set back by 1 h at ")


def test_coverage_gaps_and_stopped_event_log() -> None:
    quiet = [system(0), system(60), system(9 * 60), *(system(h * 60) for h in range(10, 24))]
    gaps = coverage_warnings({"System": quiet}, START, END, {})
    silence = (format_time(BASE + timedelta(hours=1)), format_time(BASE + timedelta(hours=9)))
    assert len(gaps) == 1 and gaps[0].startswith(f"No events at all between {silence[0]} and {silence[1]} (8 h)")
    shutdown = [system(0), system(60), system(61, "EventLog", 6006), system(9 * 60, "EventLog", 6005), *quiet[3:]]
    assert coverage_warnings({"System": shutdown}, START, END, {}) == []
    sleeping = [system(0), system(60, "Microsoft-Windows-Kernel-Power", 42), *quiet[2:]]
    assert coverage_warnings({"System": sleeping}, START, END, {}) == []
    application_only = [
        ev("Contoso-App", 1, at=0, channel="Application"),
        ev("Contoso-App", 1, at=600, channel="Application"),
    ]
    assert coverage_warnings({"Application": application_only}, START, END, {}) == []  # no boot markers to judge by
    stopped = [*steady(hours=20), system(20 * 60, "EventLog", 6006)]
    warnings = coverage_warnings({"System": stopped}, START, END, {})
    assert warnings == [
        f"The event log service stopped at {format_time(stopped[-1].time_created)} and no restart was logged before "
        f"{format_time(END)} — the system was shut down or logging stopped; nothing later is covered."
    ]
