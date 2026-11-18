"""Windows Error Reporting: Report.wer parsing (UTF-16 / UTF-8), signature layouts and report discovery."""

from __future__ import annotations

import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from loglens.core.winevent.wer import (
    REPORT_FILE,
    default_report_roots,
    describe_exception,
    exception_label,
    filetime_to_datetime,
    find_reports,
    map_signature,
    parse_hex,
    parse_report,
    read_report,
)

FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
CRASH_TIME = datetime(2026, 11, 13, 10, 15, 2, 123456, tzinfo=UTC)


def _filetime(moment: datetime) -> int:
    delta = moment - FILETIME_EPOCH
    return (delta.days * 86_400 + delta.seconds) * 10_000_000 + delta.microseconds * 10


APPCRASH_REPORT = rf"""Version=1
EventType=APPCRASH
EventTime={_filetime(CRASH_TIME)}
ReportType=2
Consent=1
ReportIdentifier=11111111-2222-3333-4444-555555555555
NsAppName=contoso.exe
Response.type=4
Sig[0].Name=Application Name
Sig[0].Value=contoso.exe
Sig[1].Name=Application Version
Sig[1].Value=1.2.3.4
Sig[2].Name=Application Timestamp
Sig[2].Value=5f3e1a2b
Sig[3].Name=Fault Module Name
Sig[3].Value=contoso.core.dll
Sig[4].Name=Fault Module Version
Sig[4].Value=2.0.0.1
Sig[5].Name=Fault Module Timestamp
Sig[5].Value=6a000000
Sig[6].Name=Exception Code
Sig[6].Value=c0000005
Sig[7].Name=Exception Offset
Sig[7].Value=000000000004f7a1
DynamicSig[1].Name=OS Version
DynamicSig[1].Value=10.0.26100.2.0.0.256.48
DynamicSig[2].Name=Locale ID
DynamicSig[2].Value=1033
UI[2]=C:\Program Files\Contoso\contoso.exe
UI[5]=Check online for a solution (recommended)
LoadedModule[0]=C:\Program Files\Contoso\contoso.exe
LoadedModule[1]=C:\Windows\SYSTEM32\ntdll.dll
LoadedModule[2]=C:\Program Files\Contoso\contoso.core.dll
FriendlyEventName=Stopped working
AppName=Contoso Desktop
AppPath=C:\Program Files\Contoso
"""

CLR_REPORT = r"""Version=1
EventType=CLR20r3
EventTime=0
ReportIdentifier=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
Sig[0].Name=Problem Signature 01
Sig[0].Value=fabrikam.worker.exe
Sig[1].Name=Problem Signature 02
Sig[1].Value=3.1.0.0
Sig[2].Name=Problem Signature 03
Sig[2].Value=91d14fcc
Sig[3].Name=Problem Signature 04
Sig[3].Value=Fabrikam.Data
Sig[4].Name=Problem Signature 05
Sig[4].Value=3.1.0.0
Sig[5].Name=Problem Signature 06
Sig[5].Value=d5703fbd
Sig[6].Name=Problem Signature 07
Sig[6].Value=1b5
Sig[7].Name=Problem Signature 08
Sig[7].Value=2a
Sig[8].Name=Problem Signature 09
Sig[8].Value=System.InvalidOperationException
AppPath=D:\Apps\Fabrikam\fabrikam.worker.exe
"""

HANG_REPORT = """EventType=AppHangB1
Sig[0].Name=Application Name
Sig[0].Value=northwind.exe
Sig[1].Name=Application Version
Sig[1].Value=5.0.0.0
Sig[3].Name=Hang Signature
Sig[3].Value=1a2b
"""


def test_parse_utf16_appcrash_report(tmp_path: Path) -> None:
    path = tmp_path / REPORT_FILE
    path.write_bytes(b"\xff\xfe" + APPCRASH_REPORT.replace("\n", "\r\n").encode("utf-16-le"))
    report = read_report(path)
    assert report.path == path
    assert report.event_type == "APPCRASH" and report.is_crash and not report.is_hang
    assert report.event_time == CRASH_TIME
    assert report.report_id == "11111111-2222-3333-4444-555555555555"
    assert (report.app_name, report.app_version) == ("contoso.exe", "1.2.3.4")
    assert (report.faulting_module, report.module_version) == ("contoso.core.dll", "2.0.0.1")
    assert report.exception_code == 0xC0000005
    assert report.fault_offset == "0x4f7a1"
    assert report.app_path == r"C:\Program Files\Contoso"
    assert report.friendly_name == "Stopped working"
    assert report.signature["Fault Module Name"] == "contoso.core.dll"
    assert next(iter(report.signature)) == "Application Name"
    assert report.dynamic_signature == {"OS Version": "10.0.26100.2.0.0.256.48", "Locale ID": "1033"}
    assert report.ui == (r"C:\Program Files\Contoso\contoso.exe", "Check online for a solution (recommended)")
    assert report.loaded_modules[1] == r"C:\Windows\SYSTEM32\ntdll.dll" and len(report.loaded_modules) == 3
    assert report.fields["Response.type"] == "4"
    summary = report.summary()
    assert "\n" not in summary
    assert summary.startswith(CRASH_TIME.astimezone().strftime("%Y-%m-%d %H:%M:%S") + " APPCRASH: ")
    assert "contoso.exe 1.2.3.4 crashed in contoso.core.dll 2.0.0.1" in summary
    assert "0xC0000005 (access violation)" in summary and "offset 0x4f7a1" in summary


def test_parse_utf8_clr_report_uses_positional_layout(tmp_path: Path) -> None:
    path = tmp_path / REPORT_FILE
    path.write_text(CLR_REPORT, encoding="utf-8")
    report = read_report(path)
    assert report.event_type == "CLR20r3" and report.is_crash
    assert report.event_time is None  # EventTime=0 means unknown
    assert report.app_name == "fabrikam.worker.exe" and report.app_version == "3.1.0.0"
    assert report.faulting_module == "Fabrikam.Data"
    assert report.exception_type == "System.InvalidOperationException"
    assert report.exception_code is None
    assert report.summary() == (
        "CLR20r3: fabrikam.worker.exe 3.1.0.0 crashed with unhandled .NET exception System.InvalidOperationException "
        "in Fabrikam.Data 3.1.0.0"
    )


def test_utf8_with_bom_and_hang_report(tmp_path: Path) -> None:
    path = tmp_path / REPORT_FILE
    path.write_bytes(b"\xef\xbb\xbf" + HANG_REPORT.encode("utf-8"))
    report = read_report(path)
    assert report.is_hang and report.app_name == "northwind.exe"
    assert report.summary() == "AppHangB1: northwind.exe 5.0.0.0 stopped responding"
    assert report.signature["Hang Signature"] == "1a2b"


def test_parse_report_tolerates_junk_lines() -> None:
    report = parse_report("\ufeff[Section]\n; comment\nno equals sign\nEventType=BEX64\nSig[7].Value=c0000409\n")
    assert report.event_type == "BEX64"
    assert report.exception_code == 0xC0000409  # BEX layout: P8 is the exception code
    assert report.signature == {"P8": "c0000409"}
    assert parse_report("").summary() == "WER report: unknown application"


def test_map_signature_names_win_over_layout() -> None:
    values = ["pkg_1.0.0.0_x64__abcdefghijklm", "praid:App", "1.0.0.0", "00000000", "mod.dll", "2.0", "0", "80010108"]
    names = ["Package Full Name", "Application Name", "Application Version"]
    mapped = map_signature("MoAppCrash", values, names)
    assert mapped["app_name"] == "pkg_1.0.0.0_x64__abcdefghijklm"  # first descriptive name wins
    assert mapped["app_version"] == "1.0.0.0"
    assert mapped["faulting_module"] == "mod.dll" and mapped["exception_code"] == "80010108"
    bex = map_signature("bex64", ["a.exe", "1.0", "t", "m.dll", "2.0", "t", "0x10", "c0000409"])
    assert bex["fault_offset"] == "0x10" and bex["exception_code"] == "c0000409"
    assert map_signature("UnknownType", ["x"]) == {}


def test_value_helpers() -> None:
    assert parse_hex("C0000005") == parse_hex("0xc0000005") == 0xC0000005
    assert parse_hex("") is None and parse_hex("xyz") is None
    assert filetime_to_datetime(str(_filetime(CRASH_TIME))) == CRASH_TIME
    assert filetime_to_datetime("not a number") is None and filetime_to_datetime("-5") is None
    assert describe_exception(0xC00000FD) == "stack overflow"
    assert exception_label(0xE0434352) == "0xE0434352 (unhandled .NET exception)"


@pytest.mark.skipif(sys.platform != "win32", reason="uses the Windows message tables")
def test_unknown_exception_codes_fall_back_to_windows_messages() -> None:
    assert describe_exception(0x80070005).lower().startswith("access is denied")


def _make_report(root: Path, name: str, modified: datetime) -> Path:
    folder = root / name
    folder.mkdir(parents=True)
    report = folder / REPORT_FILE
    report.write_text("EventType=APPCRASH\n", encoding="utf-8")
    os.utime(report, (modified.timestamp(), modified.timestamp()))
    return report


def test_find_reports_newest_first_with_since_and_unreadable_roots(tmp_path: Path) -> None:
    archive, queue = tmp_path / "ReportArchive", tmp_path / "ReportQueue"
    old = _make_report(archive, "AppCrash_old", CRASH_TIME - timedelta(days=3))
    new = _make_report(queue, "AppCrash_new", CRASH_TIME)
    middle = _make_report(archive, "AppHang_mid", CRASH_TIME - timedelta(days=1))
    (archive / "NoReportHere").mkdir()
    (archive / "stray-file.txt").write_text("x", encoding="utf-8")
    not_a_folder = tmp_path / "file-instead-of-folder"
    not_a_folder.write_text("x", encoding="utf-8")
    roots = [archive, queue, tmp_path / "missing", not_a_folder]
    assert find_reports(roots) == [new, middle, old]
    assert find_reports(roots, since=CRASH_TIME - timedelta(days=2)) == [new, middle]


def test_default_report_roots_follow_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("ProgramData", str(tmp_path / "pd"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    roots = default_report_roots()
    assert tmp_path / "pd" / "Microsoft" / "Windows" / "WER" / "ReportArchive" in roots
    assert tmp_path / "local" / "Microsoft" / "Windows" / "WER" / "ReportQueue" in roots
    assert len(roots) == 4
    assert find_reports() == []  # none of the default folders exist here
