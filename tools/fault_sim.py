"""LogLens fault simulator - our own misbehaving "application" for testing LogLens.

Sub-commands
  gen-log       write a realistic log file (app text / IIS W3C / JSON lines) of a given size
  append        keep appending to a log in real time (tail/follow testing), optional rotation
  crash-native  crash a throw-away child process (access violation 0xC0000005) -> Windows logs
                Application Error 1000 + Windows Error Reporting 1001
  crash-dotnet  compile (csc.exe, .NET Framework) and run a tiny program that throws an unhandled exception ->
                .NET Runtime 1026 + Application Error 1000 (0xE0434352) + WER 1001 (CLR20r3)
  scenario      write an application log whose error line coincides with a real crash, for correlation tests

Only processes this tool starts are crashed; nothing else on the machine is touched.

Examples
  python tools/fault_sim.py gen-log samples/generated/app.log --size-mb 50
  python tools/fault_sim.py gen-log samples/generated/u_ex261113.log --format iis --lines 200000
  python tools/fault_sim.py append samples/generated/live.log --rate 20 --rotate-kb 512
  python tools/fault_sim.py crash-native
  python tools/fault_sim.py scenario samples/generated/scenario.log --crash dotnet
"""

from __future__ import annotations

import argparse
import json
import os
import random
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

SERVICES = ["OrderService", "PaymentGateway", "InventorySync", "AuthController", "ReportWorker", "CacheManager"]
ENDPOINTS = [
    ("GET", "/api/orders"),
    ("GET", "/api/orders/{id}"),
    ("POST", "/api/orders"),
    ("POST", "/api/payments"),
    ("GET", "/api/products"),
    ("GET", "/api/products/{id}"),
    ("POST", "/api/auth/login"),
    ("GET", "/health"),
]
USER_AGENTS = ["Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)", "okhttp/4.12.0", "curl/8.4.0", "Shop-Mobile/3.2+(iOS+17.1)"]

ERRORS = [
    (
        "PaymentGateway",
        "Payment failed for order {order}",
        "System.TimeoutException",
        "The operation has timed out.",
        [
            "Shop.Payments.GatewayClient.SendAsync(PaymentRequest request) in "
            "C:\\src\\Shop\\Payments\\GatewayClient.cs:line 88",
            "Shop.Orders.OrderService.CheckoutAsync(Order order) in C:\\src\\Shop\\Orders\\OrderService.cs:line 142",
        ],
    ),
    (
        "OrderService",
        "Could not save order {order}",
        "System.Data.SqlClient.SqlException",
        "Transaction (Process ID 61) was deadlocked on lock resources with another process and has been chosen as the "
        "deadlock victim. Rerun the transaction.",
        [
            "System.Data.SqlClient.SqlConnection.OnError(SqlException exception, Boolean breakConnection)",
            "Shop.Data.OrderRepository.Save(Order order) in C:\\src\\Shop\\Data\\OrderRepository.cs:line 57",
        ],
    ),
    (
        "InventorySync",
        "Sync batch {batch} aborted",
        "System.IO.IOException",
        "The process cannot access the file 'D:\\data\\inventory\\feed.csv' because it is being used by "
        "another process.",
        [
            "System.IO.FileStream..ctor(String path, FileMode mode)",
            "Shop.Inventory.FeedReader.Open() in C:\\src\\Shop\\Inventory\\FeedReader.cs:line 23",
        ],
    ),
    (
        "AuthController",
        "Token validation failed for user {user}",
        "System.Security.Authentication.AuthenticationException",
        "The remote certificate is invalid according to the validation procedure: RemoteCertificateChainErrors",
        [
            "System.Net.Security.SslStream.ProcessAuthentication(LazyAsyncResult lazyResult)",
            "Shop.Auth.IdpClient.GetKeysAsync() in C:\\src\\Shop\\Auth\\IdpClient.cs:line 41",
        ],
    ),
    (
        "ReportWorker",
        "Report {batch} generation crashed",
        "System.OutOfMemoryException",
        "Exception of type 'System.OutOfMemoryException' was thrown.",
        [
            "System.Text.StringBuilder.ExpandByABlock(Int32 minBlockCharCount)",
            "Shop.Reports.CsvExporter.Export(IEnumerable`1 rows) in C:\\src\\Shop\\Reports\\CsvExporter.cs:line 112",
        ],
    ),
]
WARNINGS = [
    ("CacheManager", "Cache miss ratio high: {pct}% over last 5 min"),
    ("PaymentGateway", "Retrying payment request for order {order} (attempt {attempt}/3)"),
    ("ReportWorker", "Report {batch} took {ms} ms (threshold 5000 ms)"),
    ("InventorySync", "Disk D: free space low: {pct}% remaining"),
]


class AppLogGenerator:
    """log4net/NLog-style text log with stack traces and request/response pairs."""

    def __init__(self, start: datetime, seed: int = 1) -> None:
        self.t = start
        self.rng = random.Random(seed)
        self.order = 40000
        self.burst = 0  # remaining lines of an error burst

    def _ts(self) -> str:
        self.t += timedelta(milliseconds=self.rng.expovariate(1 / 40))
        return self.t.strftime("%Y-%m-%d %H:%M:%S.") + f"{self.t.microsecond // 1000:03d}"

    def _fill(self, msg: str) -> str:
        r = self.rng
        return msg.format(
            order=self.order,
            user=f"user{r.randint(1, 500)}",
            batch=r.randint(1000, 9999),
            pct=r.randint(3, 97),
            attempt=r.randint(1, 3),
            ms=r.randint(5000, 30000),
        )

    def records(self) -> Iterator[list[str]]:
        r = self.rng
        while True:
            thread = r.randint(1, 40)
            self.order += 1
            if self.burst == 0 and r.random() < 0.0008:
                self.burst = r.randint(5, 60)  # an incident: many errors in a short time
            roll = r.random()
            err_chance = 0.4 if self.burst else 0.004
            if self.burst:
                self.burst -= 1
            if roll < err_chance:
                svc, msg, exc, exc_msg, frames = r.choice(ERRORS)
                lines = [f"{self._ts()} [{thread:>4}] ERROR {svc} - {self._fill(msg)}", f"{exc}: {exc_msg}"]
                lines += [f"   at {fr}" for fr in frames]
                yield lines
            elif roll < err_chance + 0.03:
                svc, msg = r.choice(WARNINGS)
                yield [f"{self._ts()} [{thread:>4}] WARN  {svc} - {self._fill(msg)}"]
            elif roll < 0.35:
                method, ep = r.choice(ENDPOINTS)
                path = ep.replace("{id}", str(r.randint(1, 99999)))
                req = uuid.UUID(int=r.getrandbits(128)).hex[:12]
                ms = int(r.lognormvariate(3.3, 0.8)) + (r.randint(2000, 9000) if r.random() < 0.01 else 0)
                status = 200 if r.random() > 0.03 else r.choice([400, 401, 404, 500, 503])
                yield [f"{self._ts()} [{thread:>4}] INFO  HttpServer - Request started {method} {path} (req={req})"]
                yield [
                    f"{self._ts()} [{thread:>4}] INFO  HttpServer - Request finished {method} {path} "
                    f"{status} in {ms} ms (req={req})"
                ]
            elif roll < 0.45:
                yield [
                    f"{self._ts()} [{thread:>4}] DEBUG CacheManager - Cache hit for key product:{r.randint(1, 9999)}"
                ]
            else:
                svc = r.choice(SERVICES)
                yield [
                    f"{self._ts()} [{thread:>4}] INFO  {svc} - Processed order {self.order} for customer "
                    f"{r.randint(1, 5000)} in {r.randint(2, 400)} ms"
                ]


class IisLogGenerator:
    FIELDS = (
        "date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) "
        "cs(Referer) sc-status sc-substatus sc-win32-status time-taken"
    )

    def __init__(self, start: datetime, seed: int = 1) -> None:
        self.t = start
        self.rng = random.Random(seed)

    def header(self) -> list[str]:
        return [
            "#Software: Microsoft Internet Information Services 10.0",
            "#Version: 1.0",
            f"#Date: {self.t:%Y-%m-%d %H:%M:%S}",
            f"#Fields: {self.FIELDS}",
        ]

    def records(self) -> Iterator[list[str]]:
        r = self.rng
        while True:
            self.t += timedelta(milliseconds=r.expovariate(1 / 60))
            method, ep = r.choice(ENDPOINTS)
            path = ep.replace("{id}", str(r.randint(1, 99999)))
            status, sub, win32 = 200, 0, 0
            x = r.random()
            if x < 0.01:
                status, sub, win32 = r.choice([(500, 0, 0), (500, 19, 13), (503, 0, 0), (502, 3, 12002)])
            elif x < 0.05:
                status, sub = r.choice([(404, 0), (401, 2), (401, 1), (304, 0)])
            taken = int(r.lognormvariate(3.5, 0.9)) + (r.randint(5000, 30000) if status >= 500 else 0)
            yield [
                f"{self.t:%Y-%m-%d %H:%M:%S} 10.0.0.5 {method} {path} - 443 - 10.0.{r.randint(0, 9)}."
                f"{r.randint(1, 254)} {r.choice(USER_AGENTS)} - {status} {sub} {win32} {taken}"
            ]


class JsonLogGenerator(AppLogGenerator):
    """Serilog compact JSON (CLEF) built from the app generator's events."""

    def records(self) -> Iterator[list[str]]:
        for rec in super().records():
            head = rec[0]
            ts, rest = head[:23], head[24:]
            level = rest.split("]", 1)[1].split()[0]
            source, _, msg = rest.split("]", 1)[1].split(None, 1)[1].partition(" - ")
            evt: dict = {"@t": ts.replace(" ", "T") + "Z", "@m": msg, "SourceContext": source}
            if level != "INFO":
                evt["@l"] = {"WARN": "Warning", "ERROR": "Error", "DEBUG": "Debug"}.get(level, level)
            if len(rec) > 1:
                evt["@x"] = "\n".join(rec[1:])
            yield [json.dumps(evt, ensure_ascii=False)]


def make_generator(fmt: str, start: datetime, seed: int):
    return {"app": AppLogGenerator, "iis": IisLogGenerator, "json": JsonLogGenerator}[fmt](start, seed)


def cmd_gen_log(args: argparse.Namespace) -> None:
    out = Path(args.path)
    out.parent.mkdir(parents=True, exist_ok=True)
    start = datetime.now(UTC).replace(tzinfo=None) - timedelta(hours=args.hours_back)
    gen = make_generator(args.format, start, args.seed)
    limit_bytes = int(args.size_mb * 1024 * 1024) if args.size_mb else None
    written_lines = written_bytes = 0
    t0 = time.perf_counter()
    newline = "\r\n" if args.crlf else "\n"
    with out.open("w", encoding=args.encoding, newline="") as f:
        if isinstance(gen, IisLogGenerator):
            f.write(newline.join(gen.header()) + newline)
        buf: list[str] = []
        for rec in gen.records():
            for line in rec:
                buf.append(line)
                written_bytes += len(line) + len(newline)
                written_lines += 1
            if len(buf) >= 5000:
                f.write(newline.join(buf) + newline)
                buf.clear()
            if (limit_bytes and written_bytes >= limit_bytes) or (args.lines and written_lines >= args.lines):
                break
        if buf:
            f.write(newline.join(buf) + newline)
    print(
        f"wrote {written_lines:,} lines, {out.stat().st_size / 1e6:,.1f} MB to {out} in {time.perf_counter() - t0:.1f}s"
    )


def cmd_append(args: argparse.Namespace) -> None:
    out = Path(args.path)
    out.parent.mkdir(parents=True, exist_ok=True)
    gen = make_generator(args.format, datetime.now(UTC).replace(tzinfo=None), args.seed)
    delay = 1.0 / args.rate
    print(f"appending ~{args.rate} records/s to {out} (Ctrl+C to stop)")
    records = gen.records()
    try:
        while True:
            if args.rotate_kb and out.exists() and out.stat().st_size > args.rotate_kb * 1024:
                rolled = out.with_name(out.name + ".1")
                rolled.unlink(missing_ok=True)
                out.replace(rolled)
                print(f"rotated -> {rolled.name}")
            with out.open("a", encoding="utf-8") as f:
                rec = next(records)
                # make timestamps "now" for live testing
                if isinstance(gen, AppLogGenerator) and not isinstance(gen, JsonLogGenerator):
                    now = datetime.now()
                    stamp = now.strftime("%Y-%m-%d %H:%M:%S.") + f"{now.microsecond // 1000:03d}"
                    rec = [stamp + rec[0][23:], *rec[1:]]
                f.write("\n".join(rec) + "\n")
            time.sleep(delay)
    except KeyboardInterrupt:
        print("stopped")


NATIVE_CRASH = "import ctypes; ctypes.string_at(0)"  # read address 0 -> access violation in the child
CSHARP_CRASH = """
using System;
class LogLensFaultSim {
    static void Main() {
        Console.WriteLine("LogLens fault simulator: throwing an unhandled exception");
        throw new InvalidOperationException("Simulated unhandled exception from the LogLens fault simulator");
    }
}
"""
CSC_CANDIDATES = (
    Path(os.environ.get("WINDIR", r"C:\Windows")) / "Microsoft.NET" / "Framework64" / "v4.0.30319" / "csc.exe",
    Path(os.environ.get("WINDIR", r"C:\Windows")) / "Microsoft.NET" / "Framework" / "v4.0.30319" / "csc.exe",
)


def crash_native() -> int:
    """Run a child Python that dereferences a null pointer; returns its exit code (0xC0000005 as unsigned)."""
    result = subprocess.run([sys.executable, "-c", NATIVE_CRASH], check=False, capture_output=True)
    return result.returncode & 0xFFFFFFFF


def crash_dotnet() -> int:
    """Compile and run a .NET Framework program that dies of an unhandled exception; returns its exit code."""
    csc = next((c for c in CSC_CANDIDATES if c.is_file()), None)
    if csc is None:
        raise SystemExit("csc.exe (.NET Framework 4) not found - crash-dotnet needs Windows' built-in compiler")
    with tempfile.TemporaryDirectory(prefix="loglens-faultsim-") as folder:
        source, exe = Path(folder) / "LogLensFaultSim.cs", Path(folder) / "LogLensFaultSim.exe"
        source.write_text(CSHARP_CRASH, encoding="utf-8")
        subprocess.run([str(csc), "/nologo", f"/out:{exe}", str(source)], check=True, capture_output=True)
        result = subprocess.run([str(exe)], check=False, capture_output=True)
        return result.returncode & 0xFFFFFFFF


def cmd_crash(args: argparse.Namespace) -> None:
    code = crash_native() if args.cmd == "crash-native" else crash_dotnet()
    print(f"child exited with 0x{code:08X} at {datetime.now():%Y-%m-%d %H:%M:%S}")
    print("Windows needs a few seconds to write Application Error / WER events; then use LogLens:")
    print("File > Open Windows Event Logs (Application) or Inspector > Windows on a line from that time.")


def cmd_scenario(args: argparse.Namespace) -> None:
    out = Path(args.path)
    out.parent.mkdir(parents=True, exist_ok=True)

    def write(level: str, message: str) -> None:
        now = datetime.now()
        stamp = now.strftime("%Y-%m-%d %H:%M:%S,") + f"{now.microsecond // 1000:03d}"
        with out.open("a", encoding="utf-8") as f:
            f.write(f"{stamp} [{os.getpid()}] {level:<5} ScenarioWorker - {message}\n")

    write("INFO", "Worker starting, processing batch 42")
    write("WARN", "Batch 42 is taking longer than usual (12 s)")
    write("ERROR", "Worker process died unexpectedly while processing batch 42")
    code = crash_native() if args.crash == "native" else crash_dotnet()
    write("INFO", f"Supervisor: worker exited with code 0x{code:08X}, restarting")
    print(f"wrote {out}; crashed a child ({args.crash}) with 0x{code:08X}. Open the log in LogLens, select the ERROR")
    print("line and use Inspector > Windows > Find Windows events to see the crash Windows recorded.")


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gen-log", help="write a realistic log file")
    g.add_argument("path")
    g.add_argument("--format", choices=["app", "iis", "json"], default="app")
    g.add_argument("--size-mb", type=float, default=0)
    g.add_argument("--lines", type=int, default=0)
    g.add_argument("--encoding", default="utf-8", help="e.g. utf-8, utf-8-sig, utf-16")
    g.add_argument("--crlf", action="store_true")
    g.add_argument("--hours-back", type=float, default=24)
    g.add_argument("--seed", type=int, default=1)
    g.set_defaults(func=cmd_gen_log)

    a = sub.add_parser("append", help="append in real time (tail testing)")
    a.add_argument("path")
    a.add_argument("--format", choices=["app", "iis", "json"], default="app")
    a.add_argument("--rate", type=float, default=10, help="records per second")
    a.add_argument("--rotate-kb", type=int, default=0, help="rotate file to .1 when bigger than this")
    a.add_argument("--seed", type=int, default=2)
    a.set_defaults(func=cmd_append)

    for name, text in (("crash-native", "crash a child process (Application Error 1000)"),
                       ("crash-dotnet", "unhandled .NET exception (.NET Runtime 1026)")):  # fmt: skip
        sub.add_parser(name, help=text).set_defaults(func=cmd_crash)
    sc = sub.add_parser("scenario", help="app log error + a real crash at the same moment")
    sc.add_argument("path")
    sc.add_argument("--crash", choices=["native", "dotnet"], default="native")
    sc.set_defaults(func=cmd_scenario)

    args = p.parse_args(argv)
    if not (getattr(args, "size_mb", 1) or getattr(args, "lines", 1)):
        args.lines = 100_000
    args.func(args)


if __name__ == "__main__":
    sys.exit(main())
