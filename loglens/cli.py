"""Command line: ``loglens summary``, ``diagnose``, ``digest`` and ``schedule`` for scripts, CI and scheduled tasks.

Runs without a window. The installed LogLens.exe is a windowed program, so output goes to the console it was started
from (and to ``--output`` when given); the exit code is 0 for "nothing wrong", 1 for "problems found"
(``--fail-on-errors``)
and 2 for a usage or runtime error, so a script can react.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path

from . import __version__
from .core import digest as digest_module
from .core import notify
from .core.secrets import SecretMasker
from .core.text_source import TextLogSource
from .core.triage import render_markdown, triage

COMMANDS = ("summary", "diagnose", "digest", "schedule", "--help", "-h", "--version")
EXIT_OK, EXIT_PROBLEMS, EXIT_ERROR = 0, 1, 2
_SINCE = re.compile(r"^(\d+)\s*([smhdw])$", re.IGNORECASE)
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def is_cli(argv: list[str]) -> bool:
    return len(argv) > 1 and argv[1] in COMMANDS


def parse_since(text: str) -> timedelta:
    match = _SINCE.match(text.strip())
    if match is None or int(match.group(1)) == 0:
        raise ValueError(f"'{text}' is not a period like 30m, 6h or 2d.")
    return timedelta(seconds=int(match.group(1)) * _UNITS[match.group(2).lower()])


def attach_console() -> None:
    """A windowed Windows program has no console: write to the one it was started from, when there is one."""
    if sys.platform != "win32" or (sys.stdout is not None and getattr(sys.stdout, "isatty", lambda: False)()):
        return
    try:
        import ctypes

        if ctypes.windll.kernel32.AttachConsole(-1):  # ATTACH_PARENT_PROCESS
            sys.stdout = open("CONOUT$", "w", encoding="utf-8")  # noqa: SIM115
            sys.stderr = open("CONOUT$", "w", encoding="utf-8")  # noqa: SIM115
    except (AttributeError, OSError):
        pass


def _emit(text: str, output: str | None, mask: bool) -> None:
    if mask:
        masker = SecretMasker()
        text = "\n".join(masker.mask_line(line) for line in text.splitlines())
    if output:
        Path(output).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="loglens", description="LogLens command line (no window).")
    p.add_argument("--version", action="version", version=f"LogLens {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def common(s: argparse.ArgumentParser) -> None:
        s.add_argument("--output", "-o", help="write the text to this file instead of the console")
        s.add_argument("--no-mask", action="store_true", help="do not mask passwords and tokens in the output")

    s = sub.add_parser("summary", help="what is in a log and what to look at first")
    s.add_argument("file")
    s.add_argument("--fail-on-errors", action="store_true", help="exit with 1 when the log has errors")
    common(s)

    d = sub.add_parser("diagnose", help="diagnose this computer (or a saved server) from its Windows event logs")
    d.add_argument("--since", default="24h", help="period to look at, like 1h, 24h, 7d (default 24h)")
    d.add_argument("--server", help="name of a server saved in LogLens (File → Servers)")
    d.add_argument("--fail-on-errors", action="store_true", help="exit with 1 when errors or critical findings exist")
    common(d)

    g = sub.add_parser("digest", help="what is new since the last digest in some logs; optionally send it")
    g.add_argument("paths", nargs="*", help="log files, folders or globs")
    g.add_argument(
        "--events",
        action="append",
        default=[],
        metavar="CHANNEL",
        help="Windows event log channel (repeatable), e.g. System",
    )
    g.add_argument("--server", help="read --events from a server saved in LogLens (File → Servers)")
    g.add_argument("--state", help="file that remembers what was reported (default: in %%LOCALAPPDATA%%\\LogLens)")
    g.add_argument("--webhook", help="https URL to post the digest to (Slack, Teams, …)")
    g.add_argument("--mail-to", action="append", default=[], help="recipient (repeatable)")
    g.add_argument("--mail-from", default="", help="sender address")
    g.add_argument("--smtp", default="", help="SMTP server as host or host:port (password: LOGLENS_SMTP_PASSWORD)")
    g.add_argument("--smtp-user", default="")
    g.add_argument("--only-if-news", action="store_true", help="send / print only when there is something new")
    g.add_argument("--title", default="LogLens digest")
    common(g)

    t = sub.add_parser("schedule", help="print the command that runs a digest every day (Task Scheduler)")
    t.add_argument("--daily", default="08:00", help="time of day, HH:MM (default 08:00)")
    t.add_argument("--name", default="LogLens digest")
    t.add_argument("digest_args", nargs=argparse.REMAINDER, help="arguments of the digest command, after --")
    return p


def _default_state() -> Path:
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or str(Path.home() / ".cache")
    return Path(base) / "LogLens" / "digest-state.json"


def cmd_summary(args: argparse.Namespace) -> int:
    path = Path(args.file)
    if not path.is_file():
        print(f"loglens: no such file: {path}", file=sys.stderr)
        return EXIT_ERROR
    source = TextLogSource(path)
    source.build_index()
    total = source.line_count()
    result = triage(enumerate(source.get_lines(0, total)), total)
    _emit(render_markdown(result, path.name), args.output, not args.no_mask)
    return EXIT_PROBLEMS if args.fail_on_errors and result.problems else EXIT_OK


def cmd_diagnose(args: argparse.Namespace) -> int:
    from .services.diagnosis_jobs import diagnose
    from .settings import Settings

    try:
        span = parse_since(args.since)
    except ValueError as exc:
        print(f"loglens: {exc}", file=sys.stderr)
        return EXIT_ERROR
    server = None
    if args.server:
        server = next((s for s in Settings.load().servers() if s.name.lower() == args.server.lower()), None)
        if server is None:
            print(f"loglens: no saved server named '{args.server}' (File → Servers… in LogLens).", file=sys.stderr)
            return EXIT_ERROR
    end = datetime.now().astimezone()
    result = diagnose(end - span, end, server=server)
    lines = [f"Diagnosis of {server.name if server else 'this computer'}, last {args.since} ({end:%Y-%m-%d %H:%M})", ""]
    bad = 0
    for finding in result.findings:
        severity = str(finding.severity)
        bad += severity in ("critical", "error")
        lines.append(f"[{severity}] {finding.title}")
    if not result.findings:
        lines.append("No findings.")
    lines += ["", *(f"! {w}" for w in result.warnings)]
    _emit("\n".join(lines).rstrip(), args.output, not args.no_mask)
    return EXIT_PROBLEMS if args.fail_on_errors and bad else EXIT_OK


def _mail_settings(args: argparse.Namespace) -> notify.MailSettings:
    host, _, port = args.smtp.partition(":")
    return notify.MailSettings(
        host, int(port) if port.isdigit() else 587, args.mail_from, tuple(args.mail_to), args.smtp_user
    )


def cmd_digest(args: argparse.Namespace) -> int:
    state_path = Path(args.state) if args.state else _default_state()
    state = digest_module.load_state(state_path)
    if not args.paths and not args.events:
        print("loglens: give log files or folders, or --events CHANNEL.", file=sys.stderr)
        return EXIT_ERROR
    digest = digest_module.build(args.paths, state)
    if args.events:
        server = None
        if args.server:
            from .settings import Settings

            server = next((s for s in Settings.load().servers() if s.name.lower() == args.server.lower()), None)
            if server is None:
                print(f"loglens: no saved server named '{args.server}'.", file=sys.stderr)
                return EXIT_ERROR
        extra = digest_module.build_events(args.events, state, server=server)
        digest.files += extra.files
        digest.problems += extra.problems
    text = digest.render(args.title)
    if not args.no_mask:
        masker = SecretMasker()
        text = "\n".join(masker.mask_line(line) for line in text.splitlines())
    failures: list[str] = []
    if digest.has_news or not args.only_if_news:
        if args.webhook:
            try:
                notify.post_webhook(args.webhook, text)
            except notify.DeliveryError as exc:
                failures.append(str(exc))
        if args.mail_to:
            try:
                notify.send_mail(_mail_settings(args), f"{args.title}: {digest.errors} errors", text)
            except notify.DeliveryError as exc:
                failures.append(str(exc))
        if (not args.webhook and not args.mail_to) or args.output:
            _emit(text, args.output, mask=False)
    for message in failures:
        print(f"loglens: {message}", file=sys.stderr)
    if not failures:  # only remember what was reported once it was delivered
        digest_module.save_state(state_path, state)
    return EXIT_ERROR if failures else EXIT_OK


def cmd_schedule(args: argparse.Namespace) -> int:
    if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", args.daily):
        print("loglens: --daily must be HH:MM, like 08:00.", file=sys.stderr)
        return EXIT_ERROR
    rest = [a for a in args.digest_args if a != "--"]
    if not rest:
        print("loglens: add the digest arguments after --, e.g.  -- C:\\logs --webhook https://…", file=sys.stderr)
        return EXIT_ERROR
    program = f'"{sys.executable}"' if getattr(sys, "frozen", False) else f'"{sys.executable}" -m loglens'
    action = f"{program} digest " + " ".join(f'"{a}"' if " " in a else a for a in rest)
    escaped = action.replace('"', '\\"')
    print("Run this once in a Command Prompt to create the daily task (it needs no administrator rights):")
    print()
    print(f'schtasks /Create /TN "{args.name}" /SC DAILY /ST {args.daily} /TR "{escaped}"')
    print()
    print(f'Remove it later with:  schtasks /Delete /TN "{args.name}" /F')
    return EXIT_OK


def run(argv: list[str]) -> int:
    attach_console()
    try:
        args = parser().parse_args(argv[1:])
    except SystemExit as exc:  # argparse prints help / usage errors itself
        return int(exc.code) if isinstance(exc.code, int) else EXIT_ERROR
    handlers = {"summary": cmd_summary, "diagnose": cmd_diagnose, "digest": cmd_digest, "schedule": cmd_schedule}
    try:
        return handlers[args.command](args)
    except OSError as exc:
        print(f"loglens: {exc}", file=sys.stderr)
        return EXIT_ERROR
