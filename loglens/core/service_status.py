"""Windows service status, read-only (Service Control Manager enumeration — never starts or stops anything)."""

from __future__ import annotations

import logging
import sys
from collections.abc import Iterable
from dataclasses import dataclass

log = logging.getLogger(__name__)
STATES = {1: "Stopped", 2: "Starting", 3: "Stopping", 4: "Running", 5: "Continuing", 6: "Pausing", 7: "Paused"}
SERVICE_WIN32 = 0x30  # SERVICE_WIN32_OWN_PROCESS | SERVICE_WIN32_SHARE_PROCESS
SERVICE_STATE_ALL = 0x3
SC_MANAGER_ENUMERATE_SERVICE = 0x4


@dataclass(frozen=True, slots=True)
class ServiceInfo:
    name: str
    display_name: str
    state: str


def list_services() -> list[ServiceInfo]:
    """All Win32 services with their current state, sorted by display name ([] off Windows or on error)."""
    if sys.platform != "win32":  # pragma: no cover - Windows product
        return []
    import win32service  # noqa: PLC0415 - Windows-only dependency

    try:
        manager = win32service.OpenSCManager(None, None, SC_MANAGER_ENUMERATE_SERVICE)
        try:
            rows = win32service.EnumServicesStatus(manager, SERVICE_WIN32, SERVICE_STATE_ALL)
        finally:
            win32service.CloseServiceHandle(manager)
    except win32service.error as exc:
        log.warning("cannot enumerate services: %s", exc)
        return []
    services = [
        ServiceInfo(name, display, STATES.get(status[1], f"State {status[1]}")) for name, display, status in rows
    ]
    return sorted(services, key=lambda s: s.display_name.lower())


def service_states(names: Iterable[str]) -> dict[str, str]:
    """Current state of the named services ("Not installed" for unknown names)."""
    wanted = {name.lower(): name for name in names}
    found = {s.name.lower(): s.state for s in list_services() if s.name.lower() in wanted}
    return {original: found.get(key, "Not installed") for key, original in wanted.items()}
