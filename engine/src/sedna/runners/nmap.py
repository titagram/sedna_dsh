"""Argument construction for the initial non-invasive Nmap scans."""

from __future__ import annotations

import ipaddress
import re

_HOSTNAME = re.compile(
    r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z"
)
_PORTS = re.compile(r"\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*\Z")


def nmap_tcp_discovery(target: str, *, top_ports: int = 1000) -> list[str]:
    """Build a TCP connect scan suitable for an unprivileged local user."""
    _validate_target(target)
    if not 1 <= top_ports <= 65_535:
        raise ValueError("top_ports must be between 1 and 65535")
    return ["-n", "-Pn", "-sT", "--top-ports", str(top_ports), target]


def nmap_service_scan(target: str, ports: str) -> list[str]:
    """Build service detection for explicitly enumerated ports only."""
    _validate_target(target)
    _validate_ports(ports)
    return ["-n", "-Pn", "-sT", "-sV", "-p", ports, target]


def _validate_target(target: str) -> None:
    if not target or target != target.strip() or target.startswith("-"):
        raise ValueError("target must be an IP address or hostname")
    try:
        ipaddress.ip_address(target)
    except ValueError:
        if _HOSTNAME.fullmatch(target) is None:
            raise ValueError("target must be an IP address or hostname") from None


def _validate_ports(ports: str) -> None:
    if not _PORTS.fullmatch(ports):
        raise ValueError("ports must be comma-separated ports or ranges")
    for item in ports.split(","):
        start, _, end = item.partition("-")
        first = int(start)
        last = int(end) if end else first
        if not 1 <= first <= last <= 65_535:
            raise ValueError("ports must be between 1 and 65535")
